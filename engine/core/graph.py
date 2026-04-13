from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
import os
import time
from typing import Callable, Iterable

from engine.io.cdr.base import canonical_relation
from engine.io.events import Event

try:
    from engine.core import _acmin_native
except Exception:
    _acmin_native = None


def path_factor_passes(pf: float | None, threshold: float, op: str = "ge") -> bool:
    """
    Compare path_factor threshold with consistent semantics across pipeline modules.

    - pf is None or pf <= 0.0 -> fail
    - op == "ge": pf >= threshold
    - op == "le": pf <= threshold
    """
    if pf is None:
        return False
    try:
        pf_value = float(pf)
        th_value = float(threshold)
    except (TypeError, ValueError):
        return False

    if pf_value <= 0.0:
        return False
    if op == "ge":
        return pf_value >= th_value
    if op == "le":
        return pf_value <= th_value
    raise ValueError(f"Unsupported path_factor op: {op}")


@dataclass(slots=True)
class VersionedNode:
    node_id: str
    entity_id: str
    version: int
    created_at: int
    observed_ts: str | None = None


class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"
    VERSION_TRANSITION = "version_transition"


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    event_id: str
    event_type: str
    ts: str | None
    edge_type: EdgeType = EdgeType.DATA_FLOW
    relation: str = "flow"
    src_entity: str | None = None
    dst_entity: str | None = None


@dataclass(slots=True)
class RuntimeEdge:
    edge_id: int
    src: str
    dst: str
    edge_type: EdgeType = EdgeType.DATA_FLOW
    relation: str = "flow"


class ProvenanceGraph:
    """
    Directed provenance graph with node versioning.

    External API remains entity-id based for compatibility, while internal reachability
    and edge storage operate on versioned nodes.
    """

    def __init__(
        self,
        *,
        ancestor_index_mode: str = "incremental",
        ac_min_method: str = "set_diff",
    ) -> None:
        if ancestor_index_mode not in {"incremental", "lazy"}:
            raise ValueError("ancestor_index_mode must be one of: incremental, lazy")
        if ac_min_method not in {"pairwise", "set_diff"}:
            raise ValueError("ac_min_method must be one of: pairwise, set_diff")
        # Backward-compatible entity index.
        self.nodes: set[str] = set()
        # Backward-compatible union adjacency for callers that inspect `adj`.
        self.adj: dict[str, set[str]] = defaultdict(set)
        self.rev_adj: dict[str, set[str]] = defaultdict(set)
        # Internal typed adjacency (required for version-transition cost semantics).
        self.adj_data_flow: dict[str, set[str]] = defaultdict(set)
        self.rev_adj_data_flow: dict[str, set[str]] = defaultdict(set)
        self.adj_version_transition: dict[str, set[str]] = defaultdict(set)
        self.rev_adj_version_transition: dict[str, set[str]] = defaultdict(set)
        self.runtime_edges: list[RuntimeEdge] = []
        self.edges: list[Edge] = []
        self.version_nodes: dict[str, VersionedNode] = {}
        self.entity_versions: dict[str, list[str]] = defaultdict(list)
        self.current_version: dict[str, str] = {}
        self._version_counter: dict[str, int] = defaultdict(int)
        self._creation_tick: int = 0
        self.process_parents: dict[str, set[str]] = defaultdict(set)
        self._process_ancestor_cache: dict[str, set[str]] = {}
        self._path_factor_cache: dict[str, dict[str, float]] = {}
        self._edge_hooks: list[Callable[[Edge], None]] = []
        self._prune_hooks: list[Callable[[set[str], set[str]], None]] = []
        # Incremental summaries (delta-propagated on edge addition):
        # - ancestors_by_node[n]: all ancestors (inclusive) of n
        # - min_dist_from_ancestor[n][a]: shortest weighted distance a -> n
        #   where DATA_FLOW=1 and VERSION_TRANSITION=0
        self._ancestors_by_node: dict[str, set[str]] = {}
        self._min_dist_from_ancestor: dict[str, dict[str, int]] = {}
        self.semantic_adj: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.semantic_rev_adj: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.semantic_relations: list[tuple[str, str, str]] = []
        self._memory_vma_current_entity: dict[str, str] = {}
        self._entity_last_seen_ts: dict[str, datetime] = {}
        self._version_last_seen_ts: dict[str, datetime] = {}
        self.ancestor_index_mode = ancestor_index_mode
        self.ac_min_method = ac_min_method
        self._use_native_acmin = (
            _acmin_native is not None and os.getenv("HOLMES_ACMIN_NATIVE", "1").strip().lower() not in {"0", "false", "no"}
        )
        self._ancestor_index_dirty = False
        self._union_adj_dirty = False
        self._edge_id_counter = 0
        self._runtime_edge_append_time_seconds = 0.0
        self._provenance_edge_append_time_seconds = 0.0
        self._edge_hook_time_seconds = 0.0
        self._memory_sync_time_seconds = 0.0
        self._ensure_entity_time_seconds = 0.0
        self._changed_entities_time_seconds = 0.0
        self._bump_entities_time_seconds = 0.0
        self._flow_link_time_seconds = 0.0
        self._memory_transition_link_time_seconds = 0.0
        self._semantic_register_time_seconds = 0.0
        self._typed_adjacency_add_time_seconds = 0.0
        self._event_semantic_extract_time_seconds = 0.0
        self._flow_direction_time_seconds = 0.0
        self._event_version_change_eval_time_seconds = 0.0
        self._path_factor_cache_clear_time_seconds = 0.0
        self._events_with_memory_sync = 0
        self._changed_entities_total = 0
        self._max_changed_entities = 0
        self._edges_linked_total = 0
        self._max_edges_linked_in_event = 0
        self._node_meta_time_seconds = 0.0
        self._current_version_lookup_time_seconds = 0.0
        self._new_version_node_time_seconds = 0.0
        self._semantic_current_version_lookup_time_seconds = 0.0
        self._use_on_demand_ancestor = os.getenv("HOLMES_USE_ON_DEMAND_ANCESTOR", "0").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        cap_raw = os.getenv("HOLMES_ANCESTOR_ENTRY_CAP", "12000").strip()
        try:
            self._ancestor_entry_cap = max(0, int(cap_raw))
        except ValueError:
            self._ancestor_entry_cap = 12000

    def register_edge_hook(self, hook: Callable[[Edge], None]) -> None:
        self._edge_hooks.append(hook)

    def register_prune_hook(self, hook: Callable[[set[str], set[str]], None]) -> None:
        self._prune_hooks.append(hook)

    def clear_prune_hooks(self) -> None:
        self._prune_hooks.clear()

    @staticmethod
    def _semantic_relations_for_event(event: Event) -> list[tuple[str, str, str]]:
        return list(event.semantic_relations)

    def _register_semantic_edge(self, relation: str, src_entity: str, dst_entity: str) -> None:
        lookup_started = time.perf_counter()
        src_node = self.current_version_node(src_entity)
        dst_node = self.current_version_node(dst_entity)
        self._semantic_current_version_lookup_time_seconds += time.perf_counter() - lookup_started
        if not src_node or not dst_node:
            return
        self.semantic_relations.append((canonical_relation(relation), src_entity, dst_entity))
        self.semantic_adj[relation][src_node].add(dst_node)
        self.semantic_rev_adj[relation][dst_node].add(src_node)

    @staticmethod
    def _flow_direction(event: Event) -> tuple[str, str]:
        """Resolve information-flow edge direction by operation type."""
        op = event.event_type_lower

        if op in {"write", "fork", "connect", "send"}:
            return event.subject, event.object
        if op in {"read", "exec", "recv"}:
            return event.object, event.subject

        # Fallback for unknown/custom operations: keep declared order.
        return event.subject, event.object

    def _entities_requiring_new_version(self, event: Event) -> set[str]:
        """
        Taint propagation rule (explicit):
        1) write/modify/send   -> object version++
        2) read/recv           -> subject version++
        3) exec/privilege chg  -> process(subject) version++
        4) subject/object may both change in one event (independent bumps)
           via explicit raw flags: subject_state_change/object_state_change.
        """
        if not event.subject or not event.object:
            return set()

        op = event.event_type_lower
        changed: set[str] = set()

        if op in {"write", "modify", "send", "proc_to_file", "proc_to_registry", "proc_to_ip", "file_to_ip"}:
            changed.add(event.object)
        if op in {"read", "recv", "file_to_proc"}:
            changed.add(event.subject)
        if op in {"exec", "execute", "setuid", "setgid", "privilege_change", "privilege_escalation"}:
            if self._is_process_node(event.subject):
                changed.add(event.subject)

        if event.subject_state_change:
            changed.add(event.subject)
        if event.object_state_change:
            changed.add(event.object)

        # Safety fallback for unknown/custom operations: mutate object state so flow
        # edges remain forward in version-time and the internal graph stays acyclic.
        if not changed:
            changed.add(event.object)
        return changed

    def _next_tick(self) -> int:
        self._creation_tick += 1
        return self._creation_tick

    @staticmethod
    def _parse_ts(value: str | None) -> datetime | None:
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None
        try:
            numeric = float(raw)
            abs_numeric = abs(numeric)
            if abs_numeric >= 1e17:
                numeric /= 1_000_000_000.0
            elif abs_numeric >= 1e14:
                numeric /= 1_000_000.0
            elif abs_numeric >= 1e11:
                numeric /= 1_000.0
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass
        normalized = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)

    def _node_meta(self, node_id: str) -> VersionedNode:
        started = time.perf_counter()
        try:
            return self.version_nodes[node_id]
        finally:
            self._node_meta_time_seconds += time.perf_counter() - started

    def _node_entity(self, node_id: str) -> str:
        return self.version_nodes[node_id].entity_id

    def _new_version_node(
        self,
        entity_id: str,
        observed_ts: str | None = None,
        *,
        observed_dt: datetime | None = None,
    ) -> str:
        started = time.perf_counter()
        next_version = self._version_counter[entity_id] + 1
        self._version_counter[entity_id] = next_version
        node_id = f"{entity_id}#v{next_version}"
        node = VersionedNode(
            node_id=node_id,
            entity_id=entity_id,
            version=next_version,
            created_at=self._next_tick(),
            observed_ts=observed_ts,
        )
        self.version_nodes[node_id] = node
        self.entity_versions[entity_id].append(node_id)
        self.nodes.add(entity_id)
        if not self._use_on_demand_ancestor:
            self._ancestors_by_node[node_id] = {node_id}
            self._min_dist_from_ancestor[node_id] = {node_id: 0}
        if observed_dt is not None:
            self._version_last_seen_ts[node_id] = observed_dt
            prev_entity_ts = self._entity_last_seen_ts.get(entity_id)
            if prev_entity_ts is None or observed_dt > prev_entity_ts:
                self._entity_last_seen_ts[entity_id] = observed_dt
        self._new_version_node_time_seconds += time.perf_counter() - started
        return node_id

    def current_version_node(self, entity_id: str | None) -> str | None:
        if not entity_id:
            return None
        started = time.perf_counter()
        try:
            return self.current_version.get(entity_id)
        finally:
            self._current_version_lookup_time_seconds += time.perf_counter() - started

    def _ensure_entity(self, entity_id: str) -> str:
        cur = self.current_version.get(entity_id)
        if cur is not None:
            return cur
        node_id = self._new_version_node(entity_id)
        self.current_version[entity_id] = node_id
        return node_id

    def _link_version_edge(
        self,
        src_node: str,
        dst_node: str,
        event: Event,
        edge_type: EdgeType,
        relation: str,
    ) -> None:
        version_nodes = self.version_nodes
        node_meta_started = time.perf_counter()
        try:
            src_meta = version_nodes[src_node]
            dst_meta = version_nodes[dst_node]
        finally:
            self._node_meta_time_seconds += time.perf_counter() - node_meta_started
        if src_meta.created_at >= dst_meta.created_at:
            raise ValueError("Versioned DAG invariant violated: non-forward edge creation attempted")

        typed_adjacency_started = time.perf_counter()
        if edge_type == EdgeType.DATA_FLOW:
            adj_data_flow = self.adj_data_flow
            rev_adj_data_flow = self.rev_adj_data_flow
            adj_data_flow[src_node].add(dst_node)
            rev_adj_data_flow[dst_node].add(src_node)
        elif edge_type == EdgeType.VERSION_TRANSITION:
            adj_version_transition = self.adj_version_transition
            rev_adj_version_transition = self.rev_adj_version_transition
            adj_version_transition[src_node].add(dst_node)
            rev_adj_version_transition[dst_node].add(src_node)
        else:
            raise ValueError(f"Unsupported edge_type: {edge_type}")
        self._typed_adjacency_add_time_seconds += time.perf_counter() - typed_adjacency_started

        self._union_adj_dirty = True
        edge_id = self._edge_id_counter
        self._edge_id_counter += 1
        runtime_edge_started = time.perf_counter()
        self.runtime_edges.append(
            RuntimeEdge(
                edge_id=edge_id,
                src=src_node,
                dst=dst_node,
                edge_type=edge_type,
                relation=relation,
            )
        )
        self._runtime_edge_append_time_seconds += time.perf_counter() - runtime_edge_started
        provenance_edge_started = time.perf_counter()
        self.edges.append(
            Edge(
                src=src_node,
                dst=dst_node,
                event_id=event.event_id,
                event_type=event.event_type,
                ts=event.ts,
                edge_type=edge_type,
                relation=relation,
                src_entity=src_meta.entity_id,
                dst_entity=dst_meta.entity_id,
            )
        )
        self._provenance_edge_append_time_seconds += time.perf_counter() - provenance_edge_started
        emitted = self.edges[-1]
        if self.ancestor_index_mode == "incremental":
            self._propagate_ancestor_distance_delta(src_node, dst_node, edge_type)
        else:
            self._ancestor_index_dirty = True
        edge_hook_started = time.perf_counter()
        for hook in self._edge_hooks:
            hook(emitted)
        self._edge_hook_time_seconds += time.perf_counter() - edge_hook_started

    def _ensure_ancestor_index(self) -> None:
        if self._use_on_demand_ancestor:
            return
        if self.ancestor_index_mode == "incremental" and not self._ancestor_index_dirty:
            return
        if self.ancestor_index_mode == "lazy" and not self._ancestor_index_dirty:
            return
        self._rebuild_indexes_from_current_state()

    def _ensure_union_adjacency(self) -> None:
        if not self._union_adj_dirty:
            return
        self.adj = defaultdict(set)
        self.rev_adj = defaultdict(set)
        for src, nbrs in self.adj_data_flow.items():
            for dst in nbrs:
                self.adj[src].add(dst)
                self.rev_adj[dst].add(src)
        for src, nbrs in self.adj_version_transition.items():
            for dst in nbrs:
                self.adj[src].add(dst)
                self.rev_adj[dst].add(src)
        self._union_adj_dirty = False

    def _propagate_ancestor_distance_delta(self, src_node: str, dst_node: str, edge_type: EdgeType) -> None:
        if self._use_on_demand_ancestor:
            return
        edge_cost = self._edge_cost(edge_type)
        src_dist = self._min_dist_from_ancestor.get(src_node, {})
        if not src_dist:
            return

        # Queue items: (source, destination, edge_cost, delta_from_source)
        q: deque[tuple[str, str, int, dict[str, int]]] = deque([(src_node, dst_node, edge_cost, dict(src_dist))])
        while q:
            _src, cur_dst, cur_cost, delta = q.popleft()
            dst_dist = self._min_dist_from_ancestor.setdefault(cur_dst, {cur_dst: 0})
            dst_anc = self._ancestors_by_node.setdefault(cur_dst, {cur_dst})

            changed_delta: dict[str, int] = {}
            for anc, anc_to_src in delta.items():
                cand = int(anc_to_src) + int(cur_cost)
                prev = dst_dist.get(anc)
                if prev is None or cand < prev:
                    dst_dist[anc] = cand
                    dst_anc.add(anc)
                    changed_delta[anc] = cand

            if not changed_delta:
                continue

            self._apply_ancestor_entry_cap(cur_dst)

            for nxt, nxt_type in self._iter_neighbors(cur_dst):
                nxt_cost = self._edge_cost(nxt_type)
                q.append((cur_dst, nxt, nxt_cost, changed_delta))

    def _apply_ancestor_entry_cap(self, node_id: str) -> None:
        cap = int(self._ancestor_entry_cap)
        if cap <= 0:
            return
        dist = self._min_dist_from_ancestor.get(node_id)
        anc = self._ancestors_by_node.get(node_id)
        if not dist or not anc or len(dist) <= cap:
            return

        self_dist = dist.get(node_id, 0)
        # Keep the node itself + lowest-distance ancestors.
        items = sorted(dist.items(), key=lambda kv: (int(kv[1]), str(kv[0])))
        kept_pairs = items[: cap]
        kept_keys = {k for k, _ in kept_pairs}
        if node_id not in kept_keys:
            # Ensure self entry is retained.
            if kept_pairs:
                drop_key = kept_pairs[-1][0]
                kept_keys.discard(drop_key)
            kept_keys.add(node_id)

        self._min_dist_from_ancestor[node_id] = {k: (self_dist if k == node_id else int(dist[k])) for k in kept_keys}
        self._ancestors_by_node[node_id] = set(kept_keys)

    def _bump_entity(
        self,
        entity_id: str,
        event: Event,
        *,
        event_dt: datetime | None = None,
        prev_node: str | None = None,
    ) -> str:
        prev = prev_node if prev_node is not None else self._ensure_entity(entity_id)
        new_node = self._new_version_node(entity_id, observed_ts=event.ts, observed_dt=event_dt)
        self.current_version[entity_id] = new_node
        self._link_version_edge(
            prev,
            new_node,
            event,
            edge_type=EdgeType.VERSION_TRANSITION,
            relation="prev_version",
        )
        return new_node

    def _all_versions(self, entity_id: str) -> list[str]:
        return list(self.entity_versions.get(entity_id, []))

    def _resolve_query_nodes(self, token: str) -> list[str]:
        if token in self.version_nodes:
            return [token]
        if token in self.nodes:
            return self._all_versions(token)
        return []

    def _iter_neighbors(self, node_id: str) -> Iterable[tuple[str, EdgeType]]:
        for nxt in self.adj_data_flow.get(node_id, set()):
            yield nxt, EdgeType.DATA_FLOW
        for nxt in self.adj_version_transition.get(node_id, set()):
            yield nxt, EdgeType.VERSION_TRANSITION

    def _iter_prev(self, node_id: str) -> Iterable[str]:
        for prev in self.rev_adj_data_flow.get(node_id, set()):
            yield prev
        for prev in self.rev_adj_version_transition.get(node_id, set()):
            yield prev

    @staticmethod
    def _edge_cost(edge_type: EdgeType) -> int:
        return 0 if edge_type == EdgeType.VERSION_TRANSITION else 1

    def _bfs_desc_version(self, starts: list[str]) -> set[str]:
        if not starts:
            return set()
        seen: set[str] = set(starts)
        q: deque[str] = deque(starts)
        while q:
            cur = q.popleft()
            for nxt, _edge_type in self._iter_neighbors(cur):
                if nxt in seen:
                    continue
                seen.add(nxt)
                q.append(nxt)
        return seen

    def _bfs_anc_version(self, starts: list[str]) -> set[str]:
        if not starts:
            return set()
        seen: set[str] = set(starts)
        q: deque[str] = deque(starts)
        while q:
            cur = q.popleft()
            for prev in self._iter_prev(cur):
                if prev in seen:
                    continue
                seen.add(prev)
                q.append(prev)
        return seen

    def _shortest_version_path(self, src: str, dst: str) -> list[str] | None:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return None

        q: deque[str] = deque(starts)
        parent: dict[str, str | None] = {s: None for s in starts}
        hit: str | None = None
        while q and hit is None:
            cur = q.popleft()
            if cur in targets:
                hit = cur
                break
            for nxt in self._iter_neighbors(cur):
                node = nxt[0]
                if node in parent:
                    continue
                parent[node] = cur
                q.append(node)

        if hit is None:
            return None

        out: list[str] = []
        cur: str | None = hit
        while cur is not None:
            out.append(cur)
            cur = parent.get(cur)
        out.reverse()
        return out

    def _shortest_version_distance(self, src: str, dst: str) -> int | None:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return None
        best: int | None = None
        for t in targets:
            t_dist = self._min_dist_from_ancestor.get(t, {})
            for s in starts:
                d = t_dist.get(s)
                if d is None:
                    continue
                if best is None or int(d) < best:
                    best = int(d)
        return best

    def add_event(self, event: Event) -> dict[str, str] | None:
        """
        Add event-derived edges and return endpoint version-node ids.

        Return shape:
        {
          "flow_src_version": "<entity#vN>",
          "flow_dst_version": "<entity#vM>",
        }
        """
        if not event.subject or not event.object:
            return None
        ensure_entity = self._ensure_entity
        bump_entity = self._bump_entity
        link_version_edge = self._link_version_edge
        register_semantic_edge = self._register_semantic_edge
        current_version = self.current_version
        entity_last_seen_ts = self._entity_last_seen_ts
        event_dt = event.parsed_ts
        event_semantic_extract_started = time.perf_counter()
        semantic_relations = self._semantic_relations_for_event(event)
        self._event_semantic_extract_time_seconds += time.perf_counter() - event_semantic_extract_started
        memory_transition: tuple[str, str] | None = None
        edges_linked_this_event = 0
        if event.is_memory_object:
            memory_sync_started = time.perf_counter()
            original_object = event.object
            synchronized_object, memory_transition = self._synchronize_memory_vma(
                event,
                semantic_relations=semantic_relations,
            )
            event.object = synchronized_object
            raw = event.raw if isinstance(event.raw, dict) else None
            cdr = raw.get("cdr") if isinstance(raw, dict) and isinstance(raw.get("cdr"), dict) else None
            relations = cdr.get("semantic_relations") if isinstance(cdr, dict) and isinstance(cdr.get("semantic_relations"), list) else None
            if relations is not None:
                for item in relations:
                    if not isinstance(item, dict):
                        continue
                    if item.get("dst") == original_object:
                        item["dst"] = synchronized_object
            if synchronized_object != original_object:
                semantic_relations = [
                    (relation, semantic_src, synchronized_object if semantic_dst == original_object else semantic_dst)
                    for relation, semantic_src, semantic_dst in semantic_relations
                ]
            self._memory_sync_time_seconds += time.perf_counter() - memory_sync_started
            self._events_with_memory_sync += 1

        flow_direction_started = time.perf_counter()
        src_entity, dst_entity = self._flow_direction(event)
        self._flow_direction_time_seconds += time.perf_counter() - flow_direction_started
        ensure_entity_started = time.perf_counter()
        ensure_entity(src_entity)
        ensure_entity(dst_entity)
        self._ensure_entity_time_seconds += time.perf_counter() - ensure_entity_started
        if event_dt is not None:
            entity_last_seen_ts[src_entity] = event_dt
            entity_last_seen_ts[dst_entity] = event_dt

        pre_src = current_version[src_entity]
        pre_dst = current_version[dst_entity]

        changed_entities_started = time.perf_counter()
        changed_entities = self._entities_requiring_new_version(event)
        self._event_version_change_eval_time_seconds += time.perf_counter() - changed_entities_started
        # Enforce receiver-post-state modeling so all flow edges stay forward in version-time.
        if dst_entity not in changed_entities:
            changed_entities.add(dst_entity)
        self._changed_entities_total += len(changed_entities)
        self._max_changed_entities = max(self._max_changed_entities, len(changed_entities))
        self._changed_entities_time_seconds += time.perf_counter() - changed_entities_started

        post_by_entity: dict[str, str] = {}
        prev_by_entity = {entity_id: current_version[entity_id] for entity_id in changed_entities}
        bump_entities_started = time.perf_counter()
        for entity_id in sorted(changed_entities):
            post_by_entity[entity_id] = bump_entity(
                entity_id,
                event,
                event_dt=event_dt,
                prev_node=prev_by_entity[entity_id],
            )
            edges_linked_this_event += 1
        self._bump_entities_time_seconds += time.perf_counter() - bump_entities_started

        flow_src = pre_src
        flow_dst = post_by_entity.get(dst_entity, pre_dst)
        flow_link_started = time.perf_counter()
        link_version_edge(
            flow_src,
            flow_dst,
            event,
            edge_type=EdgeType.DATA_FLOW,
            relation="flow",
        )
        edges_linked_this_event += 1
        self._flow_link_time_seconds += time.perf_counter() - flow_link_started
        if memory_transition is not None:
            memory_transition_link_started = time.perf_counter()
            previous_memory_entity, current_memory_entity = memory_transition
            previous_memory_node = ensure_entity(previous_memory_entity)
            current_memory_node = current_version[current_memory_entity]
            if previous_memory_node != current_memory_node:
                link_version_edge(
                    previous_memory_node,
                    current_memory_node,
                    event,
                    edge_type=EdgeType.VERSION_TRANSITION,
                    relation="vma_prev_version",
                )
                edges_linked_this_event += 1
            self._memory_transition_link_time_seconds += time.perf_counter() - memory_transition_link_started
        self._edges_linked_total += edges_linked_this_event
        self._max_edges_linked_in_event = max(self._max_edges_linked_in_event, edges_linked_this_event)
        path_factor_cache_clear_started = time.perf_counter()
        self._path_factor_cache.clear()
        self._path_factor_cache_clear_time_seconds += time.perf_counter() - path_factor_cache_clear_started

        # Process lineage relation for common-ancestor checks.
        if event.event_type_lower in {"proc_to_proc", "fork"} and self._is_process_node(event.subject) and self._is_process_node(event.object):
            self.process_parents[event.object].add(event.subject)
            self._process_ancestor_cache.clear()
        semantic_register_started = time.perf_counter()
        for relation, semantic_src, semantic_dst in semantic_relations:
            register_semantic_edge(relation, semantic_src, semantic_dst)
        self._semantic_register_time_seconds += time.perf_counter() - semantic_register_started
        return {
            "flow_src_version": flow_src,
            "flow_dst_version": flow_dst,
            "subject_node_id": current_version[event.subject],
            "object_node_id": current_version[event.object],
        }

    def nodes_on_shortest_version_path(self, src: str, dst: str) -> set[str]:
        version_path = self._shortest_version_path(src, dst)
        if version_path is None:
            return set()
        return set(version_path)

    def exact_mac_nodes(self, src: str, dst: str) -> set[str]:
        return set(self.ac_min(src, dst))

    def prune_stale_orphaned(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
    ) -> dict[str, int]:
        watermark = self._parse_ts(watermark_ts)
        if watermark is None or retention_seconds < 0:
            return {"entities_removed": 0, "version_nodes_removed": 0, "edges_removed": 0}
        cutoff = watermark - timedelta(seconds=int(retention_seconds))
        protected_entity_set = set(protected_entities or set())
        protected_version_set = set(protected_version_nodes or set())

        removable_entities: set[str] = set()
        for entity_id in list(self.nodes):
            if entity_id in protected_entity_set:
                continue
            version_ids = list(self.entity_versions.get(entity_id, []))
            if not version_ids:
                continue
            if any(version_id in protected_version_set for version_id in version_ids):
                continue
            entity_ts = self._entity_last_seen_ts.get(entity_id)
            if entity_ts is None or entity_ts > cutoff:
                continue
            removable_entities.add(entity_id)

        if not removable_entities:
            return {"entities_removed": 0, "version_nodes_removed": 0, "edges_removed": 0}

        removable_version_nodes = {
            node_id
            for entity_id in removable_entities
            for node_id in self.entity_versions.get(entity_id, [])
            if node_id not in protected_version_set
        }
        old_edge_count = len(self.edges)
        old_semantic_count = len(self.semantic_relations)
        self.runtime_edges = [
            edge
            for edge in self.runtime_edges
            if edge.src not in removable_version_nodes and edge.dst not in removable_version_nodes
        ]
        self.edges = [
            edge
            for edge in self.edges
            if edge.src not in removable_version_nodes and edge.dst not in removable_version_nodes
        ]
        self.semantic_relations = [
            (relation, src_entity, dst_entity)
            for relation, src_entity, dst_entity in self.semantic_relations
            if src_entity not in removable_entities and dst_entity not in removable_entities
        ]
        for entity_id in removable_entities:
            self.nodes.discard(entity_id)
            self.current_version.pop(entity_id, None)
            self.entity_versions.pop(entity_id, None)
            self._version_counter.pop(entity_id, None)
            self._entity_last_seen_ts.pop(entity_id, None)
            self.process_parents.pop(entity_id, None)
            self._memory_vma_current_entity.pop(self._memory_base_key(entity_id) or "", None)
        for node_id in removable_version_nodes:
            self.version_nodes.pop(node_id, None)
            self._ancestors_by_node.pop(node_id, None)
            self._min_dist_from_ancestor.pop(node_id, None)
            self._version_last_seen_ts.pop(node_id, None)

        self._process_ancestor_cache.clear()
        self._path_factor_cache.clear()
        self._rebuild_adjacency_only_from_current_state()
        self._remove_pruned_nodes_from_indexes(removable_version_nodes)
        removed_entities_payload = set(removable_entities)
        removed_versions_payload = set(removable_version_nodes)
        for hook in self._prune_hooks:
            hook(removed_entities_payload, removed_versions_payload)
        return {
            "entities_removed": len(removable_entities),
            "version_nodes_removed": len(removable_version_nodes),
            "edges_removed": old_edge_count - len(self.edges),
            "semantic_edges_removed": old_semantic_count - len(self.semantic_relations),
        }

    def _rebuild_adjacency_only_from_current_state(self) -> None:
        self.adj = defaultdict(set)
        self.rev_adj = defaultdict(set)
        self.adj_data_flow = defaultdict(set)
        self.rev_adj_data_flow = defaultdict(set)
        self.adj_version_transition = defaultdict(set)
        self.rev_adj_version_transition = defaultdict(set)
        self.semantic_adj = defaultdict(lambda: defaultdict(set))
        self.semantic_rev_adj = defaultdict(lambda: defaultdict(set))
        for edge in self.runtime_edges:
            if edge.src not in self.version_nodes or edge.dst not in self.version_nodes:
                continue
            if edge.edge_type == EdgeType.DATA_FLOW:
                self.adj_data_flow[edge.src].add(edge.dst)
                self.rev_adj_data_flow[edge.dst].add(edge.src)
            else:
                self.adj_version_transition[edge.src].add(edge.dst)
                self.rev_adj_version_transition[edge.dst].add(edge.src)
            self.adj[edge.src].add(edge.dst)
            self.rev_adj[edge.dst].add(edge.src)
        for relation, src_entity, dst_entity in self.semantic_relations:
            src_node = self.current_version_node(src_entity)
            dst_node = self.current_version_node(dst_entity)
            if not src_node or not dst_node:
                continue
            self.semantic_adj[relation][src_node].add(dst_node)
            self.semantic_rev_adj[relation][dst_node].add(src_node)
        self._union_adj_dirty = False

    def _remove_pruned_nodes_from_indexes(self, removed_version_nodes: set[str]) -> None:
        if not removed_version_nodes:
            return
        removed = set(removed_version_nodes)
        for node_id in removed:
            self._ancestors_by_node.pop(node_id, None)
            self._min_dist_from_ancestor.pop(node_id, None)

        for node_id, anc_set in list(self._ancestors_by_node.items()):
            if anc_set & removed:
                anc_set.difference_update(removed)
                anc_set.add(node_id)
                self._ancestors_by_node[node_id] = anc_set

        for node_id, dist in list(self._min_dist_from_ancestor.items()):
            touched = False
            for rid in removed:
                if rid in dist:
                    dist.pop(rid, None)
                    touched = True
            if touched:
                dist[node_id] = min(dist.get(node_id, 0), 0)
                self._min_dist_from_ancestor[node_id] = dist
            self._apply_ancestor_entry_cap(node_id)

        # Keep indexes usable without immediate full rebuild.
        self._ancestor_index_dirty = False

    def _rebuild_indexes_from_current_state(self) -> None:
        self.adj = defaultdict(set)
        self.rev_adj = defaultdict(set)
        self.adj_data_flow = defaultdict(set)
        self.rev_adj_data_flow = defaultdict(set)
        self.adj_version_transition = defaultdict(set)
        self.rev_adj_version_transition = defaultdict(set)
        self.semantic_adj = defaultdict(lambda: defaultdict(set))
        self.semantic_rev_adj = defaultdict(lambda: defaultdict(set))
        self._ancestors_by_node = {}
        self._min_dist_from_ancestor = {}
        if not self._use_on_demand_ancestor:
            for node_id in self.version_nodes:
                self._ancestors_by_node[node_id] = {node_id}
                self._min_dist_from_ancestor[node_id] = {node_id: 0}
        for edge in self.runtime_edges:
            if edge.src not in self.version_nodes or edge.dst not in self.version_nodes:
                continue
            if edge.edge_type == EdgeType.DATA_FLOW:
                self.adj_data_flow[edge.src].add(edge.dst)
                self.rev_adj_data_flow[edge.dst].add(edge.src)
            else:
                self.adj_version_transition[edge.src].add(edge.dst)
                self.rev_adj_version_transition[edge.dst].add(edge.src)
            self.adj[edge.src].add(edge.dst)
            self.rev_adj[edge.dst].add(edge.src)
        if not self._use_on_demand_ancestor:
            for edge in self.runtime_edges:
                if edge.src not in self.version_nodes or edge.dst not in self.version_nodes:
                    continue
                self._propagate_ancestor_distance_delta(edge.src, edge.dst, edge.edge_type)
        for relation, src_entity, dst_entity in self.semantic_relations:
            src_node = self.current_version_node(src_entity)
            dst_node = self.current_version_node(dst_entity)
            if not src_node or not dst_node:
                continue
            self.semantic_adj[relation][src_node].add(dst_node)
            self.semantic_rev_adj[relation][dst_node].add(src_node)
        self._ancestor_index_dirty = False
        self._union_adj_dirty = False

    def add_events(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add_event(event)

    def has_path(self, src: str, dst: str) -> bool:
        return self.path(src, dst) is not None

    def has_path_fast(self, src: str, dst: str) -> bool:
        """
        Fast reachability check using cached ancestor index.

        This avoids shortest-path BFS when only connectivity is needed.
        """
        if src == dst:
            return True
        src_nodes = set(self._resolve_query_nodes(src))
        dst_nodes = set(self._resolve_query_nodes(dst))
        if not src_nodes or not dst_nodes:
            return False
        if self._use_on_demand_ancestor:
            return self._has_path_between_version_nodes(src_nodes, dst_nodes)
        self._ensure_ancestor_index()
        for d in dst_nodes:
            d_ancs = self._ancestors_by_node.get(d, set())
            if not d_ancs.isdisjoint(src_nodes):
                return True
        return False

    def has_any_path_fast(self, src_entities: Iterable[str], dst_entities: Iterable[str]) -> bool:
        """
        Batched fast reachability check.

        Returns True when any src -> any dst path exists.
        """
        src_nodes: set[str] = set()
        for src in src_entities:
            if not src:
                continue
            src_nodes.update(self._resolve_query_nodes(src))
        if not src_nodes:
            return False
        dst_nodes: set[str] = set()
        for dst in dst_entities:
            if not dst:
                continue
            dst_nodes.update(self._resolve_query_nodes(dst))
        if not dst_nodes:
            return False
        if self._use_on_demand_ancestor:
            return self._has_path_between_version_nodes(src_nodes, dst_nodes)
        self._ensure_ancestor_index()
        for d in dst_nodes:
            d_ancs = self._ancestors_by_node.get(d, set())
            if not d_ancs.isdisjoint(src_nodes):
                return True
        return False

    def _has_path_between_version_nodes(self, src_nodes: set[str], dst_nodes: set[str]) -> bool:
        if not src_nodes or not dst_nodes:
            return False
        q: deque[str] = deque(src_nodes)
        seen: set[str] = set(src_nodes)
        while q:
            cur = q.popleft()
            if cur in dst_nodes:
                return True
            for nxt, _edge_type in self._iter_neighbors(cur):
                if nxt in seen:
                    continue
                seen.add(nxt)
                q.append(nxt)
        return False

    def _all_ancestors_for_nodes(self, nodes: list[str]) -> set[str]:
        if not nodes:
            return set()
        return self._bfs_anc_version(nodes)

    def descendants(self, node: str) -> set[str]:
        """Entity-level reachability projection from all versions of entity `node`."""
        if node not in self.nodes:
            return set()
        version_seen = self._bfs_desc_version(self._all_versions(node))
        return {self._node_entity(v) for v in version_seen}

    def ancestors(self, node: str) -> set[str]:
        """Entity-level reverse reachability projection to all versions of entity `node`."""
        if node not in self.nodes:
            return set()
        version_seen = self._bfs_anc_version(self._all_versions(node))
        return {self._node_entity(v) for v in version_seen}

    def shortest_path_len(self, src: str, dst: str) -> int | None:
        """
        Return shortest directed path length between entity ids over versioned DAG.

        - If no src -> dst path exists, returns None.
        - If src == dst and the node exists, returns 0.
        """
        if src == dst:
            return 0 if src in self.nodes or src in self.version_nodes else None
        if self._use_on_demand_ancestor:
            return self._shortest_version_distance_ondemand(src, dst)
        self._ensure_ancestor_index()
        return self._shortest_version_distance(src, dst)

    def _shortest_version_distance_ondemand(self, src: str, dst: str) -> int | None:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return None
        dist: dict[str, int] = {}
        dq: deque[str] = deque()
        for s in starts:
            dist[s] = 0
            dq.appendleft(s)
        while dq:
            cur = dq.popleft()
            cur_d = dist[cur]
            if cur in targets:
                return cur_d
            for nxt, edge_type in self._iter_neighbors(cur):
                w = self._edge_cost(edge_type)
                cand = cur_d + w
                prev = dist.get(nxt)
                if prev is None or cand < prev:
                    dist[nxt] = cand
                    if w == 0:
                        dq.appendleft(nxt)
                    else:
                        dq.append(nxt)
        return None

    def attenuation(self, distance: int) -> float:
        """Paper-style distance attenuation over weighted DAG distance."""
        d = max(0, int(distance))
        return 1.0 / (1.0 + float(d))

    def ac(self, x: str, y: str) -> set[str]:
        """AC(x,y): set of common ancestors over resolved version nodes."""
        x_nodes = self._resolve_query_nodes(x)
        y_nodes = self._resolve_query_nodes(y)
        if not x_nodes or not y_nodes:
            return set()
        if self._use_on_demand_ancestor:
            anc_x = self._all_ancestors_for_nodes(x_nodes)
            anc_y = self._all_ancestors_for_nodes(y_nodes)
            return anc_x & anc_y
        self._ensure_ancestor_index()
        anc_x: set[str] = set()
        anc_y: set[str] = set()
        for xn in x_nodes:
            anc_x |= self._ancestors_by_node.get(xn, set())
        for yn in y_nodes:
            anc_y |= self._ancestors_by_node.get(yn, set())
        return anc_x & anc_y

    def ac_min(self, x: str, y: str) -> set[str]:
        """
        AC_min(x,y): common ancestors that are not ancestors of another common ancestor.
        """
        common = self.ac(x, y)
        if not common:
            return set()

        if self._use_on_demand_ancestor:
            result = set(common)
            for b in common:
                strict_ancestors = self._bfs_anc_version([b]) - {b}
                result.difference_update(strict_ancestors)
            return result

        if self.ac_min_method == "pairwise":
            result: set[str] = set()
            for a in common:
                is_min = True
                for b in common:
                    if a == b:
                        continue
                    if a in self._ancestors_by_node.get(b, set()):
                        is_min = False
                        break
                if is_min:
                    result.add(a)
            return result

        if self._use_native_acmin:
            try:
                return _acmin_native.ac_min_setdiff(common, self._ancestors_by_node)
            except Exception:
                # Fallback to Python path on any native error.
                pass

        result = set(common)
        for b in common:
            strict_ancestors = self._ancestors_by_node.get(b, set()) - {b}
            result.difference_update(strict_ancestors)
        return result

    def minimum_ancestral_cover_size(self, src: str, dst: str) -> int | None:
        return self.exact_mac_size(src, dst)

    def exact_mac_size(self, src: str, dst: str) -> int | None:
        if not self._use_on_demand_ancestor:
            self._ensure_ancestor_index()
        if src in self.version_nodes or dst in self.version_nodes:
            cover = self.ac_min(src, dst)
            if not cover:
                return None
            return len(cover)
        if not self.has_path_fast(src, dst):
            return None
        cover = self.ac_min(src, dst)
        if not cover:
            return None
        return len(cover)

    def dependency_strength(self, src: str, dst: str) -> float:
        """
        Backward-compatible alias derived from exact MAC size.
        """
        self._ensure_ancestor_index()
        mac_size = self.exact_mac_size(src, dst)
        if mac_size is None or mac_size <= 0:
            return 0.0
        return 1.0 / float(mac_size)

    @staticmethod
    def _is_process_node(node: str | None) -> bool:
        if not node:
            return False
        return node.split(":", 1)[0].lower() in {"proc", "proc_guid", "proc_pid"}

    @staticmethod
    def _memory_base_key(entity_id: str | None) -> str | None:
        if not entity_id or not entity_id.startswith("mem:"):
            return None
        parts = entity_id.split(":")
        if len(parts) < 4:
            return None
        return ":".join(parts[:3])

    @staticmethod
    def _memory_entity_with_version(base_key: str, version: int) -> str:
        return f"{base_key}:{version}"

    def _synchronize_memory_vma(
        self,
        event: Event,
        *,
        semantic_relations: list[tuple[str, str, str]] | None = None,
    ) -> tuple[str | None, tuple[str, str] | None]:
        if not event.object or not event.object.startswith("mem:"):
            return event.object, None
        base_key = self._memory_base_key(event.object)
        if base_key is None:
            return event.object, None
        relations = {relation for relation, _src, _dst in (semantic_relations or [])}
        current_entity = self._memory_vma_current_entity.get(base_key)
        if {"make_mem_exec", "protect_memory_exec"} & relations:
            next_version = 1
            if current_entity is not None:
                try:
                    next_version = int(current_entity.rsplit(":", 1)[1]) + 1
                except ValueError:
                    next_version = 1
            next_entity = self._memory_entity_with_version(base_key, next_version)
            self._memory_vma_current_entity[base_key] = next_entity
            if current_entity is None:
                return next_entity, None
            return next_entity, (current_entity, next_entity)
        if current_entity is None:
            current_entity = self._memory_entity_with_version(base_key, 1)
            self._memory_vma_current_entity[base_key] = current_entity
        return current_entity, None

    def _process_ancestors(self, process_node: str) -> set[str]:
        if process_node in self._process_ancestor_cache:
            return self._process_ancestor_cache[process_node]

        ancestors: set[str] = {process_node}
        q: deque[str] = deque([process_node])
        while q:
            cur = q.popleft()
            for parent in self.process_parents.get(cur, set()):
                if parent in ancestors:
                    continue
                ancestors.add(parent)
                q.append(parent)
        self._process_ancestor_cache[process_node] = ancestors
        return ancestors

    def _has_common_ancestor(self, process_a: str, process_b: str) -> bool:
        return bool(self._process_ancestors(process_a) & self._process_ancestors(process_b))

    def _paper_path_factor_map(self, src: str) -> dict[str, float]:
        """
        Paper-faithful incremental propagation (MVP):
        - pf(src, src) = 1
        - transition u -> v:
            * if v is non-process: no increment
            * if v is process and src/v share common ancestor: no increment
            * else increment by 1
        - multi-path case uses min accumulated value.
        """
        if src not in self.nodes:
            return {}

        # Dijkstra on non-negative edge costs (0/1) to realize min over multiple flows.
        import heapq

        starts = self._all_versions(src)
        best: dict[str, float] = {}
        heap: list[tuple[float, str]] = []
        for s in starts:
            best[s] = 1.0
            heap.append((1.0, s))
        heapq.heapify(heap)

        while heap:
            cur_pf, cur = heapq.heappop(heap)
            if cur_pf > best.get(cur, float("inf")):
                continue

            for nxt, edge_type in self._iter_neighbors(cur):
                inc = 0.0
                nxt_entity = self._node_entity(nxt)
                if edge_type == EdgeType.DATA_FLOW and self._is_process_node(nxt_entity):
                    if not (self._is_process_node(src) and self._has_common_ancestor(src, nxt_entity)):
                        inc = 1.0
                cand = cur_pf + inc
                if cand < best.get(nxt, float("inf")):
                    best[nxt] = cand
                    heapq.heappush(heap, (cand, nxt))
        out: dict[str, float] = {}
        for node_id, pf in best.items():
            entity = self._node_entity(node_id)
            prev = out.get(entity)
            if prev is None or pf < prev:
                out[entity] = pf
        return out

    def path_factor_legacy_mac(self, src: str, dst: str) -> float:
        """
        Legacy B5/B6 approximation retained for compatibility experiments.
        """
        cut_size = self.min_vertex_cut_size(src, dst)
        if cut_size is None:
            return 0.0
        return 1.0 / (1.0 + max(cut_size, 1))

    def min_vertex_cut_size(self, src: str, dst: str) -> int | None:
        """
        Return minimum number of intermediate vertices needed to disconnect src -> dst.

        - Directed cut, src/dst are excluded from removable vertices.
        - If no src -> dst path exists, returns None.
        """
        if not self.has_path(src, dst):
            return None
        if src == dst:
            return 0

        sub_nodes = self.descendants(src) & self.ancestors(dst)
        if src not in sub_nodes or dst not in sub_nodes:
            return None
        nodes = list(sub_nodes)
        inf = float("inf")
        entity_adj = self._entity_adjacency()

        capacity: dict[str, dict[str, float]] = defaultdict(dict)

        def add_edge(u: str, v: str, cap: float) -> None:
            capacity[u][v] = capacity[u].get(v, 0.0) + cap
            capacity[v].setdefault(u, 0.0)

        # Node splitting: vin -> vout with vertex capacity (1 for intermediates, inf for src/dst).
        for v in nodes:
            vin = f"{v}#in"
            vout = f"{v}#out"
            node_cap = inf if v in {src, dst} else 1.0
            add_edge(vin, vout, node_cap)

        # Original directed edge u -> v becomes u_out -> v_in with infinite capacity.
        for u in nodes:
            nbrs = entity_adj.get(u, set())
            for v in nbrs:
                if v not in sub_nodes:
                    continue
                add_edge(f"{u}#out", f"{v}#in", inf)

        source = f"{src}#out"
        sink = f"{dst}#in"

        # Edmonds-Karp max-flow for unit/infinite capacities on small/medium graphs.
        flow = 0.0
        while True:
            parent: dict[str, str | None] = {source: None}
            q: deque[str] = deque([source])
            while q and sink not in parent:
                cur = q.popleft()
                for nxt, cap in capacity[cur].items():
                    if cap > 0 and nxt not in parent:
                        parent[nxt] = cur
                        q.append(nxt)

            if sink not in parent:
                break

            path_cap = inf
            v = sink
            while parent[v] is not None:
                u = parent[v]
                path_cap = min(path_cap, capacity[u][v])
                v = u

            v = sink
            while parent[v] is not None:
                u = parent[v]
                capacity[u][v] -= path_cap
                capacity[v][u] += path_cap
                v = u

            flow += path_cap

        if flow == inf:
            # If only src/dst (non-removable) can cut, treat as strongest controllability.
            return 0
        return int(flow)

    def path_factor(self, src: str, dst: str) -> float | None:
        """
        Unified path-factor definition: exact |MAC|.
        """
        self._ensure_ancestor_index()
        mac_size = self.exact_mac_size(src, dst)
        if mac_size is None:
            return None
        return float(mac_size)

    def path_factor_for_edge(self, src: str, dst: str) -> float | None:
        """
        Return path_factor normalized for graph_path edge serialization.

        - Unreachable is normalized to None.
        """
        return self.path_factor(src, dst)

    def path(self, src: str, dst: str) -> list[str] | None:
        """Return one shortest path from src to dst if it exists."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]

        version_path = self._shortest_version_path(src, dst)
        if version_path is None:
            return None

        projected: list[str] = []
        for node_id in version_path:
            entity = self._node_entity(node_id)
            if not projected or projected[-1] != entity:
                projected.append(entity)
        return projected

    def _entity_adjacency(self) -> dict[str, set[str]]:
        adj: dict[str, set[str]] = defaultdict(set)
        for u, nbrs in self.adj_data_flow.items():
            src_entity = self._node_entity(u)
            for v in nbrs:
                dst_entity = self._node_entity(v)
                if src_entity == dst_entity:
                    continue
                adj[src_entity].add(dst_entity)
        return adj

    def has_semantic_path(self, src: str, dst: str, relations: set[str] | None = None) -> bool:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return False
        relation_set = {canonical_relation(r) for r in (relations or set())}
        q: deque[str] = deque(starts)
        seen: set[str] = set(starts)
        while q:
            cur = q.popleft()
            if cur in targets:
                return True
            for nxt in self.adj_version_transition.get(cur, set()):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
            for relation, rel_adj in self.semantic_adj.items():
                if relation_set and canonical_relation(relation) not in relation_set:
                    continue
                for nxt in rel_adj.get(cur, set()):
                    if nxt in seen:
                        continue
                    seen.add(nxt)
                    q.append(nxt)
        return False

    def is_dag(self) -> bool:
        """Check acyclicity of the internal versioned graph."""
        try:
            self.topological_sort_version_nodes()
            return True
        except ValueError:
            return False

    def topological_sort_version_nodes(self) -> list[str]:
        self._ensure_union_adjacency()
        indeg: dict[str, int] = {nid: 0 for nid in self.version_nodes}
        for src, nbrs in self.adj.items():
            _ = src
            for dst in nbrs:
                indeg[dst] = indeg.get(dst, 0) + 1
        q: deque[str] = deque([nid for nid, d in indeg.items() if d == 0])
        out: list[str] = []
        while q:
            cur = q.popleft()
            out.append(cur)
            for nxt in self.adj.get(cur, set()):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    q.append(nxt)
        if len(out) != len(indeg):
            raise ValueError("Versioned provenance graph contains a cycle")
        return out
