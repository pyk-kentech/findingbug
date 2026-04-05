from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Callable, Iterable

from engine.io.cdr.base import canonical_relation
from engine.io.events import Event


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


class ProvenanceGraph:
    """
    Directed provenance graph with node versioning.

    External API remains entity-id based for compatibility, while internal reachability
    and edge storage operate on versioned nodes.
    """

    def __init__(self) -> None:
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

    def register_edge_hook(self, hook: Callable[[Edge], None]) -> None:
        self._edge_hooks.append(hook)

    def register_prune_hook(self, hook: Callable[[set[str], set[str]], None]) -> None:
        self._prune_hooks.append(hook)

    def clear_prune_hooks(self) -> None:
        self._prune_hooks.clear()

    @staticmethod
    def _semantic_relations_for_event(event: Event) -> list[tuple[str, str, str]]:
        raw = event.raw if isinstance(event.raw, dict) else {}
        cdr = raw.get("cdr")
        if not isinstance(cdr, dict):
            return []
        relations = cdr.get("semantic_relations")
        if not isinstance(relations, list):
            return []
        out: list[tuple[str, str, str]] = []
        for item in relations:
            if not isinstance(item, dict):
                continue
            relation = item.get("relation")
            src = item.get("src")
            dst = item.get("dst")
            if isinstance(relation, str) and isinstance(src, str) and isinstance(dst, str):
                out.append((canonical_relation(relation), src, dst))
        return out

    def _register_semantic_edge(self, relation: str, src_entity: str, dst_entity: str) -> None:
        src_node = self.current_version_node(src_entity)
        dst_node = self.current_version_node(dst_entity)
        if not src_node or not dst_node:
            return
        self.semantic_relations.append((canonical_relation(relation), src_entity, dst_entity))
        self.semantic_adj[relation][src_node].add(dst_node)
        self.semantic_rev_adj[relation][dst_node].add(src_node)

    @staticmethod
    def _flow_direction(event: Event) -> tuple[str, str]:
        """Resolve information-flow edge direction by operation type."""
        op = event.event_type.lower()

        if op in {"write", "fork", "connect", "send"}:
            return event.subject, event.object
        if op in {"read", "exec", "recv"}:
            return event.object, event.subject

        # Fallback for unknown/custom operations: keep declared order.
        return event.subject, event.object

    @staticmethod
    def _is_truthy(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return False

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

        op = event.event_type.lower()
        changed: set[str] = set()

        if op in {"write", "modify", "send", "proc_to_file", "proc_to_registry", "proc_to_ip", "file_to_ip"}:
            changed.add(event.object)
        if op in {"read", "recv", "file_to_proc"}:
            changed.add(event.subject)
        if op in {"exec", "execute", "setuid", "setgid", "privilege_change", "privilege_escalation"}:
            if self._is_process_node(event.subject):
                changed.add(event.subject)

        raw = event.raw if isinstance(event.raw, dict) else {}
        if self._is_truthy(raw.get("subject_state_change")):
            changed.add(event.subject)
        if self._is_truthy(raw.get("object_state_change")):
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
        return self.version_nodes[node_id]

    def _node_entity(self, node_id: str) -> str:
        return self.version_nodes[node_id].entity_id

    def _new_version_node(self, entity_id: str, observed_ts: str | None = None) -> str:
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
        self._ancestors_by_node[node_id] = {node_id}
        self._min_dist_from_ancestor[node_id] = {node_id: 0}
        observed_dt = self._parse_ts(observed_ts)
        if observed_dt is not None:
            self._version_last_seen_ts[node_id] = observed_dt
            prev_entity_ts = self._entity_last_seen_ts.get(entity_id)
            if prev_entity_ts is None or observed_dt > prev_entity_ts:
                self._entity_last_seen_ts[entity_id] = observed_dt
        return node_id

    def current_version_node(self, entity_id: str | None) -> str | None:
        if not entity_id:
            return None
        return self.current_version.get(entity_id)

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
        src_meta = self._node_meta(src_node)
        dst_meta = self._node_meta(dst_node)
        if src_meta.created_at >= dst_meta.created_at:
            raise ValueError("Versioned DAG invariant violated: non-forward edge creation attempted")

        if edge_type == EdgeType.DATA_FLOW:
            self.adj_data_flow[src_node].add(dst_node)
            self.rev_adj_data_flow[dst_node].add(src_node)
        elif edge_type == EdgeType.VERSION_TRANSITION:
            self.adj_version_transition[src_node].add(dst_node)
            self.rev_adj_version_transition[dst_node].add(src_node)
        else:
            raise ValueError(f"Unsupported edge_type: {edge_type}")

        # Union adjacency for backward compatibility.
        self.adj[src_node].add(dst_node)
        self.rev_adj[dst_node].add(src_node)
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
        emitted = self.edges[-1]
        self._propagate_ancestor_distance_delta(src_node, dst_node, edge_type)
        for hook in self._edge_hooks:
            hook(emitted)

    def _propagate_ancestor_distance_delta(self, src_node: str, dst_node: str, edge_type: EdgeType) -> None:
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

            for nxt, nxt_type in self._iter_neighbors(cur_dst):
                nxt_cost = self._edge_cost(nxt_type)
                q.append((cur_dst, nxt, nxt_cost, changed_delta))

    def _bump_entity(self, entity_id: str, event: Event) -> str:
        prev = self._ensure_entity(entity_id)
        new_node = self._new_version_node(entity_id, observed_ts=event.ts)
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
        event_dt = self._parse_ts(event.ts)
        memory_transition: tuple[str, str] | None = None
        if event.object.startswith("mem:"):
            original_object = event.object
            synchronized_object, memory_transition = self._synchronize_memory_vma(event)
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

        src_entity, dst_entity = self._flow_direction(event)
        self._ensure_entity(src_entity)
        self._ensure_entity(dst_entity)
        if event_dt is not None:
            self._entity_last_seen_ts[src_entity] = event_dt
            self._entity_last_seen_ts[dst_entity] = event_dt

        pre_src = self.current_version[src_entity]
        pre_dst = self.current_version[dst_entity]

        changed_entities = self._entities_requiring_new_version(event)
        # Enforce receiver-post-state modeling so all flow edges stay forward in version-time.
        if dst_entity not in changed_entities:
            changed_entities.add(dst_entity)

        post_by_entity: dict[str, str] = {}
        for entity_id in sorted(changed_entities):
            post_by_entity[entity_id] = self._bump_entity(entity_id, event)

        flow_src = pre_src
        flow_dst = post_by_entity.get(dst_entity, pre_dst)
        self._link_version_edge(
            flow_src,
            flow_dst,
            event,
            edge_type=EdgeType.DATA_FLOW,
            relation="flow",
        )
        if memory_transition is not None:
            previous_memory_entity, current_memory_entity = memory_transition
            previous_memory_node = self._ensure_entity(previous_memory_entity)
            current_memory_node = self.current_version[current_memory_entity]
            if previous_memory_node != current_memory_node:
                self._link_version_edge(
                    previous_memory_node,
                    current_memory_node,
                    event,
                    edge_type=EdgeType.VERSION_TRANSITION,
                    relation="vma_prev_version",
                )
        self._path_factor_cache.clear()

        # Process lineage relation for common-ancestor checks.
        if event.event_type.lower() in {"proc_to_proc", "fork"} and self._is_process_node(event.subject) and self._is_process_node(event.object):
            self.process_parents[event.object].add(event.subject)
            self._process_ancestor_cache.clear()
        for relation, semantic_src, semantic_dst in self._semantic_relations_for_event(event):
            self._register_semantic_edge(relation, semantic_src, semantic_dst)
        return {
            "flow_src_version": flow_src,
            "flow_dst_version": flow_dst,
            "subject_node_id": self.current_version[event.subject],
            "object_node_id": self.current_version[event.object],
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
        self._rebuild_indexes_from_current_state()
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
        for node_id in self.version_nodes:
            self._ancestors_by_node[node_id] = {node_id}
            self._min_dist_from_ancestor[node_id] = {node_id: 0}
        for edge in self.edges:
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
        for edge in self.edges:
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

    def add_events(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add_event(event)

    def has_path(self, src: str, dst: str) -> bool:
        return self.path(src, dst) is not None

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
        return self._shortest_version_distance(src, dst)

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
        result = set(common)
        common_list = list(common)
        for a in common_list:
            for b in common_list:
                if a == b:
                    continue
                # Remove 'a' when 'a' is ancestor of another common ancestor 'b'.
                if a in self._ancestors_by_node.get(b, set()):
                    result.discard(a)
                    break
        return result

    def minimum_ancestral_cover_size(self, src: str, dst: str) -> int | None:
        return self.exact_mac_size(src, dst)

    def exact_mac_size(self, src: str, dst: str) -> int | None:
        if src in self.version_nodes or dst in self.version_nodes:
            cover = self.ac_min(src, dst)
            if not cover:
                return None
            return len(cover)
        if not self.has_path(src, dst):
            return None
        cover = self.ac_min(src, dst)
        if not cover:
            return None
        return len(cover)

    def dependency_strength(self, src: str, dst: str) -> float:
        """
        Backward-compatible alias derived from exact MAC size.
        """
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

    def _synchronize_memory_vma(self, event: Event) -> tuple[str | None, tuple[str, str] | None]:
        if not event.object or not event.object.startswith("mem:"):
            return event.object, None
        base_key = self._memory_base_key(event.object)
        if base_key is None:
            return event.object, None
        relations = {relation for relation, _src, _dst in self._semantic_relations_for_event(event)}
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
