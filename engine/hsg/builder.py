from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from collections import deque
import time

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.taint_tracker import TaintTracker
from engine.hsg.prerequisite_evaluator import PrerequisiteEvaluator
from engine.hsg.prerequisite import is_prerequisite_satisfied
from engine.rules.schema import RuleSet, infer_rule_stage, path_factor_prerequisites, prerequisite_types
import yaml

PREREQ_CONFIG = {
    "graph_path": {
        "default": {
            "from_binding": "object",
            "to_binding": "object",
            "max_path_factor": "0.0",
        },
        "by_right_rule_id": {},
        "by_pair": {},
    }
}
GRAPH_PATH_ALLOWLIST: set[tuple[str, str]] | None = None
SUPPORTED_PREREQ_POLICIES: set[str] = {"dst_only", "union"}


@dataclass(slots=True)
class HSGNode:
    match_id: str
    rule_id: str
    event_ids: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HSGEdge:
    src: str
    dst: str
    relation: str
    weight: float | None = None
    path_factor: float | None = None
    dependency_strength: float | None = None


@dataclass(slots=True)
class HSG:
    nodes: list[HSGNode] = field(default_factory=list)
    edges: list[HSGEdge] = field(default_factory=list)


class IncrementalHSGBuilder:
    def __init__(
        self,
        *,
        graph: ProvenanceGraph,
        ruleset: RuleSet,
        paper_mode: str = "hybrid",
        prereq_policy: str = "union",
        resolved_effective_config: dict | None = None,
        taint_tracker: TaintTracker | None = None,
        privilege_tracker: PrivilegeTracker | None = None,
        graph_path_allowlist: set[tuple[str, str]] | None = None,
        max_graph_path_edges: int = 10000,
        max_graph_path_candidates_per_match: int = 200,
        graph_path_eval_budget_ms: float | None = None,
        graph_path_cache_miss_policy: str = "compute",
        graph_path_candidate_preselect_factor: int = 0,
        graph_path_edge_eviction_policy: str = "none",
        pending_ttl_seconds: int | None = 30 * 24 * 60 * 60,
        max_pending_matches: int = 100000,
        scenario_dormancy_seconds: int | None = 60 * 24 * 60 * 60,
        dormant_gc_every_matches: int = 1000,
    ) -> None:
        self.graph = graph
        self.ruleset = ruleset
        self.paper_mode = paper_mode
        self.prereq_policy = prereq_policy
        self.graph_path_allowlist = graph_path_allowlist if graph_path_allowlist is not None else GRAPH_PATH_ALLOWLIST
        self.max_graph_path_edges = max_graph_path_edges
        self.max_graph_path_candidates_per_match = max_graph_path_candidates_per_match
        self.graph_path_eval_budget_ms = (
            None if graph_path_eval_budget_ms is None else max(0.0, float(graph_path_eval_budget_ms))
        )
        if graph_path_cache_miss_policy not in {"compute", "skip"}:
            raise ValueError("graph_path_cache_miss_policy must be one of: compute, skip")
        self.graph_path_cache_miss_policy = graph_path_cache_miss_policy
        self.graph_path_candidate_preselect_factor = max(0, int(graph_path_candidate_preselect_factor))
        if graph_path_edge_eviction_policy not in {"none", "low_weight_lru"}:
            raise ValueError("graph_path_edge_eviction_policy must be one of: none, low_weight_lru")
        self.graph_path_edge_eviction_policy = graph_path_edge_eviction_policy
        self.pending_ttl_seconds = None if pending_ttl_seconds is None else max(0, int(pending_ttl_seconds))
        self.max_pending_matches = max(0, int(max_pending_matches))
        self.scenario_dormancy_seconds = (
            None if scenario_dormancy_seconds is None else max(0, int(scenario_dormancy_seconds))
        )
        self.dormant_gc_every_matches = max(1, int(dormant_gc_every_matches))
        self.rule_by_id = {rule.rule_id: rule for rule in ruleset.rules}
        self.rule_has_prereq_by_id = {
            rule.rule_id: self._has_prereq(rule)
            for rule in ruleset.rules
        }
        self.evaluator = PrerequisiteEvaluator(
            graph=graph,
            taint_tracker=taint_tracker,
            privilege_tracker=privilege_tracker,
            resolved_effective_config=resolved_effective_config,
        )
        self.nodes: dict[str, HSGNode] = {}
        self.edges: list[HSGEdge] = []
        self.seen_edges: set[tuple[str, str, str]] = set()
        self.entity_to_hsg_node: dict[str, set[str]] = defaultdict(set)
        self.pending_entity_to_hsg_node: dict[str, set[str]] = defaultdict(set)
        self.matches_by_id: dict[str, TTPMatch] = {}
        self.pending_matches_by_id: dict[str, TTPMatch] = {}
        self.pending_match_ts: dict[str, datetime] = {}
        self.graph_path_edges_count = 0
        self.graph_path_candidates_by_src: dict[str, int] = defaultdict(int)
        self.pending_evicted_count = 0
        self.pending_evicted_by_rule_id: dict[str, int] = defaultdict(int)
        self.pending_evicted_ttl_count = 0
        self.pending_evicted_capacity_count = 0
        self.match_last_activity_ts: dict[str, datetime] = {}
        self.closed_scenarios_count = 0
        self.closed_matches_count = 0
        self.closed_scenarios_by_id: dict[str, int] = defaultdict(int)
        self._matches_since_dormant_gc = 0
        self.last_activated_match_ids: set[str] = set()
        self.last_closed_match_ids: list[str] = []
        self.component_map_time_seconds = 0.0
        self.candidate_match_ids_total = 0
        self.candidate_match_ids_max = 0
        self.candidate_match_ids_filtered_no_prereq_total = 0
        self.candidate_match_ids_filtered_rule_pair_total = 0
        self.pending_activation_candidate_total = 0
        self.pending_activation_candidate_max = 0
        self.pending_activation_ancestor_scan_time_seconds = 0.0
        self.add_match_built_edges_total = 0
        self.add_match_built_edges_max = 0
        self.add_match_watermark_evict_time_seconds = 0.0
        self.add_match_candidate_ids_time_seconds = 0.0
        self.add_match_ast_eval_time_seconds = 0.0
        self.add_match_pair_eval_time_seconds = 0.0
        self.add_match_pending_insert_time_seconds = 0.0
        self.add_match_pending_capacity_evict_time_seconds = 0.0
        self.add_match_pending_path_count = 0
        self.add_match_pending_size_total = 0
        self.add_match_pending_size_max = 0
        self.pair_edges_relation_eval_total = 0
        self.pair_edges_graph_path_eval_total = 0
        self.pair_edges_non_graph_path_eval_total = 0
        self.pair_edges_seen_skip_total = 0
        self.pair_edges_graph_path_skip_max_edges_total = 0
        self.pair_edges_graph_path_skip_allowlist_total = 0
        self.pair_edges_graph_path_skip_src_cap_total = 0
        self.pair_edges_graph_path_skip_candidate_total = 0
        self.pair_edges_graph_path_skip_prereq_total = 0
        self.pair_edges_graph_path_skip_metrics_total = 0
        self.pair_edges_graph_path_skip_binding_total = 0
        self.pair_edges_graph_path_skip_budget_total = 0
        self.pair_edges_graph_path_skip_cache_miss_total = 0
        self.pair_edges_graph_path_preselected_drop_total = 0
        self.pair_edges_graph_path_evicted_total = 0
        self.pair_edges_graph_path_eviction_time_seconds = 0.0
        self.pair_edges_prereq_check_time_seconds = 0.0
        self.pair_edges_graph_path_candidate_time_seconds = 0.0
        self.pair_edges_graph_path_metrics_time_seconds = 0.0
        self.pair_edges_built_total = 0
        self.pair_edges_graph_path_pf_cache_hit_total = 0
        self.pair_edges_graph_path_pf_cache_miss_total = 0
        self.pair_edges_graph_path_pf_compute_time_seconds = 0.0
        self._rule_pair_relevance_cache: dict[tuple[str, str], bool] = {}
        self._match_entities_cache: dict[str, set[str]] = {}
        self._graph_path_edge_touch_seq = 0
        self._graph_path_edge_last_seen: dict[tuple[str, str, str], int] = {}

    def _has_prereq(self, rule) -> bool:
        return bool(
            rule
            and (
                getattr(rule, "prerequisites", [])
                or isinstance(getattr(rule, "prerequisite_ast", None), dict)
            )
        )

    def _index_match(self, match: TTPMatch) -> None:
        self.matches_by_id[match.match_id] = match
        self._match_entities_cache[match.match_id] = _match_entities(match)
        self.nodes[match.match_id] = HSGNode(
            match_id=match.match_id,
            rule_id=match.rule_id,
            event_ids=list(match.event_ids),
            entities=list(match.entities),
        )
        for entity in _match_entities(match):
            self.entity_to_hsg_node[entity].add(match.match_id)

    def _pair_can_produce_edge(self, left_rule_id: str, right_rule_id: str) -> bool:
        cache_key = (left_rule_id, right_rule_id)
        cached = self._rule_pair_relevance_cache.get(cache_key)
        if cached is not None:
            return cached

        left_rule = self.rule_by_id.get(left_rule_id)
        right_rule = self.rule_by_id.get(right_rule_id)
        forward = prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)
        reverse = prerequisite_relations_for_pair(right_rule, left_rule, self.prereq_policy)
        # _pair_edges_bidirectional keeps every forward relation and only reverse graph_path.
        relevant = bool(forward) or ("graph_path" in reverse)
        self._rule_pair_relevance_cache[cache_key] = relevant
        return relevant

    @staticmethod
    def _scenario_id(match_ids: set[str]) -> str:
        if not match_ids:
            return "scenario-empty"
        return f"scenario-{sorted(match_ids)[0]}"

    @staticmethod
    def _parse_watermark(ts: object) -> datetime | None:
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
        raw = str(ts).strip()
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

    def _match_watermark(self, match: TTPMatch, watermark_ts: str | None = None) -> datetime | None:
        explicit = self._parse_watermark(watermark_ts)
        if explicit is not None:
            return explicit
        for key in ("event_ts", "ts", "timestamp"):
            parsed = self._parse_watermark(match.metadata.get(key))
            if parsed is not None:
                return parsed
        return None

    def _index_pending(self, match: TTPMatch, watermark: datetime | None = None) -> None:
        self.pending_matches_by_id[match.match_id] = match
        self._match_entities_cache[match.match_id] = _match_entities(match)
        if watermark is not None:
            self.pending_match_ts[match.match_id] = watermark
        for entity in _match_entities(match):
            self.pending_entity_to_hsg_node[entity].add(match.match_id)

    def _remove_pending(self, match_id: str) -> None:
        match = self.pending_matches_by_id.pop(match_id, None)
        self.pending_match_ts.pop(match_id, None)
        if match is None:
            return
        self._match_entities_cache.pop(match_id, None)
        for entity in _match_entities(match):
            bucket = self.pending_entity_to_hsg_node.get(entity)
            if bucket is None:
                continue
            bucket.discard(match_id)
            if not bucket:
                self.pending_entity_to_hsg_node.pop(entity, None)

    def _remove_active_match(self, match_id: str) -> None:
        match = self.matches_by_id.pop(match_id, None)
        self.nodes.pop(match_id, None)
        self.match_last_activity_ts.pop(match_id, None)
        if match is None:
            return
        self._match_entities_cache.pop(match_id, None)
        for entity in _match_entities(match):
            bucket = self.entity_to_hsg_node.get(entity)
            if bucket is None:
                continue
            bucket.discard(match_id)
            if not bucket:
                self.entity_to_hsg_node.pop(entity, None)

    def _record_pending_eviction(self, pending_match: TTPMatch | None, reason: str) -> None:
        self.pending_evicted_count += 1
        if pending_match is not None and pending_match.rule_id:
            self.pending_evicted_by_rule_id[pending_match.rule_id] += 1
        if reason == "ttl":
            self.pending_evicted_ttl_count += 1
        elif reason == "capacity":
            self.pending_evicted_capacity_count += 1

    def _evict_expired_pending(self, watermark: datetime | None) -> None:
        if watermark is None or self.pending_ttl_seconds is None:
            return
        expired_ids = [
            match_id
            for match_id, pending_ts in self.pending_match_ts.items()
            if (watermark - pending_ts).total_seconds() > float(self.pending_ttl_seconds)
        ]
        for match_id in expired_ids:
            pending_match = self.pending_matches_by_id.get(match_id)
            self._remove_pending(match_id)
            self._record_pending_eviction(pending_match, "ttl")

    def _evict_capacity_pending(self) -> None:
        if self.max_pending_matches <= 0:
            return
        while len(self.pending_matches_by_id) > self.max_pending_matches:
            if not self.pending_matches_by_id:
                break
            evict_id = min(
                self.pending_matches_by_id,
                key=self._pending_priority_key,
            )
            pending_match = self.pending_matches_by_id.get(evict_id)
            self._remove_pending(evict_id)
            self._record_pending_eviction(pending_match, "capacity")

    def _pending_priority_key(self, match_id: str) -> tuple[int, datetime, str]:
        match = self.pending_matches_by_id.get(match_id)
        rule = self.rule_by_id.get(match.rule_id) if match is not None else None
        stage = infer_rule_stage(rule) if rule is not None else 1
        ts = self.pending_match_ts.get(match_id, datetime.max.replace(tzinfo=timezone.utc))
        return int(stage), ts, match_id

    def _entities_of_match(self, match: TTPMatch) -> set[str]:
        cached = self._match_entities_cache.get(match.match_id)
        if cached is not None:
            return cached
        entities = _match_entities(match)
        self._match_entities_cache[match.match_id] = entities
        return entities

    def _graph_path_priority_key(
        self,
        left: TTPMatch,
        right: TTPMatch,
        path_factor_cache: dict[tuple[str, str], float | None] | None,
    ) -> tuple[int, float, int, int, str]:
        known_pf_rank = 1
        pf_rank = float("inf")
        config = _resolve_prereq_config("graph_path", left.rule_id, right.rule_id)
        if isinstance(config, dict):
            from_binding = config.get("from_binding")
            to_binding = config.get("to_binding")
            if from_binding and to_binding:
                from_entity = left.bindings.get(str(from_binding))
                to_entity = right.bindings.get(str(to_binding))
                if isinstance(from_entity, str) and from_entity and isinstance(to_entity, str) and to_entity:
                    cache_key = (from_entity, to_entity)
                    if path_factor_cache is not None and cache_key in path_factor_cache:
                        cached_pf = path_factor_cache[cache_key]
                        if isinstance(cached_pf, (float, int)) and float(cached_pf) > 0.0:
                            known_pf_rank = 0
                            pf_rank = float(cached_pf)
        shared_entities = len(self._entities_of_match(left) & self._entities_of_match(right))
        right_is_pending = 1 if right.match_id in self.pending_matches_by_id else 0
        return (known_pf_rank, pf_rank, right_is_pending, -shared_entities, right.match_id)

    def _candidate_priority_key(
        self,
        current: TTPMatch,
        candidate: TTPMatch,
        path_factor_cache: dict[tuple[str, str], float | None] | None,
    ) -> tuple[int, float, int, int, str]:
        forward = self._graph_path_priority_key(candidate, current, path_factor_cache)
        reverse = self._graph_path_priority_key(current, candidate, path_factor_cache)
        return forward if forward <= reverse else reverse

    def _evict_graph_path_edge_if_needed(self) -> bool:
        if self.max_graph_path_edges <= 0:
            return False
        if self.graph_path_edges_count < self.max_graph_path_edges:
            return True
        if self.graph_path_edge_eviction_policy != "low_weight_lru":
            return False
        started = time.perf_counter()
        victim_index: int | None = None
        victim_score: tuple[float, int] | None = None
        for idx, edge in enumerate(self.edges):
            if edge.relation != "graph_path":
                continue
            edge_key = (edge.src, edge.dst, edge.relation)
            last_seen = self._graph_path_edge_last_seen.get(edge_key, -1)
            score = (float(edge.weight) if edge.weight is not None else 0.0, last_seen)
            if victim_score is None or score < victim_score:
                victim_score = score
                victim_index = idx
        if victim_index is None:
            return False
        victim = self.edges.pop(victim_index)
        victim_key = (victim.src, victim.dst, victim.relation)
        self.seen_edges.discard(victim_key)
        self._graph_path_edge_last_seen.pop(victim_key, None)
        if self.graph_path_candidates_by_src.get(victim.src, 0) > 0:
            self.graph_path_candidates_by_src[victim.src] -= 1
            if self.graph_path_candidates_by_src[victim.src] <= 0:
                self.graph_path_candidates_by_src.pop(victim.src, None)
        self.graph_path_edges_count = max(0, self.graph_path_edges_count - 1)
        self.pair_edges_graph_path_evicted_total += 1
        self.pair_edges_graph_path_eviction_time_seconds += time.perf_counter() - started
        return self.graph_path_edges_count < self.max_graph_path_edges

    def _component_map(self) -> dict[str, set[str]]:
        started = time.perf_counter()
        try:
            if not self.nodes:
                return {}
            adjacency: dict[str, set[str]] = defaultdict(set)
            for node_id in self.nodes:
                adjacency.setdefault(node_id, set())
            for edge in self.edges:
                if edge.src not in self.nodes or edge.dst not in self.nodes:
                    continue
                adjacency[edge.src].add(edge.dst)
                adjacency[edge.dst].add(edge.src)

            components: dict[str, set[str]] = {}
            seen: set[str] = set()
            for root in sorted(self.nodes):
                if root in seen:
                    continue
                queue: deque[str] = deque([root])
                component: set[str] = set()
                seen.add(root)
                while queue:
                    cur = queue.popleft()
                    component.add(cur)
                    for nxt in adjacency.get(cur, set()):
                        if nxt in seen:
                            continue
                        seen.add(nxt)
                        queue.append(nxt)
                components[self._scenario_id(component)] = component
            return components
        finally:
            self.component_map_time_seconds += time.perf_counter() - started

    def _touch_match_activity(self, match_ids: set[str], watermark: datetime | None) -> None:
        if watermark is None:
            return
        for match_id in match_ids:
            if match_id in self.matches_by_id:
                self.match_last_activity_ts[match_id] = watermark

    def gc_dormant_scenarios(self, watermark_ts: str | None = None) -> list[str]:
        watermark = self._parse_watermark(watermark_ts)
        if watermark is None or self.scenario_dormancy_seconds is None:
            return []
        components = self._component_map()
        closed_match_ids: list[str] = []
        for scenario_id, match_ids in components.items():
            last_activity = max(
                (self.match_last_activity_ts.get(match_id) for match_id in match_ids),
                default=None,
            )
            if last_activity is None:
                continue
            if (watermark - last_activity).total_seconds() <= float(self.scenario_dormancy_seconds):
                continue
            for match_id in sorted(match_ids):
                self._remove_active_match(match_id)
                closed_match_ids.append(match_id)
            self.closed_scenarios_count += 1
            self.closed_matches_count += len(match_ids)
            self.closed_scenarios_by_id[scenario_id] += 1
        if closed_match_ids:
            self.edges = [e for e in self.edges if e.src in self.nodes and e.dst in self.nodes]
            self.seen_edges = {(e.src, e.dst, e.relation) for e in self.edges}
            self.graph_path_edges_count = len([e for e in self.edges if e.relation == "graph_path"])
            self.graph_path_candidates_by_src = defaultdict(int)
            self._graph_path_edge_last_seen = {}
            self._graph_path_edge_touch_seq = 0
            for edge in self.edges:
                if edge.relation == "graph_path":
                    self.graph_path_candidates_by_src[edge.src] += 1
                    self._graph_path_edge_touch_seq += 1
                    self._graph_path_edge_last_seen[(edge.src, edge.dst, edge.relation)] = self._graph_path_edge_touch_seq
        return closed_match_ids

    def _candidate_match_ids(self, match: TTPMatch, extra_candidate_ids: set[str] | None = None) -> set[str]:
        ids = set(extra_candidate_ids or set())
        for entity in _match_entities(match):
            ids |= self.entity_to_hsg_node.get(entity, set())
            ids |= self.pending_entity_to_hsg_node.get(entity, set())
        ids.discard(match.match_id)
        if not self.rule_has_prereq_by_id.get(match.rule_id, False):
            before = len(ids)
            ids = {
                candidate_id
                for candidate_id in ids
                if self.rule_has_prereq_by_id.get(
                    (self.matches_by_id.get(candidate_id) or self.pending_matches_by_id.get(candidate_id)).rule_id,
                    False,
                )
            }
            self.candidate_match_ids_filtered_no_prereq_total += before - len(ids)
        filtered_ids: set[str] = set()
        before_rule_pair = len(ids)
        for candidate_id in ids:
            candidate_match = self.matches_by_id.get(candidate_id) or self.pending_matches_by_id.get(candidate_id)
            if candidate_match is None:
                continue
            if self._pair_can_produce_edge(candidate_match.rule_id, match.rule_id):
                filtered_ids.add(candidate_id)
        ids = filtered_ids
        self.candidate_match_ids_filtered_rule_pair_total += before_rule_pair - len(ids)
        self.candidate_match_ids_total += len(ids)
        self.candidate_match_ids_max = max(self.candidate_match_ids_max, len(ids))
        return ids

    def _maybe_gc_dormant_scenarios(self, watermark_ts: str | None = None) -> list[str]:
        self._matches_since_dormant_gc += 1
        if self._matches_since_dormant_gc < self.dormant_gc_every_matches:
            return []
        self._matches_since_dormant_gc = 0
        return self.gc_dormant_scenarios(watermark_ts)

    def _graph_path_edge_metrics(
        self,
        left: TTPMatch,
        right: TTPMatch,
        left_rule,
        right_rule,
        relation: str,
        config: dict | None = None,
        path_factor_cache: dict[tuple[str, str], float | None] | None = None,
        graph_path_deadline: float | None = None,
    ) -> tuple[float | None, float | None, float | None] | None:
        if graph_path_deadline is not None and time.perf_counter() >= graph_path_deadline:
            self.pair_edges_graph_path_skip_budget_total += 1
            return None
        effective_config = config if config is not None else _resolve_prereq_config(relation, left.rule_id, right.rule_id)
        if not effective_config:
            return None
        from_binding = effective_config.get("from_binding")
        to_binding = effective_config.get("to_binding")
        if not from_binding or not to_binding:
            return None
        from_entity = left.bindings.get(from_binding)
        to_entity = right.bindings.get(to_binding)
        if not from_entity or not to_entity:
            return None
        cache_key = (str(from_entity), str(to_entity))
        edge_pf: float | None
        if path_factor_cache is not None and cache_key in path_factor_cache:
            self.pair_edges_graph_path_pf_cache_hit_total += 1
            edge_pf = path_factor_cache[cache_key]
        else:
            self.pair_edges_graph_path_pf_cache_miss_total += 1
            if self.graph_path_cache_miss_policy == "skip":
                self.pair_edges_graph_path_skip_cache_miss_total += 1
                return None
            if graph_path_deadline is not None and time.perf_counter() >= graph_path_deadline:
                self.pair_edges_graph_path_skip_budget_total += 1
                return None
            edge_pf_started = time.perf_counter()
            edge_pf = self.graph.path_factor_for_edge(from_entity, to_entity)
            self.pair_edges_graph_path_pf_compute_time_seconds += time.perf_counter() - edge_pf_started
            if path_factor_cache is not None:
                path_factor_cache[cache_key] = edge_pf
        if edge_pf is None or edge_pf <= 0.0:
            return None
        pf_reqs = path_factor_prerequisites_for_pair(left_rule, right_rule, self.prereq_policy)
        if pf_reqs:
            for prereq in pf_reqs:
                try:
                    threshold = float(prereq.max_path_factor)
                except (TypeError, ValueError):
                    return None
                if threshold < 0.0:
                    return None
                if float(edge_pf) > threshold:
                    return None
        max_path_factor = float(effective_config.get("max_path_factor", 0.0))
        if max_path_factor > 0.0 and float(edge_pf) > max_path_factor:
            return None
        weight = 1.0 / float(edge_pf)
        return weight, float(edge_pf), weight

    def _pair_edges(
        self,
        left: TTPMatch,
        right: TTPMatch,
        path_factor_cache: dict[tuple[str, str], float | None] | None = None,
        descendants_cache: dict[tuple[str, str], bool] | None = None,
        graph_path_deadline: float | None = None,
    ) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)
        built: list[HSGEdge] = []
        for relation in prereq_types:
            self.pair_edges_relation_eval_total += 1
            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                self.pair_edges_seen_skip_total += 1
                continue
            if relation == "graph_path":
                self.pair_edges_graph_path_eval_total += 1
                if graph_path_deadline is not None and time.perf_counter() >= graph_path_deadline:
                    self.pair_edges_graph_path_skip_budget_total += 1
                    continue
                if self.max_graph_path_edges <= 0:
                    self.pair_edges_graph_path_skip_max_edges_total += 1
                    continue
                if self.graph_path_edges_count >= self.max_graph_path_edges and not self._evict_graph_path_edge_if_needed():
                    self.pair_edges_graph_path_skip_max_edges_total += 1
                    continue
                if self.graph_path_allowlist is not None and (left.rule_id, right.rule_id) not in self.graph_path_allowlist:
                    self.pair_edges_graph_path_skip_allowlist_total += 1
                    continue
                if self.graph_path_candidates_by_src[left.match_id] >= self.max_graph_path_candidates_per_match:
                    self.pair_edges_graph_path_skip_src_cap_total += 1
                    continue
                config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
                from_binding = str(config.get("from_binding")) if isinstance(config, dict) and config.get("from_binding") else None
                to_binding = str(config.get("to_binding")) if isinstance(config, dict) and config.get("to_binding") else None
                graph_path_candidate_started = time.perf_counter()
                if from_binding is not None and to_binding is not None:
                    from_entity = left.bindings.get(from_binding)
                    to_entity = right.bindings.get(to_binding)
                    if not from_entity or not to_entity:
                        graph_path_candidate_ok = False
                        self.pair_edges_graph_path_skip_binding_total += 1
                    else:
                        graph_path_candidate_ok = _reachable_entity(
                            self.graph,
                            str(from_entity),
                            str(to_entity),
                            descendants_cache if descendants_cache is not None else {},
                        )
                else:
                    graph_path_candidate_ok = is_graph_path_candidate(
                        self.graph,
                        left,
                        right,
                        descendants_cache if descendants_cache is not None else {},
                        left_entities=self._entities_of_match(left),
                        right_entities=self._entities_of_match(right),
                    )
                self.pair_edges_graph_path_candidate_time_seconds += time.perf_counter() - graph_path_candidate_started
                if not graph_path_candidate_ok:
                    self.pair_edges_graph_path_skip_candidate_total += 1
                    continue
                graph_path_metrics_started = time.perf_counter()
                metrics = self._graph_path_edge_metrics(
                    left,
                    right,
                    left_rule,
                    right_rule,
                    relation,
                    config=config,
                    path_factor_cache=path_factor_cache,
                    graph_path_deadline=graph_path_deadline,
                )
                self.pair_edges_graph_path_metrics_time_seconds += time.perf_counter() - graph_path_metrics_started
                if metrics is None:
                    self.pair_edges_graph_path_skip_metrics_total += 1
                    continue
                edge_dependency_strength, edge_path_factor, weight = metrics
                self.graph_path_candidates_by_src[left.match_id] += 1
            else:
                self.pair_edges_non_graph_path_eval_total += 1
                config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
                prereq_check_started = time.perf_counter()
                prereq_ok = is_prerequisite_satisfied(self.graph, left, right, relation, config)
                self.pair_edges_prereq_check_time_seconds += time.perf_counter() - prereq_check_started
                if not prereq_ok:
                    continue
                edge_dependency_strength = None
                edge_path_factor = None
                weight = None
            self.seen_edges.add(edge_key)
            built.append(
                HSGEdge(
                    src=left.match_id,
                    dst=right.match_id,
                    relation=relation,
                    weight=weight,
                    path_factor=edge_path_factor,
                    dependency_strength=edge_dependency_strength,
                )
            )
            self.pair_edges_built_total += 1
            if relation == "graph_path":
                self.graph_path_edges_count += 1
                self._graph_path_edge_touch_seq += 1
                self._graph_path_edge_last_seen[edge_key] = self._graph_path_edge_touch_seq
        return built

    def _pair_edges_bidirectional(
        self,
        left: TTPMatch,
        right: TTPMatch,
        path_factor_cache: dict[tuple[str, str], float | None] | None = None,
        descendants_cache: dict[tuple[str, str], bool] | None = None,
        graph_path_deadline: float | None = None,
    ) -> list[HSGEdge]:
        built = self._pair_edges(
            left,
            right,
            path_factor_cache=path_factor_cache,
            descendants_cache=descendants_cache,
            graph_path_deadline=graph_path_deadline,
        )
        built.extend(
            [
                edge
                for edge in self._pair_edges(
                    right,
                    left,
                    path_factor_cache=path_factor_cache,
                    descendants_cache=descendants_cache,
                    graph_path_deadline=graph_path_deadline,
                )
                if edge.relation == "graph_path"
            ]
        )
        return built

    def _try_activate_pending_for(
        self,
        active_match: TTPMatch,
        path_factor_cache: dict[tuple[str, str], float | None] | None = None,
        descendants_cache: dict[tuple[str, str], bool] | None = None,
        graph_path_deadline: float | None = None,
    ) -> tuple[list[HSGEdge], set[str]]:
        activated_edges: list[HSGEdge] = []
        activated_match_ids: set[str] = set()
        candidate_pending = set()
        ancestor_started = time.perf_counter()
        for entity in _match_entities(active_match):
            candidate_pending |= self.pending_entity_to_hsg_node.get(entity, set())
            for ancestor in self.graph.ancestors(entity):
                candidate_pending |= self.pending_entity_to_hsg_node.get(ancestor, set())
        self.pending_activation_ancestor_scan_time_seconds += time.perf_counter() - ancestor_started
        self.pending_activation_candidate_total += len(candidate_pending)
        self.pending_activation_candidate_max = max(self.pending_activation_candidate_max, len(candidate_pending))
        for pending_id in sorted(candidate_pending):
            pending_match = self.pending_matches_by_id.get(pending_id)
            if pending_match is None:
                continue
            built_edges = self._pair_edges_bidirectional(
                pending_match,
                active_match,
                path_factor_cache=path_factor_cache,
                descendants_cache=descendants_cache,
                graph_path_deadline=graph_path_deadline,
            )
            if not built_edges:
                continue
            self._remove_pending(pending_id)
            self._index_match(pending_match)
            activated_match_ids.add(pending_id)
            self.edges.extend(built_edges)
            activated_edges.extend(built_edges)
        return activated_edges, activated_match_ids

    def add_match(
        self,
        match: TTPMatch,
        extra_candidate_ids: set[str] | None = None,
        watermark_ts: str | None = None,
        path_factor_cache: dict[tuple[str, str], float | None] | None = None,
        descendants_cache: dict[tuple[str, str], bool] | None = None,
    ) -> tuple[bool, list[HSGEdge]]:
        effective_path_factor_cache = path_factor_cache if path_factor_cache is not None else {}
        effective_descendants_cache = descendants_cache if descendants_cache is not None else {}
        graph_path_deadline: float | None = None
        if self.graph_path_eval_budget_ms is not None and self.graph_path_eval_budget_ms > 0.0:
            graph_path_deadline = time.perf_counter() + (self.graph_path_eval_budget_ms / 1000.0)
        self.last_activated_match_ids = set()
        self.last_closed_match_ids = []
        watermark = self._match_watermark(match, watermark_ts)
        evict_started = time.perf_counter()
        self._evict_expired_pending(watermark)
        self.add_match_watermark_evict_time_seconds += time.perf_counter() - evict_started
        rule = self.rule_by_id.get(match.rule_id)
        candidate_started = time.perf_counter()
        candidate_ids = self._candidate_match_ids(match, extra_candidate_ids)
        self.add_match_candidate_ids_time_seconds += time.perf_counter() - candidate_started
        built_edges: list[HSGEdge] = []
        if isinstance(getattr(rule, "prerequisite_ast", None), dict):
            prior_matches = dict(self.matches_by_id)
            ast_eval_started = time.perf_counter()
            result = self.evaluator.evaluate_rule(rule, match, prior_matches)
            self.add_match_ast_eval_time_seconds += time.perf_counter() - ast_eval_started
            if not result.satisfied:
                if not self._has_prereq(rule):
                    self._index_match(match)
                    self._touch_match_activity({match.match_id}, watermark)
                    self.last_closed_match_ids = self._maybe_gc_dormant_scenarios(watermark_ts)
                    return True, []
                pending_insert_started = time.perf_counter()
                self._index_pending(match, watermark)
                self.add_match_pending_insert_time_seconds += time.perf_counter() - pending_insert_started
                self.add_match_pending_path_count += 1
                pending_size = len(self.pending_matches_by_id)
                self.add_match_pending_size_total += pending_size
                self.add_match_pending_size_max = max(self.add_match_pending_size_max, pending_size)
                return False, []
            for ast_edge in result.edges:
                edge_key = (ast_edge.src_match_id, match.match_id, ast_edge.relation)
                if edge_key in self.seen_edges or ast_edge.src_match_id not in self.matches_by_id:
                    continue
                self.seen_edges.add(edge_key)
                built_edges.append(
                    HSGEdge(
                        src=ast_edge.src_match_id,
                        dst=match.match_id,
                        relation=ast_edge.relation,
                        weight=ast_edge.weight,
                        path_factor=ast_edge.path_factor,
                        dependency_strength=ast_edge.dependency_strength,
                    )
                )
        else:
            pair_eval_started = time.perf_counter()
            ordered_candidate_ids = sorted(candidate_ids)
            if (
                self.graph_path_candidate_preselect_factor > 0
                and self.max_graph_path_candidates_per_match > 0
                and len(ordered_candidate_ids) > (self.max_graph_path_candidates_per_match * self.graph_path_candidate_preselect_factor)
            ):
                candidate_cap = self.max_graph_path_candidates_per_match * self.graph_path_candidate_preselect_factor
                ordered_candidate_ids = sorted(
                    ordered_candidate_ids,
                    key=lambda cid: self._candidate_priority_key(
                        match,
                        self.matches_by_id.get(cid) or self.pending_matches_by_id.get(cid) or match,
                        effective_path_factor_cache,
                    ),
                )[:candidate_cap]
                self.pair_edges_graph_path_preselected_drop_total += max(0, len(candidate_ids) - len(ordered_candidate_ids))
            for candidate_id in ordered_candidate_ids:
                prior = self.matches_by_id.get(candidate_id) or self.pending_matches_by_id.get(candidate_id)
                if prior is None:
                    continue
                built_edges.extend(
                    self._pair_edges_bidirectional(
                        prior,
                        match,
                        path_factor_cache=effective_path_factor_cache,
                        descendants_cache=effective_descendants_cache,
                        graph_path_deadline=graph_path_deadline,
                    )
                )
            self.add_match_pair_eval_time_seconds += time.perf_counter() - pair_eval_started
        if self._has_prereq(rule) and not built_edges:
            pending_insert_started = time.perf_counter()
            self._index_pending(match, watermark)
            self.add_match_pending_insert_time_seconds += time.perf_counter() - pending_insert_started
            pending_capacity_started = time.perf_counter()
            self._evict_capacity_pending()
            self.add_match_pending_capacity_evict_time_seconds += time.perf_counter() - pending_capacity_started
            self.add_match_pending_path_count += 1
            pending_size = len(self.pending_matches_by_id)
            self.add_match_pending_size_total += pending_size
            self.add_match_pending_size_max = max(self.add_match_pending_size_max, pending_size)
            return False, []
        for edge in built_edges:
            if edge.src in self.pending_matches_by_id:
                pending_match = self.pending_matches_by_id.get(edge.src)
                if pending_match is not None:
                    self._remove_pending(edge.src)
                    self._index_match(pending_match)
                    self._touch_match_activity({pending_match.match_id}, watermark)
        self._index_match(match)
        touched_match_ids = {match.match_id}
        touched_match_ids.update(edge.src for edge in built_edges)
        touched_match_ids.update(edge.dst for edge in built_edges)
        self.edges.extend(built_edges)
        activated_edges, activated_match_ids = self._try_activate_pending_for(
            match,
            path_factor_cache=effective_path_factor_cache,
            descendants_cache=effective_descendants_cache,
            graph_path_deadline=graph_path_deadline,
        )
        self.last_activated_match_ids = set(activated_match_ids)
        built_edges.extend(activated_edges)
        self.add_match_built_edges_total += len(built_edges)
        self.add_match_built_edges_max = max(self.add_match_built_edges_max, len(built_edges))
        touched_match_ids.update(edge.src for edge in built_edges)
        touched_match_ids.update(edge.dst for edge in built_edges)
        self._touch_match_activity(touched_match_ids, watermark)
        self.last_closed_match_ids = self._maybe_gc_dormant_scenarios(watermark_ts)
        return True, built_edges

    def as_hsg(self) -> HSG:
        return HSG(nodes=list(self.nodes.values()), edges=list(self.edges))


def _entity_prefix(entity: str | None) -> str:
    if not entity:
        return ""
    return entity.split(":", 1)[0].lower()


def _match_entities(match: TTPMatch) -> set[str]:
    entities = {e for e in match.entities if isinstance(e, str) and e}
    for value in match.bindings.values():
        if isinstance(value, str) and value:
            entities.add(value)
    return entities


def _prefix_overlap_entities(left_entities: set[str], right_entities: set[str]) -> bool:
    left_prefixes = {_entity_prefix(e) for e in left_entities if _entity_prefix(e)}
    right_prefixes = {_entity_prefix(e) for e in right_entities if _entity_prefix(e)}
    return bool(left_prefixes & right_prefixes)


def _reachable_quick_check(
    graph: ProvenanceGraph,
    left_entities: set[str],
    right_entities: set[str],
    descendants_cache: dict[object, object],
) -> bool:
    # In lazy mode, ancestor index rebuild on every check is too expensive.
    # Keep descendants-cache BFS projection to avoid global index rebuild churn.
    if getattr(graph, "ancestor_index_mode", "incremental") == "lazy":
        for src in left_entities:
            if not src:
                continue
            desc_key = ("desc", src)
            reachable = descendants_cache.get(desc_key)
            if not isinstance(reachable, set):
                reachable = graph.descendants(src)
                descendants_cache[desc_key] = reachable
            for dst in right_entities:
                if dst in reachable:
                    return True
        return False

    # Incremental mode: batched fast path first.
    if graph.has_any_path_fast(left_entities, right_entities):
        return True

    # Pairwise cache fallback.
    for src in left_entities:
        if not src:
            continue
        for dst in right_entities:
            if not dst:
                continue
            key = (src, dst)
            cached = descendants_cache.get(key)
            if cached is None:
                cached = graph.has_path_fast(src, dst)
                descendants_cache[key] = cached
            if cached:
                return True
    return False


def _reachable_entity(
    graph: ProvenanceGraph,
    src_entity: str,
    dst_entity: str,
    descendants_cache: dict[object, object],
) -> bool:
    if getattr(graph, "ancestor_index_mode", "incremental") == "lazy":
        desc_key = ("desc", src_entity)
        reachable = descendants_cache.get(desc_key)
        if not isinstance(reachable, set):
            reachable = graph.descendants(src_entity)
            descendants_cache[desc_key] = reachable
        return dst_entity in reachable

    key = (src_entity, dst_entity)
    cached = descendants_cache.get(key)
    if cached is None:
        cached = graph.has_path_fast(src_entity, dst_entity)
        descendants_cache[key] = cached
    return cached


def is_graph_path_candidate(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    descendants_cache: dict[object, object] | None = None,
    left_entities: set[str] | None = None,
    right_entities: set[str] | None = None,
) -> bool:
    """
    Cheap pruning before expensive graph_path prerequisite evaluation.

    Keep candidate when either:
    - entity prefix overlap exists, or
    - directed reachability exists from left entities to right entities.
    """
    cache = descendants_cache if descendants_cache is not None else {}
    left_set = left_entities if left_entities is not None else _match_entities(left)
    right_set = right_entities if right_entities is not None else _match_entities(right)
    return _prefix_overlap_entities(left_set, right_set) or _reachable_quick_check(graph, left_set, right_set, cache)


def load_graph_path_allowlist(path: str | Path | None) -> set[tuple[str, str]] | None:
    if path is None:
        return None
    raw = str(path).strip()
    if not raw or raw.lower() == "none":
        return None

    payload = yaml.safe_load(Path(raw).read_text(encoding="utf-8"))
    if payload is None:
        return set()
    if isinstance(payload, dict):
        payload = payload.get("allowlist", payload.get("pairs", payload))
    if not isinstance(payload, list):
        raise ValueError("graph-path allowlist file must contain a list")

    pairs: set[tuple[str, str]] = set()
    for item in payload:
        left = None
        right = None
        if isinstance(item, str):
            if "->" in item:
                left, right = item.split("->", 1)
            elif "," in item:
                left, right = item.split(",", 1)
        elif isinstance(item, list) and len(item) == 2:
            left, right = item[0], item[1]
        elif isinstance(item, dict):
            left = item.get("src") or item.get("left") or item.get("from")
            right = item.get("dst") or item.get("right") or item.get("to")
        if isinstance(left, str) and isinstance(right, str):
            pairs.add((left.strip(), right.strip()))
    return pairs


def _resolve_prereq_config(relation: str, left_rule_id: str, right_rule_id: str) -> dict | None:
    entry = PREREQ_CONFIG.get(relation)
    if not isinstance(entry, dict):
        return None

    # Direct shape: {"graph_path": {"from_binding": ..., ...}}
    if "from_binding" in entry and "to_binding" in entry:
        return entry

    pair_map = entry.get("by_pair", {})
    if isinstance(pair_map, dict):
        pair_cfg = pair_map.get(f"{left_rule_id}->{right_rule_id}")
        if isinstance(pair_cfg, dict):
            return pair_cfg

    right_map = entry.get("by_right_rule_id", {})
    if isinstance(right_map, dict):
        right_cfg = right_map.get(right_rule_id)
        if isinstance(right_cfg, dict):
            return right_cfg

    default_cfg = entry.get("default")
    if isinstance(default_cfg, dict):
        return default_cfg
    return None


def prerequisite_relations_for_pair(
    left_rule,
    right_rule,
    prereq_policy: str,
) -> set[str]:
    if prereq_policy == "dst_only":
        return prerequisite_types(right_rule)
    if prereq_policy == "union":
        return prerequisite_types(left_rule) | prerequisite_types(right_rule)
    raise ValueError(f"Unsupported prereq_policy: {prereq_policy}")


def path_factor_prerequisites_for_pair(
    left_rule,
    right_rule,
    prereq_policy: str,
):
    if prereq_policy == "dst_only":
        return path_factor_prerequisites(right_rule)
    if prereq_policy == "union":
        return path_factor_prerequisites(left_rule) + path_factor_prerequisites(right_rule)
    raise ValueError(f"Unsupported prereq_policy: {prereq_policy}")


def build_hsg(
    matches: list[TTPMatch],
    graph: ProvenanceGraph,
    ruleset: RuleSet,
    paper_mode: str = "hybrid",
    prereq_policy: str = "union",
    resolved_effective_config: dict | None = None,
    taint_tracker: TaintTracker | None = None,
    graph_path_allowlist: set[tuple[str, str]] | None = None,
    max_graph_path_edges: int = 10000,
    max_graph_path_candidates_per_match: int = 200,
    graph_path_candidate_preselect_factor: int = 0,
    graph_path_edge_eviction_policy: str = "none",
) -> HSG:
    if paper_mode not in {"hybrid", "strict"}:
        raise ValueError("paper_mode must be 'hybrid' or 'strict'")
    if prereq_policy not in SUPPORTED_PREREQ_POLICIES:
        raise ValueError("prereq_policy must be 'dst_only' or 'union'")
    if max_graph_path_edges < 0:
        raise ValueError("max_graph_path_edges must be >= 0")
    if max_graph_path_candidates_per_match < 0:
        raise ValueError("max_graph_path_candidates_per_match must be >= 0")
    if graph_path_candidate_preselect_factor < 0:
        raise ValueError("graph_path_candidate_preselect_factor must be >= 0")

    incremental = IncrementalHSGBuilder(
        graph=graph,
        ruleset=ruleset,
        paper_mode=paper_mode,
        prereq_policy=prereq_policy,
        resolved_effective_config=resolved_effective_config,
        taint_tracker=taint_tracker,
        graph_path_allowlist=graph_path_allowlist,
        max_graph_path_edges=max_graph_path_edges,
        max_graph_path_candidates_per_match=max_graph_path_candidates_per_match,
        graph_path_candidate_preselect_factor=graph_path_candidate_preselect_factor,
        graph_path_edge_eviction_policy=graph_path_edge_eviction_policy,
    )
    ordered_matches = sorted(matches, key=lambda m: (int(m.sequence or 0), m.match_id))
    for match in ordered_matches:
        incremental.add_match(match, watermark_ts=str(match.metadata.get("event_ts") or match.metadata.get("ts") or ""))
    return incremental.as_hsg()


def hsg_to_dict(hsg: HSG) -> dict:
    return {
        "nodes": [
            {
                "match_id": n.match_id,
                "rule_id": n.rule_id,
                "event_ids": n.event_ids,
                "entities": n.entities,
            }
            for n in hsg.nodes
        ],
        "edges": [
            (
                {
                    "src": e.src,
                    "dst": e.dst,
                    "relation": e.relation,
                    **({"weight": e.weight} if e.weight is not None else {}),
                    **({"path_factor": e.path_factor} if e.path_factor is not None else {}),
                    **({"dependency_strength": e.dependency_strength} if e.dependency_strength is not None else {}),
                }
            )
            for e in hsg.edges
        ],
    }


def dump_hsg_json(hsg: HSG, output_path: str | Path) -> None:
    p = Path(output_path)
    p.write_text(json.dumps(hsg_to_dict(hsg), indent=2), encoding="utf-8")
