from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from collections import deque

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.taint_tracker import TaintTracker
from engine.hsg.prerequisite_evaluator import PrerequisiteEvaluator
from engine.hsg.prerequisite import is_path_factor_satisfied, is_prerequisite_satisfied
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
        pending_ttl_seconds: int | None = 30 * 24 * 60 * 60,
        max_pending_matches: int = 100000,
        scenario_dormancy_seconds: int | None = 60 * 24 * 60 * 60,
    ) -> None:
        self.graph = graph
        self.ruleset = ruleset
        self.paper_mode = paper_mode
        self.prereq_policy = prereq_policy
        self.graph_path_allowlist = graph_path_allowlist if graph_path_allowlist is not None else GRAPH_PATH_ALLOWLIST
        self.max_graph_path_edges = max_graph_path_edges
        self.max_graph_path_candidates_per_match = max_graph_path_candidates_per_match
        self.pending_ttl_seconds = None if pending_ttl_seconds is None else max(0, int(pending_ttl_seconds))
        self.max_pending_matches = max(0, int(max_pending_matches))
        self.scenario_dormancy_seconds = (
            None if scenario_dormancy_seconds is None else max(0, int(scenario_dormancy_seconds))
        )
        self.rule_by_id = {rule.rule_id: rule for rule in ruleset.rules}
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
        self.nodes[match.match_id] = HSGNode(
            match_id=match.match_id,
            rule_id=match.rule_id,
            event_ids=list(match.event_ids),
            entities=list(match.entities),
        )
        for entity in _match_entities(match):
            self.entity_to_hsg_node[entity].add(match.match_id)

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
        if watermark is not None:
            self.pending_match_ts[match.match_id] = watermark
        for entity in _match_entities(match):
            self.pending_entity_to_hsg_node[entity].add(match.match_id)

    def _remove_pending(self, match_id: str) -> None:
        match = self.pending_matches_by_id.pop(match_id, None)
        self.pending_match_ts.pop(match_id, None)
        if match is None:
            return
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

    def _component_map(self) -> dict[str, set[str]]:
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
            for edge in self.edges:
                if edge.relation == "graph_path":
                    self.graph_path_candidates_by_src[edge.src] += 1
        return closed_match_ids

    def _candidate_match_ids(self, match: TTPMatch, extra_candidate_ids: set[str] | None = None) -> set[str]:
        ids = set(extra_candidate_ids or set())
        for entity in _match_entities(match):
            ids |= self.entity_to_hsg_node.get(entity, set())
            ids |= self.pending_entity_to_hsg_node.get(entity, set())
            for ancestor in self.graph.ancestors(entity):
                ids |= self.entity_to_hsg_node.get(ancestor, set())
                ids |= self.pending_entity_to_hsg_node.get(ancestor, set())
            for descendant in self.graph.descendants(entity):
                ids |= self.entity_to_hsg_node.get(descendant, set())
                ids |= self.pending_entity_to_hsg_node.get(descendant, set())
        ids.discard(match.match_id)
        return ids

    def _graph_path_edge_metrics(
        self,
        left: TTPMatch,
        right: TTPMatch,
        left_rule,
        right_rule,
        relation: str,
    ) -> tuple[float | None, float | None, float | None] | None:
        config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
        if not config:
            return None
        from_binding = config.get("from_binding")
        to_binding = config.get("to_binding")
        if not from_binding or not to_binding:
            return None
        from_entity = left.bindings.get(from_binding)
        to_entity = right.bindings.get(to_binding)
        if not from_entity or not to_entity:
            return None
        pf_reqs = path_factor_prerequisites_for_pair(left_rule, right_rule, self.prereq_policy)
        if pf_reqs and any(
            not is_path_factor_satisfied(self.graph, from_entity, to_entity, prereq.max_path_factor)
            for prereq in pf_reqs
        ):
            return None
        edge_pf = self.graph.path_factor_for_edge(from_entity, to_entity)
        if edge_pf is None or edge_pf <= 0.0:
            return None
        weight = 1.0 / float(edge_pf)
        return weight, float(edge_pf), weight

    def _pair_edges(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)
        built: list[HSGEdge] = []
        for relation in prereq_types:
            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue
            if relation == "graph_path":
                if self.graph_path_edges_count >= self.max_graph_path_edges:
                    continue
                if self.graph_path_allowlist is not None and (left.rule_id, right.rule_id) not in self.graph_path_allowlist:
                    continue
                if self.graph_path_candidates_by_src[left.match_id] >= self.max_graph_path_candidates_per_match:
                    continue
                if not is_graph_path_candidate(self.graph, left, right, {}):
                    continue
                config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
                if not is_prerequisite_satisfied(self.graph, left, right, relation, config):
                    continue
                metrics = self._graph_path_edge_metrics(left, right, left_rule, right_rule, relation)
                if metrics is None:
                    continue
                edge_dependency_strength, edge_path_factor, weight = metrics
                self.graph_path_candidates_by_src[left.match_id] += 1
            else:
                config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
                if not is_prerequisite_satisfied(self.graph, left, right, relation, config):
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
            if relation == "graph_path":
                self.graph_path_edges_count += 1
        return built

    def _pair_edges_bidirectional(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        built = self._pair_edges(left, right)
        built.extend([edge for edge in self._pair_edges(right, left) if edge.relation == "graph_path"])
        return built

    def _try_activate_pending_for(self, active_match: TTPMatch) -> list[HSGEdge]:
        activated_edges: list[HSGEdge] = []
        candidate_pending = set()
        for entity in _match_entities(active_match):
            candidate_pending |= self.pending_entity_to_hsg_node.get(entity, set())
            for ancestor in self.graph.ancestors(entity):
                candidate_pending |= self.pending_entity_to_hsg_node.get(ancestor, set())
        for pending_id in sorted(candidate_pending):
            pending_match = self.pending_matches_by_id.get(pending_id)
            if pending_match is None:
                continue
            built_edges = self._pair_edges_bidirectional(pending_match, active_match)
            if not built_edges:
                continue
            self._remove_pending(pending_id)
            self._index_match(pending_match)
            self.edges.extend(built_edges)
            activated_edges.extend(built_edges)
        return activated_edges

    def add_match(
        self,
        match: TTPMatch,
        extra_candidate_ids: set[str] | None = None,
        watermark_ts: str | None = None,
    ) -> tuple[bool, list[HSGEdge]]:
        watermark = self._match_watermark(match, watermark_ts)
        self._evict_expired_pending(watermark)
        rule = self.rule_by_id.get(match.rule_id)
        candidate_ids = self._candidate_match_ids(match, extra_candidate_ids)
        built_edges: list[HSGEdge] = []
        if isinstance(getattr(rule, "prerequisite_ast", None), dict):
            prior_matches = dict(self.matches_by_id)
            result = self.evaluator.evaluate_rule(rule, match, prior_matches)
            if not result.satisfied:
                if not self._has_prereq(rule):
                    self._index_match(match)
                    self._touch_match_activity({match.match_id}, watermark)
                    self.gc_dormant_scenarios(watermark_ts)
                    return True, []
                self._index_pending(match, watermark)
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
            for candidate_id in sorted(candidate_ids):
                prior = self.matches_by_id.get(candidate_id) or self.pending_matches_by_id.get(candidate_id)
                if prior is None:
                    continue
                built_edges.extend(self._pair_edges_bidirectional(prior, match))
        if self._has_prereq(rule) and not built_edges:
            self._index_pending(match, watermark)
            self._evict_capacity_pending()
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
        built_edges.extend(self._try_activate_pending_for(match))
        touched_match_ids.update(edge.src for edge in built_edges)
        touched_match_ids.update(edge.dst for edge in built_edges)
        self._touch_match_activity(touched_match_ids, watermark)
        self.gc_dormant_scenarios(watermark_ts)
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


def _prefix_overlap(left: TTPMatch, right: TTPMatch) -> bool:
    left_prefixes = {_entity_prefix(e) for e in _match_entities(left) if _entity_prefix(e)}
    right_prefixes = {_entity_prefix(e) for e in _match_entities(right) if _entity_prefix(e)}
    return bool(left_prefixes & right_prefixes)


def _reachable_quick_check(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    descendants_cache: dict[str, set[str]],
) -> bool:
    for src in _match_entities(left):
        if not src:
            continue
        if src not in descendants_cache:
            descendants_cache[src] = graph.descendants(src)
        reachable = descendants_cache[src]
        for dst in _match_entities(right):
            if dst in reachable:
                return True
    return False


def is_graph_path_candidate(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    descendants_cache: dict[str, set[str]] | None = None,
) -> bool:
    """
    Cheap pruning before expensive graph_path prerequisite evaluation.

    Keep candidate when either:
    - entity prefix overlap exists, or
    - directed reachability exists from left entities to right entities.
    """
    cache = descendants_cache if descendants_cache is not None else {}
    return _prefix_overlap(left, right) or _reachable_quick_check(graph, left, right, cache)


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
) -> HSG:
    if paper_mode not in {"hybrid", "strict"}:
        raise ValueError("paper_mode must be 'hybrid' or 'strict'")
    if prereq_policy not in SUPPORTED_PREREQ_POLICIES:
        raise ValueError("prereq_policy must be 'dst_only' or 'union'")
    if max_graph_path_edges < 0:
        raise ValueError("max_graph_path_edges must be >= 0")
    if max_graph_path_candidates_per_match < 0:
        raise ValueError("max_graph_path_candidates_per_match must be >= 0")

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
