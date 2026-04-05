from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time
from typing import Any

from engine.core.graph import Edge, ProvenanceGraph
from engine.core.matcher import Matcher, TTPMatch
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.taint_tracker import TaintTracker
import engine.hsg.builder as hsg_builder
from engine.hsg.builder import HSG, HSGEdge, HSGNode, IncrementalHSGBuilder, hsg_to_dict
from engine.hsg.online_index import OnlineIndex
from engine.hsg.paper_exact import IncrementalPaperExactScorer
from engine.hsg.prerequisite_evaluator import PrerequisiteEvaluator
from engine.hsg.scorer import rank_hsg_scenarios
from engine.io.export import export_alert_scenario_artifact
from engine.io.events import Event
from engine.noise.filter import NoiseConfig, apply_noise_filter, filter_matches
from engine.noise.model import NoiseModel, get_benign_drop_ids
from engine.noise.profile import BenignProfile, load_benign_profile
from engine.rules.schema import APT_STAGES, RuleSet, infer_rule_cvss, infer_rule_stage
from engine.stream.workers import iter_parsed_events_parallel


@dataclass(slots=True)
class StreamingStats:
    events: int = 0
    raw_matches: int = 0
    dropped_matches: int = 0
    binding_drop_count: int = 0
    by_signature: int = 0
    by_byte_volume: int = 0
    by_dynamic_threshold: int = 0
    byte_volume_by_rule_id: dict[str, int] | None = None
    dynamic_threshold_by_rule_id: dict[str, int] | None = None
    candidate_pairs_considered: int = 0
    binding_drop_by_rule_id: dict[str, int] | None = None
    pending_evicted_count: int = 0
    pending_evicted_by_rule_id: dict[str, int] | None = None
    pending_evicted_ttl_count: int = 0
    pending_evicted_capacity_count: int = 0
    dormant_scenarios_closed_count: int = 0
    dormant_matches_closed_count: int = 0
    dormant_scenarios_closed_by_id: dict[str, int] | None = None
    graph_pruned_entity_count: int = 0
    graph_pruned_version_node_count: int = 0
    graph_pruned_edge_count: int = 0
    graph_pruned_semantic_edge_count: int = 0
    benign_profile_drop_count: int = 0
    reorder_buffer_saturation_count: int = 0
    max_observed_out_of_order_distance: int = 0
    stall_duration_seconds: float = 0.0
    current_reorder_buffer_depth: int = 0
    max_observed_reorder_buffer_depth: int = 0


@dataclass(slots=True)
class APTAlert:
    alert_id: str
    scenario_id: str
    triggered_at: str | None
    severity_score: float
    threshold: float
    kill_chain_stages: list[str]
    achieved_stages: list[str]
    core_entities: list[str]
    tainted_entities: list[str]
    root_entities: list[str]
    match_ids: list[str]
    graph_artifact_path: str | None = None


class StreamingEngine:
    def __init__(
        self,
        ruleset: RuleSet,
        scoring_mode: str = "legacy",
        paper_weights: list[float] | None = None,
        tau: float | None = None,
        paper_mode: str = "hybrid",
        prereq_policy: str = "union",
        alpha: float | None = None,
        noise_config: NoiseConfig | None = None,
        noise_model: NoiseModel | None = None,
        noise_bytes_threshold: str = "p95",
        noise_signature_min_ratio: float = 0.1,
        graph_path_allowlist: set[tuple[str, str]] | None = None,
        max_graph_path_edges: int = 10000,
        max_graph_path_candidates_per_match: int = 200,
        use_online_prereq: bool = True,
        resolved_effective_config: dict[str, Any] | None = None,
        global_refine_mode: str = "off",
        global_refine_every: int = 1000,
        dropped_match_telemetry_path: str | Path | None = None,
        apt_alert_threshold: float = 80.0,
        alerts_path: str | Path | None = None,
        max_pending_matches: int = 100000,
        scenario_dormancy_days: int = 60,
        graph_retention_days: int = 60,
        benign_profile: BenignProfile | None = None,
        benign_profile_path: str | Path | None = None,
        metrics_path: str | Path | None = None,
        metrics_every_events: int = 1000,
        metrics_interval_sec: float = 60.0,
    ) -> None:
        self.ruleset = ruleset
        self.scoring_mode = scoring_mode
        self.paper_weights = list(paper_weights) if paper_weights is not None else [1.0] * 7
        self.tau = float(tau) if tau is not None else None
        self.paper_mode = paper_mode
        if prereq_policy not in hsg_builder.SUPPORTED_PREREQ_POLICIES:
            raise ValueError("prereq_policy must be 'dst_only' or 'union'")
        self.prereq_policy = prereq_policy
        self.noise_config = noise_config or NoiseConfig(
            noise_model=noise_model,
            noise_bytes_threshold=noise_bytes_threshold,
            noise_signature_min_ratio=max(0.0, min(1.0, float(noise_signature_min_ratio))),
        )
        if noise_model is not None and self.noise_config.noise_model is None:
            self.noise_config.noise_model = noise_model
        self.noise_model = self.noise_config.noise_model
        self.noise_bytes_threshold = self.noise_config.noise_bytes_threshold
        self.noise_signature_min_ratio = max(0.0, min(1.0, float(self.noise_config.noise_signature_min_ratio)))
        self.graph_path_allowlist = graph_path_allowlist
        self.max_graph_path_edges = max_graph_path_edges
        self.max_graph_path_candidates_per_match = max_graph_path_candidates_per_match
        self.use_online_prereq = bool(use_online_prereq)
        if global_refine_mode not in {"off", "snapshot", "every_n_events"}:
            raise ValueError("global_refine_mode must be one of: off, snapshot, every_n_events")
        self.global_refine_mode = global_refine_mode
        self.global_refine_every = max(1, int(global_refine_every))
        self.apt_alert_threshold = float(apt_alert_threshold)
        self.scenario_dormancy_days = max(0, int(scenario_dormancy_days))
        self.graph_retention_days = max(0, int(graph_retention_days))
        self.benign_profile = benign_profile or (load_benign_profile(benign_profile_path) if benign_profile_path else None)
        self.metrics_path = Path(metrics_path) if metrics_path else None
        self.metrics_every_events = max(1, int(metrics_every_events))
        self.metrics_interval_sec = max(1.0, float(metrics_interval_sec))
        self.global_refine_ran_at_snapshots_count = 0
        self.global_refine_ran_at_events_count = 0
        self._events_processed = 0
        if resolved_effective_config is None:
            is_paper_like = scoring_mode in {"paper", "paper_exact"}
            default_path_thres = 3.0 if is_paper_like else 0.0
            default_path_factor_op = "le" if is_paper_like else "ge"
            self.resolved_effective_config = {
                "path_thres": default_path_thres,
                "path_factor_op": default_path_factor_op,
                "scoring": scoring_mode,
                "paper_mode": paper_mode,
                "paper_weights": list(self.paper_weights),
            }
            if self.tau is not None:
                self.resolved_effective_config["tau"] = self.tau
        else:
            self.resolved_effective_config = dict(resolved_effective_config)

        self.graph = ProvenanceGraph()
        self.taint_tracker = TaintTracker(self.graph)
        self.privilege_tracker = PrivilegeTracker(self.graph)
        self.online_index = OnlineIndex()
        self.graph.register_edge_hook(self._on_graph_edge)
        self.graph.clear_prune_hooks()
        self.graph.register_prune_hook(self.taint_tracker.cleanup)
        self.graph.register_prune_hook(self.privilege_tracker.cleanup)
        self.matcher = Matcher()
        self.matcher.benign_profile = self.benign_profile
        self.prerequisite_evaluator = PrerequisiteEvaluator(
            graph=self.graph,
            taint_tracker=self.taint_tracker,
            privilege_tracker=self.privilege_tracker,
            resolved_effective_config=self.resolved_effective_config,
        )
        self.rule_by_id = {r.rule_id: r for r in ruleset.rules}
        self.rule_order = {r.rule_id: i for i, r in enumerate(ruleset.rules)}
        self.rule_severity = {r.rule_id: r.severity for r in ruleset.rules}
        self.rule_stage = {r.rule_id: infer_rule_stage(r) for r in ruleset.rules}
        self.rule_cvss = {r.rule_id: infer_rule_cvss(r) for r in ruleset.rules}
        if ruleset.has_scoring_alpha:
            self.alpha = ruleset.scoring_alpha
        elif alpha is not None:
            self.alpha = float(alpha)
        else:
            self.alpha = 1.0

        self.events_by_id: dict[str, Event] = {}
        self.dropped_match_telemetry_path = Path(dropped_match_telemetry_path) if dropped_match_telemetry_path else None
        self.alerts_path = Path(alerts_path) if alerts_path else None
        self.graph_artifact_dir = (
            self.alerts_path.parent / "graph_artifacts"
            if self.alerts_path is not None
            else None
        )
        if self.dropped_match_telemetry_path is not None:
            self.dropped_match_telemetry_path.parent.mkdir(parents=True, exist_ok=True)
            self.dropped_match_telemetry_path.write_text("", encoding="utf-8")
        if self.alerts_path is not None:
            self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
            self.alerts_path.write_text("", encoding="utf-8")
        if self.graph_artifact_dir is not None:
            self.graph_artifact_dir.mkdir(parents=True, exist_ok=True)
        if self.metrics_path is not None:
            self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
            self.metrics_path.write_text("", encoding="utf-8")
        self.matches: list[TTPMatch] = []
        self.match_by_id: dict[str, TTPMatch] = {}
        self.hsg_nodes: dict[str, HSGNode] = {}
        self.hsg_edges: list[HSGEdge] = []
        self.seen_edges: set[tuple[str, str, str]] = set()
        self._graph_path_edges_count = 0
        self._graph_path_candidates_by_src: dict[str, int] = defaultdict(int)
        self._descendants_cache: dict[str, set[str]] = {}

        # Legacy indexes kept for output shaping.
        self.node_to_matches: dict[str, set[str]] = defaultdict(set)
        self.match_to_entities: dict[str, set[str]] = {}
        self.entity_to_hsg_node: dict[str, set[str]] = defaultdict(set)

        self._match_serial = 1
        self.stats = StreamingStats(
            byte_volume_by_rule_id={},
            dynamic_threshold_by_rule_id={},
            binding_drop_by_rule_id={},
            pending_evicted_by_rule_id={},
            dormant_scenarios_closed_by_id={},
        )
        self.top_scenarios: list[dict[str, Any]] = []
        self.alerts: list[APTAlert] = []
        self._scenario_alert_state: dict[str, dict[str, Any]] = {}
        self._noise_before_override: dict[str, int] | None = None
        self.hsg_builder = IncrementalHSGBuilder(
            graph=self.graph,
            ruleset=self.ruleset,
            paper_mode=self.paper_mode,
            prereq_policy=self.prereq_policy,
            resolved_effective_config=self.resolved_effective_config,
            taint_tracker=self.taint_tracker,
            privilege_tracker=self.privilege_tracker,
            graph_path_allowlist=self.graph_path_allowlist,
            max_graph_path_edges=self.max_graph_path_edges,
            max_graph_path_candidates_per_match=self.max_graph_path_candidates_per_match,
            max_pending_matches=max_pending_matches,
            scenario_dormancy_seconds=self.scenario_dormancy_days * 24 * 60 * 60,
        )
        self.hsg_builder.pending_evicted_count = self.stats.pending_evicted_count
        self.hsg_builder.pending_evicted_by_rule_id.update(self.stats.pending_evicted_by_rule_id or {})
        self._processing_started_at = time.perf_counter()
        self._matcher_time_seconds = 0.0
        self._hsg_update_time_seconds = 0.0
        self._graph_gc_time_seconds = 0.0
        self._last_metrics_emitted_at = time.monotonic()
        self._last_metrics_emitted_events = 0
        self.paper_exact = (
            IncrementalPaperExactScorer(weights=self.paper_weights, tau=self.tau)
            if self.scoring_mode == "paper_exact"
            else None
        )

    def update_stream_observability(self, telemetry: dict[str, Any] | None) -> None:
        if not isinstance(telemetry, dict):
            return
        self.stats.reorder_buffer_saturation_count = max(
            int(self.stats.reorder_buffer_saturation_count),
            int(telemetry.get("reorder_buffer_saturation_count", 0)),
        )
        self.stats.max_observed_out_of_order_distance = max(
            int(self.stats.max_observed_out_of_order_distance),
            int(telemetry.get("max_observed_out_of_order_distance", 0)),
        )
        self.stats.stall_duration_seconds = max(
            float(self.stats.stall_duration_seconds),
            float(telemetry.get("stall_duration_seconds", 0.0)),
        )
        self.stats.current_reorder_buffer_depth = max(
            0,
            int(telemetry.get("current_reorder_buffer_depth", 0)),
        )
        self.stats.max_observed_reorder_buffer_depth = max(
            int(self.stats.max_observed_reorder_buffer_depth),
            int(telemetry.get("max_observed_reorder_buffer_depth", 0)),
        )

    def _build_performance_metrics(self) -> dict[str, Any]:
        elapsed_seconds = max(time.perf_counter() - self._processing_started_at, 1e-9)
        hsg = self.current_hsg()
        return {
            "events_per_second": float(self.stats.events) / elapsed_seconds,
            "matcher_time_seconds": float(self._matcher_time_seconds),
            "matcher_avg_ms_per_event": (float(self._matcher_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "hsg_update_time_seconds": float(self._hsg_update_time_seconds),
            "hsg_update_avg_ms_per_event": (float(self._hsg_update_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_gc_time_seconds": float(self._graph_gc_time_seconds),
            "graph_entity_count": len(self.graph.nodes),
            "graph_version_node_count": len(self.graph.version_nodes),
            "active_match_count": len(self.matches),
            "active_hsg_node_count": len(hsg.nodes),
            "active_hsg_edge_count": len(hsg.edges),
            "pending_match_count": len(self.hsg_builder.pending_matches_by_id),
            "reorder_buffer_saturation_count": int(self.stats.reorder_buffer_saturation_count),
            "max_observed_out_of_order_distance": int(self.stats.max_observed_out_of_order_distance),
            "stall_duration_seconds": float(self.stats.stall_duration_seconds),
            "current_reorder_buffer_depth": int(self.stats.current_reorder_buffer_depth),
            "max_observed_reorder_buffer_depth": int(self.stats.max_observed_reorder_buffer_depth),
        }

    def _emit_metrics_if_due(self, *, force: bool = False) -> None:
        if self.metrics_path is None:
            return
        now = time.monotonic()
        due_by_events = (self.stats.events - self._last_metrics_emitted_events) >= self.metrics_every_events
        due_by_time = (now - self._last_metrics_emitted_at) >= self.metrics_interval_sec
        if not force and not due_by_events and not due_by_time:
            return
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "events_processed": int(self.stats.events),
            "performance_metrics": self._build_performance_metrics(),
        }
        with self.metrics_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=True) + "\n")
        self._last_metrics_emitted_at = now
        self._last_metrics_emitted_events = int(self.stats.events)

    def _sync_pending_eviction_stats_from_builder(self) -> None:
        self.stats.pending_evicted_count = int(self.hsg_builder.pending_evicted_count)
        merged = dict(self.stats.pending_evicted_by_rule_id or {})
        for rule_id, count in self.hsg_builder.pending_evicted_by_rule_id.items():
            merged[rule_id] = int(count)
        self.stats.pending_evicted_by_rule_id = merged
        self.stats.pending_evicted_ttl_count = int(self.hsg_builder.pending_evicted_ttl_count)
        self.stats.pending_evicted_capacity_count = int(self.hsg_builder.pending_evicted_capacity_count)
        self.stats.dormant_scenarios_closed_count = int(self.hsg_builder.closed_scenarios_count)
        self.stats.dormant_matches_closed_count = int(self.hsg_builder.closed_matches_count)
        self.stats.dormant_scenarios_closed_by_id = dict(self.hsg_builder.closed_scenarios_by_id)

    def _sync_online_state_from_builder(self) -> None:
        active_matches = sorted(
            self.hsg_builder.matches_by_id.values(),
            key=lambda m: (int(m.sequence or 0), m.match_id),
        )
        self.matches = list(active_matches)
        self.match_by_id = {m.match_id: m for m in active_matches}
        hsg = self.hsg_builder.as_hsg()
        self.hsg_nodes = {n.match_id: n for n in hsg.nodes}
        self.hsg_edges = list(hsg.edges)
        self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}

        self.node_to_matches = defaultdict(set)
        self.match_to_entities = {}
        self.entity_to_hsg_node = defaultdict(set)
        for match in active_matches:
            entities = set(match.entities)
            self.match_to_entities[match.match_id] = entities
            for entity in entities:
                self.node_to_matches[entity].add(match.match_id)
                self.entity_to_hsg_node[entity].add(match.match_id)

    def _rebuild_online_index_from_active_matches(self) -> None:
        self.online_index = OnlineIndex()
        for edge in self.graph.edges:
            self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)
        for match in self.matches:
            for node_id in (match.subject_node_id, match.object_node_id):
                if node_id:
                    self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=match.match_id,
                        rule_id=match.rule_id,
                        sequence=int(match.sequence or 0),
                        origin_node_id=node_id,
                    )

    def _protected_graph_entities(self) -> set[str]:
        protected: set[str] = set()
        for match in self.matches:
            protected.update(e for e in match.entities if isinstance(e, str))
            protected.update(v for v in match.bindings.values() if isinstance(v, str))
        for pending in self.hsg_builder.pending_matches_by_id.values():
            protected.update(e for e in pending.entities if isinstance(e, str))
            protected.update(v for v in pending.bindings.values() if isinstance(v, str))
        protected.update(self.taint_tracker.tainted_entities())
        protected.update(self.privilege_tracker.privileged_entities())
        return protected

    def _protected_graph_version_nodes(self) -> set[str]:
        protected = set(self.taint_tracker.tainted_version_nodes()) | set(self.privilege_tracker.elevated_version_nodes())
        for match in self.matches:
            protected.update(match.binding_node_ids.values())
            if match.subject_node_id:
                protected.add(match.subject_node_id)
            if match.object_node_id:
                protected.add(match.object_node_id)
        for pending in self.hsg_builder.pending_matches_by_id.values():
            protected.update(pending.binding_node_ids.values())
            if pending.subject_node_id:
                protected.add(pending.subject_node_id)
            if pending.object_node_id:
                protected.add(pending.object_node_id)
        return protected

    def _run_graph_deep_gc(self, watermark_ts: str | None) -> None:
        if self.graph_retention_days <= 0:
            return
        started = time.perf_counter()
        pruned = self.graph.prune_stale_orphaned(
            watermark_ts=watermark_ts,
            retention_seconds=self.graph_retention_days * 24 * 60 * 60,
            protected_entities=self._protected_graph_entities(),
            protected_version_nodes=self._protected_graph_version_nodes(),
        )
        self._graph_gc_time_seconds += time.perf_counter() - started
        self.stats.graph_pruned_entity_count += int(pruned.get("entities_removed", 0))
        self.stats.graph_pruned_version_node_count += int(pruned.get("version_nodes_removed", 0))
        self.stats.graph_pruned_edge_count += int(pruned.get("edges_removed", 0))
        self.stats.graph_pruned_semantic_edge_count += int(pruned.get("semantic_edges_removed", 0))
        if any(int(pruned.get(key, 0)) > 0 for key in ("entities_removed", "version_nodes_removed", "edges_removed", "semantic_edges_removed")):
            self._rebuild_online_index_from_active_matches()

    def _next_match_id(self) -> str:
        mid = f"m{self._match_serial}"
        self._match_serial += 1
        return mid

    def _reid_match(self, m: TTPMatch) -> TTPMatch:
        return TTPMatch(
            match_id=self._next_match_id(),
            rule_id=m.rule_id,
            event_ids=list(m.event_ids),
            entities=list(m.entities),
            bindings=dict(m.bindings),
            metadata=dict(m.metadata),
            binding_node_ids=dict(m.binding_node_ids),
            subject_node_id=m.subject_node_id,
            object_node_id=m.object_node_id,
            sequence=m.sequence,
            attributes=dict(m.attributes),
        )

    def _on_graph_edge(self, edge: Edge) -> None:
        self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)

    @staticmethod
    def _shared_node_id(left: TTPMatch, right: TTPMatch) -> str | None:
        left_nodes = {left.subject_node_id, left.object_node_id}
        right_nodes = {right.subject_node_id, right.object_node_id}
        common = {x for x in (left_nodes & right_nodes) if x}
        if not common:
            return None
        return sorted(common)[0]

    @staticmethod
    def _node_for_binding(match: TTPMatch, binding: str | None) -> str | None:
        if binding == "subject":
            return match.subject_node_id
        if binding == "object":
            return match.object_node_id
        return None

    def _edge_for_pair_online(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = hsg_builder.prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)

        built: list[HSGEdge] = []
        for relation in prereq_types:
            if relation not in {"graph_path", "shared_entity"}:
                continue
            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue

            weight: float | None = None
            edge_path_factor: float | None = None
            edge_dependency_strength: float | None = None
            if relation == "graph_path":
                if self._graph_path_edges_count >= self.max_graph_path_edges:
                    continue
                allowlist = self.graph_path_allowlist if self.graph_path_allowlist is not None else hsg_builder.GRAPH_PATH_ALLOWLIST
                if allowlist is not None and (left.rule_id, right.rule_id) not in allowlist:
                    continue
                cfg = hsg_builder._resolve_prereq_config(relation, left.rule_id, right.rule_id)  # noqa: SLF001
                if not cfg:
                    continue
                from_binding = cfg.get("from_binding")
                to_binding = cfg.get("to_binding")
                from_node = self._node_for_binding(left, from_binding)
                to_node = self._node_for_binding(right, to_binding)
                if not from_node or not to_node:
                    continue
                if not self.online_index.mapper_contains_match(to_node, left.match_id, origin_node_id=from_node):
                    continue
                hops = self.online_index.mapper_min_hops(to_node, left.match_id, origin_node_id=from_node)
                if hops is None:
                    continue
                edge_pf = 1.0 + float(hops)
                edge_path_factor = float(edge_pf)
                weight = 1.0 / float(edge_pf)
                edge_dependency_strength = weight
            elif relation == "shared_entity":
                shared = self._shared_node_id(left, right)
                if not shared:
                    continue

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
                self._graph_path_edges_count += 1
        return built

    def _edge_for_pair_legacy(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = hsg_builder.prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)

        built: list[HSGEdge] = []
        for relation in prereq_types:
            if relation == "graph_path":
                allowlist = self.graph_path_allowlist if self.graph_path_allowlist is not None else hsg_builder.GRAPH_PATH_ALLOWLIST
                if allowlist is not None and (left.rule_id, right.rule_id) not in allowlist:
                    continue
                if self._graph_path_candidates_by_src[left.match_id] >= self.max_graph_path_candidates_per_match:
                    continue
                if self._graph_path_edges_count >= self.max_graph_path_edges:
                    continue
                if not hsg_builder.is_graph_path_candidate(self.graph, left, right, self._descendants_cache):
                    continue
                self._graph_path_candidates_by_src[left.match_id] += 1

            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue

            config = hsg_builder._resolve_prereq_config(relation, left.rule_id, right.rule_id)  # noqa: SLF001
            if not hsg_builder.is_prerequisite_satisfied(self.graph, left, right, relation, config):
                continue

            weight: float | None = None
            edge_path_factor: float | None = None
            edge_dependency_strength: float | None = None
            if relation == "graph_path" and config:
                from_binding = config.get("from_binding")
                to_binding = config.get("to_binding")
                if from_binding and to_binding:
                    from_entity = left.bindings.get(from_binding)
                    to_entity = right.bindings.get(to_binding)
                    if from_entity and to_entity:
                        pf_reqs = hsg_builder.path_factor_prerequisites_for_pair(left_rule, right_rule, self.prereq_policy)
                        if pf_reqs and any(
                            not hsg_builder.is_path_factor_satisfied(
                                self.graph,
                                from_entity,
                                to_entity,
                                prereq.max_path_factor,
                            )
                            for prereq in pf_reqs
                        ):
                            continue
                        dependency = self.graph.dependency_strength(from_entity, to_entity)
                        edge_dependency_strength = dependency
                        edge_pf = self.graph.path_factor_for_edge(from_entity, to_entity)
                        if edge_pf is None:
                            continue
                        edge_path_factor = float(edge_pf)
                        if self.paper_mode == "strict":
                            weight = edge_path_factor
                        else:
                            weight = dependency * edge_path_factor

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
                self._graph_path_edges_count += 1
        return built

    def _required_ttp_ids(self, rule_id: str) -> set[str]:
        rule = self.rule_by_id.get(rule_id)
        if rule is None:
            return set()
        raw = getattr(rule, "required_ttp_ids", None)
        if isinstance(raw, list):
            return {x for x in raw if isinstance(x, str)}
        return set()

    def _candidate_antecedents_for_graph_path(self, new_match: TTPMatch) -> set[str]:
        ids: set[str] = set()
        for entity in set(new_match.entities) | set(new_match.bindings.values()):
            ids |= self.entity_to_hsg_node.get(entity, set())
        for node_id in (new_match.subject_node_id, new_match.object_node_id):
            if not node_id:
                continue
            ids |= self.online_index.mapper_match_ids(node_id)
        return ids

    def _candidate_antecedents_for_shared_entity(self, new_match: TTPMatch) -> set[str]:
        ids: set[str] = set()
        for entity in set(new_match.entities) | set(new_match.bindings.values()):
            ids |= self.entity_to_hsg_node.get(entity, set())
        return ids

    def _prereq_satisfied_online(self, new_match: TTPMatch) -> tuple[bool, set[str]]:
        rule = self.rule_by_id.get(new_match.rule_id)
        if rule is None:
            return False, set()

        if isinstance(getattr(rule, "prerequisite_ast", None), dict):
            result = self.prerequisite_evaluator.evaluate_rule(rule, new_match, self.match_by_id)
            for key, value in result.resolved_symbols.items():
                if key and value:
                    new_match.attributes[f"resolved:{key}"] = value
            antecedents = {edge.src_match_id for edge in result.edges if edge.src_match_id}
            return result.satisfied, antecedents

        prereq_types = hsg_builder.prerequisite_types(rule)
        required_ttp_ids = self._required_ttp_ids(new_match.rule_id)
        antecedents: set[str] = set()

        # previous-ttp prerequisite via mapper O(1)
        for required in required_ttp_ids:
            if not new_match.object_node_id or not self.online_index.mapper_contains_rule(new_match.object_node_id, required):
                return False, set()

        # graph_path prerequisite via mapper lookup only (no graph traversal)
        if "graph_path" in prereq_types:
            antecedents |= self._candidate_antecedents_for_graph_path(new_match)
            if not antecedents:
                return False, set()

        # shared_entity prerequisite via local node index only
        if "shared_entity" in prereq_types:
            local = self._candidate_antecedents_for_shared_entity(new_match)
            if not local:
                return False, set()
            antecedents |= local

        # time-order prerequisite (if required_ttp_ids configured) via earliest seq O(1)
        for required in required_ttp_ids:
            if not new_match.object_node_id:
                return False, set()
            earliest = self.online_index.mapper_earliest_seq(new_match.object_node_id, required)
            if earliest is None:
                return False, set()
            if new_match.sequence is not None and earliest >= new_match.sequence:
                return False, set()

        return True, antecedents

    def _edge_for_ast_prereqs(self, new_match: TTPMatch) -> list[HSGEdge]:
        rule = self.rule_by_id.get(new_match.rule_id)
        if rule is None or not isinstance(getattr(rule, "prerequisite_ast", None), dict):
            return []
        prior_matches = {k: v for k, v in self.match_by_id.items() if k != new_match.match_id}
        result = self.prerequisite_evaluator.evaluate_rule(rule, new_match, prior_matches)
        if not result.satisfied:
            return []
        built: list[HSGEdge] = []
        for edge in result.edges:
            edge_key = (edge.src_match_id, new_match.match_id, edge.relation)
            if edge_key in self.seen_edges:
                continue
            if edge.src_match_id not in self.match_by_id:
                continue
            self.seen_edges.add(edge_key)
            built.append(
                HSGEdge(
                    src=edge.src_match_id,
                    dst=new_match.match_id,
                    relation=edge.relation,
                    weight=edge.weight,
                    path_factor=edge.path_factor,
                    dependency_strength=edge.dependency_strength,
                )
            )
            if edge.relation == "graph_path":
                self._graph_path_edges_count += 1
        return built

    def _apply_noise_model(self, new_matches: list[TTPMatch]) -> list[TTPMatch]:
        if not new_matches:
            return new_matches
        kept = list(new_matches)
        if self.noise_model is not None:
            drop_ids, noise_stats = get_benign_drop_ids(
                kept,
                rule_by_id=self.rule_by_id,
                model=self.noise_model,
                events_by_id=self.events_by_id,
                bytes_threshold=self.noise_bytes_threshold,
                signature_min_ratio=self.noise_signature_min_ratio,
            )
            self.stats.by_signature += int(noise_stats.get("by_signature", 0))
            self.stats.by_byte_volume += int(noise_stats.get("by_byte_volume", 0))
            by_rule = noise_stats.get("byte_volume_by_rule_id", {})
            if isinstance(by_rule, dict) and self.stats.byte_volume_by_rule_id is not None:
                for rid, cnt in by_rule.items():
                    self.stats.byte_volume_by_rule_id[rid] = self.stats.byte_volume_by_rule_id.get(rid, 0) + int(cnt)

            before_signature_filter = len(kept)
            kept = [m for m in kept if m.match_id not in drop_ids]
            self.stats.dropped_matches += before_signature_filter - len(kept)

        if self.noise_config.noise_model is not None and kept:
            before_dynamic_filter = len(kept)
            kept = filter_matches(
                kept,
                self.noise_config,
                events_by_id=self.events_by_id,
                reset_dynamic_state=False,
            )
            dynamic_stats = self.noise_config.last_trained_noise_stats
            self.stats.by_dynamic_threshold += int(dynamic_stats.get("by_dynamic_threshold", 0))
            by_rule = dynamic_stats.get("dynamic_threshold_by_rule_id", {})
            if isinstance(by_rule, dict) and self.stats.dynamic_threshold_by_rule_id is not None:
                for rid, cnt in by_rule.items():
                    self.stats.dynamic_threshold_by_rule_id[rid] = self.stats.dynamic_threshold_by_rule_id.get(rid, 0) + int(cnt)
            self.stats.dropped_matches += before_dynamic_filter - len(kept)
        return kept

    def _record_binding_drop_telemetry(self, entries: list[dict[str, Any]]) -> None:
        if not entries:
            return
        if self.stats.binding_drop_by_rule_id is None:
            self.stats.binding_drop_by_rule_id = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            self.stats.binding_drop_count += 1
            rule_id = str(entry.get("rule_id") or "")
            if rule_id:
                self.stats.binding_drop_by_rule_id[rule_id] = self.stats.binding_drop_by_rule_id.get(rule_id, 0) + 1
            if self.dropped_match_telemetry_path is not None:
                with self.dropped_match_telemetry_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=True) + "\n")

    def _refresh_scores(self) -> None:
        if self.scoring_mode == "paper_exact" and self.paper_exact is not None:
            state = self.paper_exact.state
            stage_severity = {APT_STAGES[i]: float(state.stage_severity[i]) for i in range(len(APT_STAGES))}
            scenario = {
                "score": float(state.score),
                "score_legacy": 0.0,
                "score_paper": float(state.score),
                "score_paper_exact": float(state.score),
                "score_paper_exact_log": float(state.log_score),
                "threat_tuple": list(state.stage_severity),
                "threat_tuple_exact": list(state.stage_severity),
                "stage_severity": stage_severity,
                "stage_severity_exact": stage_severity,
                "paper_weights": list(self.paper_weights),
                "scenario_id": f"scenario-{sorted(self.hsg_nodes)[0]}" if self.hsg_nodes else "scenario-empty",
                "match_ids": sorted(self.hsg_nodes.keys()),
                "nodes": len(self.hsg_nodes),
                "edges": len(self.hsg_edges),
            }
            self.top_scenarios = [scenario]
            while len(self.top_scenarios) < 3:
                self.top_scenarios.append(
                    {
                        "score": 0.0,
                        "score_legacy": 0.0,
                        "score_paper": 1.0,
                        "score_paper_exact": 1.0,
                        "score_paper_exact_log": 0.0,
                        "threat_tuple": [1.0] * len(APT_STAGES),
                        "threat_tuple_exact": [1.0] * len(APT_STAGES),
                        "stage_severity": {APT_STAGES[i]: 1.0 for i in range(len(APT_STAGES))},
                        "stage_severity_exact": {APT_STAGES[i]: 1.0 for i in range(len(APT_STAGES))},
                        "paper_weights": list(self.paper_weights),
                        "scenario_id": "scenario-empty",
                        "match_ids": [],
                        "nodes": 0,
                        "edges": 0,
                    }
                )
            self._update_alerts()
            return
        self.top_scenarios = rank_hsg_scenarios(
            self.current_hsg(),
            scoring="weighted",
            rule_severity=self.rule_severity,
            alpha=self.alpha,
            top_k=3,
            score_mode=self.scoring_mode,
            rule_stage=self.rule_stage,
            rule_cvss=self.rule_cvss,
            paper_weights=self.paper_weights,
        )
        self._update_alerts()

    def _update_alerts(self) -> None:
        if self.apt_alert_threshold <= 0.0:
            return
        for scenario in self.top_scenarios:
            score = float(scenario.get("score", 0.0))
            if score < self.apt_alert_threshold:
                continue
            scenario_id = str(scenario.get("scenario_id") or "")
            if not scenario_id:
                continue
            match_ids = sorted(str(mid) for mid in scenario.get("match_ids", []) if isinstance(mid, str))
            if not match_ids:
                continue
            stage_severity = scenario.get("stage_severity", {})
            stages = sorted(str(stage) for stage, sev in stage_severity.items() if float(sev) > 0.0)
            stage_set = set(stages)
            previous = self._scenario_alert_state.get(scenario_id)
            if previous is not None:
                score_delta = float(score) - float(previous.get("last_alert_score", 0.0))
                new_stage_added = not stage_set.issubset(set(previous.get("last_stage_set", set())))
                if score_delta < 10.0 and not new_stage_added:
                    continue
            entities: set[str] = set()
            triggered_at: str | None = None
            tainted_entities: set[str] = set()
            root_entities: set[str] = set()
            for match_id in match_ids:
                match = self.match_by_id.get(match_id)
                if match is None:
                    continue
                entities.update(e for e in match.entities if isinstance(e, str))
                tainted_entities.update(
                    e for e in match.entities
                    if isinstance(e, str) and self.taint_tracker.is_tainted_entity(e)
                )
                rule = self.rule_by_id.get(match.rule_id)
                if rule is not None:
                    stage_num = infer_rule_stage(rule)
                    if stage_num == 1:
                        root_entities.update(e for e in match.entities if isinstance(e, str))
                if triggered_at is None and isinstance(match.metadata.get("event_ts"), str):
                    triggered_at = str(match.metadata.get("event_ts"))
            artifact_path: str | None = None
            if self.graph_artifact_dir is not None:
                exported = export_alert_scenario_artifact(
                    graph=self.graph,
                    hsg=self.current_hsg(),
                    scenario_id=scenario_id,
                    match_ids=match_ids,
                    entities=entities,
                    tainted_entities=tainted_entities,
                    privileged_entities=self.privilege_tracker.privileged_entities(),
                    tainted_version_nodes=self.taint_tracker.tainted_version_nodes(),
                    elevated_version_nodes=self.privilege_tracker.elevated_version_nodes(),
                    out_dir=self.graph_artifact_dir,
                )
                artifact_path = str(exported)
            alert = APTAlert(
                alert_id=f"apt-alert-{len(self.alerts) + 1}",
                scenario_id=scenario_id,
                triggered_at=triggered_at,
                severity_score=score,
                threshold=self.apt_alert_threshold,
                kill_chain_stages=stages,
                achieved_stages=stages,
                core_entities=sorted(entities)[:10],
                tainted_entities=sorted(tainted_entities)[:20],
                root_entities=sorted(root_entities)[:20],
                match_ids=match_ids,
                graph_artifact_path=artifact_path,
            )
            self.alerts.append(alert)
            self._scenario_alert_state[scenario_id] = {
                "last_alert_score": score,
                "last_stage_set": set(stages),
            }
            if self.alerts_path is not None:
                with self.alerts_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(alert), ensure_ascii=True) + "\n")

    def process_event(self, event: Event) -> None:
        self.stats.events += 1
        self.events_by_id[event.event_id] = event
        node_info = self.graph.add_event(event)
        if node_info is None:
            return
        self.taint_tracker.on_graph_event(event, node_info)
        self.privilege_tracker.on_graph_event(event, node_info)

        matcher_started = time.perf_counter()
        raw_matches = [self._reid_match(m) for m in self.matcher.match(self.graph, self.ruleset, [event])]
        self._matcher_time_seconds += time.perf_counter() - matcher_started
        self._record_binding_drop_telemetry(self.matcher.last_drop_telemetry)
        self.stats.benign_profile_drop_count += int(self.matcher.last_benign_profile_drop_count)
        self.stats.raw_matches += len(raw_matches)
        new_matches = self._apply_noise_model(raw_matches)

        hsg_update_started = time.perf_counter()
        for new_match in new_matches:
            new_match.subject_node_id = node_info.get("subject_node_id")
            new_match.object_node_id = node_info.get("object_node_id")
            new_match.metadata["event_ts"] = event.ts
            binding_node_ids: dict[str, str] = {}
            for symbol, entity_id in new_match.bindings.items():
                if entity_id == event.subject and new_match.subject_node_id:
                    binding_node_ids[symbol] = new_match.subject_node_id
                    continue
                if entity_id == event.object and new_match.object_node_id:
                    binding_node_ids[symbol] = new_match.object_node_id
                    continue
                version_node = self.graph.current_version_node(entity_id)
                if version_node:
                    binding_node_ids[symbol] = version_node
            if any(symbol.startswith("$") and symbol not in binding_node_ids for symbol in new_match.bindings):
                missing_symbols = [symbol for symbol in new_match.bindings if symbol.startswith("$") and symbol not in binding_node_ids]
                self._record_binding_drop_telemetry(
                    [
                        {
                            "reason": "binding_version_node_missing",
                            "rule_id": new_match.rule_id,
                            "rule_name": self.rule_by_id.get(new_match.rule_id).name if self.rule_by_id.get(new_match.rule_id) else "",
                            "event_id": event.event_id,
                            "symbol": symbol,
                            "field": None,
                            "fields": [],
                        }
                        for symbol in missing_symbols
                    ]
                )
                continue
            new_match.binding_node_ids = binding_node_ids
            new_match.sequence = self.stats.events
            new_match.attributes = {
                "subject_node_id": new_match.subject_node_id,
                "object_node_id": new_match.object_node_id,
                "binding_node_ids": dict(binding_node_ids),
            }

            if self.use_online_prereq:
                satisfied, antecedents = self._prereq_satisfied_online(new_match)
                rule = self.rule_by_id.get(new_match.rule_id)
                has_prereq = bool(
                    rule
                    and (
                        hsg_builder.prerequisite_types(rule)
                        or isinstance(getattr(rule, "prerequisite_ast", None), dict)
                    )
                )
                if has_prereq and not satisfied:
                    self.hsg_builder.add_match(new_match, antecedents, watermark_ts=event.ts)
                    self._sync_pending_eviction_stats_from_builder()
                    self._sync_online_state_from_builder()
                    self._rebuild_online_index_from_active_matches()
                    continue
            self.matches.append(new_match)
            self.match_by_id[new_match.match_id] = new_match
            self.hsg_nodes[new_match.match_id] = HSGNode(
                match_id=new_match.match_id,
                rule_id=new_match.rule_id,
                event_ids=list(new_match.event_ids),
                entities=list(new_match.entities),
            )
            entities = set(new_match.entities)
            self.match_to_entities[new_match.match_id] = entities
            for entity in entities:
                self.node_to_matches[entity].add(new_match.match_id)
                self.entity_to_hsg_node[entity].add(new_match.match_id)
            for node_id in (new_match.subject_node_id, new_match.object_node_id):
                if node_id:
                    self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=new_match.match_id,
                        rule_id=new_match.rule_id,
                        sequence=int(new_match.sequence or self.stats.events),
                        origin_node_id=node_id,
                    )
            self.taint_tracker.mark_initial_compromise(new_match, self.rule_by_id.get(new_match.rule_id))
            if self.use_online_prereq:
                self.stats.candidate_pairs_considered += len(antecedents)
                _accepted, built_edges = self.hsg_builder.add_match(new_match, antecedents, watermark_ts=event.ts)
                self._sync_pending_eviction_stats_from_builder()
                self._sync_online_state_from_builder()
            if self.paper_exact is not None:
                self.paper_exact.update(
                    stage=int(self.rule_stage.get(new_match.rule_id, 1)),
                    raw_severity=self.rule_cvss.get(new_match.rule_id, self.rule_severity.get(new_match.rule_id, 1.0)),
                    event_time=event.ts,
                    sequence=new_match.sequence,
                )
        if self.use_online_prereq:
            closed_match_ids = self.hsg_builder.gc_dormant_scenarios(event.ts)
            self._sync_pending_eviction_stats_from_builder()
            if closed_match_ids:
                self._sync_online_state_from_builder()
                self._rebuild_online_index_from_active_matches()
        self._run_graph_deep_gc(event.ts)
        self._hsg_update_time_seconds += time.perf_counter() - hsg_update_started

        if not self.use_online_prereq:
            ordered_matches = sorted(
                self.matches,
                key=lambda m: (
                    int(self.rule_order.get(m.rule_id, 10**9)),
                    int(m.sequence or 0),
                    m.match_id,
                ),
            )
            remap: dict[str, str] = {}
            for i, m in enumerate(ordered_matches, start=1):
                new_id = f"m{i}"
                remap[m.match_id] = new_id
            for m in ordered_matches:
                m.match_id = remap[m.match_id]
            self.matches = ordered_matches
            self.match_by_id = {m.match_id: m for m in ordered_matches}
            hsg = hsg_builder.build_hsg(
                ordered_matches,
                self.graph,
                self.ruleset,
                paper_mode=self.paper_mode,
                prereq_policy=self.prereq_policy,
                resolved_effective_config=self.resolved_effective_config,
                taint_tracker=self.taint_tracker,
                graph_path_allowlist=self.graph_path_allowlist,
                max_graph_path_edges=self.max_graph_path_edges,
                max_graph_path_candidates_per_match=self.max_graph_path_candidates_per_match,
            )
            self.hsg_nodes = {n.match_id: n for n in hsg.nodes}
            self.hsg_edges = list(hsg.edges)
            self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}
            self._graph_path_edges_count = len([e for e in self.hsg_edges if e.relation == "graph_path"])

        self._refresh_scores()
        self._events_processed += 1
        self._emit_metrics_if_due()
        if self.global_refine_mode == "every_n_events" and self._events_processed % self.global_refine_every == 0:
            self._maybe_global_refine("periodic")

    def process_source(self, source: Any) -> int:
        count = 0
        for event in source:
            self.process_event(event)
            count += 1
        return count

    def process_raw_source(
        self,
        raw_source: Any,
        *,
        parser_workers: int = 0,
        parser_queue_size: int = 1024,
    ) -> int:
        count = 0
        for event in iter_parsed_events_parallel(
            raw_source,
            worker_count=max(1, int(parser_workers)),
            queue_size=max(1, int(parser_queue_size)),
        ):
            self.process_event(event)
            count += 1
        return count

    def current_hsg(self) -> HSG:
        return HSG(nodes=list(self.hsg_nodes.values()), edges=list(self.hsg_edges))

    def _replace_state_from_filtered(
        self,
        matches_after: list[TTPMatch],
        hsg_after: HSG,
        *,
        before_matches: int | None = None,
        before_nodes: int | None = None,
        before_edges: int | None = None,
    ) -> None:
        if before_matches is not None and before_nodes is not None and before_edges is not None:
            self._noise_before_override = {
                "matches": int(before_matches),
                "hsg_nodes": int(before_nodes),
                "hsg_edges": int(before_edges),
            }
        self.matches = list(matches_after)
        self.match_by_id = {m.match_id: m for m in self.matches}
        self.hsg_nodes = {n.match_id: n for n in hsg_after.nodes}
        self.hsg_edges = list(hsg_after.edges)
        self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}

        self.node_to_matches = defaultdict(set)
        self.match_to_entities = {}
        self.entity_to_hsg_node = defaultdict(set)
        for m in self.matches:
            entities = set(m.entities)
            self.match_to_entities[m.match_id] = entities
            for entity in entities:
                self.node_to_matches[entity].add(m.match_id)
                self.entity_to_hsg_node[entity].add(m.match_id)

        self._graph_path_edges_count = len([e for e in self.hsg_edges if e.relation == "graph_path"])
        # Rebuild online index from current graph + kept matches.
        self.online_index = OnlineIndex()
        self.taint_tracker = TaintTracker(self.graph)
        self.privilege_tracker = PrivilegeTracker(self.graph)
        self.graph.clear_prune_hooks()
        self.graph.register_prune_hook(self.taint_tracker.cleanup)
        self.graph.register_prune_hook(self.privilege_tracker.cleanup)
        self.prerequisite_evaluator = PrerequisiteEvaluator(
            graph=self.graph,
            taint_tracker=self.taint_tracker,
            privilege_tracker=self.privilege_tracker,
            resolved_effective_config=self.resolved_effective_config,
        )
        self.hsg_builder = IncrementalHSGBuilder(
            graph=self.graph,
            ruleset=self.ruleset,
            paper_mode=self.paper_mode,
            prereq_policy=self.prereq_policy,
            resolved_effective_config=self.resolved_effective_config,
            taint_tracker=self.taint_tracker,
            privilege_tracker=self.privilege_tracker,
            graph_path_allowlist=self.graph_path_allowlist,
            max_graph_path_edges=self.max_graph_path_edges,
            max_graph_path_candidates_per_match=self.max_graph_path_candidates_per_match,
            max_pending_matches=self.hsg_builder.max_pending_matches,
            scenario_dormancy_seconds=self.hsg_builder.scenario_dormancy_seconds,
        )
        self.hsg_builder.pending_evicted_count = self.stats.pending_evicted_count
        self.hsg_builder.pending_evicted_by_rule_id.update(self.stats.pending_evicted_by_rule_id or {})
        self.hsg_builder.pending_evicted_ttl_count = self.stats.pending_evicted_ttl_count
        self.hsg_builder.pending_evicted_capacity_count = self.stats.pending_evicted_capacity_count
        self.hsg_builder.closed_scenarios_count = self.stats.dormant_scenarios_closed_count
        self.hsg_builder.closed_matches_count = self.stats.dormant_matches_closed_count
        self.hsg_builder.closed_scenarios_by_id.update(self.stats.dormant_scenarios_closed_by_id or {})
        for edge in self.graph.edges:
            self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)
        for m in self.matches:
            self.taint_tracker.mark_initial_compromise(m, self.rule_by_id.get(m.rule_id))
            for node_id in (m.subject_node_id, m.object_node_id):
                if node_id:
                    self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=m.match_id,
                        rule_id=m.rule_id,
                        sequence=int(m.sequence or 0),
                        origin_node_id=node_id,
                    )
            self.hsg_builder.add_match(m, watermark_ts=m.metadata.get("event_ts"))
        self._sync_pending_eviction_stats_from_builder()

    def _maybe_global_refine(self, trigger: str) -> None:
        if self.global_refine_mode == "off":
            return
        if trigger == "snapshot" and self.global_refine_mode != "snapshot":
            return
        if trigger == "periodic" and self.global_refine_mode != "every_n_events":
            return

        current_hsg = self.current_hsg()
        noise_config = NoiseConfig(
            min_graph_path_weight=0.0,
            min_path_factor=float(self.resolved_effective_config.get("path_thres", 0.0)),
            path_factor_op=str(self.resolved_effective_config.get("path_factor_op", "ge")),
        )
        if self.noise_model and self.matches:
            drop_ids, _ = get_benign_drop_ids(
                self.matches,
                rule_by_id=self.rule_by_id,
                model=self.noise_model,
                events_by_id=self.events_by_id,
                bytes_threshold=self.noise_bytes_threshold,
                signature_min_ratio=self.noise_signature_min_ratio,
            )
            noise_config.drop_match_ids = set(drop_ids)

        matches_after, hsg_after = apply_noise_filter(self.matches, current_hsg, noise_config, events_by_id=self.events_by_id)
        self._replace_state_from_filtered(matches_after, hsg_after)
        self._refresh_scores()

        if trigger == "snapshot":
            self.global_refine_ran_at_snapshots_count += 1
        elif trigger == "periodic":
            self.global_refine_ran_at_events_count += 1

    def build_result(self) -> dict[str, Any]:
        hsg = self.current_hsg()
        before_counts = self._noise_before_override or {
            "matches": self.stats.raw_matches,
            "hsg_nodes": self.stats.raw_matches,
            "hsg_edges": len(hsg.edges),
        }
        noise_filter = {
            "before": before_counts,
            "after": {
                "matches": len(self.matches),
                "hsg_nodes": len(hsg.nodes),
                "hsg_edges": len(hsg.edges),
            },
            "dropped": {
                "matches": int(before_counts["matches"]) - len(self.matches),
                "hsg_nodes": int(before_counts["hsg_nodes"]) - len(hsg.nodes),
                "hsg_edges": int(before_counts["hsg_edges"]) - len(hsg.edges),
            },
        }
        legacy_snapshot_mode = (self.scoring_mode == "legacy" and not self.use_online_prereq)
        include_trained_noise = (
            (not legacy_snapshot_mode)
            or self.noise_model is not None
            or self.stats.dropped_matches > 0
            or self.stats.by_signature > 0
            or self.stats.by_byte_volume > 0
        )
        if include_trained_noise:
            noise_filter["trained_noise"] = {
                "dropped_matches": self.stats.dropped_matches,
                "by_signature": self.stats.by_signature,
                "by_byte_volume": self.stats.by_byte_volume,
                "by_dynamic_threshold": self.stats.by_dynamic_threshold,
                "byte_volume_by_rule_id": self.stats.byte_volume_by_rule_id or {},
                "dynamic_threshold_by_rule_id": self.stats.dynamic_threshold_by_rule_id or {},
            }
        dropped_match_telemetry = {
            "binding_drop_count": self.stats.binding_drop_count,
            "binding_drop_by_rule_id": self.stats.binding_drop_by_rule_id or {},
            "benign_profile_drop_count": int(self.stats.benign_profile_drop_count),
            "path": str(self.dropped_match_telemetry_path) if self.dropped_match_telemetry_path is not None else None,
        }
        pending_eviction_telemetry = {
            "pending_evicted_count": int(self.stats.pending_evicted_count),
            "pending_evicted_by_rule_id": dict(self.stats.pending_evicted_by_rule_id or {}),
            "pending_evicted_ttl_count": int(self.stats.pending_evicted_ttl_count),
            "pending_evicted_capacity_count": int(self.stats.pending_evicted_capacity_count),
            "pending_ttl_seconds": self.hsg_builder.pending_ttl_seconds,
            "max_pending_matches": self.hsg_builder.max_pending_matches,
        }
        dormant_scenario_telemetry = {
            "closed_scenarios_count": int(self.stats.dormant_scenarios_closed_count),
            "closed_matches_count": int(self.stats.dormant_matches_closed_count),
            "closed_scenarios_by_id": dict(self.stats.dormant_scenarios_closed_by_id or {}),
            "scenario_dormancy_seconds": self.hsg_builder.scenario_dormancy_seconds,
        }
        graph_gc_telemetry = {
            "retention_days": int(self.graph_retention_days),
            "entities_removed": int(self.stats.graph_pruned_entity_count),
            "version_nodes_removed": int(self.stats.graph_pruned_version_node_count),
            "edges_removed": int(self.stats.graph_pruned_edge_count),
            "semantic_edges_removed": int(self.stats.graph_pruned_semantic_edge_count),
        }
        alerts_summary = {
            "count": len(self.alerts),
            "threshold": float(self.apt_alert_threshold),
            "path": str(self.alerts_path) if self.alerts_path is not None else None,
        }
        performance_metrics = self._build_performance_metrics()
        top1 = self.top_scenarios[0] if self.top_scenarios else {}
        paper_exact_state = self.paper_exact.state if self.paper_exact is not None else None
        paper_scoring = {
            "threat_tuple": top1.get("threat_tuple", []),
            "stage_severity": top1.get("stage_severity", {}),
            "paper_weights": top1.get("paper_weights", self.resolved_effective_config.get("paper_weights", [1.0] * 7)),
            "score_paper": top1.get("score_paper", top1.get("score_paper_exact", 1.0)),
        }
        if not legacy_snapshot_mode:
            paper_scoring["score_paper_exact"] = top1.get("score_paper_exact", top1.get("score_paper", 1.0))
            paper_scoring["score_paper_exact_log"] = top1.get("score_paper_exact_log", 0.0)
            paper_scoring["tau"] = self.tau
            paper_scoring["tau_log"] = None if self.tau is None else self.paper_exact.log_tau if self.paper_exact is not None else None
        if paper_exact_state is not None:
            paper_scoring["stage_earliest_detection_time"] = {
                APT_STAGES[i]: paper_exact_state.stage_earliest_detection_time[i] for i in range(len(APT_STAGES))
            }
            paper_scoring["stage_earliest_detection_sequence"] = {
                APT_STAGES[i]: paper_exact_state.stage_earliest_detection_sequence[i] for i in range(len(APT_STAGES))
            }
            paper_scoring["apt_detected"] = bool(paper_exact_state.detected)
            paper_scoring["first_detection_time"] = paper_exact_state.first_detection_time
            paper_scoring["first_detection_sequence"] = paper_exact_state.first_detection_sequence
            paper_scoring["first_detection_score"] = paper_exact_state.first_detection_score
            paper_scoring["first_detection_log_score"] = paper_exact_state.first_detection_log_score
            paper_scoring["first_detection_tuple_snapshot"] = paper_exact_state.first_detection_tuple_snapshot
            paper_scoring["first_detection_contributing_stages"] = [
                {"stage_index": i, "stage_name": APT_STAGES[i - 1]} for i in paper_exact_state.first_detection_contributing_stages
            ]
        summary: dict[str, Any] = {
            "events": self.stats.events,
            "rules": len(self.ruleset.rules),
            "matches": len(self.matches),
            "hsg_nodes": len(hsg.nodes),
            "hsg_edges": len(hsg.edges),
            "noise_filter": noise_filter,
            "resolved_effective_config": self.resolved_effective_config,
            "paper_scoring": paper_scoring,
            "top_scenarios": self.top_scenarios,
            "dropped_match_telemetry": dropped_match_telemetry,
            "pending_eviction_telemetry": pending_eviction_telemetry,
            "dormant_scenario_telemetry": dormant_scenario_telemetry,
            "graph_gc_telemetry": graph_gc_telemetry,
            "alerts": alerts_summary,
            "performance_metrics": performance_metrics,
        }
        if not legacy_snapshot_mode:
            summary["online_index"] = {"candidate_pairs_considered": self.stats.candidate_pairs_considered}
            summary["streaming"] = {
                "global_refine": {
                    "mode": self.global_refine_mode,
                    "every": self.global_refine_every,
                    "ran_at_snapshots_count": self.global_refine_ran_at_snapshots_count,
                    "ran_at_events_count": self.global_refine_ran_at_events_count,
                }
            }
        matches_out = []
        for m in self.matches:
            row = {
                "match_id": m.match_id,
                "rule_id": m.rule_id,
                "event_ids": m.event_ids,
                "entities": m.entities,
                "bindings": m.bindings,
                "metadata": m.metadata,
            }
            if not legacy_snapshot_mode:
                row["subject_node_id"] = m.subject_node_id
                row["object_node_id"] = m.object_node_id
                row["sequence"] = m.sequence
                row["attributes"] = m.attributes
            matches_out.append(row)
        return {"summary": summary, "matches": matches_out, "hsg": hsg_to_dict(hsg)}

    def write_snapshot(self, out_dir: str | Path) -> dict[str, Any]:
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
        self._emit_metrics_if_due(force=True)
        if self.dropped_match_telemetry_path is None:
            self.dropped_match_telemetry_path = p / "debug" / "dropped_matches.jsonl"
            self.dropped_match_telemetry_path.parent.mkdir(parents=True, exist_ok=True)
            self.dropped_match_telemetry_path.touch(exist_ok=True)
        if self.alerts_path is None:
            self.alerts_path = p / "alerts.jsonl"
            self.alerts_path.write_text("", encoding="utf-8")
            if self.alerts:
                with self.alerts_path.open("a", encoding="utf-8") as fh:
                    for alert in self.alerts:
                        fh.write(json.dumps(asdict(alert), ensure_ascii=True) + "\n")
        if self.graph_artifact_dir is None:
            self.graph_artifact_dir = p / "graph_artifacts"
            self.graph_artifact_dir.mkdir(parents=True, exist_ok=True)
        self._maybe_global_refine("snapshot")
        result = self.build_result()
        (p / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        (p / "summary.json").write_text(json.dumps(result["summary"], indent=2), encoding="utf-8")
        (p / "matches.json").write_text(json.dumps(result["matches"], indent=2), encoding="utf-8")
        (p / "hsg.json").write_text(json.dumps(result["hsg"], indent=2), encoding="utf-8")
        return result
