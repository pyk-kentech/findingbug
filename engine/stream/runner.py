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
from engine.io.events import Event, EventMeta
from engine.noise.filter import NoiseConfig, apply_noise_filter, filter_matches
from engine.noise.model import NoiseModel, get_benign_drop_ids
from engine.noise.profile import BenignProfile, load_benign_profile
from engine.native import NativeEngineBackend, load_native_backend
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
        graph_path_eval_budget_ms: float | None = None,
        graph_path_cache_miss_policy: str = "compute",
        graph_path_candidate_preselect_factor: int = 0,
        graph_path_edge_eviction_policy: str = "none",
        ac_min_method: str = "set_diff",
        ab_performance: str = "a",
        ab_quality: str = "a",
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
        defer_snapshot_updates: bool = False,
        graph_gc_every_events: int = 1000,
        ancestor_index_mode: str = "incremental",
        online_score_refresh_every: int = 1000,
        native_backend: NativeEngineBackend | None = None,
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
        self.graph_path_eval_budget_ms = (
            None if graph_path_eval_budget_ms is None else max(0.0, float(graph_path_eval_budget_ms))
        )
        self.graph_path_cache_miss_policy = str(graph_path_cache_miss_policy)
        self.graph_path_candidate_preselect_factor = max(0, int(graph_path_candidate_preselect_factor))
        self.graph_path_edge_eviction_policy = str(graph_path_edge_eviction_policy)
        self.ac_min_method = str(ac_min_method)
        self.ab_performance = str(ab_performance)
        self.ab_quality = str(ab_quality)
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
        self.defer_snapshot_updates = bool(defer_snapshot_updates)
        self.graph_gc_every_events = max(1, int(graph_gc_every_events))
        self.online_score_refresh_every = max(1, int(online_score_refresh_every))
        self._online_score_refresh_pending_events = 0
        self.global_refine_ran_at_snapshots_count = 0
        self.global_refine_ran_at_events_count = 0
        self._events_processed = 0
        self._snapshot_state_dirty = False
        self._score_state_dirty = False
        self._last_graph_gc_events = 0
        self._pending_online_graph_edges: list[tuple[str, str, Any]] = []
        self.native_backend = native_backend if native_backend is not None else load_native_backend()
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

        self.graph = ProvenanceGraph(
            ancestor_index_mode=ancestor_index_mode,
            ac_min_method=self.ac_min_method,
        )
        self.taint_tracker = TaintTracker(self.graph)
        self.privilege_tracker = PrivilegeTracker(self.graph)
        self.online_index = OnlineIndex()
        self.graph.register_edge_hook(self._on_graph_edge)
        self.graph.clear_prune_hooks()
        self.graph.register_prune_hook(self.taint_tracker.cleanup)
        self.graph.register_prune_hook(self.privilege_tracker.cleanup)
        self.graph.register_prune_hook(self.online_index.prune)
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

        self.events_by_id: dict[str, EventMeta] = {}
        self._last_event_ts: str | None = None
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
        self._descendants_cache: dict[object, object] = {}

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
            graph_path_eval_budget_ms=self.graph_path_eval_budget_ms,
            graph_path_cache_miss_policy=self.graph_path_cache_miss_policy,
            graph_path_candidate_preselect_factor=self.graph_path_candidate_preselect_factor,
            graph_path_edge_eviction_policy=self.graph_path_edge_eviction_policy,
            max_pending_matches=max_pending_matches,
            scenario_dormancy_seconds=self.scenario_dormancy_days * 24 * 60 * 60,
        )
        self.hsg_builder.pending_evicted_count = self.stats.pending_evicted_count
        self.hsg_builder.pending_evicted_by_rule_id.update(self.stats.pending_evicted_by_rule_id or {})
        self._processing_started_at = time.perf_counter()
        self._matcher_time_seconds = 0.0
        self._hsg_update_time_seconds = 0.0
        self._graph_gc_time_seconds = 0.0
        self._graph_add_time_seconds = 0.0
        self._tracker_update_time_seconds = 0.0
        self._noise_filter_time_seconds = 0.0
        self._binding_resolve_time_seconds = 0.0
        self._taint_mark_time_seconds = 0.0
        self._match_store_time_seconds = 0.0
        self._online_prereq_time_seconds = 0.0
        self._paper_exact_time_seconds = 0.0
        self._snapshot_bookkeeping_time_seconds = 0.0
        self._online_graph_edge_flush_time_seconds = 0.0
        self._online_prereq_check_time_seconds = 0.0
        self._online_builder_add_match_time_seconds = 0.0
        self._online_pending_builder_add_match_time_seconds = 0.0
        self._online_pending_builder_add_match_accepted_count = 0
        self._online_pending_builder_add_match_rejected_count = 0
        self._online_pending_builder_add_match_accepted_time_seconds = 0.0
        self._online_pending_builder_add_match_rejected_time_seconds = 0.0
        self._online_add_active_match_time_seconds = 0.0
        self._online_add_active_match_list_store_time_seconds = 0.0
        self._online_add_active_match_node_store_time_seconds = 0.0
        self._online_add_active_match_entity_index_time_seconds = 0.0
        self._online_add_active_match_online_index_time_seconds = 0.0
        self._online_extend_edges_time_seconds = 0.0
        self._online_full_resync_time_seconds = 0.0
        self._online_score_refresh_time_seconds = 0.0
        self._online_index_match_add_calls = 0
        self._online_index_match_add_changed_count = 0
        self._online_index_match_add_noop_count = 0
        self._online_index_match_add_time_seconds = 0.0
        self._online_index_match_add_local_update_time_seconds = 0.0
        self._online_index_match_add_mapper_update_time_seconds = 0.0
        self._online_index_match_add_propagate_time_seconds = 0.0
        self._online_prereq_antecedent_total = 0
        self._online_prereq_antecedent_max = 0
        self._online_built_edges_total = 0
        self._online_built_edges_max = 0
        self._online_activated_matches_total = 0
        self._online_activated_matches_max = 0
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
        ancestor_cache_node_count = len(self.graph._ancestors_by_node)  # noqa: SLF001
        ancestor_cache_entry_count = sum(len(v) for v in self.graph._ancestors_by_node.values())  # noqa: SLF001
        min_dist_node_count = len(self.graph._min_dist_from_ancestor)  # noqa: SLF001
        min_dist_entry_count = sum(len(v) for v in self.graph._min_dist_from_ancestor.values())  # noqa: SLF001
        return {
            "events_per_second": float(self.stats.events) / elapsed_seconds,
            "graph_add_time_seconds": float(self._graph_add_time_seconds),
            "graph_add_avg_ms_per_event": (float(self._graph_add_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_runtime_edge_append_time_seconds": float(self.graph._runtime_edge_append_time_seconds),  # noqa: SLF001
            "graph_runtime_edge_append_avg_ms_per_event": (float(self.graph._runtime_edge_append_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_provenance_edge_append_time_seconds": float(self.graph._provenance_edge_append_time_seconds),  # noqa: SLF001
            "graph_provenance_edge_append_avg_ms_per_event": (float(self.graph._provenance_edge_append_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_edge_hook_time_seconds": float(self.graph._edge_hook_time_seconds),  # noqa: SLF001
            "graph_edge_hook_avg_ms_per_event": (float(self.graph._edge_hook_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_memory_sync_time_seconds": float(self.graph._memory_sync_time_seconds),  # noqa: SLF001
            "graph_memory_sync_avg_ms_per_event": (float(self.graph._memory_sync_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_ensure_entity_time_seconds": float(self.graph._ensure_entity_time_seconds),  # noqa: SLF001
            "graph_ensure_entity_avg_ms_per_event": (float(self.graph._ensure_entity_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_changed_entities_time_seconds": float(self.graph._changed_entities_time_seconds),  # noqa: SLF001
            "graph_changed_entities_avg_ms_per_event": (float(self.graph._changed_entities_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_bump_entities_time_seconds": float(self.graph._bump_entities_time_seconds),  # noqa: SLF001
            "graph_bump_entities_avg_ms_per_event": (float(self.graph._bump_entities_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_flow_link_time_seconds": float(self.graph._flow_link_time_seconds),  # noqa: SLF001
            "graph_flow_link_avg_ms_per_event": (float(self.graph._flow_link_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_memory_transition_link_time_seconds": float(self.graph._memory_transition_link_time_seconds),  # noqa: SLF001
            "graph_memory_transition_link_avg_ms_per_event": (float(self.graph._memory_transition_link_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_semantic_register_time_seconds": float(self.graph._semantic_register_time_seconds),  # noqa: SLF001
            "graph_semantic_register_avg_ms_per_event": (float(self.graph._semantic_register_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_event_semantic_extract_time_seconds": float(self.graph._event_semantic_extract_time_seconds),  # noqa: SLF001
            "graph_event_semantic_extract_avg_ms_per_event": (float(self.graph._event_semantic_extract_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_flow_direction_time_seconds": float(self.graph._flow_direction_time_seconds),  # noqa: SLF001
            "graph_flow_direction_avg_ms_per_event": (float(self.graph._flow_direction_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_event_version_change_eval_time_seconds": float(self.graph._event_version_change_eval_time_seconds),  # noqa: SLF001
            "graph_event_version_change_eval_avg_ms_per_event": (float(self.graph._event_version_change_eval_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_path_factor_cache_clear_time_seconds": float(self.graph._path_factor_cache_clear_time_seconds),  # noqa: SLF001
            "graph_path_factor_cache_clear_avg_ms_per_event": (float(self.graph._path_factor_cache_clear_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_typed_adjacency_add_time_seconds": float(self.graph._typed_adjacency_add_time_seconds),  # noqa: SLF001
            "graph_typed_adjacency_add_avg_ms_per_event": (float(self.graph._typed_adjacency_add_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_events_with_memory_sync": int(self.graph._events_with_memory_sync),  # noqa: SLF001
            "graph_changed_entities_total": int(self.graph._changed_entities_total),  # noqa: SLF001
            "graph_avg_changed_entities_per_event": (float(self.graph._changed_entities_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_max_changed_entities_in_event": int(self.graph._max_changed_entities),  # noqa: SLF001
            "graph_edges_linked_total": int(self.graph._edges_linked_total),  # noqa: SLF001
            "graph_avg_edges_linked_per_event": (float(self.graph._edges_linked_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_max_edges_linked_in_event": int(self.graph._max_edges_linked_in_event),  # noqa: SLF001
            "graph_node_meta_time_seconds": float(self.graph._node_meta_time_seconds),  # noqa: SLF001
            "graph_node_meta_avg_ms_per_event": (float(self.graph._node_meta_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_current_version_lookup_time_seconds": float(self.graph._current_version_lookup_time_seconds),  # noqa: SLF001
            "graph_current_version_lookup_avg_ms_per_event": (float(self.graph._current_version_lookup_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_new_version_node_time_seconds": float(self.graph._new_version_node_time_seconds),  # noqa: SLF001
            "graph_new_version_node_avg_ms_per_event": (float(self.graph._new_version_node_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_semantic_current_version_lookup_time_seconds": float(self.graph._semantic_current_version_lookup_time_seconds),  # noqa: SLF001
            "graph_semantic_current_version_lookup_avg_ms_per_event": (float(self.graph._semantic_current_version_lookup_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "tracker_update_time_seconds": float(self._tracker_update_time_seconds),
            "tracker_update_avg_ms_per_event": (float(self._tracker_update_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "matcher_time_seconds": float(self._matcher_time_seconds),
            "matcher_avg_ms_per_event": (float(self._matcher_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "noise_filter_time_seconds": float(self._noise_filter_time_seconds),
            "noise_filter_avg_ms_per_event": (float(self._noise_filter_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "binding_resolve_time_seconds": float(self._binding_resolve_time_seconds),
            "binding_resolve_avg_ms_per_event": (float(self._binding_resolve_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "taint_mark_time_seconds": float(self._taint_mark_time_seconds),
            "taint_mark_avg_ms_per_event": (float(self._taint_mark_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "match_store_time_seconds": float(self._match_store_time_seconds),
            "match_store_avg_ms_per_event": (float(self._match_store_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_prereq_time_seconds": float(self._online_prereq_time_seconds),
            "online_prereq_avg_ms_per_event": (float(self._online_prereq_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "paper_exact_time_seconds": float(self._paper_exact_time_seconds),
            "paper_exact_avg_ms_per_event": (float(self._paper_exact_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "snapshot_bookkeeping_time_seconds": float(self._snapshot_bookkeeping_time_seconds),
            "snapshot_bookkeeping_avg_ms_per_event": (float(self._snapshot_bookkeeping_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_graph_edge_flush_time_seconds": float(self._online_graph_edge_flush_time_seconds),
            "online_graph_edge_flush_avg_ms_per_event": (float(self._online_graph_edge_flush_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_prereq_check_time_seconds": float(self._online_prereq_check_time_seconds),
            "online_prereq_check_avg_ms_per_event": (float(self._online_prereq_check_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_builder_add_match_time_seconds": float(self._online_builder_add_match_time_seconds),
            "online_builder_add_match_avg_ms_per_event": (float(self._online_builder_add_match_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_pending_builder_add_match_time_seconds": float(self._online_pending_builder_add_match_time_seconds),
            "online_pending_builder_add_match_avg_ms_per_event": (
                float(self._online_pending_builder_add_match_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_pending_builder_add_match_accepted_count": int(self._online_pending_builder_add_match_accepted_count),
            "online_pending_builder_add_match_rejected_count": int(self._online_pending_builder_add_match_rejected_count),
            "online_pending_builder_add_match_accepted_time_seconds": float(
                self._online_pending_builder_add_match_accepted_time_seconds
            ),
            "online_pending_builder_add_match_rejected_time_seconds": float(
                self._online_pending_builder_add_match_rejected_time_seconds
            ),
            "online_pending_builder_add_match_accepted_avg_ms_per_call": (
                float(self._online_pending_builder_add_match_accepted_time_seconds)
                * 1000.0
                / float(self._online_pending_builder_add_match_accepted_count)
            )
            if self._online_pending_builder_add_match_accepted_count
            else 0.0,
            "online_pending_builder_add_match_rejected_avg_ms_per_call": (
                float(self._online_pending_builder_add_match_rejected_time_seconds)
                * 1000.0
                / float(self._online_pending_builder_add_match_rejected_count)
            )
            if self._online_pending_builder_add_match_rejected_count
            else 0.0,
            "online_add_active_match_time_seconds": float(self._online_add_active_match_time_seconds),
            "online_add_active_match_avg_ms_per_event": (float(self._online_add_active_match_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_add_active_match_list_store_time_seconds": float(self._online_add_active_match_list_store_time_seconds),
            "online_add_active_match_list_store_avg_ms_per_event": (
                float(self._online_add_active_match_list_store_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_add_active_match_node_store_time_seconds": float(self._online_add_active_match_node_store_time_seconds),
            "online_add_active_match_node_store_avg_ms_per_event": (
                float(self._online_add_active_match_node_store_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_add_active_match_entity_index_time_seconds": float(self._online_add_active_match_entity_index_time_seconds),
            "online_add_active_match_entity_index_avg_ms_per_event": (
                float(self._online_add_active_match_entity_index_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_add_active_match_online_index_time_seconds": float(self._online_add_active_match_online_index_time_seconds),
            "online_add_active_match_online_index_avg_ms_per_event": (
                float(self._online_add_active_match_online_index_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_index_match_add_calls": int(self._online_index_match_add_calls),
            "online_index_match_add_changed_count": int(self._online_index_match_add_changed_count),
            "online_index_match_add_noop_count": int(self._online_index_match_add_noop_count),
            "online_index_match_add_change_ratio": (
                float(self._online_index_match_add_changed_count) / float(self._online_index_match_add_calls)
            )
            if self._online_index_match_add_calls
            else 0.0,
            "online_index_match_add_time_seconds": float(self._online_index_match_add_time_seconds),
            "online_index_match_add_avg_ms_per_call": (
                float(self._online_index_match_add_time_seconds) * 1000.0 / float(self._online_index_match_add_calls)
            )
            if self._online_index_match_add_calls
            else 0.0,
            "online_index_match_add_avg_ms_per_event": (
                float(self._online_index_match_add_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_index_match_add_local_update_time_seconds": float(
                self._online_index_match_add_local_update_time_seconds
            ),
            "online_index_match_add_local_update_avg_ms_per_call": (
                float(self._online_index_match_add_local_update_time_seconds)
                * 1000.0
                / float(self._online_index_match_add_calls)
            )
            if self._online_index_match_add_calls
            else 0.0,
            "online_index_match_add_mapper_update_time_seconds": float(
                self._online_index_match_add_mapper_update_time_seconds
            ),
            "online_index_match_add_mapper_update_avg_ms_per_call": (
                float(self._online_index_match_add_mapper_update_time_seconds)
                * 1000.0
                / float(self._online_index_match_add_calls)
            )
            if self._online_index_match_add_calls
            else 0.0,
            "online_index_match_add_propagate_time_seconds": float(
                self._online_index_match_add_propagate_time_seconds
            ),
            "online_index_match_add_propagate_avg_ms_per_call": (
                float(self._online_index_match_add_propagate_time_seconds)
                * 1000.0
                / float(self._online_index_match_add_calls)
            )
            if self._online_index_match_add_calls
            else 0.0,
            "online_index_match_add_propagate_avg_ms_per_changed_call": (
                float(self._online_index_match_add_propagate_time_seconds)
                * 1000.0
                / float(self._online_index_match_add_changed_count)
            )
            if self._online_index_match_add_changed_count
            else 0.0,
            "online_index_propagation_max_depth": int(getattr(self.online_index, "max_propagation_depth", 0)),
            "online_index_propagation_depth_cutoff_total": int(
                getattr(self.online_index, "propagation_depth_cutoff_total", 0)
            ),
            "online_index_propagation_max_fan_out": int(getattr(self.online_index, "max_fan_out", 0)),
            "online_index_propagation_fanout_cutoff_total": int(
                getattr(self.online_index, "propagation_fanout_cutoff_total", 0)
            ),
            "online_extend_edges_time_seconds": float(self._online_extend_edges_time_seconds),
            "online_extend_edges_avg_ms_per_event": (float(self._online_extend_edges_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_full_resync_time_seconds": float(self._online_full_resync_time_seconds),
            "online_full_resync_avg_ms_per_event": (float(self._online_full_resync_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_score_refresh_time_seconds": float(self._online_score_refresh_time_seconds),
            "online_score_refresh_avg_ms_per_event": (
                float(self._online_score_refresh_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_component_map_time_seconds": float(self.hsg_builder.component_map_time_seconds),
            "builder_component_map_avg_ms_per_event": (float(self.hsg_builder.component_map_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "builder_candidate_match_ids_total": int(self.hsg_builder.candidate_match_ids_total),
            "builder_candidate_match_ids_avg_per_event": (float(self.hsg_builder.candidate_match_ids_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "builder_candidate_match_ids_max": int(self.hsg_builder.candidate_match_ids_max),
            "builder_candidate_match_ids_filtered_no_prereq_total": int(
                self.hsg_builder.candidate_match_ids_filtered_no_prereq_total
            ),
            "builder_candidate_match_ids_filtered_no_prereq_avg_per_event": (
                float(self.hsg_builder.candidate_match_ids_filtered_no_prereq_total) / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_candidate_match_ids_filtered_rule_pair_total": int(
                self.hsg_builder.candidate_match_ids_filtered_rule_pair_total
            ),
            "builder_candidate_match_ids_filtered_rule_pair_avg_per_event": (
                float(self.hsg_builder.candidate_match_ids_filtered_rule_pair_total) / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_pending_activation_candidate_total": int(self.hsg_builder.pending_activation_candidate_total),
            "builder_pending_activation_candidate_avg_per_event": (float(self.hsg_builder.pending_activation_candidate_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "builder_pending_activation_candidate_max": int(self.hsg_builder.pending_activation_candidate_max),
            "builder_pending_activation_ancestor_scan_time_seconds": float(self.hsg_builder.pending_activation_ancestor_scan_time_seconds),
            "builder_pending_activation_ancestor_scan_avg_ms_per_event": (float(self.hsg_builder.pending_activation_ancestor_scan_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "builder_add_match_built_edges_total": int(self.hsg_builder.add_match_built_edges_total),
            "builder_add_match_built_edges_avg_per_event": (float(self.hsg_builder.add_match_built_edges_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "builder_add_match_built_edges_max": int(self.hsg_builder.add_match_built_edges_max),
            "builder_add_match_watermark_evict_time_seconds": float(self.hsg_builder.add_match_watermark_evict_time_seconds),
            "builder_add_match_watermark_evict_avg_ms_per_event": (
                float(self.hsg_builder.add_match_watermark_evict_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_candidate_ids_time_seconds": float(self.hsg_builder.add_match_candidate_ids_time_seconds),
            "builder_add_match_candidate_ids_avg_ms_per_event": (
                float(self.hsg_builder.add_match_candidate_ids_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_ast_eval_time_seconds": float(self.hsg_builder.add_match_ast_eval_time_seconds),
            "builder_add_match_ast_eval_avg_ms_per_event": (
                float(self.hsg_builder.add_match_ast_eval_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_pair_eval_time_seconds": float(self.hsg_builder.add_match_pair_eval_time_seconds),
            "builder_add_match_pair_eval_avg_ms_per_event": (
                float(self.hsg_builder.add_match_pair_eval_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_pending_insert_time_seconds": float(self.hsg_builder.add_match_pending_insert_time_seconds),
            "builder_add_match_pending_insert_avg_ms_per_event": (
                float(self.hsg_builder.add_match_pending_insert_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_pending_capacity_evict_time_seconds": float(
                self.hsg_builder.add_match_pending_capacity_evict_time_seconds
            ),
            "builder_add_match_pending_capacity_evict_avg_ms_per_event": (
                float(self.hsg_builder.add_match_pending_capacity_evict_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_pending_path_count": int(self.hsg_builder.add_match_pending_path_count),
            "builder_add_match_pending_path_ratio": (
                float(self.hsg_builder.add_match_pending_path_count) / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_add_match_pending_size_avg": (
                float(self.hsg_builder.add_match_pending_size_total) / float(self.hsg_builder.add_match_pending_path_count)
            )
            if self.hsg_builder.add_match_pending_path_count
            else 0.0,
            "builder_add_match_pending_size_max": int(self.hsg_builder.add_match_pending_size_max),
            "builder_pair_edges_relation_eval_total": int(self.hsg_builder.pair_edges_relation_eval_total),
            "builder_pair_edges_graph_path_eval_total": int(self.hsg_builder.pair_edges_graph_path_eval_total),
            "builder_pair_edges_non_graph_path_eval_total": int(self.hsg_builder.pair_edges_non_graph_path_eval_total),
            "builder_pair_edges_seen_skip_total": int(self.hsg_builder.pair_edges_seen_skip_total),
            "builder_pair_edges_graph_path_skip_max_edges_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_max_edges_total
            ),
            "builder_pair_edges_graph_path_skip_allowlist_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_allowlist_total
            ),
            "builder_pair_edges_graph_path_skip_src_cap_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_src_cap_total
            ),
            "builder_pair_edges_graph_path_skip_candidate_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_candidate_total
            ),
            "builder_pair_edges_graph_path_skip_binding_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_binding_total
            ),
            "builder_pair_edges_graph_path_skip_budget_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_budget_total
            ),
            "builder_pair_edges_graph_path_skip_cache_miss_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_cache_miss_total
            ),
            "builder_pair_edges_graph_path_preselected_drop_total": int(
                self.hsg_builder.pair_edges_graph_path_preselected_drop_total
            ),
            "builder_pair_edges_graph_path_evicted_total": int(
                self.hsg_builder.pair_edges_graph_path_evicted_total
            ),
            "builder_pair_edges_graph_path_skip_prereq_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_prereq_total
            ),
            "builder_pair_edges_graph_path_skip_metrics_total": int(
                self.hsg_builder.pair_edges_graph_path_skip_metrics_total
            ),
            "builder_pair_edges_built_total": int(self.hsg_builder.pair_edges_built_total),
            "builder_pair_edges_prereq_check_time_seconds": float(self.hsg_builder.pair_edges_prereq_check_time_seconds),
            "builder_pair_edges_prereq_check_avg_ms_per_event": (
                float(self.hsg_builder.pair_edges_prereq_check_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_pair_edges_graph_path_candidate_time_seconds": float(
                self.hsg_builder.pair_edges_graph_path_candidate_time_seconds
            ),
            "builder_pair_edges_graph_path_candidate_avg_ms_per_event": (
                float(self.hsg_builder.pair_edges_graph_path_candidate_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_pair_edges_graph_path_metrics_time_seconds": float(
                self.hsg_builder.pair_edges_graph_path_metrics_time_seconds
            ),
            "builder_pair_edges_graph_path_metrics_avg_ms_per_event": (
                float(self.hsg_builder.pair_edges_graph_path_metrics_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_pair_edges_graph_path_eviction_time_seconds": float(
                self.hsg_builder.pair_edges_graph_path_eviction_time_seconds
            ),
            "builder_pair_edges_graph_path_eviction_avg_ms_per_event": (
                float(self.hsg_builder.pair_edges_graph_path_eviction_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "builder_pair_edges_graph_path_pf_cache_hit_total": int(
                self.hsg_builder.pair_edges_graph_path_pf_cache_hit_total
            ),
            "builder_pair_edges_graph_path_pf_cache_miss_total": int(
                self.hsg_builder.pair_edges_graph_path_pf_cache_miss_total
            ),
            "builder_pair_edges_graph_path_pf_cache_hit_ratio": (
                float(self.hsg_builder.pair_edges_graph_path_pf_cache_hit_total)
                / float(
                    self.hsg_builder.pair_edges_graph_path_pf_cache_hit_total
                    + self.hsg_builder.pair_edges_graph_path_pf_cache_miss_total
                )
            )
            if (
                self.hsg_builder.pair_edges_graph_path_pf_cache_hit_total
                + self.hsg_builder.pair_edges_graph_path_pf_cache_miss_total
            )
            else 0.0,
            "builder_pair_edges_graph_path_pf_compute_time_seconds": float(
                self.hsg_builder.pair_edges_graph_path_pf_compute_time_seconds
            ),
            "builder_pair_edges_graph_path_pf_compute_avg_ms_per_event": (
                float(self.hsg_builder.pair_edges_graph_path_pf_compute_time_seconds) * 1000.0 / float(self.stats.events)
            )
            if self.stats.events
            else 0.0,
            "online_prereq_antecedent_total": int(self._online_prereq_antecedent_total),
            "online_prereq_antecedent_avg_per_event": (float(self._online_prereq_antecedent_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_prereq_antecedent_max": int(self._online_prereq_antecedent_max),
            "online_built_edges_total": int(self._online_built_edges_total),
            "online_built_edges_avg_per_event": (float(self._online_built_edges_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_built_edges_max": int(self._online_built_edges_max),
            "online_activated_matches_total": int(self._online_activated_matches_total),
            "online_activated_matches_avg_per_event": (float(self._online_activated_matches_total) / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "online_activated_matches_max": int(self._online_activated_matches_max),
            "hsg_update_time_seconds": float(self._hsg_update_time_seconds),
            "hsg_update_avg_ms_per_event": (float(self._hsg_update_time_seconds) * 1000.0 / float(self.stats.events))
            if self.stats.events
            else 0.0,
            "graph_gc_time_seconds": float(self._graph_gc_time_seconds),
            "graph_entity_count": len(self.graph.nodes),
            "graph_version_node_count": len(self.graph.version_nodes),
            "graph_edge_count": len(self.graph.edges),
            "graph_data_flow_adjacency_count": sum(len(v) for v in self.graph.adj_data_flow.values()),
            "graph_version_transition_adjacency_count": sum(len(v) for v in self.graph.adj_version_transition.values()),
            "graph_semantic_relation_count": len(self.graph.semantic_relations),
            "graph_current_version_count": len(self.graph.current_version),
            "graph_entity_versions_count": sum(len(v) for v in self.graph.entity_versions.values()),
            "graph_process_parent_edge_count": sum(len(v) for v in self.graph.process_parents.values()),
            "graph_path_factor_cache_node_count": len(self.graph._path_factor_cache),  # noqa: SLF001
            "graph_ancestor_cache_node_count": ancestor_cache_node_count,
            "graph_ancestor_cache_entry_count": ancestor_cache_entry_count,
            "graph_min_dist_node_count": min_dist_node_count,
            "graph_min_dist_entry_count": min_dist_entry_count,
            "retained_event_meta_count": len(self.events_by_id),
            "active_match_count": len(self.matches),
            "active_hsg_node_count": len(self.hsg_nodes),
            "active_hsg_edge_count": len(self.hsg_edges),
            "builder_active_match_count": len(self.hsg_builder.matches_by_id),
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

    def _add_active_match_to_online_state(self, match: TTPMatch, *, add_to_online_index: bool) -> None:
        if match.match_id in self.match_by_id:
            return
        list_store_started = time.perf_counter()
        self.matches.append(match)
        self.match_by_id[match.match_id] = match
        self._online_add_active_match_list_store_time_seconds += time.perf_counter() - list_store_started
        node_store_started = time.perf_counter()
        self.hsg_nodes[match.match_id] = HSGNode(
            match_id=match.match_id,
            rule_id=match.rule_id,
            event_ids=list(match.event_ids),
            entities=list(match.entities),
        )
        self._online_add_active_match_node_store_time_seconds += time.perf_counter() - node_store_started
        entity_index_started = time.perf_counter()
        entities = set(match.entities)
        self.match_to_entities[match.match_id] = entities
        for entity in entities:
            self.node_to_matches[entity].add(match.match_id)
            self.entity_to_hsg_node[entity].add(match.match_id)
        self._online_add_active_match_entity_index_time_seconds += time.perf_counter() - entity_index_started
        if add_to_online_index:
            online_index_started = time.perf_counter()
            for node_id in (match.subject_node_id, match.object_node_id):
                if node_id:
                    telemetry = self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=match.match_id,
                        rule_id=match.rule_id,
                        sequence=int(match.sequence or self.stats.events),
                        origin_node_id=node_id,
                    )
                    self._record_online_index_match_add_telemetry(telemetry)
                    if self.native_backend.available:
                        self.native_backend.register_online_match(
                            node_id=node_id,
                            match_id=match.match_id,
                            rule_id=match.rule_id,
                            sequence=int(match.sequence or self.stats.events),
                        )
            self._online_add_active_match_online_index_time_seconds += time.perf_counter() - online_index_started

    def _extend_online_edges(self, edges: list[HSGEdge]) -> None:
        for edge in edges:
            edge_key = (edge.src, edge.dst, edge.relation)
            if edge_key in self.seen_edges:
                continue
            self.seen_edges.add(edge_key)
            self.hsg_edges.append(edge)
            if edge.relation == "graph_path":
                self._graph_path_edges_count += 1

    def _rebuild_online_index_from_active_matches(self) -> None:
        self.online_index = OnlineIndex()
        if self.native_backend.available:
            self.native_backend.reset_online_index()
        for edge in self.graph.runtime_edges:
            self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type, propagate=False)
            if self.native_backend.available:
                self.native_backend.add_online_edge(
                    edge.src,
                    edge.dst,
                    self._native_edge_type_name(edge.edge_type),
                )
        self.online_index.flush_pending_edges()
        for match in self.matches:
            for node_id in (match.subject_node_id, match.object_node_id):
                if node_id:
                    telemetry = self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=match.match_id,
                        rule_id=match.rule_id,
                        sequence=int(match.sequence or 0),
                        origin_node_id=node_id,
                    )
                    self._record_online_index_match_add_telemetry(telemetry)
                    if self.native_backend.available:
                        self.native_backend.register_online_match(
                            node_id=node_id,
                            match_id=match.match_id,
                            rule_id=match.rule_id,
                            sequence=int(match.sequence or 0),
                        )

    def _record_online_index_match_add_telemetry(
        self,
        telemetry: tuple[bool, float, float, float],
    ) -> None:
        changed, local_update_seconds, mapper_update_seconds, propagate_seconds = telemetry
        self._online_index_match_add_calls += 1
        if changed:
            self._online_index_match_add_changed_count += 1
        else:
            self._online_index_match_add_noop_count += 1
        self._online_index_match_add_local_update_time_seconds += float(local_update_seconds)
        self._online_index_match_add_mapper_update_time_seconds += float(mapper_update_seconds)
        self._online_index_match_add_propagate_time_seconds += float(propagate_seconds)
        self._online_index_match_add_time_seconds += (
            float(local_update_seconds) + float(mapper_update_seconds) + float(propagate_seconds)
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

    def _run_graph_deep_gc(self, watermark_ts: str | None, *, force: bool = False) -> None:
        if self.graph_retention_days <= 0:
            return
        if not force and (self.stats.events - self._last_graph_gc_events) < self.graph_gc_every_events:
            return
        started = time.perf_counter()
        pruned = self.graph.prune_stale_orphaned(
            watermark_ts=watermark_ts,
            retention_seconds=self.graph_retention_days * 24 * 60 * 60,
            protected_entities=self._protected_graph_entities(),
            protected_version_nodes=self._protected_graph_version_nodes(),
        )
        self._graph_gc_time_seconds += time.perf_counter() - started
        self._last_graph_gc_events = int(self.stats.events)
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
        if not self.use_online_prereq:
            return
        self._pending_online_graph_edges.append((edge.src, edge.dst, edge.edge_type))

    @staticmethod
    def _native_edge_type_name(edge_type: Any) -> str:
        return str(getattr(edge_type, "value", edge_type))

    def _flush_pending_online_graph_edges(self) -> None:
        if not self.use_online_prereq or not self._pending_online_graph_edges:
            return
        started = time.perf_counter()
        pending = self._pending_online_graph_edges
        self._pending_online_graph_edges = []
        for src, dst, edge_type in pending:
            self.online_index.on_edge_added(src, dst, edge_type, propagate=False)
            if self.native_backend.available:
                self.native_backend.add_online_edge(src, dst, self._native_edge_type_name(edge_type))
        self.online_index.flush_pending_edges()
        if self.native_backend.available:
            self.native_backend.flush()
        self._online_graph_edge_flush_time_seconds += time.perf_counter() - started

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
        self._score_state_dirty = False

    def _maybe_refresh_scores_online(self, *, force: bool = False) -> None:
        if not self.use_online_prereq:
            return
        if not self._score_state_dirty and not force:
            return
        if not force and self._online_score_refresh_pending_events < self.online_score_refresh_every:
            return
        refresh_started = time.perf_counter()
        self._refresh_scores()
        self._online_score_refresh_time_seconds += time.perf_counter() - refresh_started
        self._online_score_refresh_pending_events = 0

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
        self.events_by_id[event.event_id] = EventMeta(
            event_id=event.event_id,
            ts=event.ts,
            bytes_transferred=event.bytes_transferred,
        )
        self._last_event_ts = event.ts
        graph_started = time.perf_counter()
        node_info = self.graph.add_event(event)
        self._flush_pending_online_graph_edges()
        self._graph_add_time_seconds += time.perf_counter() - graph_started
        if node_info is None:
            return
        tracker_started = time.perf_counter()
        self.taint_tracker.on_graph_event(event, node_info)
        self.privilege_tracker.on_graph_event(event, node_info)
        self._tracker_update_time_seconds += time.perf_counter() - tracker_started

        matcher_started = time.perf_counter()
        raw_matches = [self._reid_match(m) for m in self.matcher.match(self.graph, self.ruleset, [event])]
        self._matcher_time_seconds += time.perf_counter() - matcher_started
        self._record_binding_drop_telemetry(self.matcher.last_drop_telemetry)
        self.stats.benign_profile_drop_count += int(self.matcher.last_benign_profile_drop_count)
        self._apply_event_matches(
            event=event,
            node_info=node_info,
            raw_matches=raw_matches,
        )

    def process_event_with_precomputed_matches(
        self,
        event: Event,
        raw_matches: list[TTPMatch] | None = None,
        drop_telemetry: list[dict[str, Any]] | None = None,
        benign_profile_drop_count: int = 0,
        matcher_elapsed_seconds: float = 0.0,
    ) -> None:
        self.stats.events += 1
        self.events_by_id[event.event_id] = EventMeta(
            event_id=event.event_id,
            ts=event.ts,
            bytes_transferred=event.bytes_transferred,
        )
        self._last_event_ts = event.ts
        graph_started = time.perf_counter()
        node_info = self.graph.add_event(event)
        self._flush_pending_online_graph_edges()
        self._graph_add_time_seconds += time.perf_counter() - graph_started
        if node_info is None:
            return
        tracker_started = time.perf_counter()
        self.taint_tracker.on_graph_event(event, node_info)
        self.privilege_tracker.on_graph_event(event, node_info)
        self._tracker_update_time_seconds += time.perf_counter() - tracker_started

        effective_raw_matches = [self._reid_match(m) for m in (raw_matches or [])]
        self._matcher_time_seconds += float(matcher_elapsed_seconds)
        self._record_binding_drop_telemetry(drop_telemetry or [])
        self.stats.benign_profile_drop_count += int(benign_profile_drop_count)
        self._apply_event_matches(
            event=event,
            node_info=node_info,
            raw_matches=effective_raw_matches,
        )

    def _apply_event_matches(
        self,
        *,
        event: Event,
        node_info: dict[str, str],
        raw_matches: list[TTPMatch],
    ) -> None:
        self.stats.raw_matches += len(raw_matches)
        online_state_changed = False
        noise_started = time.perf_counter()
        new_matches = self._apply_noise_model(raw_matches)
        self._noise_filter_time_seconds += time.perf_counter() - noise_started

        hsg_update_started = time.perf_counter()
        for new_match in new_matches:
            new_match.subject_node_id = node_info.get("subject_node_id")
            new_match.object_node_id = node_info.get("object_node_id")
            new_match.metadata["event_ts"] = event.ts
            binding_node_ids: dict[str, str] = {}
            binding_started = time.perf_counter()
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
            self._binding_resolve_time_seconds += time.perf_counter() - binding_started
            new_match.binding_node_ids = binding_node_ids
            new_match.sequence = self.stats.events
            new_match.attributes = {
                "subject_node_id": new_match.subject_node_id,
                "object_node_id": new_match.object_node_id,
                "binding_node_ids": dict(binding_node_ids),
            }

            if self.use_online_prereq:
                online_prereq_started = time.perf_counter()
                satisfied, antecedents = self._prereq_satisfied_online(new_match)
                self._online_prereq_check_time_seconds += time.perf_counter() - online_prereq_started
                rule = self.rule_by_id.get(new_match.rule_id)
                has_prereq = bool(
                    rule
                    and (
                        hsg_builder.prerequisite_types(rule)
                        or isinstance(getattr(rule, "prerequisite_ast", None), dict)
                    )
                )
                if has_prereq:
                    antecedent_count = len(antecedents)
                    self._online_prereq_antecedent_total += antecedent_count
                    self._online_prereq_antecedent_max = max(self._online_prereq_antecedent_max, antecedent_count)
                if has_prereq and not satisfied:
                    pending_builder_add_started = time.perf_counter()
                    accepted, built_edges = self.hsg_builder.add_match(
                        new_match,
                        antecedents,
                        watermark_ts=event.ts,
                    )
                    pending_elapsed = time.perf_counter() - pending_builder_add_started
                    self._online_pending_builder_add_match_time_seconds += pending_elapsed
                    if accepted:
                        self._online_pending_builder_add_match_accepted_count += 1
                        self._online_pending_builder_add_match_accepted_time_seconds += pending_elapsed
                        store_started = time.perf_counter()
                        active_add_started = time.perf_counter()
                        self._add_active_match_to_online_state(new_match, add_to_online_index=True)
                        self._online_add_active_match_time_seconds += time.perf_counter() - active_add_started
                        self._match_store_time_seconds += time.perf_counter() - store_started
                        taint_started = time.perf_counter()
                        self.taint_tracker.mark_initial_compromise(new_match, self.rule_by_id.get(new_match.rule_id))
                        self._taint_mark_time_seconds += time.perf_counter() - taint_started

                        activated_match_ids = set(self.hsg_builder.last_activated_match_ids)
                        closed_match_ids = list(self.hsg_builder.last_closed_match_ids)
                        built_edges_count = len(built_edges)
                        activated_count = len(activated_match_ids)
                        self._online_built_edges_total += built_edges_count
                        self._online_built_edges_max = max(self._online_built_edges_max, built_edges_count)
                        self._online_activated_matches_total += activated_count
                        self._online_activated_matches_max = max(self._online_activated_matches_max, activated_count)
                        for activated_match_id in sorted(activated_match_ids):
                            activated_match = self.hsg_builder.matches_by_id.get(activated_match_id)
                            if activated_match is not None:
                                active_add_started = time.perf_counter()
                                self._add_active_match_to_online_state(activated_match, add_to_online_index=True)
                                self._online_add_active_match_time_seconds += time.perf_counter() - active_add_started
                        extend_started = time.perf_counter()
                        self._extend_online_edges(built_edges)
                        self._online_extend_edges_time_seconds += time.perf_counter() - extend_started
                        if closed_match_ids:
                            full_resync_started = time.perf_counter()
                            self._sync_online_state_from_builder()
                            self._rebuild_online_index_from_active_matches()
                            self._online_full_resync_time_seconds += time.perf_counter() - full_resync_started
                    else:
                        self._online_pending_builder_add_match_rejected_count += 1
                        self._online_pending_builder_add_match_rejected_time_seconds += pending_elapsed
                    self._sync_pending_eviction_stats_from_builder()
                    online_state_changed = True
                    self._online_builder_add_match_time_seconds += 0.0
                    self._online_prereq_time_seconds += time.perf_counter() - online_prereq_started
                    continue
                self._online_prereq_time_seconds += time.perf_counter() - online_prereq_started
            store_started = time.perf_counter()
            if self.use_online_prereq:
                active_add_started = time.perf_counter()
                self._add_active_match_to_online_state(new_match, add_to_online_index=True)
                self._online_add_active_match_time_seconds += time.perf_counter() - active_add_started
            else:
                self.matches.append(new_match)
                self.match_by_id[new_match.match_id] = new_match
                self.hsg_nodes[new_match.match_id] = HSGNode(
                    match_id=new_match.match_id,
                    rule_id=new_match.rule_id,
                    event_ids=list(new_match.event_ids),
                    entities=list(new_match.entities),
                )
            self._match_store_time_seconds += time.perf_counter() - store_started
            taint_started = time.perf_counter()
            self.taint_tracker.mark_initial_compromise(new_match, self.rule_by_id.get(new_match.rule_id))
            self._taint_mark_time_seconds += time.perf_counter() - taint_started
            if self.use_online_prereq:
                self.stats.candidate_pairs_considered += len(antecedents)
                online_apply_started = time.perf_counter()
                builder_add_started = time.perf_counter()
                _accepted, built_edges = self.hsg_builder.add_match(
                    new_match,
                    antecedents,
                    watermark_ts=event.ts,
                )
                self._online_builder_add_match_time_seconds += time.perf_counter() - builder_add_started
                self._sync_pending_eviction_stats_from_builder()
                activated_match_ids = set(self.hsg_builder.last_activated_match_ids)
                closed_match_ids = list(self.hsg_builder.last_closed_match_ids)
                built_edges_count = len(built_edges)
                activated_count = len(activated_match_ids)
                self._online_built_edges_total += built_edges_count
                self._online_built_edges_max = max(self._online_built_edges_max, built_edges_count)
                self._online_activated_matches_total += activated_count
                self._online_activated_matches_max = max(self._online_activated_matches_max, activated_count)
                for activated_match_id in sorted(activated_match_ids):
                    activated_match = self.hsg_builder.matches_by_id.get(activated_match_id)
                    if activated_match is not None:
                        active_add_started = time.perf_counter()
                        self._add_active_match_to_online_state(activated_match, add_to_online_index=True)
                        self._online_add_active_match_time_seconds += time.perf_counter() - active_add_started
                extend_started = time.perf_counter()
                self._extend_online_edges(built_edges)
                self._online_extend_edges_time_seconds += time.perf_counter() - extend_started
                if closed_match_ids:
                    full_resync_started = time.perf_counter()
                    self._sync_online_state_from_builder()
                    self._rebuild_online_index_from_active_matches()
                    self._online_full_resync_time_seconds += time.perf_counter() - full_resync_started
                online_state_changed = True
                self._online_prereq_time_seconds += time.perf_counter() - online_apply_started
            if self.paper_exact is not None:
                paper_started = time.perf_counter()
                self.paper_exact.update(
                    stage=int(self.rule_stage.get(new_match.rule_id, 1)),
                    raw_severity=self.rule_cvss.get(new_match.rule_id, self.rule_severity.get(new_match.rule_id, 1.0)),
                    event_time=event.ts,
                    sequence=new_match.sequence,
                )
                self._paper_exact_time_seconds += time.perf_counter() - paper_started
        if self.use_online_prereq:
            self._sync_pending_eviction_stats_from_builder()
        self._run_graph_deep_gc(event.ts)
        self._hsg_update_time_seconds += time.perf_counter() - hsg_update_started

        if not self.use_online_prereq:
            snapshot_started = time.perf_counter()
            if self.defer_snapshot_updates:
                self._snapshot_state_dirty = True
            else:
                self._rebuild_snapshot_state()
            self._snapshot_bookkeeping_time_seconds += time.perf_counter() - snapshot_started

        if self.use_online_prereq:
            self._score_state_dirty = self._score_state_dirty or online_state_changed
            if online_state_changed:
                self._online_score_refresh_pending_events += 1
            self._maybe_refresh_scores_online(force=False)
        elif not self.defer_snapshot_updates:
            self._refresh_scores()
        self._events_processed += 1
        self._emit_metrics_if_due()
        if self.global_refine_mode == "every_n_events" and self._events_processed % self.global_refine_every == 0:
            self._maybe_global_refine("periodic")

    def process_source(self, source: Any) -> int:
        return self.process_source_batched(source, batch_size=1)

    def process_event_batch(self, events: list[Event]) -> int:
        if not events:
            return 0
        if self.native_backend.available and self.native_backend.process_events(events):
            self.native_backend.flush()
            return len(events)
        for event in events:
            self.process_event(event)
        return len(events)

    def process_source_batched(self, source: Any, *, batch_size: int = 5000) -> int:
        count = 0
        effective_batch_size = max(1, int(batch_size))
        batch: list[Event] = []
        for event in source:
            batch.append(event)
            if len(batch) < effective_batch_size:
                continue
            count += self.process_event_batch(batch)
            batch = []
        if batch:
            count += self.process_event_batch(batch)
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

    def _rebuild_snapshot_state(self) -> None:
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
            graph_path_candidate_preselect_factor=self.graph_path_candidate_preselect_factor,
            graph_path_edge_eviction_policy=self.graph_path_edge_eviction_policy,
        )
        self.hsg_nodes = {n.match_id: n for n in hsg.nodes}
        self.hsg_edges = list(hsg.edges)
        self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}
        self._graph_path_edges_count = len([e for e in self.hsg_edges if e.relation == "graph_path"])
        self._snapshot_state_dirty = False

    def _ensure_snapshot_state(self) -> None:
        if self._snapshot_state_dirty and not self.use_online_prereq:
            self._rebuild_snapshot_state()

    def current_hsg(self) -> HSG:
        self._ensure_snapshot_state()
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
        self.graph.register_prune_hook(self.online_index.prune)
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
            graph_path_eval_budget_ms=self.graph_path_eval_budget_ms,
            graph_path_cache_miss_policy=self.graph_path_cache_miss_policy,
            graph_path_candidate_preselect_factor=self.graph_path_candidate_preselect_factor,
            graph_path_edge_eviction_policy=self.graph_path_edge_eviction_policy,
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
        for edge in self.graph.runtime_edges:
            self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)
        for m in self.matches:
            self.taint_tracker.mark_initial_compromise(m, self.rule_by_id.get(m.rule_id))
            for node_id in (m.subject_node_id, m.object_node_id):
                if node_id:
                    telemetry = self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=m.match_id,
                        rule_id=m.rule_id,
                        sequence=int(m.sequence or 0),
                        origin_node_id=node_id,
                    )
                    self._record_online_index_match_add_telemetry(telemetry)
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

    def _build_summary(self, *, hsg_nodes_count: int, hsg_edges_count: int) -> dict[str, Any]:
        before_counts = self._noise_before_override or {
            "matches": self.stats.raw_matches,
            "hsg_nodes": self.stats.raw_matches,
            "hsg_edges": hsg_edges_count,
        }
        noise_filter = {
            "before": before_counts,
            "after": {
                "matches": len(self.matches),
                "hsg_nodes": hsg_nodes_count,
                "hsg_edges": hsg_edges_count,
            },
            "dropped": {
                "matches": int(before_counts["matches"]) - len(self.matches),
                "hsg_nodes": int(before_counts["hsg_nodes"]) - hsg_nodes_count,
                "hsg_edges": int(before_counts["hsg_edges"]) - hsg_edges_count,
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
            "hsg_nodes": hsg_nodes_count,
            "hsg_edges": hsg_edges_count,
            "ab_config": {
                "performance": self.ab_performance,
                "quality": self.ab_quality,
                "ac_min_method": self.ac_min_method,
                "graph_path_eval_budget_ms": self.graph_path_eval_budget_ms,
                "graph_path_cache_miss_policy": self.graph_path_cache_miss_policy,
                "graph_path_candidate_preselect_factor": self.graph_path_candidate_preselect_factor,
                "graph_path_edge_eviction_policy": self.graph_path_edge_eviction_policy,
            },
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
        return summary

    def _iter_match_rows(self):
        legacy_snapshot_mode = (self.scoring_mode == "legacy" and not self.use_online_prereq)
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
            yield row

    @staticmethod
    def _write_json_array(path: Path, items) -> None:
        with path.open("w", encoding="utf-8") as fh:
            fh.write("[\n")
            for idx, item in enumerate(items):
                if idx:
                    fh.write(",\n")
                fh.write(json.dumps(item, ensure_ascii=False, indent=2))
            fh.write("\n]\n")

    @staticmethod
    def _write_hsg_json(path: Path, *, nodes, edges) -> None:
        with path.open("w", encoding="utf-8") as fh:
            fh.write("{\n  \"nodes\": [\n")
            for idx, n in enumerate(nodes):
                if idx:
                    fh.write(",\n")
                fh.write(
                    json.dumps(
                        {
                            "match_id": n.match_id,
                            "rule_id": n.rule_id,
                            "event_ids": n.event_ids,
                            "entities": n.entities,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            fh.write("\n  ],\n  \"edges\": [\n")
            for idx, e in enumerate(edges):
                if idx:
                    fh.write(",\n")
                payload = {
                    "src": e.src,
                    "dst": e.dst,
                    "relation": e.relation,
                }
                if e.weight is not None:
                    payload["weight"] = e.weight
                if e.path_factor is not None:
                    payload["path_factor"] = e.path_factor
                if e.dependency_strength is not None:
                    payload["dependency_strength"] = e.dependency_strength
                fh.write(json.dumps(payload, ensure_ascii=False, indent=2))
            fh.write("\n  ]\n}\n")

    def build_result(self) -> dict[str, Any]:
        hsg = self.current_hsg()
        return {
            "summary": self._build_summary(hsg_nodes_count=len(hsg.nodes), hsg_edges_count=len(hsg.edges)),
            "matches": list(self._iter_match_rows()),
            "hsg": hsg_to_dict(hsg),
        }

    def write_snapshot(self, out_dir: str | Path) -> dict[str, Any]:
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
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
        self._ensure_snapshot_state()
        if self.use_online_prereq:
            self._maybe_refresh_scores_online(force=True)
        summary = self._build_summary(
            hsg_nodes_count=len(self.hsg_nodes),
            hsg_edges_count=len(self.hsg_edges),
        )
        (p / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        self._write_json_array(p / "matches.json", self._iter_match_rows())
        self._write_hsg_json(p / "hsg.json", nodes=self.hsg_nodes.values(), edges=self.hsg_edges)
        return {"summary": summary}
