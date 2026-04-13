from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher
from engine.hsg.builder import load_graph_path_allowlist
from engine.io.events import count_raw_records_jsonl, iter_raw_records_jsonl, load_events_jsonl
from engine.noise.filter import NoiseConfig, apply_noise_filter, load_noise_config
from engine.noise.trainer import save_benign_noise_model, train_benign_noise_model
from engine.rules.schema import load_rules
from engine.stream.runner import StreamingEngine
from engine.stream.workers import iter_parsed_events_parallel


class _ProgressBar:
    def __init__(self, total: int, enabled: bool = True, label: str = "events") -> None:
        self.total = max(0, int(total))
        self.enabled = bool(enabled)
        self.label = label
        self.start_ts = time.perf_counter()
        self.last_render_ts = 0.0

    def render(self, current: int, *, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.perf_counter()
        if not force and (now - self.last_render_ts) < 0.2:
            return
        self.last_render_ts = now
        current = max(0, min(int(current), self.total if self.total > 0 else int(current)))
        elapsed = max(now - self.start_ts, 1e-9)
        rate = current / elapsed
        pct = (current / self.total) if self.total > 0 else 1.0
        filled = int(pct * 30)
        bar = "#" * filled + "-" * (30 - filled)
        remain_items = max(0, self.total - current)
        eta = (remain_items / rate) if rate > 0 else 0.0
        msg = (
            f"\r[{bar}] {pct*100:6.2f}% "
            f"{current}/{self.total} {self.label} "
            f"{rate:8.1f} ev/s ETA {eta:8.1f}s"
        )
        sys.stdout.write(msg)
        sys.stdout.flush()
        if force:
            sys.stdout.write("\n")
            sys.stdout.flush()


def _parse_paper_weights(raw: str) -> list[float]:
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 7:
        raise ValueError("--paper-weights must contain exactly 7 comma-separated floats")
    try:
        return [float(p) for p in parts]
    except ValueError as exc:
        raise ValueError("--paper-weights must contain valid floats") from exc


def _resolve_effective_config(
    *,
    scoring_mode: str,
    paper_mode: str,
    paper_weights: str,
    tau: float | None,
    min_path_factor: float | None,
    path_factor_op: str | None,
) -> dict[str, object]:
    if path_factor_op is not None and path_factor_op not in {"ge", "le"}:
        raise ValueError("path_factor_op must be one of: ge, le")

    if scoring_mode in {"paper", "paper_exact"}:
        resolved_path_thres = 3.0 if min_path_factor is None else float(min_path_factor)
        resolved_op = "le" if path_factor_op is None else path_factor_op
    else:
        resolved_path_thres = 0.0 if min_path_factor is None else float(min_path_factor)
        resolved_op = "ge" if path_factor_op is None else path_factor_op

    out = {
        "path_thres": resolved_path_thres,
        "path_factor_op": resolved_op,
        "scoring": scoring_mode,
        "paper_mode": paper_mode,
        "paper_weights": _parse_paper_weights(paper_weights),
    }
    if tau is not None:
        out["tau"] = float(tau)
    return out


def run_pipeline(
    events_path: str,
    rules_path: str,
    output_path: str,
    noise_path: str | None = None,
    alpha: float | None = None,
    min_graph_path_weight: float = 0.0,
    min_path_factor: float | None = None,
    path_factor_op: str | None = None,
    scoring_mode: str = "legacy",
    paper_weights: str = "1.0,1.0,1.0,1.0,1.0,1.0,1.0",
    tau: float | None = None,
    paper_mode: str = "hybrid",
    prereq_policy: str = "union",
    noise_model_path: str | None = None,
    noise_bytes_threshold: str = "p95",
    noise_signature_min_ratio: float = 0.1,
    graph_path_allowlist: str | None = "none",
    max_graph_path_edges: int = 10000,
    max_graph_path_candidates_per_match: int = 200,
    ab_performance: str = "a",
    ab_quality: str = "a",
    graph_path_eval_budget_ms: float | None = None,
    graph_path_candidate_preselect_factor: int | None = None,
    graph_path_edge_eviction_policy: str | None = None,
    graph_gc_every_events: int | None = None,
    online_score_refresh_every: int | None = None,
    use_online_prereq: bool = False,
    apt_alert_threshold: float = 80.0,
    max_pending_matches: int = 100000,
    matcher_workers: int = 1,
    matcher_batch_size: int = 50000,
    ancestor_index_mode: str = "incremental",
    progress: bool = True,
) -> dict:
    if prereq_policy not in {"dst_only", "union"}:
        raise ValueError("prereq_policy must be one of: dst_only, union")
    effective_ancestor_index_mode = str(ancestor_index_mode).strip().lower()
    if effective_ancestor_index_mode not in {"incremental", "lazy"}:
        raise ValueError("ancestor_index_mode must be one of: incremental, lazy")
    force_incremental_online = os.getenv("HOLMES_FORCE_INCREMENTAL_ANCESTOR_FOR_ONLINE", "1").strip().lower() not in {"0", "false", "no"}
    if bool(use_online_prereq) and force_incremental_online and effective_ancestor_index_mode == "lazy":
        effective_ancestor_index_mode = "incremental"
    perf_variant = str(ab_performance).strip().lower()
    quality_variant = str(ab_quality).strip().lower()
    if perf_variant not in {"a", "b"}:
        raise ValueError("ab_performance must be one of: a, b")
    if quality_variant not in {"a", "b"}:
        raise ValueError("ab_quality must be one of: a, b")
    # Force set-difference AC_min path for stability in large streaming graphs.
    effective_ac_min_method = "set_diff"
    if quality_variant == "b":
        if graph_path_eval_budget_ms is None:
            effective_graph_path_eval_budget_ms = 1.0
        else:
            effective_graph_path_eval_budget_ms = max(0.0, float(graph_path_eval_budget_ms))
            if effective_graph_path_eval_budget_ms <= 0.0:
                effective_graph_path_eval_budget_ms = 1.0
        effective_graph_path_cache_miss_policy = "skip"
        if graph_path_candidate_preselect_factor is None:
            effective_graph_path_candidate_preselect_factor = 4
        else:
            effective_graph_path_candidate_preselect_factor = max(0, int(graph_path_candidate_preselect_factor))
        if graph_path_edge_eviction_policy is None:
            effective_graph_path_edge_eviction_policy = "low_weight_lru"
        else:
            effective_graph_path_edge_eviction_policy = str(graph_path_edge_eviction_policy).strip().lower()
    else:
        effective_graph_path_eval_budget_ms = None
        effective_graph_path_cache_miss_policy = "compute"
        effective_graph_path_candidate_preselect_factor = max(0, int(graph_path_candidate_preselect_factor or 0))
        effective_graph_path_edge_eviction_policy = (
            str(graph_path_edge_eviction_policy).strip().lower()
            if graph_path_edge_eviction_policy is not None
            else "none"
        )
    if effective_graph_path_edge_eviction_policy not in {"none", "low_weight_lru"}:
        raise ValueError("graph_path_edge_eviction_policy must be one of: none, low_weight_lru")
    noise_signature_min_ratio = max(0.0, min(1.0, float(noise_signature_min_ratio)))
    resolved_effective_config = _resolve_effective_config(
        scoring_mode=scoring_mode,
        paper_mode=paper_mode,
        paper_weights=paper_weights,
        tau=tau,
        min_path_factor=min_path_factor,
        path_factor_op=path_factor_op,
    )

    ruleset = load_rules(rules_path)
    allowlist = load_graph_path_allowlist(graph_path_allowlist)
    runtime_noise_config = load_noise_config(
        noise_path,
        model_path=noise_model_path,
        noise_bytes_threshold=noise_bytes_threshold,
        noise_signature_min_ratio=noise_signature_min_ratio,
    )
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode=scoring_mode,
        paper_weights=_parse_paper_weights(paper_weights),
        tau=tau,
        paper_mode=paper_mode,
        prereq_policy=prereq_policy,
        alpha=alpha,
        noise_config=runtime_noise_config,
        graph_path_allowlist=allowlist,
        max_graph_path_edges=max_graph_path_edges,
        max_graph_path_candidates_per_match=max_graph_path_candidates_per_match,
        graph_path_eval_budget_ms=effective_graph_path_eval_budget_ms,
        graph_path_cache_miss_policy=effective_graph_path_cache_miss_policy,
        graph_path_candidate_preselect_factor=effective_graph_path_candidate_preselect_factor,
        graph_path_edge_eviction_policy=effective_graph_path_edge_eviction_policy,
        ac_min_method=effective_ac_min_method,
        ab_performance=perf_variant,
        ab_quality=quality_variant,
        use_online_prereq=use_online_prereq,
        resolved_effective_config=resolved_effective_config,
        global_refine_mode="off",
        dropped_match_telemetry_path=Path(output_path) / "debug" / "dropped_matches.jsonl",
        alerts_path=Path(output_path) / "alerts.jsonl",
        metrics_path=Path(output_path) / "debug" / "metrics.jsonl",
        metrics_every_events=50000,
        metrics_interval_sec=60.0,
        apt_alert_threshold=apt_alert_threshold,
        max_pending_matches=max_pending_matches,
        defer_snapshot_updates=not bool(use_online_prereq),
        graph_gc_every_events=(
            max(1, int(graph_gc_every_events))
            if graph_gc_every_events is not None
            else (1000 if bool(use_online_prereq) else 50000)
        ),
        online_score_refresh_every=(
            max(1, int(online_score_refresh_every))
            if online_score_refresh_every is not None
            else (5000 if bool(use_online_prereq) else 1000)
        ),
        ancestor_index_mode=effective_ancestor_index_mode,
    )
    parser_workers = max(1, int(matcher_workers))
    parser_queue_size = max(1, int(matcher_batch_size))
    total_records = count_raw_records_jsonl(events_path) if progress else 0
    progress_bar = _ProgressBar(total=total_records, enabled=bool(progress), label="events")
    processed = 0
    raw_source = iter_raw_records_jsonl(events_path)
    for processed, event in enumerate(
        iter_parsed_events_parallel(
            raw_source,
            worker_count=parser_workers,
            queue_size=parser_queue_size,
        ),
        start=1,
    ):
        engine.process_event(event)
        progress_bar.render(processed, force=False)
    if progress:
        progress_bar.render(processed, force=True)

    resolved_path_thres = float(resolved_effective_config["path_thres"])
    resolved_path_factor_op = str(resolved_effective_config["path_factor_op"])
    if noise_path or min_graph_path_weight > 0.0 or resolved_path_thres > 0.0:
        before_hsg = engine.current_hsg()
        noise_config = load_noise_config(
            noise_path,
            noise_bytes_threshold=noise_bytes_threshold,
            noise_signature_min_ratio=noise_signature_min_ratio,
        ) if noise_path else NoiseConfig()
        noise_config.min_graph_path_weight = max(noise_config.min_graph_path_weight, min_graph_path_weight)
        noise_config.min_path_factor = max(noise_config.min_path_factor, resolved_path_thres)
        noise_config.path_factor_op = resolved_path_factor_op
        matches_after, hsg_after = apply_noise_filter(engine.matches, before_hsg, noise_config, events_by_id=engine.events_by_id)
        engine._replace_state_from_filtered(  # noqa: SLF001
            matches_after,
            hsg_after,
            before_matches=len(engine.matches),
            before_nodes=len(before_hsg.nodes),
            before_edges=len(before_hsg.edges),
        )
        engine._refresh_scores()  # noqa: SLF001

    return engine.write_snapshot(output_path)


def train_noise_model_pipeline(
    train_events_path: str,
    rules_path: str,
    output_path: str,
    save_noise_model_path: str,
    min_count: int = 5,
    bytes_min_count: int = 20,
    signature_min_ratio: float = 0.1,
    dynamic_margin_ratio: float = 0.25,
    dynamic_min_margin_bytes: int = 1,
    dynamic_min_samples: int = 1,
) -> dict:
    signature_min_ratio = max(0.0, min(1.0, float(signature_min_ratio)))
    events = list(load_events_jsonl(train_events_path))
    graph = ProvenanceGraph(ac_min_method="set_diff")
    graph.add_events(events)

    ruleset = load_rules(rules_path)
    matcher = Matcher()
    matches = matcher.match(graph=graph, ruleset=ruleset, events=events)
    rule_by_id = {r.rule_id: r for r in ruleset.rules}
    events_by_id = {e.event_id: e for e in events}
    model = train_benign_noise_model(
        matches,
        rule_by_id=rule_by_id,
        events_by_id=events_by_id,
        min_count=min_count,
        bytes_min_count=bytes_min_count,
        signature_min_ratio=signature_min_ratio,
        dynamic_margin_ratio=dynamic_margin_ratio,
        dynamic_min_margin_bytes=dynamic_min_margin_bytes,
        dynamic_min_samples=dynamic_min_samples,
    )
    save_benign_noise_model(model, save_noise_model_path)

    result = {
        "summary": {
            "mode": "train_noise_model",
            "events": len(events),
            "rules": len(ruleset.rules),
            "matches": len(matches),
            "benign_signatures": len(model.benign_signatures),
            "noise_model_path": str(save_noise_model_path),
            "min_count": int(min_count),
            "bytes_min_count": int(bytes_min_count),
            "signature_min_ratio": float(signature_min_ratio),
            "dynamic_margin_ratio": float(dynamic_margin_ratio),
            "dynamic_min_margin_bytes": int(dynamic_min_margin_bytes),
            "dynamic_min_samples": int(dynamic_min_samples),
        },
        "noise_model": {
            "version": model.version,
            "benign_signatures": len(model.benign_signatures),
            "has_byte_volume": bool(model.byte_volume),
            "dynamic_pair_thresholds": len(model.dynamic_thresholds.get("pair_thresholds", {})),
            "dynamic_rule_thresholds": len(model.dynamic_thresholds.get("rule_thresholds", {})),
        },
    }

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (output_dir / "summary.json").write_text(json.dumps(result["summary"], indent=2), encoding="utf-8")
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HOLMES-style APT detection MVP pipeline")
    parser.add_argument("--events", required=False, help="Path to input events JSONL (detect mode)")
    parser.add_argument("--train-events", dest="train_events", required=False, help="Path to benign events JSONL (train mode)")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    parser.add_argument(
        "--out",
        "--output",
        dest="out",
        required=True,
        help="Path to output directory (result.json/summary.json/matches.json/hsg.json)",
    )
    parser.add_argument(
        "--noise",
        dest="noise",
        default=None,
        help="Path to static noise config YAML (optional; when omitted no noise filter is applied)",
    )
    parser.add_argument(
        "--noise-model",
        dest="noise_model",
        default=None,
        help="Path to trained benign noise model JSON (optional; detect mode).",
    )
    parser.add_argument(
        "--save-noise-model",
        dest="save_noise_model",
        default=None,
        help="Output path for trained noise model JSON (train mode).",
    )
    parser.add_argument(
        "--noise-min-count",
        dest="noise_min_count",
        type=int,
        default=5,
        help="Minimum signature count to keep as benign in training (default: 5).",
    )
    parser.add_argument(
        "--noise-bytes-min-count",
        dest="noise_bytes_min_count",
        type=int,
        default=20,
        help="Minimum samples per rule_id for byte-volume model in training (default: 20).",
    )
    parser.add_argument(
        "--noise-bytes-threshold",
        dest="noise_bytes_threshold",
        choices=["p50", "p95", "p99", "max"],
        default="p95",
        help="Byte-volume threshold key used in detect mode with --noise-model (default: p95).",
    )
    parser.add_argument(
        "--noise-signature-min-ratio",
        dest="noise_signature_min_ratio",
        type=float,
        default=0.1,
        help="Minimum benign signature frequency ratio within the same rule_id needed to drop (default: 0.1).",
    )
    parser.add_argument(
        "--noise-dynamic-margin-ratio",
        dest="noise_dynamic_margin_ratio",
        type=float,
        default=0.25,
        help="Margin ratio added above the maximum benign cumulative byte volume (default: 0.25).",
    )
    parser.add_argument(
        "--noise-dynamic-min-margin-bytes",
        dest="noise_dynamic_min_margin_bytes",
        type=int,
        default=1,
        help="Minimum additive byte margin for dynamic benign thresholds (default: 1).",
    )
    parser.add_argument(
        "--noise-dynamic-min-samples",
        dest="noise_dynamic_min_samples",
        type=int,
        default=1,
        help="Minimum samples required before emitting a dynamic benign threshold (default: 1).",
    )
    parser.add_argument(
        "--alpha",
        dest="alpha",
        type=float,
        default=None,
        help="Weighted-scenario alpha (severity + alpha*weight). Overridden by rules scoring.alpha if set.",
    )
    parser.add_argument(
        "--min-graph-path-weight",
        dest="min_graph_path_weight",
        type=float,
        default=0.0,
        help="Drop graph_path edges with weight below this threshold (default: 0.0).",
    )
    parser.add_argument(
        "--min-path-factor",
        dest="min_path_factor",
        type=float,
        default=None,
        help=(
            "Path-factor threshold. In paper/paper_exact mode this is interpreted as path_thres. "
            "Resolver default is 3 only when scoring is paper-like and value is omitted."
        ),
    )
    parser.add_argument(
        "--path-factor-op",
        dest="path_factor_op",
        choices=["ge", "le"],
        default=None,
        help=(
            "Path-factor threshold direction. Resolver default is le for paper-like scoring "
            "and ge for legacy when omitted."
        ),
    )
    parser.add_argument(
        "--scoring",
        dest="scoring_mode",
        choices=["legacy", "paper", "paper_exact"],
        default="legacy",
        help="Scenario scoring mode (legacy additive, paper approximate, or paper_exact weighted-product).",
    )
    parser.add_argument(
        "--paper-weights",
        dest="paper_weights",
        default="1.0,1.0,1.0,1.0,1.0,1.0,1.0",
        help="Comma-separated 7 floats for paper weighted-product scoring.",
    )
    parser.add_argument(
        "--tau",
        dest="tau",
        type=float,
        default=None,
        help="Detection threshold tau for paper_exact mode. Alert when score >= tau.",
    )
    parser.add_argument(
        "--paper-mode",
        dest="paper_mode",
        choices=["hybrid", "strict"],
        default="hybrid",
        help="graph_path edge-weight mode: hybrid=dependency_strength*path_factor, strict=path_factor.",
    )
    parser.add_argument(
        "--prereq-policy",
        dest="prereq_policy",
        choices=["dst_only", "union"],
        default="union",
        help="Prerequisite relation policy: union keeps legacy behavior; dst_only uses only destination rule prerequisites.",
    )
    parser.add_argument(
        "--graph-path-allowlist",
        dest="graph_path_allowlist",
        default="none",
        help="Optional allowlist file for graph_path rule pairs; use 'none' to disable (default).",
    )
    parser.add_argument(
        "--max-graph-path-edges",
        dest="max_graph_path_edges",
        type=int,
        default=10000,
        help="Maximum number of graph_path edges to create (default: 10000).",
    )
    parser.add_argument(
        "--max-graph-path-candidates-per-match",
        dest="max_graph_path_candidates_per_match",
        type=int,
        default=200,
        help="Maximum graph_path destination candidates evaluated per source match (default: 200).",
    )
    parser.add_argument(
        "--ab-performance",
        dest="ab_performance",
        choices=["a", "b", "A", "B"],
        default="a",
        help="Performance A/B: A=baseline ac_min(pairwise), B=ac_min(set_diff).",
    )
    parser.add_argument(
        "--ab-quality",
        dest="ab_quality",
        choices=["a", "b", "A", "B"],
        default="a",
        help="Quality A/B: A=full graph_path eval, B=budgeted graph_path eval.",
    )
    parser.add_argument(
        "--graph-path-eval-budget-ms",
        dest="graph_path_eval_budget_ms",
        type=float,
        default=None,
        help=(
            "Per add_match graph_path evaluation budget in milliseconds when --ab-quality B is used. "
            "If omitted in B mode, defaults to 1.0ms."
        ),
    )
    parser.add_argument(
        "--graph-path-candidate-preselect-factor",
        dest="graph_path_candidate_preselect_factor",
        type=int,
        default=None,
        help=(
            "Preselect factor for candidate ranking before graph_path pair evaluation. "
            "Candidate cap becomes max_graph_path_candidates_per_match * factor. "
            "In --ab-quality B mode, defaults to 4 when omitted."
        ),
    )
    parser.add_argument(
        "--graph-path-edge-eviction-policy",
        dest="graph_path_edge_eviction_policy",
        choices=["none", "low_weight_lru"],
        default=None,
        help=(
            "Graph-path edge cap policy when max_graph_path_edges is reached. "
            "In --ab-quality B mode, defaults to low_weight_lru when omitted."
        ),
    )
    parser.add_argument(
        "--graph-gc-every-events",
        dest="graph_gc_every_events",
        type=int,
        default=None,
        help="Run graph prune/gc every N events (default: online=1000, offline=50000).",
    )
    parser.add_argument(
        "--online-score-refresh-every",
        dest="online_score_refresh_every",
        type=int,
        default=None,
        help="Refresh online scenario scoring every N events (default: 1000).",
    )
    parser.add_argument(
        "--use-online-prereq",
        dest="use_online_prereq",
        action="store_true",
        help="Use online prerequisite/index propagation path (default off for legacy compatibility).",
    )
    parser.add_argument(
        "--apt-alert-threshold",
        dest="apt_alert_threshold",
        type=float,
        default=80.0,
        help="Emit an APT alert when scenario severity reaches this threshold (default: 80.0).",
    )
    parser.add_argument(
        "--max-pending-matches",
        dest="max_pending_matches",
        type=int,
        default=100000,
        help="Maximum pending prerequisite matches retained before FIFO eviction (default: 100000).",
    )
    parser.add_argument(
        "--matcher-workers",
        dest="matcher_workers",
        type=int,
        default=1,
        help="Number of parser worker processes used for detect-mode JSON parsing (default: 1).",
    )
    parser.add_argument(
        "--matcher-batch-size",
        dest="matcher_batch_size",
        type=int,
        default=50000,
        help="Queue size for detect-mode parser worker pipeline (default: 50000).",
    )
    parser.add_argument(
        "--no-progress",
        dest="no_progress",
        action="store_true",
        help="Disable realtime progress bar output.",
    )
    parser.add_argument(
        "--ancestor-index-mode",
        dest="ancestor_index_mode",
        choices=("incremental", "lazy"),
        default="incremental",
        help="Graph ancestor/distance index maintenance mode. Use 'lazy' to defer heavy cache rebuilds until graph path queries are actually needed.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.train_events:
        if not args.save_noise_model:
            raise SystemExit("--save-noise-model is required when --train-events is used")
        train_noise_model_pipeline(
            train_events_path=args.train_events,
            rules_path=args.rules,
            output_path=args.out,
            save_noise_model_path=args.save_noise_model,
            min_count=max(1, int(args.noise_min_count)),
            bytes_min_count=max(1, int(args.noise_bytes_min_count)),
            signature_min_ratio=max(0.0, min(1.0, float(args.noise_signature_min_ratio))),
            dynamic_margin_ratio=max(0.0, float(args.noise_dynamic_margin_ratio)),
            dynamic_min_margin_bytes=max(1, int(args.noise_dynamic_min_margin_bytes)),
            dynamic_min_samples=max(1, int(args.noise_dynamic_min_samples)),
        )
    else:
        if not args.events:
            raise SystemExit("--events is required in detect mode")
        run_pipeline(
            events_path=args.events,
            rules_path=args.rules,
            output_path=args.out,
            noise_path=args.noise,
            alpha=args.alpha,
            min_graph_path_weight=args.min_graph_path_weight,
            min_path_factor=args.min_path_factor,
            path_factor_op=args.path_factor_op,
            scoring_mode=args.scoring_mode,
            paper_weights=args.paper_weights,
            tau=args.tau,
            paper_mode=args.paper_mode,
            prereq_policy=args.prereq_policy,
            noise_model_path=args.noise_model,
            noise_bytes_threshold=args.noise_bytes_threshold,
            noise_signature_min_ratio=max(0.0, min(1.0, float(args.noise_signature_min_ratio))),
            graph_path_allowlist=args.graph_path_allowlist,
            max_graph_path_edges=args.max_graph_path_edges,
            max_graph_path_candidates_per_match=args.max_graph_path_candidates_per_match,
            ab_performance=str(args.ab_performance).lower(),
            ab_quality=str(args.ab_quality).lower(),
            graph_path_eval_budget_ms=args.graph_path_eval_budget_ms,
            graph_path_candidate_preselect_factor=args.graph_path_candidate_preselect_factor,
            graph_path_edge_eviction_policy=args.graph_path_edge_eviction_policy,
            graph_gc_every_events=args.graph_gc_every_events,
            online_score_refresh_every=args.online_score_refresh_every,
            use_online_prereq=bool(args.use_online_prereq),
            apt_alert_threshold=float(args.apt_alert_threshold),
            max_pending_matches=max(0, int(args.max_pending_matches)),
            matcher_workers=max(1, int(args.matcher_workers)),
            matcher_batch_size=max(1, int(args.matcher_batch_size)),
            ancestor_index_mode=str(args.ancestor_index_mode),
            progress=not bool(args.no_progress),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
