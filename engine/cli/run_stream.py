from __future__ import annotations

import argparse
import time
from pathlib import Path

from engine.cli.run_pipeline import _parse_paper_weights, _resolve_effective_config
from engine.utils.config_loader import apply_config_defaults, load_yaml_config, validate_mode_config
from engine.hsg.builder import load_graph_path_allowlist
from engine.noise.filter import load_noise_config
from engine.noise.profile import load_benign_profile
from engine.rules.schema import load_rules
from engine.stream.runner import StreamingEngine
from engine.stream.source import (
    DirectoryWatcherRawLineSource,
    FileJsonlSource,
    FileRawLineSource,
    KafkaSource,
    RawStringPreFilter,
)
from engine.stream.workers import iter_parsed_events_parallel


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HOLMES streaming MVP runner")
    parser.add_argument("--config", dest="config", default=None, help="Optional pipeline YAML config.")
    parser.add_argument("--events", required=False, help="Path to input events JSONL")
    parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    parser.add_argument("--out", "--output", dest="out", required=True, help="Path to output snapshot directory")
    parser.add_argument("--follow", action="store_true", help="Follow the JSONL file as it grows (tail -f style).")
    parser.add_argument("--watch-dir", dest="watch_dir", default=None, help="Directory to watch for live JSONL append-only files.")
    parser.add_argument("--kafka-bootstrap-servers", dest="kafka_bootstrap_servers", default=None, help="Kafka bootstrap servers host:port list.")
    parser.add_argument("--kafka-topic", dest="kafka_topic", default=None, help="Kafka topic to consume.")
    parser.add_argument("--kafka-group-id", dest="kafka_group_id", default="holmes-stream", help="Kafka consumer group id.")
    parser.add_argument("--kafka-auto-offset-reset", dest="kafka_auto_offset_reset", choices=["latest", "earliest"], default="latest")
    parser.add_argument("--alpha", dest="alpha", type=float, default=None, help="Legacy weighted-scenario alpha override.")
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
        default="1,1,1,1,1,1,1",
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
    parser.add_argument("--noise-model", dest="noise_model", default=None, help="Path to trained benign noise model JSON.")
    parser.add_argument(
        "--noise-bytes-threshold",
        dest="noise_bytes_threshold",
        choices=["p50", "p95", "p99", "max"],
        default="p95",
        help="Byte-volume threshold key used with --noise-model.",
    )
    parser.add_argument(
        "--noise-signature-min-ratio",
        dest="noise_signature_min_ratio",
        type=float,
        default=0.1,
        help="Minimum benign signature frequency ratio within the same rule_id needed to drop (default: 0.1).",
    )
    parser.add_argument("--snapshot-every", dest="snapshot_every", type=int, default=10, help="Write snapshot every N events.")
    parser.add_argument(
        "--snapshot-interval-sec",
        dest="snapshot_interval_sec",
        type=float,
        default=5.0,
        help="When --follow, force periodic snapshots after this interval.",
    )
    parser.add_argument(
        "--global-refine",
        dest="global_refine",
        choices=["off", "snapshot", "every_n_events"],
        default="off",
        help="Optional global refinement trigger mode for streaming state (default: off).",
    )
    parser.add_argument(
        "--global-refine-every",
        dest="global_refine_every",
        type=int,
        default=1000,
        help="Event interval used only when --global-refine every_n_events (default: 1000).",
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
        help="Maximum pending prerequisite matches retained in memory before FIFO eviction (default: 100000).",
    )
    parser.add_argument("--benign-profile", dest="benign_profile", default=None, help="Optional benign_profile.json for matcher-time strict filtering.")
    parser.add_argument("--raw-prefilter", dest="raw_prefilter", action="store_true", help="Enable raw-line prefilter before json parsing.")
    parser.add_argument("--parser-workers", dest="parser_workers", type=int, default=0, help="Number of parser worker processes for raw sources.")
    parser.add_argument("--parser-queue-size", dest="parser_queue_size", type=int, default=1024, help="Queue size for parser worker pipeline.")
    parser.add_argument("--max-reorder-buffer", dest="max_reorder_buffer", type=int, default=1024, help="Maximum in-memory reorder buffer size for parsed out-of-order events.")
    parser.add_argument("--metrics-every-events", dest="metrics_every_events", type=int, default=1000, help="Emit metrics.jsonl at least every N events.")
    parser.add_argument("--metrics-interval-sec", dest="metrics_interval_sec", type=float, default=60.0, help="Emit metrics.jsonl at least every N seconds.")
    return parser

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    config = load_yaml_config(args.config)
    args = apply_config_defaults(
        parser,
        args,
        config,
        {
            "events": ("source", "events"),
            "watch_dir": ("source", "watch_dir"),
            "follow": ("source", "follow"),
            "kafka_bootstrap_servers": ("kafka", "bootstrap_servers"),
            "kafka_topic": ("kafka", "topic"),
            "kafka_group_id": ("kafka", "group_id"),
            "kafka_auto_offset_reset": ("kafka", "auto_offset_reset"),
            "raw_prefilter": ("prefilter", "enabled"),
            "parser_workers": ("performance", "parser_workers"),
            "parser_queue_size": ("performance", "parser_queue_size"),
            "max_reorder_buffer": ("performance", "max_reorder_buffer"),
            "snapshot_every": ("performance", "snapshot_every"),
            "snapshot_interval_sec": ("performance", "snapshot_interval_sec"),
            "metrics_every_events": ("performance", "metrics_every_events"),
            "metrics_interval_sec": ("performance", "metrics_interval_sec"),
            "apt_alert_threshold": ("engine", "apt_alert_threshold"),
            "max_pending_matches": ("engine", "max_pending_matches"),
            "benign_profile": ("noise", "benign_profile"),
        },
    )
    validate_mode_config("stream", args, config)
    resolved_effective_config = _resolve_effective_config(
        scoring_mode=args.scoring_mode,
        paper_mode=args.paper_mode,
        paper_weights=args.paper_weights,
        tau=args.tau,
        min_path_factor=args.min_path_factor,
        path_factor_op=args.path_factor_op,
    )
    ruleset = load_rules(args.rules)
    noise_config = load_noise_config(
        model_path=args.noise_model,
        noise_bytes_threshold=args.noise_bytes_threshold,
        noise_signature_min_ratio=max(0.0, min(1.0, float(args.noise_signature_min_ratio))),
    )
    allowlist = load_graph_path_allowlist(args.graph_path_allowlist)
    benign_profile = load_benign_profile(args.benign_profile) if args.benign_profile else None
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode=str(resolved_effective_config["scoring"]),
        paper_weights=list(resolved_effective_config["paper_weights"]),
        tau=(float(resolved_effective_config["tau"]) if "tau" in resolved_effective_config else None),
        paper_mode=str(resolved_effective_config["paper_mode"]),
        resolved_effective_config=resolved_effective_config,
        prereq_policy=args.prereq_policy,
        alpha=args.alpha,
        noise_config=noise_config,
        graph_path_allowlist=allowlist,
        max_graph_path_edges=args.max_graph_path_edges,
        max_graph_path_candidates_per_match=args.max_graph_path_candidates_per_match,
        global_refine_mode=args.global_refine,
        global_refine_every=max(1, int(args.global_refine_every)),
        dropped_match_telemetry_path=Path(args.out) / "debug" / "dropped_matches.jsonl",
        alerts_path=Path(args.out) / "alerts.jsonl",
        apt_alert_threshold=float(args.apt_alert_threshold),
        max_pending_matches=max(0, int(args.max_pending_matches)),
        benign_profile=benign_profile,
        metrics_path=Path(args.out) / "metrics.jsonl",
        metrics_every_events=max(1, int(args.metrics_every_events)),
        metrics_interval_sec=max(1.0, float(args.metrics_interval_sec)),
    )
    raw_prefilter = None
    if bool(args.raw_prefilter):
        raw_prefilter = RawStringPreFilter.from_ruleset(ruleset, benign_profile=benign_profile)

    source_mode_count = int(bool(args.events)) + int(bool(args.watch_dir)) + int(bool(args.kafka_topic))
    if source_mode_count != 1:
        raise ValueError("Specify exactly one input source: --events, --watch-dir, or --kafka-topic")

    if args.kafka_topic:
        if not args.kafka_bootstrap_servers:
            raise ValueError("--kafka-bootstrap-servers is required with --kafka-topic")
        source = KafkaSource(
            bootstrap_servers=args.kafka_bootstrap_servers,
            topic=args.kafka_topic,
            group_id=args.kafka_group_id,
            auto_offset_reset=args.kafka_auto_offset_reset,
            prefilter=raw_prefilter,
        )
        use_raw_source = False
    elif args.watch_dir:
        source = DirectoryWatcherRawLineSource(
            args.watch_dir,
            poll_interval_sec=args.snapshot_interval_sec if args.follow else 0.5,
            prefilter=raw_prefilter,
        )
        use_raw_source = True
    else:
        if not args.events:
            raise ValueError("--events is required for file mode")
        if args.parser_workers > 0 or raw_prefilter is not None:
            source = FileRawLineSource(
                args.events,
                follow=args.follow,
                prefilter=raw_prefilter,
            )
            use_raw_source = True
        else:
            source = FileJsonlSource(args.events, follow=args.follow)
            use_raw_source = False

    event_count = 0
    last_snapshot = time.monotonic()
    parser_telemetry = {
        "reorder_buffer_saturation_count": 0,
        "max_observed_out_of_order_distance": 0,
        "stall_duration_seconds": 0.0,
        "current_reorder_buffer_depth": 0,
        "max_observed_reorder_buffer_depth": 0,
    }
    iterable = (
        iter_parsed_events_parallel(
            source,
            worker_count=max(1, int(args.parser_workers)),
            queue_size=max(1, int(args.parser_queue_size)),
            max_reorder_buffer=max(1, int(args.max_reorder_buffer)),
            telemetry=parser_telemetry,
        )
        if use_raw_source
        else source
    )

    for event in iterable:
        engine.process_event(event)
        engine.update_stream_observability(parser_telemetry)
        event_count += 1
        should_snapshot = args.snapshot_every > 0 and (event_count % args.snapshot_every == 0)
        if not should_snapshot and args.follow:
            should_snapshot = (time.monotonic() - last_snapshot) >= float(args.snapshot_interval_sec)
        if should_snapshot:
            engine.update_stream_observability(parser_telemetry)
            engine.write_snapshot(args.out)
            last_snapshot = time.monotonic()

    engine.update_stream_observability(parser_telemetry)
    engine.write_snapshot(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
