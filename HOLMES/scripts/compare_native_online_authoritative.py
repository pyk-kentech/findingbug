from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any


METRIC_KEYS = [
    "events_per_second",
    "online_graph_edge_flush_time_seconds",
    "online_graph_edge_flush_flush_call_time_seconds",
    "online_index_propagate_across_new_edge_seed_merge_time_seconds",
    "online_add_active_match_online_index_time_seconds",
    "online_index_match_add_time_seconds",
    "native_online_read_primary_enabled",
    "native_online_flush_authoritative_enabled",
    "online_graph_edge_flush_native_authoritative_count",
    "online_match_add_native_authoritative_count",
    "online_match_remove_native_authoritative_count",
    "native_online_read_fallback_total",
    "native_online_fallback_activation_total",
    "native_online_fallback_mutation_failure_total",
    "native_online_fallback_read_mismatch_total",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run auth-off/auth-on A/B for HOLMES native online path.")
    parser.add_argument("--events", required=True, help="Path to input events file.")
    parser.add_argument("--rules", required=True, help="Path to rules YAML.")
    parser.add_argument("--out-dir", required=True, help="Directory where auth_off/auth_on outputs and report will be written.")
    parser.add_argument("--snapshot-every", type=int, default=100000, help="Snapshot cadence passed to run_stream.")
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Extra CLI arg forwarded to run_stream. Repeat for multiple args, e.g. --extra-arg=--scoring --extra-arg=legacy",
    )
    return parser.parse_args()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _count_events(path: str) -> int | None:
    try:
        with Path(path).open("r", encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except Exception:
        return None


def _read_latest_metrics(metrics_path: Path) -> dict[str, Any] | None:
    if not metrics_path.exists() or metrics_path.stat().st_size <= 0:
        return None
    try:
        last = ""
        with metrics_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                last = line
        return json.loads(last) if last.strip() else None
    except Exception:
        return None


def _format_progress(label: str, metrics: dict[str, Any], total_events: int | None) -> str:
    events = int(metrics.get("events_processed", 0))
    pm = metrics.get("performance_metrics", {}) or {}
    eps = float(pm.get("events_per_second", 0.0) or 0.0)
    ts = metrics.get("ts", "")
    if total_events and total_events > 0:
        pct = min(100.0, (events / total_events) * 100.0)
        return f"[{label}] {ts} events={events}/{total_events} ({pct:.2f}%) eps={eps:.1f}"
    return f"[{label}] {ts} events={events} eps={eps:.1f}"


def _run_variant(label: str, *, events: str, rules: str, out_dir: Path, snapshot_every: int, extra_args: list[str]) -> dict[str, Any]:
    repo_root = _repo_root()
    variant_out = out_dir / label
    if variant_out.exists():
        shutil.rmtree(variant_out)
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env["HOLMES_NATIVE_BACKEND"] = "rust"
    env["HOLMES_NATIVE_ONLINE_READ_PRIMARY"] = "1"
    env["HOLMES_NATIVE_SHADOW_CHECK"] = "0"
    env["HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE"] = "1" if label == "auth_on" else "0"
    cmd = [
        sys.executable,
        "-m",
        "engine.cli.run_stream",
        "--events",
        events,
        "--rules",
        rules,
        "--out",
        str(variant_out),
        "--snapshot-every",
        str(snapshot_every),
        *extra_args,
    ]
    metrics_path = variant_out / "metrics.jsonl"
    total_events = _count_events(events)
    print(f"[{label}] starting", flush=True)
    if total_events:
        print(f"[{label}] total events={total_events}", flush=True)
    proc = subprocess.Popen(cmd, cwd=repo_root, env=env)
    last_progress: str | None = None
    try:
        while True:
            rc = proc.poll()
            metrics = _read_latest_metrics(metrics_path)
            if metrics is not None:
                progress = _format_progress(label, metrics, total_events)
                if progress != last_progress:
                    print(progress, flush=True)
                    last_progress = progress
            if rc is not None:
                if rc != 0:
                    raise subprocess.CalledProcessError(rc, cmd)
                break
            time.sleep(10.0)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
    summary = json.loads((variant_out / "summary.json").read_text(encoding="utf-8"))
    pm = summary["performance_metrics"]
    metrics = {key: pm.get(key) for key in METRIC_KEYS}
    metrics["events"] = summary.get("events")
    metrics["matches"] = summary.get("matches")
    metrics["hsg_edges"] = summary.get("hsg_edges")
    print(f"[{label}] finished events={metrics['events']} matches={metrics['matches']} hsg_edges={metrics['hsg_edges']}", flush=True)
    return metrics


def _diff(base: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    diffs: dict[str, Any] = {}
    for key in METRIC_KEYS:
        b = base.get(key)
        c = candidate.get(key)
        if isinstance(b, (int, float)) and isinstance(c, (int, float)) and b not in (0, 0.0):
            diffs[key] = {
                "base": b,
                "candidate": c,
                "delta": c - b,
                "delta_pct": ((c - b) / b) * 100.0,
            }
        else:
            diffs[key] = {
                "base": b,
                "candidate": c,
            }
    diffs["workload"] = {
        "events": base.get("events"),
        "matches_base": base.get("matches"),
        "matches_candidate": candidate.get("matches"),
        "hsg_edges_base": base.get("hsg_edges"),
        "hsg_edges_candidate": candidate.get("hsg_edges"),
        "seed_merge_exercised": bool(
            (base.get("online_index_propagate_across_new_edge_seed_merge_time_seconds") or 0) > 0
            or (candidate.get("online_index_propagate_across_new_edge_seed_merge_time_seconds") or 0) > 0
            or (base.get("matches") or 0) > 0
            or (candidate.get("matches") or 0) > 0
        ),
    }
    return diffs


def main() -> int:
    args = _parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    auth_off = _run_variant(
        "auth_off",
        events=args.events,
        rules=args.rules,
        out_dir=out_dir,
        snapshot_every=args.snapshot_every,
        extra_args=list(args.extra_arg),
    )
    auth_on = _run_variant(
        "auth_on",
        events=args.events,
        rules=args.rules,
        out_dir=out_dir,
        snapshot_every=args.snapshot_every,
        extra_args=list(args.extra_arg),
    )
    report = {
        "auth_off": auth_off,
        "auth_on": auth_on,
        "diff": _diff(auth_off, auth_on),
    }
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
