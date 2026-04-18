from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
import tempfile

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from evaluate_darpa_tc import _load_ground_truth, evaluate_scenario_coverage
from engine.rules.schema import load_rules
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def _set_max_path_factor(payload: dict, value: int) -> dict:
    cloned = yaml.safe_load(yaml.safe_dump(payload))
    rules = cloned.get("rules", [])
    for rule in rules:
        prerequisites = rule.get("prerequisites", [])
        if not isinstance(prerequisites, list):
            continue
        for prereq in prerequisites:
            if isinstance(prereq, dict) and prereq.get("type") == "path_factor":
                prereq["max_path_factor"] = int(value)
    return cloned


def _run_evaluation(
    *,
    events_path: str,
    rules_path: Path,
    ground_truth_path: str,
    out_dir: Path,
    apt_alert_threshold: float,
    benign_profile_path: str | None = None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    ruleset = load_rules(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_mode="strict",
        apt_alert_threshold=float(apt_alert_threshold),
        alerts_path=out_dir / "alerts.jsonl",
        dropped_match_telemetry_path=out_dir / "debug" / "dropped_matches.jsonl",
        benign_profile_path=benign_profile_path,
    )
    for event in FileJsonlSource(events_path, follow=False):
        engine.process_event(event)
    engine.write_snapshot(out_dir)
    alerts = [
        json.loads(line)
        for line in (out_dir / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ground_truth = _load_ground_truth(ground_truth_path)
    return evaluate_scenario_coverage(alerts, ground_truth)


def main() -> int:
    parser = argparse.ArgumentParser(description="Grid-search DARPA HOLMES hyperparameters.")
    parser.add_argument("--events", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-path-factors", default="2,3,4")
    parser.add_argument("--alert-thresholds", default="50.0,80.0,100.0")
    parser.add_argument("--benign-profile")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_rules_payload = yaml.safe_load(Path(args.rules).read_text(encoding="utf-8"))
    if not isinstance(base_rules_payload, dict):
        raise ValueError("rules yaml root must be a mapping")

    max_path_factors = [int(item.strip()) for item in str(args.max_path_factors).split(",") if item.strip()]
    alert_thresholds = [float(item.strip()) for item in str(args.alert_thresholds).split(",") if item.strip()]

    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="darpa_tune_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        for max_path_factor in max_path_factors:
            tuned_payload = _set_max_path_factor(base_rules_payload, max_path_factor)
            tuned_rules_path = tmp_root / f"rules_pf_{max_path_factor}.yaml"
            tuned_rules_path.write_text(yaml.safe_dump(tuned_payload, sort_keys=False), encoding="utf-8")
            for threshold in alert_thresholds:
                eval_out = tmp_root / f"pf_{max_path_factor}_thr_{str(threshold).replace('.', '_')}"
                metrics = _run_evaluation(
                    events_path=args.events,
                    rules_path=tuned_rules_path,
                    ground_truth_path=args.ground_truth,
                    out_dir=eval_out,
                    apt_alert_threshold=threshold,
                    benign_profile_path=args.benign_profile,
                )
                rows.append(
                    {
                        "max_path_factor": max_path_factor,
                        "apt_alert_threshold": threshold,
                        "precision": metrics["precision"],
                        "recall": metrics["recall"],
                        "f1": metrics["f1"],
                        "fragmentation_ratio": metrics["fragmentation_ratio"],
                    }
                )

    csv_path = out_dir / "tuning_results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "max_path_factor",
                "apt_alert_threshold",
                "precision",
                "recall",
                "f1",
                "fragmentation_ratio",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    rows_sorted = sorted(rows, key=lambda row: (float(row["f1"]), float(row["recall"]), -float(row["fragmentation_ratio"])), reverse=True)
    table_lines = [
        "max_path_factor,apt_alert_threshold,precision,recall,f1,fragmentation_ratio"
    ]
    for row in rows_sorted:
        table_lines.append(
            f'{row["max_path_factor"]},{row["apt_alert_threshold"]},{row["precision"]:.4f},{row["recall"]:.4f},{row["f1"]:.4f},{row["fragmentation_ratio"]:.4f}'
        )
    summary = {
        "best": rows_sorted[0] if rows_sorted else None,
        "csv_path": str(csv_path),
        "rows": rows_sorted,
    }
    (out_dir / "tuning_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n".join(table_lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
