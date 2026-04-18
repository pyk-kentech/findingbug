from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import shutil
import sys
import tempfile

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from evaluate_darpa_tc import _load_ground_truth, evaluate_scenario_coverage, select_diverse_top_k_alerts
from engine.utils.config_loader import apply_config_defaults, load_yaml_config, validate_mode_config
from engine.noise.profile import save_benign_profile, train_benign_profile
from engine.rules.schema import load_rules
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource
from tune_hyperparameters import _set_max_path_factor


def _train_profile(events_path: str, out_path: Path, min_count: int) -> dict[str, object]:
    event_count = sum(1 for _ in FileJsonlSource(events_path, follow=False))
    profile = train_benign_profile(
        FileJsonlSource(events_path, follow=False),
        min_count=max(1, int(min_count)),
    )
    save_benign_profile(profile, out_path)
    return {
        "events": event_count,
        "patterns": len(profile.patterns),
        "path": str(out_path),
    }


def _evaluate_once(
    *,
    events_path: str,
    rules_path: Path,
    ground_truth_path: str,
    out_dir: Path,
    apt_alert_threshold: float,
    benign_profile_path: str | None,
    top_k: int,
    top_k_jaccard_threshold: float,
) -> dict[str, object]:
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

    alerts_path = out_dir / "alerts.jsonl"
    alerts = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ground_truth = _load_ground_truth(ground_truth_path)
    metrics = evaluate_scenario_coverage(alerts, ground_truth)
    ranked_alerts = select_diverse_top_k_alerts(
        alerts,
        top_k=max(0, int(top_k)),
        jaccard_threshold=float(top_k_jaccard_threshold),
    )
    report = {
        "events_path": str(Path(events_path)),
        "rules_path": str(rules_path),
        "ground_truth_path": str(Path(ground_truth_path)),
        "alerts_path": str(alerts_path),
        "metrics": metrics,
        "top_k_alerts": [
            {
                "alert_id": alert.get("alert_id"),
                "scenario_id": alert.get("scenario_id"),
                "severity_score": alert.get("severity_score"),
                "graph_artifact_path": alert.get("graph_artifact_path"),
                "achieved_stages": alert.get("achieved_stages", []),
                "entities": sorted(
                    set(str(entity) for key in ("tainted_entities", "root_entities", "core_entities") for entity in alert.get(key, []) if isinstance(entity, str))
                ),
            }
            for alert in ranked_alerts
        ],
    }
    (out_dir / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {
        "metrics": metrics,
        "alerts": alerts,
        "ranked_alerts": ranked_alerts,
        "evaluation_path": str(out_dir / "evaluation.json"),
        "alerts_path": str(alerts_path),
        "summary_path": str(out_dir / "summary.json"),
    }


def _tune(
    *,
    events_path: str,
    rules_payload: dict[str, object],
    ground_truth_path: str,
    out_dir: Path,
    max_path_factors: list[int],
    alert_thresholds: list[float],
    benign_profile_path: str | None,
    top_k: int,
    top_k_jaccard_threshold: float,
) -> list[dict[str, object]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="holmes_pipeline_tune_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        for max_path_factor in max_path_factors:
            tuned_payload = _set_max_path_factor(rules_payload, max_path_factor)
            tuned_rules_path = tmp_root / f"rules_pf_{max_path_factor}.yaml"
            tuned_rules_path.write_text(yaml.safe_dump(tuned_payload, sort_keys=False), encoding="utf-8")
            for threshold in alert_thresholds:
                eval_out = tmp_root / f"pf_{max_path_factor}_thr_{str(threshold).replace('.', '_')}"
                result = _evaluate_once(
                    events_path=events_path,
                    rules_path=tuned_rules_path,
                    ground_truth_path=ground_truth_path,
                    out_dir=eval_out,
                    apt_alert_threshold=threshold,
                    benign_profile_path=benign_profile_path,
                    top_k=top_k,
                    top_k_jaccard_threshold=top_k_jaccard_threshold,
                )
                metrics = result["metrics"]
                assert isinstance(metrics, dict)
                rows.append(
                    {
                        "max_path_factor": int(max_path_factor),
                        "apt_alert_threshold": float(threshold),
                        "precision": float(metrics["precision"]),
                        "recall": float(metrics["recall"]),
                        "f1": float(metrics["f1"]),
                        "fragmentation_ratio": float(metrics["fragmentation_ratio"]),
                    }
                )
    rows_sorted = sorted(
        rows,
        key=lambda row: (
            float(row["f1"]),
            float(row["recall"]),
            -float(row["fragmentation_ratio"]),
        ),
        reverse=True,
    )
    with (out_dir / "tuning_results.csv").open("w", encoding="utf-8", newline="") as fh:
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
        writer.writerows(rows_sorted)
    (out_dir / "tuning_results.json").write_text(
        json.dumps({"best": rows_sorted[0] if rows_sorted else None, "rows": rows_sorted}, indent=2),
        encoding="utf-8",
    )
    return rows_sorted


def _copy_top_k_graph_artifacts(
    alerts: list[dict[str, object]],
    out_dir: Path,
    top_k: int,
    top_k_jaccard_threshold: float,
) -> list[str]:
    exported_paths: list[str] = []
    top_dir = out_dir / "top_scenarios"
    top_dir.mkdir(parents=True, exist_ok=True)
    ranked_alerts = select_diverse_top_k_alerts(
        [alert for alert in alerts if isinstance(alert, dict)],
        top_k=max(0, int(top_k)),
        jaccard_threshold=float(top_k_jaccard_threshold),
    )
    for index, alert in enumerate(ranked_alerts, start=1):
        artifact_path = alert.get("graph_artifact_path")
        if not isinstance(artifact_path, str) or not artifact_path:
            continue
        src = Path(artifact_path)
        if not src.exists():
            continue
        scenario_id = str(alert.get("scenario_id") or f"scenario_{index}")
        dst = top_dir / f"{index:02d}_{scenario_id}.cytoscape.json"
        shutil.copyfile(src, dst)
        exported_paths.append(str(dst))
    return exported_paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Run train -> tune -> evaluate HOLMES experiments in one command.")
    parser.add_argument("--config", dest="config", default=None, help="Optional shared pipeline YAML config.")
    parser.add_argument("--benign-events", required=False, help="Path to benign JSONL/JSONL.GZ used for whitelist training.")
    parser.add_argument("--attack-events", required=False, help="Path to attack JSONL/JSONL.GZ used for tuning/evaluation.")
    parser.add_argument("--rules", required=False, help="Path to HOLMES rules YAML.")
    parser.add_argument("--ground-truth", required=False, help="Path to ground truth JSON.")
    parser.add_argument("--out", required=False, help="Pipeline output directory.")
    parser.add_argument("--min-count", type=int, default=5)
    parser.add_argument("--max-path-factors", default="2,3,4")
    parser.add_argument("--alert-thresholds", default="50.0,80.0,100.0")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--top-k-jaccard-threshold", type=float, default=0.8)
    args = parser.parse_args()
    config = load_yaml_config(args.config)
    args = apply_config_defaults(
        parser,
        args,
        config,
        {
            "benign_events": ("experiments", "benign_events"),
            "attack_events": ("experiments", "attack_events"),
            "rules": ("experiments", "rules"),
            "ground_truth": ("experiments", "ground_truth"),
            "out": ("experiments", "out"),
            "min_count": ("experiments", "min_count"),
            "max_path_factors": ("experiments", "max_path_factors"),
            "alert_thresholds": ("experiments", "alert_thresholds"),
            "top_k": ("experiments", "top_k"),
            "top_k_jaccard_threshold": ("experiments", "top_k_jaccard_threshold"),
        },
    )
    validate_mode_config("experiments", args, config)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_dir = out_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    benign_profile_path = output_dir / "benign_profile.json"
    train_summary = _train_profile(args.benign_events, benign_profile_path, args.min_count)

    rules_payload = yaml.safe_load(Path(args.rules).read_text(encoding="utf-8"))
    if not isinstance(rules_payload, dict):
        raise ValueError("rules yaml root must be a mapping")

    max_path_factors = [int(item.strip()) for item in str(args.max_path_factors).split(",") if item.strip()]
    alert_thresholds = [float(item.strip()) for item in str(args.alert_thresholds).split(",") if item.strip()]
    tuning_dir = output_dir / "tuning"
    tuning_rows = _tune(
        events_path=args.attack_events,
        rules_payload=rules_payload,
        ground_truth_path=args.ground_truth,
        out_dir=tuning_dir,
        max_path_factors=max_path_factors,
        alert_thresholds=alert_thresholds,
        benign_profile_path=str(benign_profile_path),
        top_k=max(1, int(args.top_k)),
        top_k_jaccard_threshold=float(args.top_k_jaccard_threshold),
    )
    if not tuning_rows:
        raise ValueError("no tuning combinations were produced")
    best = tuning_rows[0]

    final_rules_payload = _set_max_path_factor(rules_payload, int(best["max_path_factor"]))
    final_rules_path = output_dir / "best_rules.yaml"
    final_rules_path.write_text(yaml.safe_dump(final_rules_payload, sort_keys=False), encoding="utf-8")

    final_eval_dir = output_dir / "final_evaluation"
    final_result = _evaluate_once(
        events_path=args.attack_events,
        rules_path=final_rules_path,
        ground_truth_path=args.ground_truth,
        out_dir=final_eval_dir,
        apt_alert_threshold=float(best["apt_alert_threshold"]),
        benign_profile_path=str(benign_profile_path),
        top_k=max(1, int(args.top_k)),
        top_k_jaccard_threshold=float(args.top_k_jaccard_threshold),
    )
    top_k_graph_artifact_paths = _copy_top_k_graph_artifacts(
        final_result["alerts"],
        output_dir,
        max(1, int(args.top_k)),
        float(args.top_k_jaccard_threshold),
    )

    pipeline_report = {
        "train": train_summary,
        "best_hyperparameters": best,
        "evaluation_path": final_result["evaluation_path"],
        "alerts_path": final_result["alerts_path"],
        "summary_path": final_result["summary_path"],
        "top_k_graph_artifact_paths": top_k_graph_artifact_paths,
        "output_dir": str(output_dir),
    }
    (output_dir / "pipeline_report.json").write_text(json.dumps(pipeline_report, indent=2), encoding="utf-8")
    print(json.dumps(pipeline_report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
