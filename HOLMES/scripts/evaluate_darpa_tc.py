from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from engine.rules.schema import load_rules
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def _load_ground_truth(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("ground truth file must be a JSON object")
    return payload


def _normalize_scenarios(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = payload.get("scenarios", [])
    if not isinstance(scenarios, list):
        raise ValueError("ground truth scenarios must be a list")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(scenarios, start=1):
        if not isinstance(item, dict):
            continue
        stages = [str(stage) for stage in item.get("stages", []) if isinstance(stage, str) and stage.strip()]
        exact_entities = [str(entity) for entity in item.get("exact_entities", []) if isinstance(entity, str) and entity.strip()]
        contains_entities = [str(entity) for entity in item.get("contains_entities", item.get("contains", [])) if isinstance(entity, str) and entity.strip()]
        normalized.append(
            {
                "scenario_id": str(item.get("scenario_id") or f"gt-scenario-{index}"),
                "stages": stages,
                "exact_entities": exact_entities,
                "contains_entities": contains_entities,
            }
        )
    return normalized


def _alert_entities(alert: dict[str, Any]) -> set[str]:
    entities: set[str] = set()
    for key in ("tainted_entities", "root_entities", "core_entities"):
        values = alert.get(key, [])
        if not isinstance(values, list):
            continue
        entities.update(value for value in values if isinstance(value, str))
    return entities


def _alert_matches_ground_truth(alert: dict[str, Any], scenario: dict[str, Any]) -> bool:
    achieved_stages = set(
        stage for stage in alert.get("achieved_stages", []) if isinstance(stage, str)
    )
    required_stages = set(scenario.get("stages", []))
    if required_stages and not required_stages.issubset(achieved_stages):
        return False

    entities = _alert_entities(alert)
    exact_entities = set(scenario.get("exact_entities", []))
    if exact_entities and not exact_entities.issubset(entities):
        return False

    contains_entities = set(scenario.get("contains_entities", []))
    for token in contains_entities:
        if not any(token in entity for entity in entities):
            return False
    return True


def _alert_overlaps_ground_truth(alert: dict[str, Any], scenario: dict[str, Any]) -> bool:
    achieved_stages = set(stage for stage in alert.get("achieved_stages", []) if isinstance(stage, str))
    scenario_stages = set(scenario.get("stages", []))
    entities = _alert_entities(alert)
    exact_entities = set(scenario.get("exact_entities", []))
    contains_entities = set(scenario.get("contains_entities", []))
    has_stage_overlap = bool(achieved_stages & scenario_stages) if scenario_stages else False
    has_exact_overlap = bool(entities & exact_entities) if exact_entities else False
    has_contains_overlap = any(any(token in entity for entity in entities) for token in contains_entities)
    return has_stage_overlap or has_exact_overlap or has_contains_overlap


def evaluate_scenario_coverage(alerts: list[dict[str, Any]], ground_truth: dict[str, Any]) -> dict[str, Any]:
    gt_scenarios = _normalize_scenarios(ground_truth)
    matched_gt_ids: set[str] = set()
    matched_alert_ids: set[str] = set()
    per_alert_matches: list[dict[str, Any]] = []
    scenario_to_alert_ids: dict[str, set[str]] = {}
    scenario_to_overlap_alert_ids: dict[str, set[str]] = {}

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        alert_id = str(alert.get("alert_id") or alert.get("scenario_id") or f"alert-{len(per_alert_matches) + 1}")
        matched_scenarios = [
            scenario["scenario_id"]
            for scenario in gt_scenarios
            if _alert_matches_ground_truth(alert, scenario)
        ]
        overlapping_scenarios = [
            scenario["scenario_id"]
            for scenario in gt_scenarios
            if _alert_overlaps_ground_truth(alert, scenario)
        ]
        if matched_scenarios:
            matched_alert_ids.add(alert_id)
            matched_gt_ids.update(matched_scenarios)
            for scenario_id in matched_scenarios:
                scenario_to_alert_ids.setdefault(scenario_id, set()).add(alert_id)
        for scenario_id in overlapping_scenarios:
            scenario_to_overlap_alert_ids.setdefault(scenario_id, set()).add(alert_id)
        per_alert_matches.append(
            {
                "alert_id": alert_id,
                "scenario_id": alert.get("scenario_id"),
                "matched_ground_truth_scenarios": matched_scenarios,
                "achieved_stages": alert.get("achieved_stages", []),
                "entities": sorted(_alert_entities(alert)),
            }
        )

    tp = len(matched_gt_ids)
    fp = len(
        [
            item
            for item in per_alert_matches
            if not item["matched_ground_truth_scenarios"]
        ]
    )
    fn = max(0, len(gt_scenarios) - tp)
    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(len(matched_gt_ids)) / float(len(gt_scenarios)) if gt_scenarios else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fragmented_scenarios = sorted(
        scenario["scenario_id"]
        for scenario in gt_scenarios
        if len(scenario_to_overlap_alert_ids.get(scenario["scenario_id"], set())) > 1
        and len(scenario_to_alert_ids.get(scenario["scenario_id"], set())) == 0
    )
    fragmentation_ratio = (
        float(len(fragmented_scenarios)) / float(len(gt_scenarios))
        if gt_scenarios
        else 0.0
    )
    return {
        "mode": "scenario_coverage",
        "tp_scenarios": tp,
        "fp_alerts": fp,
        "fn_scenarios": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fragmented_scenarios": fragmented_scenarios,
        "fragmentation_ratio": fragmentation_ratio,
        "matched_ground_truth_scenarios": sorted(matched_gt_ids),
        "ground_truth_scenarios": [scenario["scenario_id"] for scenario in gt_scenarios],
        "per_alert_matches": per_alert_matches,
    }


def rank_alerts_by_severity(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        [alert for alert in alerts if isinstance(alert, dict)],
        key=lambda alert: float(alert.get("severity_score", 0.0)),
        reverse=True,
    )


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 0.0
    return float(len(left & right)) / float(len(union))


def _alert_rank_key(alert: dict[str, Any]) -> tuple[float, int, str]:
    scenario_id = str(alert.get("scenario_id") or "")
    achieved_stages = alert.get("achieved_stages", [])
    stage_count = len([stage for stage in achieved_stages if isinstance(stage, str)])
    return (
        float(alert.get("severity_score", 0.0)),
        int(stage_count),
        scenario_id,
    )


def dedupe_alerts_by_scenario_id(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    ungrouped: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        scenario_id = str(alert.get("scenario_id") or "").strip()
        if not scenario_id:
            ungrouped.append(alert)
            continue
        current = grouped.get(scenario_id)
        if current is None or _alert_rank_key(alert) > _alert_rank_key(current):
            grouped[scenario_id] = alert
    ranked = sorted(grouped.values(), key=_alert_rank_key, reverse=True)
    ranked.extend(sorted(ungrouped, key=_alert_rank_key, reverse=True))
    return ranked


def select_diverse_top_k_alerts(
    alerts: list[dict[str, Any]],
    *,
    top_k: int,
    jaccard_threshold: float = 0.8,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for candidate in dedupe_alerts_by_scenario_id([alert for alert in alerts if isinstance(alert, dict)]):
        candidate_entities = _alert_entities(candidate)
        if any(_jaccard_similarity(candidate_entities, _alert_entities(existing)) >= float(jaccard_threshold) for existing in selected):
            continue
        selected.append(candidate)
        if len(selected) >= max(0, int(top_k)):
            break
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate HOLMES DARPA TC alerts against scenario-level ground truth.")
    parser.add_argument("--events", required=True, help="Path to sample.jsonl or original .json.gz input.")
    parser.add_argument("--rules", required=True, help="Path to HOLMES rules file.")
    parser.add_argument("--ground-truth", required=True, help="Path to ground truth JSON.")
    parser.add_argument("--out", required=True, help="Output directory for snapshot and evaluation report.")
    parser.add_argument("--scoring", default="paper", choices=["legacy", "paper", "paper_exact"])
    parser.add_argument("--paper-mode", default="strict", choices=["hybrid", "strict"])
    parser.add_argument("--apt-alert-threshold", type=float, default=1.0)
    parser.add_argument("--benign-profile", help="Optional benign_profile.json to strict-drop whitelisted benign events.")
    parser.add_argument("--top-k", type=int, default=3, help="Number of top-severity scenario alerts to include in the evaluation report.")
    parser.add_argument("--top-k-jaccard-threshold", type=float, default=0.8, help="Suppress near-duplicate scenario alerts whose entity Jaccard similarity exceeds this threshold.")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ruleset = load_rules(args.rules)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode=args.scoring,
        paper_mode=args.paper_mode,
        apt_alert_threshold=float(args.apt_alert_threshold),
        alerts_path=out_dir / "alerts.jsonl",
        dropped_match_telemetry_path=out_dir / "debug" / "dropped_matches.jsonl",
        benign_profile_path=args.benign_profile,
    )
    for event in FileJsonlSource(args.events, follow=False):
        engine.process_event(event)
    engine.write_snapshot(out_dir)

    alerts = [
        json.loads(line)
        for line in (out_dir / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ground_truth = _load_ground_truth(args.ground_truth)
    evaluation = evaluate_scenario_coverage(alerts, ground_truth)
    ranked_alerts = select_diverse_top_k_alerts(
        alerts,
        top_k=max(0, int(args.top_k)),
        jaccard_threshold=float(args.top_k_jaccard_threshold),
    )
    report = {
        "events_path": str(Path(args.events)),
        "rules_path": str(Path(args.rules)),
        "ground_truth_path": str(Path(args.ground_truth)),
        "alerts_path": str(out_dir / "alerts.jsonl"),
        "metrics": evaluation,
        "top_k_alerts": [
            {
                "alert_id": alert.get("alert_id"),
                "scenario_id": alert.get("scenario_id"),
                "severity_score": alert.get("severity_score"),
                "graph_artifact_path": alert.get("graph_artifact_path"),
                "achieved_stages": alert.get("achieved_stages", []),
                "entities": sorted(_alert_entities(alert)),
            }
            for alert in ranked_alerts
        ],
    }
    report_path = out_dir / "evaluation.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
