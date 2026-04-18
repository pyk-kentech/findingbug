from __future__ import annotations

from dataclasses import dataclass
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import time
import tracemalloc
from typing import Any, Callable

import yaml

from engine.io.events import Event
from engine.rules.schema import APT_STAGES, Rule, RuleSet
from engine.stream.runner import StreamingEngine
from experiments.parameters import ResolvedPaperParameters, load_paper_parameters


@dataclass(slots=True)
class CampaignWindow:
    campaign_id: str
    label: str
    campaign_start_event: int
    campaign_end_event: int
    stage_end_event_index: list[int]


def load_experiment_config(path: str | Path) -> tuple[dict[str, Any], str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Experiment config not found: {p}")
    text = p.read_text(encoding="utf-8")
    cfg = yaml.safe_load(text) if p.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if not isinstance(cfg, dict):
        raise ValueError("Experiment config root must be an object")
    return cfg, str(p.resolve())


def config_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _paper_weights(cfg: dict[str, Any]) -> list[float]:
    scoring = cfg.get("scoring", {})
    weights = scoring.get("weights", [1.0] * len(APT_STAGES))
    if not isinstance(weights, list) or len(weights) != len(APT_STAGES):
        raise ValueError("scoring.weights must be a 7-item list")
    return [float(x) for x in weights]


def _tau(cfg: dict[str, Any]) -> float:
    scoring = cfg.get("scoring", {})
    tau = float(scoring.get("tau", 1000.0))
    if tau <= 0.0:
        raise ValueError("scoring.tau must be > 0")
    return tau


def _seed(cfg: dict[str, Any]) -> int:
    return int(cfg.get("seed", 42))


def build_synthetic_ruleset(stage_order: list[str]) -> RuleSet:
    rules: list[Rule] = []
    if len(stage_order) != len(APT_STAGES):
        raise ValueError("stage count mismatch for ruleset generation")
    for i in range(1, len(stage_order) + 1):
        rules.append(
            Rule(
                rule_id=f"R_STAGE_{i}",
                name=f"stage_{i}",
                stage=i,
                cvss=6.0,
                event_predicate={"event_type": f"stage_{i}"},
            )
        )
    return RuleSet(rules=rules)


def _mk_event(idx: int, event_type: str, rng: random.Random) -> Event:
    subj = f"proc:p{rng.randint(1, 20)}"
    obj = f"file:f{rng.randint(1, 50)}"
    ts = f"2026-01-01T00:00:{idx:06d}Z"
    return Event(
        event_id=f"evt-{idx}",
        ts=ts,
        event_type=event_type,
        subject=subj,
        object=obj,
        raw={"event_type": event_type},
    )


def generate_synthetic_stream(cfg: dict[str, Any]) -> tuple[list[Event], list[CampaignWindow]]:
    rng = random.Random(_seed(cfg))
    scenario_type = str(cfg.get("scenario_type", "mixed")).lower()
    if scenario_type not in {"attack", "benign", "mixed"}:
        raise ValueError("scenario_type must be one of: attack, benign, mixed")
    noise_rate = float(cfg.get("noise_injection_rate", 0.2))
    noise_rate = max(0.0, min(1.0, noise_rate))
    campaign_window_events = max(8, int(cfg.get("campaign_window_events", 80)))
    num_campaigns = int(cfg.get("num_campaigns", 6))
    attack_ratio = float(cfg.get("attack_ratio", 0.5))
    attack_ratio = max(0.0, min(1.0, attack_ratio))

    events: list[Event] = []
    campaigns: list[CampaignWindow] = []
    k = len(APT_STAGES)

    for cidx in range(num_campaigns):
        start = len(events)
        if scenario_type == "attack":
            label = "attack"
        elif scenario_type == "benign":
            label = "benign"
        else:
            label = "attack" if rng.random() < attack_ratio else "benign"

        stage_positions: list[int] = []
        if label == "attack":
            # Place one marker per stage in order, strictly increasing inside the window.
            for si in range(k):
                pos = int(round(((si + 1) * campaign_window_events) / (k + 1)))
                pos = max(si, min(campaign_window_events - (k - si), pos))
                stage_positions.append(pos)

        stage_end_global: list[int] = []
        stage_pos_to_idx = {p: i + 1 for i, p in enumerate(stage_positions)}
        for local_idx in range(campaign_window_events):
            if label == "attack" and local_idx in stage_pos_to_idx:
                stage_idx = stage_pos_to_idx[local_idx]
                ev_type = f"stage_{stage_idx}"
                stage_end_global.append(len(events))
            else:
                ev_type = "noise" if rng.random() < noise_rate else "benign"
            events.append(_mk_event(len(events), ev_type, rng))

        end = len(events) - 1
        campaigns.append(
            CampaignWindow(
                campaign_id=f"cmp-{cidx + 1}",
                label=label,
                campaign_start_event=start,
                campaign_end_event=end,
                stage_end_event_index=stage_end_global,
            )
        )

    return events, campaigns


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = int(math.ceil((p / 100.0) * len(vals))) - 1
    idx = max(0, min(len(vals) - 1, idx))
    return float(vals[idx])


def run_latency_throughput(
    events: list[Event],
    ruleset: RuleSet,
    cfg: dict[str, Any],
    params: ResolvedPaperParameters,
    *,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, float]:
    weights = list(params.weights)
    tau = float(params.tau)
    sample_every = max(1, int(cfg.get("latency_sample_every", 1)))

    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper_exact",
        paper_weights=weights,
        tau=tau,
        paper_mode=str(cfg.get("paper_mode", "strict")),
        global_refine_mode="off",
    )
    latency_samples: list[float] = []
    t0 = perf_counter_fn()
    for i, ev in enumerate(events, start=1):
        if i % sample_every == 0:
            s0 = perf_counter_fn()
            engine.process_event(ev)
            latency_samples.append(perf_counter_fn() - s0)
        else:
            engine.process_event(ev)
    total = perf_counter_fn() - t0
    throughput = float(len(events)) / total if total > 0.0 else 0.0
    avg = float(sum(latency_samples) / len(latency_samples)) if latency_samples else 0.0
    return {
        "latency_avg": avg,
        "latency_p50": _percentile(latency_samples, 50),
        "latency_p95": _percentile(latency_samples, 95),
        "throughput_eps": throughput,
    }


def run_memory_profile(events: list[Event], ruleset: RuleSet, cfg: dict[str, Any]) -> dict[str, Any]:
    params = _resolve_runtime_parameters(cfg)
    weights = list(params.weights)
    tau = float(params.tau)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper_exact",
        paper_weights=weights,
        tau=tau,
        paper_mode=str(cfg.get("paper_mode", "strict")),
        global_refine_mode="off",
    )
    tracemalloc.start()
    try:
        for ev in events:
            engine.process_event(ev)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {"peak_mem_bytes": int(peak), "method": "separate_runner_tracemalloc_end_of_stream"}


def _stage_to_detect(campaign: CampaignWindow, detect_event: int | None) -> int | None:
    if detect_event is None:
        return len(APT_STAGES) + 1
    if not campaign.stage_end_event_index:
        return None
    for i, stage_end in enumerate(campaign.stage_end_event_index, start=1):
        if detect_event <= stage_end:
            return i
    return len(campaign.stage_end_event_index)


def detect_campaigns(
    events: list[Event],
    campaigns: list[CampaignWindow],
    ruleset: RuleSet,
    cfg: dict[str, Any],
    params: ResolvedPaperParameters,
) -> list[dict[str, Any]]:
    weights = list(params.weights)
    tau = float(params.tau)
    rows: list[dict[str, Any]] = []
    for c in campaigns:
        engine = StreamingEngine(
            ruleset=ruleset,
            scoring_mode="paper_exact",
            paper_weights=weights,
            tau=tau,
            paper_mode=str(cfg.get("paper_mode", "strict")),
            global_refine_mode="off",
        )
        window = events[c.campaign_start_event : c.campaign_end_event + 1]
        for ev in window:
            engine.process_event(ev)
        summary = engine.build_result()["summary"]
        ps = summary.get("paper_scoring", {})
        detected = bool(ps.get("apt_detected", False))
        first_seq = ps.get("first_detection_sequence")
        detect_event = None
        if detected and isinstance(first_seq, int):
            detect_event = c.campaign_start_event + int(first_seq) - 1
        rows.append(
            {
                "campaign_id": c.campaign_id,
                "label": c.label,
                "campaign_start_event": c.campaign_start_event,
                "campaign_end_event": c.campaign_end_event,
                "detected": detected,
                "detect_event": detect_event,
                "score_at_detect": ps.get("first_detection_score"),
                "Stage-to-Detect": _stage_to_detect(c, detect_event),
                "Events-to-Detect": (detect_event - c.campaign_start_event) if detect_event is not None else None,
                "tuple_snapshot_at_detect": ps.get("first_detection_tuple_snapshot") if detected else None,
                "contributing_stages_at_detect": ps.get("first_detection_contributing_stages") if detected else None,
            }
        )
    return rows


def compute_campaign_metrics(rows: list[dict[str, Any]]) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    for r in rows:
        is_attack = str(r.get("label")) == "attack"
        detected = bool(r.get("detected"))
        if is_attack and detected:
            tp += 1
        elif is_attack and not detected:
            fn += 1
        elif (not is_attack) and detected:
            fp += 1
        else:
            tn += 1
    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    attack_n = tp + fn
    benign_n = fp + tn
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detection_rate_attack": (float(tp) / float(attack_n)) if attack_n > 0 else 0.0,
        "false_positive_rate_benign": (float(fp) / float(benign_n)) if benign_n > 0 else 0.0,
    }


def write_detections_csv(rows: list[dict[str, Any]], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    cols = [
        "campaign_id",
        "label",
        "campaign_start_event",
        "campaign_end_event",
        "detected",
        "detect_event",
        "score_at_detect",
        "Stage-to-Detect",
        "Events-to-Detect",
        "tuple_snapshot_at_detect",
        "contributing_stages_at_detect",
    ]
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            row = dict(r)
            row["tuple_snapshot_at_detect"] = (
                json.dumps(row["tuple_snapshot_at_detect"], ensure_ascii=False) if row.get("tuple_snapshot_at_detect") is not None else ""
            )
            row["contributing_stages_at_detect"] = (
                json.dumps(row["contributing_stages_at_detect"], ensure_ascii=False)
                if row.get("contributing_stages_at_detect") is not None
                else ""
            )
            row["detect_event"] = "" if row.get("detect_event") is None else row.get("detect_event")
            row["score_at_detect"] = "" if row.get("score_at_detect") is None else row.get("score_at_detect")
            row["Stage-to-Detect"] = "" if row.get("Stage-to-Detect") is None else row.get("Stage-to-Detect")
            row["Events-to-Detect"] = "" if row.get("Events-to-Detect") is None else row.get("Events-to-Detect")
            w.writerow(row)


def run_experiment(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    perf_counter_fn: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    cfg = dict(config)
    cfg.setdefault("scoring", {})
    cfg["scoring"]["mode"] = "paper_exact"

    params = _resolve_runtime_parameters(cfg)
    ruleset = build_synthetic_ruleset(params.stage_order)
    events, campaigns = generate_synthetic_stream(cfg)

    lt = run_latency_throughput(events, ruleset, cfg, params, perf_counter_fn=perf_counter_fn)
    detections = detect_campaigns(events, campaigns, ruleset, cfg, params)
    cm = compute_campaign_metrics(detections)
    mem = {"peak_mem_bytes": None, "method": "disabled"}
    if bool(cfg.get("enable_memory_profile", False)):
        mem = run_memory_profile(events, ruleset, cfg)

    cfg_hash = config_hash(cfg)
    out_dir = Path(str(cfg.get("output_dir", "results"))) / cfg_hash[:12]
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "config_used.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    campaigns_json = [
        {
            "campaign_id": c.campaign_id,
            "label": c.label,
            "campaign_start_event": c.campaign_start_event,
            "campaign_end_event": c.campaign_end_event,
            "stage_end_event_index": c.stage_end_event_index,
        }
        for c in campaigns
    ]
    (out_dir / "campaigns.json").write_text(json.dumps(campaigns_json, indent=2), encoding="utf-8")
    write_detections_csv(detections, out_dir / "detections.csv")

    metrics = {
        **cm,
        **lt,
        "peak_mem_bytes": mem.get("peak_mem_bytes"),
        "peak_mem_method": mem.get("method"),
        "config_hash": cfg_hash,
        "config_path": config_path,
        "seed": _seed(cfg),
        "tau": float(params.tau),
        "weights": list(params.weights),
        "scoring_mode": "paper_exact",
        "paper_defaults_path": params.paper_defaults_path,
        "paper_defaults_digest": params.paper_defaults_digest,
        "assumptions_path": params.assumptions_path,
        "assumptions_digest": params.assumptions_digest,
        "assumptions_hash": params.assumptions_digest,
        "stage_order_digest": params.stage_order_digest,
        "parameter_provenance": params.parameter_provenance,
        "paper_defaults_source": params.paper_defaults_source,
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return {"output_dir": str(out_dir), "metrics": metrics, "detections": detections, "campaigns": campaigns_json}


def _resolve_runtime_parameters(cfg: dict[str, Any]) -> ResolvedPaperParameters:
    paper_defaults_path = str(cfg.get("paper_defaults_path", "configs/paper_defaults.yaml"))
    assumptions_path = str(cfg.get("assumptions_path", "configs/assumptions.yaml"))
    docs_path = str(cfg.get("paper_parameters_doc_path", "docs/paper_parameters.md"))
    return load_paper_parameters(
        paper_defaults_path=paper_defaults_path,
        assumptions_path=assumptions_path,
        docs_path=docs_path,
    )
