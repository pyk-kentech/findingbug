from __future__ import annotations

import tracemalloc

from experiments.pipeline import (
    _stage_to_detect,
    _resolve_runtime_parameters,
    build_synthetic_ruleset,
    compute_campaign_metrics,
    generate_synthetic_stream,
    run_experiment,
    run_latency_throughput,
)
from experiments.pipeline import CampaignWindow


def test_experiment_reproducibility_same_seed_same_metrics():
    cfg = {
        "seed": 777,
        "scenario_type": "mixed",
        "num_campaigns": 4,
        "campaign_window_events": 40,
        "noise_injection_rate": 0.3,
        "enable_memory_profile": False,
        "latency_sample_every": 2,
        "output_dir": "results",
        "scoring": {"mode": "paper_exact", "tau": 200.0, "weights": [1, 1, 1, 1, 1, 1, 1]},
    }

    ticks = [float(i) / 1000.0 for i in range(100000)]
    idx = {"i": 0}

    def fake_perf_counter() -> float:
        val = ticks[idx["i"]]
        idx["i"] += 1
        return val

    r1 = run_experiment(cfg, perf_counter_fn=fake_perf_counter)
    idx["i"] = 0
    r2 = run_experiment(cfg, perf_counter_fn=fake_perf_counter)
    assert r1["metrics"] == r2["metrics"]


def test_campaign_level_metrics_not_event_level_trap():
    # 4 campaigns only (2 attack, 2 benign). Event counts inside windows must not affect TP/FP/TN/FN.
    rows = [
        {"campaign_id": "a1", "label": "attack", "detected": True, "campaign_start_event": 0, "campaign_end_event": 999},
        {"campaign_id": "a2", "label": "attack", "detected": False, "campaign_start_event": 1000, "campaign_end_event": 1999},
        {"campaign_id": "b1", "label": "benign", "detected": True, "campaign_start_event": 2000, "campaign_end_event": 2999},
        {"campaign_id": "b2", "label": "benign", "detected": False, "campaign_start_event": 3000, "campaign_end_event": 10000},
    ]
    m = compute_campaign_metrics(rows)
    assert m["tp"] == 1
    assert m["fn"] == 1
    assert m["fp"] == 1
    assert m["tn"] == 1
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5


def test_latency_runner_has_no_memory_probe_calls(monkeypatch):
    params = _resolve_runtime_parameters({})
    ruleset = build_synthetic_ruleset(params.stage_order)
    events, _ = generate_synthetic_stream(
        {
            "seed": 3,
            "scenario_type": "attack",
            "num_campaigns": 1,
            "campaign_window_events": 40,
            "noise_injection_rate": 0.1,
        }
    )

    called = {"n": 0}
    orig = tracemalloc.get_traced_memory

    def spy() -> tuple[int, int]:
        called["n"] += 1
        return orig()

    monkeypatch.setattr("tracemalloc.get_traced_memory", spy)
    run_latency_throughput(events, ruleset, {}, params)
    assert called["n"] == 0


def test_stage_to_detect_from_stage_boundaries():
    c = CampaignWindow(
        campaign_id="cmp-1",
        label="attack",
        campaign_start_event=100,
        campaign_end_event=180,
        stage_end_event_index=[110, 120, 130, 140, 150, 160, 170],
    )
    assert _stage_to_detect(c, 135) == 4
    assert _stage_to_detect(c, None) == 8
