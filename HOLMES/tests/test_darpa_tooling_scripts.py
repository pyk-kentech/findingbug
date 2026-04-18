import importlib.util
import json
from pathlib import Path
import sys
import types
import yaml


def _load_script_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_download_single_gdrive_file_uses_explicit_file_id(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "download_and_sample_darpa.py"
    module = _load_script_module(script, "download_and_sample_darpa_test")

    calls = {}

    fake_gdown = types.SimpleNamespace()

    def fake_download(*, id, output, quiet, fuzzy):
        calls["id"] = id
        calls["output"] = output
        Path(output).write_text("stub", encoding="utf-8")
        return output

    fake_gdown.download = fake_download
    monkeypatch.setitem(sys.modules, "gdown", fake_gdown)

    output = module.download_single_gdrive_file(file_id="abc123", output_dir=tmp_path, output_name="trace.json.gz")

    assert calls["id"] == "abc123"
    assert output == tmp_path / "trace.json.gz"
    assert output.exists()


def test_download_manifest_alias_and_retry_backoff(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "download_and_sample_darpa.py"
    module = _load_script_module(script, "download_and_sample_darpa_manifest_test")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        yaml.safe_dump({"datasets": {"trace_e3_day1": {"file_id": "abc123", "filename": "trace.json.gz"}}}),
        encoding="utf-8",
    )

    entry = module.resolve_dataset_entry(manifest, "trace_e3_day1")
    assert entry["file_id"] == "abc123"

    attempts = {"count": 0}
    sleeps: list[float] = []
    fake_gdown = types.SimpleNamespace()

    def fake_download(*, id, output, quiet, fuzzy):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("transient")
        Path(output).write_text("ok", encoding="utf-8")
        return output

    fake_gdown.download = fake_download
    monkeypatch.setitem(sys.modules, "gdown", fake_gdown)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(seconds))

    output = module.download_single_gdrive_file(file_id="abc123", output_dir=tmp_path, output_name="trace.json.gz", max_retries=3)

    assert output.exists()
    assert attempts["count"] == 3
    assert sleeps == [1.0, 2.0]


def test_evaluate_darpa_tc_script_reports_scenario_coverage(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    truth_path = tmp_path / "truth.json"
    out_dir = tmp_path / "eval_out"

    events_path.write_text(
        "\n".join(
            [
                '{"event_id":"e1","ts":"2025-01-01T00:00:00Z","event_type":"proc_to_file","subject":"proc:nginx","object":"file:/tmp/a"}',
                '{"event_id":"e2","ts":"2025-01-01T00:00:01Z","event_type":"file_to_ip","subject":"file:/tmp/a","object":"ip:6.6.6.6"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R1",
                "    name: Initial",
                "    apt_stage: Initial Compromise",
                "    stage: 1",
                "    prerequisites: []",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "  - rule_id: R2",
                "    name: Exfil",
                "    apt_stage: Exfiltration",
                "    stage: 7",
                "    prerequisites: [graph_path]",
                "    event_predicate:",
                "      event_type: file_to_ip",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    truth_path.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "gt-nginx-exfil",
                        "stages": ["Initial Compromise", "Exfiltration"],
                        "exact_entities": ["proc:nginx", "ip:6.6.6.6"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_darpa_tc.py"
    module = _load_script_module(script, "evaluate_darpa_tc_test")
    monkeypatch_argv = [
        "evaluate_darpa_tc.py",
        "--events",
        str(events_path),
        "--rules",
        str(rules_path),
        "--ground-truth",
        str(truth_path),
        "--out",
        str(out_dir),
        "--apt-alert-threshold",
        "1.0",
    ]
    old_argv = sys.argv[:]
    sys.argv = monkeypatch_argv
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    report = json.loads((out_dir / "evaluation.json").read_text(encoding="utf-8"))
    assert report["metrics"]["mode"] == "scenario_coverage"
    assert "tp_scenarios" in report["metrics"]
    assert report["metrics"]["precision"] >= 0.0
    assert report["metrics"]["recall"] >= 0.0
    assert "fragmentation_ratio" in report["metrics"]
    assert "top_k_alerts" in report
    assert (out_dir / "alerts.jsonl").exists()


def test_evaluate_scenario_coverage_reports_fragmentation(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_darpa_tc.py"
    module = _load_script_module(script, "evaluate_darpa_tc_fragmentation_test")

    alerts = [
        {
            "alert_id": "a1",
            "scenario_id": "scenario-1",
            "achieved_stages": ["Initial Compromise"],
            "tainted_entities": ["proc:nginx"],
            "root_entities": ["proc:nginx"],
            "core_entities": ["proc:nginx"],
        },
        {
            "alert_id": "a2",
            "scenario_id": "scenario-2",
            "achieved_stages": ["Exfiltration"],
            "tainted_entities": ["ip:6.6.6.6"],
            "root_entities": [],
            "core_entities": ["ip:6.6.6.6"],
        },
    ]
    ground_truth = {
        "scenarios": [
            {
                "scenario_id": "gt-1",
                "stages": ["Initial Compromise", "Exfiltration"],
                "exact_entities": ["proc:nginx", "ip:6.6.6.6"],
            }
        ]
    }

    metrics = module.evaluate_scenario_coverage(alerts, ground_truth)

    assert metrics["fragmentation_ratio"] == 1.0
    assert metrics["fragmented_scenarios"] == ["gt-1"]


def test_evaluate_scenario_coverage_uses_scenario_tp_not_alert_tp(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_darpa_tc.py"
    module = _load_script_module(script, "evaluate_darpa_tc_scenario_metrics_test")

    alerts = [
        {
            "alert_id": "a1",
            "scenario_id": "scenario-1",
            "achieved_stages": ["Initial Compromise", "Exfiltration"],
            "tainted_entities": ["proc:nginx", "ip:6.6.6.6"],
            "root_entities": ["proc:nginx"],
            "core_entities": ["ip:6.6.6.6"],
        },
        {
            "alert_id": "a2",
            "scenario_id": "scenario-1",
            "achieved_stages": ["Initial Compromise", "Exfiltration", "Move Laterally"],
            "tainted_entities": ["proc:nginx", "ip:6.6.6.6", "proc:beta"],
            "root_entities": ["proc:nginx"],
            "core_entities": ["ip:6.6.6.6"],
        },
        {
            "alert_id": "a3",
            "scenario_id": "scenario-noise",
            "achieved_stages": ["Initial Compromise"],
            "tainted_entities": ["proc:noise"],
            "root_entities": ["proc:noise"],
            "core_entities": ["proc:noise"],
        },
    ]
    ground_truth = {
        "scenarios": [
            {
                "scenario_id": "gt-1",
                "stages": ["Initial Compromise", "Exfiltration"],
                "exact_entities": ["proc:nginx", "ip:6.6.6.6"],
            }
        ]
    }

    metrics = module.evaluate_scenario_coverage(alerts, ground_truth)

    assert metrics["tp_scenarios"] == 1
    assert metrics["fp_alerts"] == 1
    assert metrics["fn_scenarios"] == 0
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0


def test_select_diverse_top_k_alerts_suppresses_high_jaccard_variants(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_darpa_tc.py"
    module = _load_script_module(script, "evaluate_darpa_tc_diversity_test")

    alerts = [
        {
            "alert_id": "a1",
            "severity_score": 100.0,
            "tainted_entities": ["proc:a", "ip:1.1.1.1"],
            "root_entities": [],
            "core_entities": [],
        },
        {
            "alert_id": "a2",
            "severity_score": 99.0,
            "tainted_entities": ["proc:a", "ip:1.1.1.1", "file:/tmp/x"],
            "root_entities": [],
            "core_entities": [],
        },
        {
            "alert_id": "a3",
            "severity_score": 80.0,
            "tainted_entities": ["proc:b", "ip:2.2.2.2"],
            "root_entities": [],
            "core_entities": [],
        },
    ]

    selected = module.select_diverse_top_k_alerts(alerts, top_k=2, jaccard_threshold=0.5)

    assert [alert["alert_id"] for alert in selected] == ["a1", "a3"]


def test_select_diverse_top_k_alerts_hard_dedups_same_scenario_id_first(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_darpa_tc.py"
    module = _load_script_module(script, "evaluate_darpa_tc_scenario_dedup_test")

    alerts = [
        {
            "alert_id": "a1",
            "scenario_id": "scenario-1",
            "severity_score": 90.0,
            "achieved_stages": ["Initial Compromise"],
            "tainted_entities": ["proc:a"],
            "root_entities": [],
            "core_entities": [],
        },
        {
            "alert_id": "a2",
            "scenario_id": "scenario-1",
            "severity_score": 95.0,
            "achieved_stages": ["Initial Compromise", "Exfiltration"],
            "tainted_entities": ["proc:a", "ip:1.1.1.1"],
            "root_entities": [],
            "core_entities": [],
        },
        {
            "alert_id": "a3",
            "scenario_id": "scenario-2",
            "severity_score": 80.0,
            "achieved_stages": ["Initial Compromise"],
            "tainted_entities": ["proc:b"],
            "root_entities": [],
            "core_entities": [],
        },
    ]

    selected = module.select_diverse_top_k_alerts(alerts, top_k=3, jaccard_threshold=0.9)

    assert [alert["alert_id"] for alert in selected] == ["a2", "a3"]


def test_tune_hyperparameters_script_writes_csv(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    truth_path = tmp_path / "truth.json"
    out_dir = tmp_path / "tune_out"

    events_path.write_text(
        "\n".join(
            [
                '{"event_id":"e1","ts":"2025-01-01T00:00:00Z","event_type":"proc_to_file","subject":"proc:nginx","object":"file:/tmp/a"}',
                '{"event_id":"e2","ts":"2025-01-01T00:00:01Z","event_type":"file_to_ip","subject":"file:/tmp/a","object":"ip:6.6.6.6"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R1",
                "    name: Initial",
                "    apt_stage: Initial Compromise",
                "    stage: 1",
                "    prerequisites: []",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "  - rule_id: R2",
                "    name: Exfil",
                "    apt_stage: Exfiltration",
                "    stage: 6",
                "    prerequisites:",
                "      - graph_path",
                "      - type: path_factor",
                "        max_path_factor: 3",
                "    event_predicate:",
                "      event_type: file_to_ip",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    truth_path.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "scenario_id": "gt-nginx-exfil",
                        "stages": ["Initial Compromise", "Exfiltration"],
                        "exact_entities": ["proc:nginx", "ip:6.6.6.6"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    script = Path(__file__).resolve().parents[1] / "scripts" / "tune_hyperparameters.py"
    module = _load_script_module(script, "tune_hyperparameters_test")
    old_argv = sys.argv[:]
    sys.argv = [
        "tune_hyperparameters.py",
        "--events",
        str(events_path),
        "--rules",
        str(rules_path),
        "--ground-truth",
        str(truth_path),
        "--out",
        str(out_dir),
        "--max-path-factors",
        "2,3",
        "--alert-thresholds",
        "1.0,2.0",
    ]
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert (out_dir / "tuning_results.csv").exists()
    csv_lines = (out_dir / "tuning_results.csv").read_text(encoding="utf-8").splitlines()
    assert len(csv_lines) == 5
