import gzip
import json
from pathlib import Path

from engine.cli import run_stream
from engine.cli.run_pipeline import run_pipeline
from engine.io.events import Event
from engine.rules.schema import Rule, RuleSet
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import DirectoryWatcherSource, FileJsonlSource, FileRawLineSource, RawStringPreFilter
from engine.stream.workers import iter_parsed_events_parallel


def test_streaming_engine_file_source_builds_hsg_and_matches_batch_summary(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_stream = tmp_path / "out_stream"
    out_batch = tmp_path / "out_batch"

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_weights=[1.0] * 7,
        paper_mode="strict",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    stream_result = engine.write_snapshot(out_stream)

    batch_result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_batch),
        scoring_mode="paper",
        paper_mode="strict",
    )

    hsg = json.loads((out_stream / "hsg.json").read_text(encoding="utf-8"))
    assert any(e.get("relation") == "graph_path" for e in hsg.get("edges", []))
    assert stream_result["summary"]["events"] == batch_result["summary"]["events"]
    assert stream_result["summary"]["matches"] == batch_result["summary"]["matches"]
    assert stream_result["summary"]["hsg_edges"] == batch_result["summary"]["hsg_edges"]


def test_file_jsonl_source_reads_gzip_stream_without_extracting(tmp_path):
    gz_path = tmp_path / "events.jsonl.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        fh.write('{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}\n')
        fh.write('{"event_id":"e2","event_type":"file_to_ip","subject":"file:x","object":"ip:1.2.3.4"}\n')

    events = list(FileJsonlSource(gz_path, follow=False))

    assert [event.event_id for event in events] == ["e1", "e2"]


def test_directory_watcher_source_reads_new_lines_from_watched_directory(tmp_path):
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    log_path = watch_dir / "events.jsonl"
    log_path.write_text("", encoding="utf-8")

    source = DirectoryWatcherSource(watch_dir, poll_interval_sec=0.01)
    iterator = iter(source)

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write('{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}\n')
        fh.flush()

    event = next(iterator)
    assert event.event_id == "e1"


def test_raw_string_prefilter_skips_benign_line_without_json_parse(tmp_path):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        '\n'.join(
            [
                '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:/var/log/auth.log","Image":"/usr/sbin/sshd"}',
                '{"event_id":"e2","event_type":"proc_to_file","subject":"proc:b","object":"file:/etc/shadow","Image":"/usr/bin/cat"}',
            ]
        ),
        encoding="utf-8",
    )
    prefilter = RawStringPreFilter(
        benign_markers={"/var/log/auth.log", "sshd"},
        threat_keywords={"/etc/shadow", "shadow"},
    )

    records = list(FileRawLineSource(events_path, prefilter=prefilter))

    assert len(records) == 1
    assert '"event_id":"e2"' in records[0][1]


def test_raw_string_prefilter_does_not_skip_darpa_relational_line():
    prefilter = RawStringPreFilter(
        benign_markers={"firefox", "/usr/local/firefox-54.0.1"},
        threat_keywords={"shadow"},
    )
    darpa_line = '{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"abc","cmdLine":{"string":"firefox"}}},"CDMVersion":"18"}'

    assert prefilter.should_skip(darpa_line) is False


def test_parser_workers_preserve_order_for_raw_records():
    records = [
        (1, '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}'),
        (2, '{"event_id":"e2","event_type":"file_to_ip","subject":"file:x","object":"ip:1.2.3.4"}'),
    ]
    telemetry = {}

    events = list(iter_parsed_events_parallel(records, worker_count=2, queue_size=4, max_reorder_buffer=2, telemetry=telemetry))

    assert [event.event_id for event in events] == ["e1", "e2"]
    assert telemetry["max_observed_out_of_order_distance"] >= 0
    assert telemetry["reorder_buffer_saturation_count"] >= 0
    assert telemetry["stall_duration_seconds"] >= 0.0


def test_run_stream_writes_resolved_effective_config(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_cli"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--paper-weights",
            "1.1,1.2,1.3,1.4,1.5,1.6,1.7",
            "--snapshot-every",
            "1000",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    resolved = summary["resolved_effective_config"]
    assert resolved == {
        "path_thres": 3.0,
        "path_factor_op": "le",
        "scoring": "paper",
        "paper_mode": "strict",
        "paper_weights": [1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7],
    }
    ps = summary["paper_scoring"]
    assert "threat_tuple" in ps
    assert "stage_severity" in ps
    assert "paper_weights" in ps
    assert "score_paper" in ps


def test_run_stream_loads_pipeline_config(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_cfg"
    cfg_path = tmp_path / "pipeline.yaml"
    events_text = str(events_path).replace("\\", "/")
    cfg_path.write_text(
        "\n".join(
            [
                "source:",
                f"  events: \"{events_text}\"",
                "performance:",
                "  snapshot_every: 1000",
                "  parser_workers: 0",
                "engine:",
                "  apt_alert_threshold: 12.0",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--config",
            str(cfg_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["alerts"]["threshold"] == 12.0
    assert "stall_duration_seconds" in summary["performance_metrics"]
    metrics_lines = (out_dir / "metrics.jsonl").read_text(encoding="utf-8").splitlines()
    assert metrics_lines


def test_run_experiments_pipeline_loads_shared_config(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    benign_events = repo_root / "experiments" / "sample.jsonl"
    attack_events = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    gt_path = tmp_path / "gt.json"
    gt_path.write_text('{"scenarios":[]}', encoding="utf-8")
    cfg_path = tmp_path / "pipeline.yaml"
    out_dir = tmp_path / "pipeline_out"
    benign_text = str(benign_events).replace("\\", "/")
    attack_text = str(attack_events).replace("\\", "/")
    rules_text = str(rules_path).replace("\\", "/")
    gt_text = str(gt_path).replace("\\", "/")
    out_text = str(out_dir).replace("\\", "/")
    cfg_path.write_text(
        "\n".join(
            [
                "experiments:",
                f"  benign_events: \"{benign_text}\"",
                f"  attack_events: \"{attack_text}\"",
                f"  rules: \"{rules_text}\"",
                f"  ground_truth: \"{gt_text}\"",
                f"  out: \"{out_text}\"",
                "  max_path_factors: \"2\"",
                "  alert_thresholds: \"1.0\"",
                "  top_k: 1",
            ]
        ),
        encoding="utf-8",
    )

    rc = __import__("subprocess").run(
        [
            "python",
            str(repo_root / "scripts" / "run_experiments_pipeline.py"),
            "--config",
            str(cfg_path),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(repo_root)},
        timeout=120,
    )

    assert rc.returncode == 0, rc.stderr
    assert (out_dir / "output" / "pipeline_report.json").exists()


def test_global_refine_off_default_keeps_streaming_baseline(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_refine_off"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--snapshot-every",
            "2",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    gf = summary["streaming"]["global_refine"]
    assert gf["mode"] == "off"
    assert gf["ran_at_snapshots_count"] == 0
    assert gf["ran_at_events_count"] == 0
    assert "resolved_effective_config" in summary
    assert "paper_scoring" in summary


def test_global_refine_snapshot_runs_and_preserves_pf_zero_invariant(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_refine_snapshot"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--snapshot-every",
            "2",
            "--global-refine",
            "snapshot",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    gf = summary["streaming"]["global_refine"]
    assert gf["mode"] == "snapshot"
    assert gf["ran_at_snapshots_count"] >= 1

    for name in ("result.json", "summary.json", "hsg.json", "matches.json"):
        text = (out_dir / name).read_text(encoding="utf-8")
        assert '"path_factor": 0' not in text
        assert '"path_factor": 0.0' not in text


def test_stream_summary_exposes_pending_eviction_telemetry(tmp_path):
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[], event_predicate={"event_type": "proc_to_file"}),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"], event_predicate={"event_type": "file_to_ip"}),
        ]
    )
    engine = StreamingEngine(ruleset=ruleset)
    engine.hsg_builder.pending_ttl_seconds = 24 * 60 * 60

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="file_to_ip",
            subject="file:stale",
            object="ip:1.2.3.4",
            raw={},
        )
    )
    engine.process_event(
        Event(
            event_id="e2",
            ts="2025-01-03T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:new",
            object="file:new",
            raw={},
        )
    )

    result = engine.write_snapshot(tmp_path / "out_stream_eviction")
    telemetry = result["summary"]["pending_eviction_telemetry"]

    assert telemetry["pending_evicted_count"] == 1
    assert telemetry["pending_evicted_by_rule_id"] == {"R_B": 1}
    assert telemetry["pending_ttl_seconds"] == 24 * 60 * 60


def test_stream_emits_alerts_jsonl_when_threshold_is_crossed(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_mode="strict",
        apt_alert_threshold=2.0,
        alerts_path=tmp_path / "alerts.jsonl",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    result = engine.write_snapshot(tmp_path / "out_stream_alerts")

    summary = result["summary"]["alerts"]
    alerts_path = tmp_path / "alerts.jsonl"
    lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    assert summary["count"] >= 1
    assert summary["threshold"] == 2.0
    assert summary["path"] == str(alerts_path)
    assert lines
    assert "severity_score" in lines[0]
    assert "kill_chain_stages" in lines[0]
    assert "core_entities" in lines[0]
    assert "scenario_id" in lines[0]
    assert "achieved_stages" in lines[0]
    assert "tainted_entities" in lines[0]
    assert "root_entities" in lines[0]
    assert "graph_artifact_path" in lines[0]
    assert Path(lines[0]["graph_artifact_path"]).exists()

    artifact = json.loads(Path(lines[0]["graph_artifact_path"]).read_text(encoding="utf-8"))
    assert artifact["scenario_id"] == lines[0]["scenario_id"]
    assert "hsg" in artifact
    assert "provenance" in artifact


def test_alert_suppression_emits_update_only_on_new_stage_and_not_on_repeat_snapshot(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    ruleset = load_rules_yaml(rules_path)
    alerts_path = tmp_path / "alerts_updates.jsonl"

    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_mode="strict",
        apt_alert_threshold=1.0,
        alerts_path=alerts_path,
    )
    events = list(FileJsonlSource(events_path, follow=False))

    engine.process_event(events[0])
    engine.write_snapshot(tmp_path / "out_alert_step1")
    first_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(first_lines) == 1

    engine.process_event(events[1])
    engine.write_snapshot(tmp_path / "out_alert_step2")
    second_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(second_lines) == 2
    assert second_lines[0]["scenario_id"] == second_lines[1]["scenario_id"]
    assert set(second_lines[1]["achieved_stages"]) > set(second_lines[0]["achieved_stages"])

    engine.write_snapshot(tmp_path / "out_alert_step3")
    third_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(third_lines) == 2


def test_stream_summary_exposes_performance_metrics_and_dormant_gc(tmp_path):
    ruleset = RuleSet(rules=[Rule(rule_id="R_A", name="a", prerequisites=[], event_predicate={"event_type": "proc_to_file"})])
    engine = StreamingEngine(
        ruleset=ruleset,
        scenario_dormancy_days=1,
        alerts_path=tmp_path / "alerts.jsonl",
    )

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:a",
            object="file:x",
            raw={},
        )
    )
    engine.process_event(
        Event(
            event_id="e2",
            ts="2025-01-03T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:b",
            object="file:y",
            raw={},
        )
    )

    result = engine.write_snapshot(tmp_path / "out_stream_metrics")
    perf = result["summary"]["performance_metrics"]
    gc = result["summary"]["dormant_scenario_telemetry"]
    graph_gc = result["summary"]["graph_gc_telemetry"]

    assert perf["events_per_second"] > 0.0
    assert perf["matcher_time_seconds"] >= 0.0
    assert perf["hsg_update_time_seconds"] >= 0.0
    assert perf["graph_gc_time_seconds"] >= 0.0
    assert perf["graph_entity_count"] >= 2
    assert "graph_version_node_count" in perf
    assert gc["closed_scenarios_count"] >= 1
    assert gc["closed_matches_count"] >= 1
    assert graph_gc["retention_days"] == 60
