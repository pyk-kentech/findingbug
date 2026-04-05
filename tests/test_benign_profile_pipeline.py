import importlib.util
import json
from pathlib import Path
import sys

from engine.io.events import Event
from engine.noise.profile import BenignProfile, load_benign_profile, save_benign_profile, train_benign_profile
from engine.rules.schema import Rule, RuleSet
from engine.stream.runner import StreamingEngine


def _load_script_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_train_benign_profile_roundtrip_and_event_matching(tmp_path):
    event = Event(
        event_id="e1",
        ts="2025-01-01T00:00:00Z",
        event_type="semantic",
        subject="proc_guid:1234-5678",
        object="file:/etc/nginx/nginx.conf",
        raw={
            "Image": "/usr/sbin/nginx",
            "cdr": {
                "semantic_relations": [
                    {
                        "src": "proc_guid:1234-5678",
                        "relation": "read",
                        "dst": "file:/etc/nginx/nginx.conf",
                    }
                ]
            }
        },
    )
    profile = train_benign_profile([event, event], min_count=2)
    path = tmp_path / "benign_profile.json"
    save_benign_profile(profile, path)
    loaded = load_benign_profile(path)

    assert len(loaded.patterns) == 1
    assert loaded.event_is_benign(event) is True
    only_key = next(iter(loaded.patterns.keys()))
    assert "proc_guid" not in only_key
    assert "/usr/sbin/nginx" in only_key


def test_train_benign_profile_uses_basename_fallback_when_image_path_missing(tmp_path):
    event = Event(
        event_id="e1",
        ts="2025-01-01T00:00:00Z",
        event_type="semantic",
        subject="proc_guid:pid-1",
        object="file:/etc/nginx/nginx.conf",
        raw={
            "CommandLine": "nginx -g daemon off;",
            "cdr": {
                "semantic_relations": [
                    {
                        "src": "proc_guid:pid-1",
                        "relation": "read",
                        "dst": "file:/etc/nginx/nginx.conf",
                    }
                ]
            },
        },
    )
    profile = train_benign_profile([event], min_count=1)
    only_key = next(iter(profile.patterns.keys()))
    assert "process_image:nginx" in only_key


def test_streaming_engine_drops_whitelisted_benign_events(tmp_path):
    benign_profile = BenignProfile(
        patterns={
            json.dumps(
                {
                    "subject": "process_image:/usr/sbin/nginx",
                    "relation": "read",
                    "object": "file:/etc/nginx/nginx.conf",
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ): {"count": 3}
        }
    )
    profile_path = tmp_path / "benign_profile.json"
    save_benign_profile(benign_profile, profile_path)

    ruleset = RuleSet(
        rules=[
            Rule(
                rule_id="R1",
                name="nginx read",
                prerequisites=[],
                event_predicate={"event_type": "semantic"},
            )
        ]
    )
    engine = StreamingEngine(
        ruleset=ruleset,
        benign_profile_path=profile_path,
        alerts_path=tmp_path / "alerts.jsonl",
    )
    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="semantic",
            subject="proc_guid:abcd",
            object="file:/etc/nginx/nginx.conf",
            raw={
                "Image": "/usr/sbin/nginx",
                "cdr": {
                    "semantic_relations": [
                        {
                            "src": "proc_guid:abcd",
                            "relation": "read",
                            "dst": "file:/etc/nginx/nginx.conf",
                        }
                    ]
                }
            },
        )
    )

    result = engine.write_snapshot(tmp_path / "out")
    assert result["summary"]["matches"] == 0
    assert result["summary"]["dropped_match_telemetry"]["benign_profile_drop_count"] == 1


def test_bypass_benign_filter_allows_high_risk_rule(tmp_path):
    benign_profile = BenignProfile(
        patterns={
            json.dumps(
                {
                    "subject": "process_image:/usr/sbin/nginx",
                    "relation": "connect",
                    "object": "ip:6.6.6.6",
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ): {"count": 5}
        }
    )
    profile_path = tmp_path / "benign_profile.json"
    save_benign_profile(benign_profile, profile_path)
    ruleset = RuleSet(
        rules=[
            Rule(
                rule_id="R_EXFIL",
                name="exfil",
                prerequisites=[],
                event_predicate={"event_type": "semantic"},
                bypass_benign_filter=True,
            )
        ]
    )
    engine = StreamingEngine(ruleset=ruleset, benign_profile_path=profile_path, alerts_path=tmp_path / "alerts.jsonl")
    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="semantic",
            subject="proc_guid:abcd",
            object="ip:6.6.6.6",
            raw={
                "Image": "/usr/sbin/nginx",
                "cdr": {
                    "semantic_relations": [
                        {
                            "src": "proc_guid:abcd",
                            "relation": "connect",
                            "dst": "ip:6.6.6.6",
                        }
                    ]
                },
            },
        )
    )
    result = engine.write_snapshot(tmp_path / "out_bypass")
    assert result["summary"]["matches"] == 1
    assert result["summary"]["dropped_match_telemetry"]["benign_profile_drop_count"] == 0


def test_run_experiments_pipeline_writes_final_outputs(tmp_path):
    benign_events = tmp_path / "benign.jsonl"
    attack_events = tmp_path / "attack.jsonl"
    rules_path = tmp_path / "rules.yaml"
    truth_path = tmp_path / "truth.json"
    out_dir = tmp_path / "pipeline"

    benign_events.write_text(
        '{"event_id":"b1","ts":"2025-01-01T00:00:00Z","event_type":"benign","subject":"proc:nginx","object":"file:/etc/nginx/nginx.conf","cdr":{"semantic_relations":[{"src":"proc:nginx","relation":"read","dst":"file:/etc/nginx/nginx.conf"}]}}\n'
        '{"event_id":"b2","ts":"2025-01-01T00:00:01Z","event_type":"benign","subject":"proc:nginx","object":"file:/etc/nginx/nginx.conf","cdr":{"semantic_relations":[{"src":"proc:nginx","relation":"read","dst":"file:/etc/nginx/nginx.conf"}]}}\n',
        encoding="utf-8",
    )
    attack_events.write_text(
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

    script = Path(__file__).resolve().parents[1] / "scripts" / "run_experiments_pipeline.py"
    module = _load_script_module(script, "run_experiments_pipeline_test")
    old_argv = sys.argv[:]
    sys.argv = [
        "run_experiments_pipeline.py",
        "--benign-events",
        str(benign_events),
        "--attack-events",
        str(attack_events),
        "--rules",
        str(rules_path),
        "--ground-truth",
        str(truth_path),
        "--out",
        str(out_dir),
        "--min-count",
        "2",
        "--max-path-factors",
        "2,3",
        "--alert-thresholds",
        "1.0,2.0",
        "--top-k",
        "2",
    ]
    try:
        rc = module.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    output_dir = out_dir / "output"
    assert (output_dir / "benign_profile.json").exists()
    assert (output_dir / "tuning" / "tuning_results.csv").exists()
    assert (output_dir / "final_evaluation" / "evaluation.json").exists()
    assert (output_dir / "pipeline_report.json").exists()
    assert (output_dir / "top_scenarios").exists()

    report = json.loads((output_dir / "pipeline_report.json").read_text(encoding="utf-8"))
    assert report["best_hyperparameters"]["f1"] >= 0.0
    assert Path(report["evaluation_path"]).exists()
    assert "top_k_graph_artifact_paths" in report
    for path in report["top_k_graph_artifact_paths"]:
        assert Path(path).exists()
