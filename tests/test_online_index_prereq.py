from pathlib import Path

from engine.rules.schema import Rule, RuleSet
from engine.stream.runner import StreamingEngine
from engine.io.events import Event
from engine.core.graph import ProvenanceGraph
from engine.cli.run_stream import main as run_stream_main


def _ruleset_for_online_graph_path() -> RuleSet:
    return RuleSet(
        rules=[
            Rule(
                rule_id="R_BASE",
                name="base",
                source_types=["process"],
                target_types=["file"],
                event_predicate={"event_type": "proc_to_file"},
                prerequisites=[],
            ),
            Rule(
                rule_id="R_NEEDS_PATH",
                name="needs path",
                source_types=["file"],
                target_types=["ip"],
                event_predicate={"event_type": "file_to_ip"},
                prerequisites=["graph_path"],
            ),
        ]
    )


def test_online_index_avoids_pair_explosion_with_1000_garbage_events():
    engine = StreamingEngine(ruleset=_ruleset_for_online_graph_path())

    # Garbage: prerequisite rule matches, but mapper antecedent is empty.
    for i in range(1000):
        engine.process_event(
            Event(
                event_id=f"g{i}",
                ts=None,
                event_type="file_to_ip",
                subject=f"file:/tmp/noise{i}.tmp",
                object=f"ip:10.0.0.{i % 255}",
                raw={},
            )
        )

    # Valid chain: base match then graph_path match.
    engine.process_event(
        Event(
            event_id="v1",
            ts=None,
            event_type="proc_to_file",
            subject="proc:a",
            object="file:/tmp/seed.txt",
            raw={},
        )
    )
    engine.process_event(
        Event(
            event_id="v2",
            ts=None,
            event_type="file_to_ip",
            subject="file:/tmp/seed.txt",
            object="ip:203.0.113.10",
            raw={},
        )
    )

    assert engine.stats.candidate_pairs_considered < 20
    assert any(m.rule_id == "R_NEEDS_PATH" for m in engine.matches)


def test_matching_stage_does_not_call_graph_traversal_methods(monkeypatch):
    calls = {"has_path": 0, "ancestors": 0, "descendants": 0}

    def _spy(name):
        fn = getattr(ProvenanceGraph, name)

        def wrapped(self, *args, **kwargs):
            calls[name] += 1
            return fn(self, *args, **kwargs)

        return wrapped

    monkeypatch.setattr(ProvenanceGraph, "has_path", _spy("has_path"))
    monkeypatch.setattr(ProvenanceGraph, "ancestors", _spy("ancestors"))
    monkeypatch.setattr(ProvenanceGraph, "descendants", _spy("descendants"))

    engine = StreamingEngine(ruleset=_ruleset_for_online_graph_path())
    engine.process_event(Event(event_id="e1", ts=None, event_type="file_to_ip", subject="file:x", object="ip:y", raw={}))
    engine.process_event(Event(event_id="e2", ts=None, event_type="proc_to_file", subject="proc:p", object="file:x", raw={}))
    engine.process_event(Event(event_id="e3", ts=None, event_type="file_to_ip", subject="file:x", object="ip:y", raw={}))

    assert calls == {"has_path": 0, "ancestors": 0, "descendants": 0}


def test_run_stream_smoke_with_online_index(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_online"

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
            "--snapshot-every",
            "1000",
        ],
    )
    assert run_stream_main() == 0
