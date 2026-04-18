from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.core.graph import ProvenanceGraph
from engine.io.events import Event
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import FileJsonlSource


def test_repeated_read_write_pattern_remains_dag():
    g = ProvenanceGraph()
    events = [
        Event(event_id="e1", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}),
        Event(event_id="e2", ts=None, event_type="read", subject="proc:P", object="file:F", raw={}),
        Event(event_id="e3", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}),
        Event(event_id="e4", ts=None, event_type="read", subject="proc:P", object="file:F", raw={}),
        Event(event_id="e5", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}),
    ]
    g.add_events(events)

    assert g.is_dag() is True
    topo = g.topological_sort_version_nodes()
    assert len(topo) == len(g.version_nodes)

    # Entity-level view can be mutually reachable while internal version graph remains acyclic.
    assert g.has_path("proc:P", "file:F") is True
    assert g.has_path("file:F", "proc:P") is True


def test_version_links_are_forward_only():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="send", subject="proc:P", object="sock:S", raw={}),
            Event(event_id="e2", ts=None, event_type="recv", subject="proc:P", object="sock:S", raw={}),
            Event(event_id="e3", ts=None, event_type="send", subject="proc:P", object="sock:S", raw={}),
        ]
    )

    for edge in g.edges:
        src_meta = g.version_nodes[edge.src]
        dst_meta = g.version_nodes[edge.dst]
        assert src_meta.created_at < dst_meta.created_at
    assert g.is_dag() is True


def test_batch_and_stream_smoke_with_versioned_graph(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    batch = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_batch_versioned"),
        scoring_mode="paper",
        paper_mode="strict",
    )
    assert batch["summary"]["events"] > 0

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_weights=[1.0] * 7,
        paper_mode="strict",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    stream = engine.write_snapshot(tmp_path / "out_stream_versioned")
    assert stream["summary"]["events"] == batch["summary"]["events"]
