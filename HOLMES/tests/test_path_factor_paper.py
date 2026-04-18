import pytest

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_path_factor_paper_self_is_one():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="file:X", raw={}))

    assert g.path_factor("proc:A", "proc:A") == 1.0


def test_path_factor_paper_non_process_propagates_one():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="file:X", raw={}))

    assert g.path_factor("proc:A", "file:X") == 1.0


def test_path_factor_unique_process_path_still_has_mac_size_one():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="proc:C", raw={}))

    assert g.path_factor("proc:A", "proc:C") == 1.0


def test_path_factor_parallel_version_queries_reflect_larger_mac():
    g = ProvenanceGraph()
    e1 = g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:R", object="file:X", raw={}))
    e2 = g.add_event(Event(event_id="e2", ts=None, event_type="write", subject="proc:R", object="file:Y", raw={}))
    assert e1 is not None and e2 is not None

    assert g.path_factor(e1["object_node_id"], e2["object_node_id"]) == pytest.approx(1.0)
