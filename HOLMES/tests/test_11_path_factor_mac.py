import pytest

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_path_factor_mac_distinguishes_single_vs_parallel_two_hop_paths():
    # Graph 1: single 2-hop path A -> X -> B
    g_single = ProvenanceGraph()
    g_single.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
        ]
    )

    # Graph 2: parallel 2-hop paths A -> X -> B and A -> Y -> B
    g_parallel = ProvenanceGraph()
    g_parallel.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="A", object="Y", raw={}),
            Event(event_id="e4", ts=None, event_type="flow", subject="Y", object="B", raw={}),
        ]
    )

    assert g_single.shortest_path_len("A", "B") == 2
    assert g_parallel.shortest_path_len("A", "B") == 2

    assert g_single.min_vertex_cut_size("A", "B") == 1
    assert g_parallel.min_vertex_cut_size("A", "B") == 2

    pf_single = g_single.path_factor_legacy_mac("A", "B")
    pf_parallel = g_parallel.path_factor_legacy_mac("A", "B")
    assert pf_single == pytest.approx(0.5)
    assert pf_parallel == pytest.approx(1.0 / 3.0)
    assert pf_single > pf_parallel


def test_path_factor_mac_no_path_is_zero():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))
    g.add_event(Event(event_id="e2", ts=None, event_type="flow", subject="C", object="D", raw={}))

    assert g.min_vertex_cut_size("A", "D") is None
    assert g.path_factor_legacy_mac("A", "D") == 0.0
