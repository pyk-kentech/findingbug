from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_min_vertex_cut_ignores_unrelated_noise_path():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="C", object="Y", raw={}),
            Event(event_id="e4", ts=None, event_type="flow", subject="Y", object="D", raw={}),
        ]
    )

    # Unrelated branch C->Y->D must not affect A->B cut in ancestral subgraph.
    assert g.min_vertex_cut_size("A", "B") == 1


def test_min_vertex_cut_parallel_paths_stays_two_with_unrelated_branch():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="A", object="Y", raw={}),
            Event(event_id="e4", ts=None, event_type="flow", subject="Y", object="B", raw={}),
            Event(event_id="e5", ts=None, event_type="flow", subject="U", object="V", raw={}),
            Event(event_id="e6", ts=None, event_type="flow", subject="V", object="W", raw={}),
        ]
    )

    assert g.min_vertex_cut_size("A", "B") == 2
