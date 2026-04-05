from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_dependency_strength_one_hop_is_inverse_mac_size():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))

    assert g.shortest_path_len("A", "B") == 1
    assert g.exact_mac_size("A", "B") == 1
    assert g.dependency_strength("A", "B") == 1.0


def test_dependency_strength_unique_two_hop_path_still_has_mac_size_one():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="X", object="B", raw={}),
        ]
    )

    assert g.shortest_path_len("A", "B") == 2
    assert g.exact_mac_size("A", "B") == 1
    assert g.dependency_strength("A", "B") == 1.0


def test_dependency_strength_no_path_is_zero():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))
    g.add_event(Event(event_id="e2", ts=None, event_type="flow", subject="C", object="D", raw={}))

    assert g.shortest_path_len("C", "B") is None
    assert g.dependency_strength("C", "B") == 0.0


def test_path_factor_equals_exact_mac_size():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="A", object="X", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="X", object="C", raw={}),
        ]
    )

    assert g.path_factor("A", "B") == 1.0
    assert g.path_factor("A", "C") == 1.0


def test_path_factor_no_path_is_none():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="A", object="B", raw={}))

    assert g.path_factor("C", "B") is None
    assert g.path_factor_for_edge("C", "B") is None
