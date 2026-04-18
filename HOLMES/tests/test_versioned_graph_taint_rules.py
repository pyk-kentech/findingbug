from engine.core.graph import EdgeType, ProvenanceGraph
from engine.io.events import Event


def _current_version_index(graph: ProvenanceGraph, entity_id: str) -> int:
    node_id = graph.current_version[entity_id]
    return graph.version_nodes[node_id].version


def test_taint_rule_write_bumps_object_only():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}))
    assert _current_version_index(g, "proc:P") == 1
    assert _current_version_index(g, "file:F") == 2


def test_taint_rule_read_bumps_subject():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="read", subject="proc:P", object="file:F", raw={}))
    assert _current_version_index(g, "file:F") == 1
    assert _current_version_index(g, "proc:P") == 2


def test_taint_rule_exec_bumps_process_subject():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="exec", subject="proc:P", object="file:BIN", raw={}))
    assert _current_version_index(g, "file:BIN") == 1
    assert _current_version_index(g, "proc:P") == 2


def test_taint_rule_both_endpoints_can_bump_independently():
    g = ProvenanceGraph()
    g.add_event(
        Event(
            event_id="e1",
            ts=None,
            event_type="write",
            subject="proc:P",
            object="file:F",
            raw={"subject_state_change": True, "object_state_change": True},
        )
    )
    assert _current_version_index(g, "proc:P") == 2
    assert _current_version_index(g, "file:F") == 2


def test_edge_types_and_transition_cost_zero_in_shortest_path():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}))
    assert any(e.edge_type == EdgeType.DATA_FLOW for e in g.edges)
    assert any(e.edge_type == EdgeType.VERSION_TRANSITION for e in g.edges)

    # path P->F should count only DATA_FLOW edge cost (transition is zero-cost).
    assert g.shortest_path_len("proc:P", "file:F") == 1
