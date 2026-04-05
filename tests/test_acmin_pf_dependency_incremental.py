from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_acmin_case_a_single_common_ancestor_pf_one():
    g = ProvenanceGraph()
    e1 = g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:R", object="file:X", raw={}))
    e2 = g.add_event(Event(event_id="e2", ts=None, event_type="write", subject="proc:R", object="file:Y", raw={}))
    assert e1 is not None and e2 is not None
    x = e1["object_node_id"]
    y = e2["object_node_id"]

    ac_min = g.ac_min(x, y)
    assert len(ac_min) == 1
    assert g.path_factor(x, y) == 1.0


def test_acmin_case_b_remove_ancestors_of_other_common_ancestors():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:R", object="proc:A", raw={}))
    g.add_event(Event(event_id="e2", ts=None, event_type="write", subject="proc:R", object="proc:B", raw={}))
    g.add_event(Event(event_id="e3", ts=None, event_type="write", subject="proc:A", object="file:X", raw={}))
    e4 = g.add_event(Event(event_id="e4", ts=None, event_type="write", subject="proc:B", object="file:X", raw={}))
    g.add_event(Event(event_id="e5", ts=None, event_type="write", subject="proc:A", object="file:Y", raw={}))
    e6 = g.add_event(Event(event_id="e6", ts=None, event_type="write", subject="proc:B", object="file:Y", raw={}))
    assert e4 is not None and e6 is not None
    x = e4["object_node_id"]
    y = e6["object_node_id"]

    ac = g.ac(x, y)
    ac_min = g.ac_min(x, y)
    assert len(ac) > len(ac_min)
    assert len(ac_min) == 2
    assert g.path_factor(x, y) == 2.0


def test_case_c_version_transition_has_zero_distance_cost():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:P", object="file:F", raw={}))
    v1, v2 = g.entity_versions["file:F"][0], g.entity_versions["file:F"][1]
    assert g.shortest_path_len(v1, v2) == 0
    assert g.path_factor(v1, v2) == 1.0
    assert g.dependency_strength(v1, v2) == 1.0


def test_incremental_consistency_without_retoposort(monkeypatch):
    g = ProvenanceGraph()
    topo_calls = {"n": 0}
    orig = ProvenanceGraph.topological_sort_version_nodes

    def _wrapped(self):
        topo_calls["n"] += 1
        return orig(self)

    monkeypatch.setattr(ProvenanceGraph, "topological_sort_version_nodes", _wrapped)

    events = [
        Event(event_id="e1", ts=None, event_type="write", subject="proc:R", object="proc:A", raw={}),
        Event(event_id="e2", ts=None, event_type="write", subject="proc:A", object="file:X", raw={}),
        Event(event_id="e3", ts=None, event_type="write", subject="proc:A", object="file:Y", raw={}),
        Event(event_id="e4", ts=None, event_type="write", subject="proc:R", object="proc:B", raw={}),
        Event(event_id="e5", ts=None, event_type="write", subject="proc:B", object="file:X", raw={}),
        Event(event_id="e6", ts=None, event_type="write", subject="proc:B", object="file:Y", raw={}),
    ]
    last_x = None
    last_y = None
    for ev in events:
        info = g.add_event(ev)
        if info and ev.object == "file:X":
            last_x = info["object_node_id"]
        if info and ev.object == "file:Y":
            last_y = info["object_node_id"]
        if last_x and last_y:
            pf = g.path_factor(last_x, last_y)
            assert pf is None or pf > 0.0

    assert topo_calls["n"] == 0


def test_dependency_strength_does_not_call_graph_traversal_methods(monkeypatch):
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:R", object="file:X", raw={}))
    g.add_event(Event(event_id="e2", ts=None, event_type="write", subject="proc:R", object="file:Y", raw={}))
    x = g.current_version["file:X"]
    y = g.current_version["file:Y"]

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

    _ = g.dependency_strength(x, y)
    assert calls == {"has_path": 0, "ancestors": 0, "descendants": 0}
