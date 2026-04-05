from engine.core.graph import EdgeType, ProvenanceGraph
from engine.hsg.online_index import OnlineIndex


def test_trigger_edge_first_match_later_propagates_transitively():
    idx = OnlineIndex()
    idx.on_edge_added("u", "v", EdgeType.DATA_FLOW)
    idx.on_edge_added("v", "w", EdgeType.DATA_FLOW)

    idx.on_match_added("u", ttp_id="T1", sequence=1)

    assert "T1" in idx.mapper_match_ids("v")
    assert "T1" in idx.mapper_match_ids("w")


def test_trigger_match_first_edge_later_propagates_immediately():
    idx = OnlineIndex()
    idx.on_match_added("u", ttp_id="T1", sequence=1)

    idx.on_edge_added("u", "v", EdgeType.DATA_FLOW)
    assert "T1" in idx.mapper_match_ids("v")


def test_data_and_version_transition_propagate_others_do_not():
    idx = OnlineIndex()
    idx.on_match_added("u", ttp_id="T1", sequence=1)

    idx.on_edge_added("u", "v_data", EdgeType.DATA_FLOW)
    idx.on_edge_added("u", "v_ver", EdgeType.VERSION_TRANSITION)
    idx.on_edge_added("u", "v_other", "control")

    assert "T1" in idx.mapper_match_ids("v_data")
    assert "T1" in idx.mapper_match_ids("v_ver")
    assert "T1" not in idx.mapper_match_ids("v_other")


def test_propagation_uses_no_graph_traversal_calls(monkeypatch):
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

    idx = OnlineIndex()
    idx.on_edge_added("u", "v", EdgeType.DATA_FLOW)
    idx.on_edge_added("v", "w", EdgeType.VERSION_TRANSITION)
    idx.on_match_added("u", ttp_id="T1", sequence=1)

    assert "T1" in idx.mapper_match_ids("w")
    assert calls == {"has_path": 0, "ancestors": 0, "descendants": 0}
