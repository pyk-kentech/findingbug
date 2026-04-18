from engine.core.graph import ProvenanceGraph
from engine.io.events import Event


def test_provenance_graph_path_and_has_path():
    events = [
        Event(event_id="e1", ts=None, event_type="flow", subject="a", object="b", raw={}),
        Event(event_id="e2", ts=None, event_type="flow", subject="b", object="c", raw={}),
    ]

    g = ProvenanceGraph()
    g.add_events(events)

    assert g.has_path("a", "c") is True
    assert g.path("a", "c") == ["a", "b", "c"]
    assert g.has_path("c", "a") is False


def test_op_write_flow_process_to_file():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="write", subject="proc:p", object="file:f", raw={}))
    assert g.has_path("proc:p", "file:f") is True
    assert g.has_path("file:f", "proc:p") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "proc:p" and flow_edges[0].dst_entity == "file:f"


def test_op_read_flow_file_to_process():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="read", subject="proc:p", object="file:f", raw={}))
    assert g.has_path("file:f", "proc:p") is True
    assert g.has_path("proc:p", "file:f") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "file:f" and flow_edges[0].dst_entity == "proc:p"


def test_op_exec_flow_file_to_process_new():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="exec", subject="proc:new", object="file:bin", raw={}))
    assert g.has_path("file:bin", "proc:new") is True
    assert g.has_path("proc:new", "file:bin") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "file:bin" and flow_edges[0].dst_entity == "proc:new"


def test_op_fork_flow_parent_to_child():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="fork", subject="proc:parent", object="proc:child", raw={}))
    assert g.has_path("proc:parent", "proc:child") is True
    assert g.has_path("proc:child", "proc:parent") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "proc:parent" and flow_edges[0].dst_entity == "proc:child"


def test_op_connect_flow_process_to_socket():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="connect", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("proc:p", "sock:s") is True
    assert g.has_path("sock:s", "proc:p") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "proc:p" and flow_edges[0].dst_entity == "sock:s"


def test_op_send_flow_process_to_socket():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="send", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("proc:p", "sock:s") is True
    assert g.has_path("sock:s", "proc:p") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "proc:p" and flow_edges[0].dst_entity == "sock:s"


def test_op_recv_flow_socket_to_process():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="recv", subject="proc:p", object="sock:s", raw={}))
    assert g.has_path("sock:s", "proc:p") is True
    assert g.has_path("proc:p", "sock:s") is False
    flow_edges = [e for e in g.edges if e.relation == "flow"]
    assert len(flow_edges) == 1
    assert flow_edges[0].src_entity == "sock:s" and flow_edges[0].dst_entity == "proc:p"


def test_prune_stale_orphaned_removes_old_benign_entities_but_keeps_protected():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts="2025-01-01T00:00:00Z", event_type="proc_to_file", subject="proc:old", object="file:old", raw={}))
    g.add_event(Event(event_id="e2", ts="2025-01-10T00:00:00Z", event_type="proc_to_file", subject="proc:new", object="file:new", raw={}))

    pruned = g.prune_stale_orphaned(
        watermark_ts="2025-03-20T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities={"proc:new", "file:new"},
        protected_version_nodes=set(),
    )

    assert pruned["entities_removed"] >= 1
    assert "proc:new" in g.nodes
    assert "file:new" in g.nodes


def test_prune_stale_orphaned_can_drop_old_versions_while_keeping_protected_current_version():
    g = ProvenanceGraph()
    info1 = g.add_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )
    info2 = g.add_event(
        Event(
            event_id="e2",
            ts="2025-03-15T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )

    protected_versions = {info2["subject_node_id"], info2["object_node_id"]}
    pruned = g.prune_stale_orphaned(
        watermark_ts="2025-04-15T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities={"proc:p1", "file:f1"},
        protected_version_nodes=protected_versions,
    )

    assert pruned["version_nodes_removed"] >= 1
    assert "proc:p1" in g.nodes
    assert "file:f1" in g.nodes
    assert g.current_version["file:f1"] == info2["object_node_id"]
    assert info1["object_node_id"] not in g.version_nodes


def test_prune_stale_orphaned_uses_low_watermark_after_hard_cap_pressure():
    g = ProvenanceGraph()
    infos = []
    for idx in range(6):
        infos.append(
            g.add_event(
                Event(
                    event_id=f"e{idx}",
                    ts=f"2025-01-{idx + 1:02d}T00:00:00Z",
                    event_type="proc_to_file",
                    subject="proc:p1",
                    object="file:f1",
                    raw={},
                )
            )
        )

    latest = infos[-1]
    pruned = g.prune_stale_orphaned(
        watermark_ts="2025-02-15T00:00:00Z",
        retention_seconds=365 * 24 * 60 * 60,
        protected_entities={"proc:p1", "file:f1"},
        protected_version_nodes={latest["subject_node_id"], latest["object_node_id"]},
        max_version_nodes=4,
        cap_low_watermark_ratio=0.5,
    )

    assert pruned["version_nodes_removed"] >= 4
    assert len(g.version_nodes) <= 3
    assert g.current_version["file:f1"] == latest["object_node_id"]


def test_parse_ts_supports_epoch_ns_and_ms():
    ns_dt = ProvenanceGraph._parse_ts("1523627786654000000")
    ms_dt = ProvenanceGraph._parse_ts("1523627786654")

    assert ns_dt is not None
    assert ms_dt is not None
    assert ns_dt.year == 2018
    assert ms_dt.year == 2018
    assert ns_dt.tzinfo is not None
    assert ms_dt.tzinfo is not None
