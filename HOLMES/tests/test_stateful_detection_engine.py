from engine.stream.stateful_detection import HSG_Edge, RuleEngine, StatefulDetectionEngine


def test_stateful_detection_engine_creates_edge_from_ancestor():
    engine = StatefulDetectionEngine(
        RuleEngine({"attack.t1562.002": {"attack.t1190", "attack.t1059"}})
    )

    engine.process_event(1000.0, "proc-grandparent", None, "w3wp.exe", "attack.t1190")
    engine.process_event(1005.0, "proc-parent", "proc-grandparent", "cmd.exe", None)
    engine.process_event(1012.5, "proc-child", "proc-parent", "reg.exe", "attack.t1562.002")

    assert len(engine.hsg_edges) == 1
    assert engine.hsg_edges[0] == HSG_Edge(
        src_guid="proc-grandparent",
        src_ttp="attack.t1190",
        dst_guid="proc-child",
        dst_ttp="attack.t1562.002",
        time_delta=12.5,
        distance=2,
    )


def test_stateful_detection_engine_creates_edge_from_same_process():
    engine = StatefulDetectionEngine(
        RuleEngine({"attack.t1562.002": {"attack.t1190", "attack.t1059"}})
    )

    engine.process_event(1000.0, "proc-webshell", None, "nginx.exe", "attack.t1190")
    engine.process_event(1004.0, "proc-webshell", None, "nginx.exe", "attack.t1562.002")

    assert len(engine.hsg_edges) == 1
    assert engine.hsg_edges[0].src_guid == "proc-webshell"
    assert engine.hsg_edges[0].distance == 0
    assert engine.hsg_edges[0].time_delta == 4.0


def test_stateful_detection_engine_creates_edge_via_file_flow():
    engine = StatefulDetectionEngine(
        RuleEngine({"attack.t1562.002": {"attack.t1190", "attack.t1059"}})
    )

    engine.process_event(1000.0, "proc-nginx", None, "nginx.exe", "attack.t1190")
    engine.process_file_event(1002.0, "proc-nginx", r"C:\temp\malware.exe", "WRITE")
    engine.process_event(1008.0, "proc-explorer", None, "explorer.exe", None)
    engine.process_file_event(1009.0, "proc-explorer", r"C:\temp\malware.exe", "READ")
    engine.process_event(1012.5, "proc-explorer", None, "explorer.exe", "attack.t1562.002")

    assert len(engine.hsg_edges) == 1
    assert engine.hsg_edges[0] == HSG_Edge(
        src_guid="proc-nginx",
        src_ttp="attack.t1190",
        dst_guid="proc-explorer",
        dst_ttp="attack.t1562.002",
        time_delta=12.5,
        distance=1,
    )


def test_stateful_detection_engine_rejects_non_past_prerequisite():
    engine = StatefulDetectionEngine(
        RuleEngine({"attack.t1562.002": {"attack.t1190"}})
    )

    engine.process_event(2000.0, "proc-a", None, "nginx.exe", "attack.t1562.002")
    engine.process_event(2001.0, "proc-a", None, "nginx.exe", "attack.t1190")

    assert engine.hsg_edges == []


def test_stateful_detection_engine_gc_removes_terminated_process():
    engine = StatefulDetectionEngine(RuleEngine())

    engine.process_event(3000.0, "proc-old", None, "cmd.exe", None)
    assert engine.terminate_process("proc-old", timestamp=3005.0) is True

    collected = engine.garbage_collect(current_time=3016.0, max_age=10.0)

    assert collected == ["proc-old"]
    assert "proc-old" not in engine.node_map
