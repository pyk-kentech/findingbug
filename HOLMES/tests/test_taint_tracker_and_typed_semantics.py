from engine.core.graph import ProvenanceGraph
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.matcher import TTPMatch
from engine.core.taint_tracker import TaintTracker
from engine.hsg.prerequisite_evaluator import PrerequisiteEvaluator
from engine.io.events import Event, normalize_event
from engine.rules.schema import Rule
from engine.stream.runner import StreamingEngine


def test_taint_tracker_propagates_compromise_over_information_flow():
    g = ProvenanceGraph()
    tracker = TaintTracker(g)

    first_event = normalize_event({"event_id": "e1", "event_type": "proc_to_file", "subject": "proc:p1", "object": "file:f1"}, 1)
    e1 = g.add_event(first_event)
    assert e1 is not None
    match = TTPMatch(
        match_id="m1",
        rule_id="R_INIT",
        entities=["proc:p1"],
        bindings={"$current_process": "proc:p1"},
        binding_node_ids={"$current_process": e1["subject_node_id"]},
    )
    tracker.mark_initial_compromise(match, Rule(rule_id="R_INIT", name="init", apt_stage="Initial Compromise"))

    second_event = normalize_event({"event_id": "e2", "event_type": "proc_to_file", "subject": "proc:p1", "object": "file:f2"}, 2)
    e2 = g.add_event(second_event)
    assert e2 is not None
    tracker.on_graph_event(second_event, e2)

    assert tracker.is_tainted_entity("proc:p1")
    assert tracker.is_tainted_entity("file:f2")


def test_taint_tracker_read_relation_taints_reader_from_tainted_object():
    g = ProvenanceGraph()
    tracker = TaintTracker(g)

    seed = g.add_event(normalize_event({"event_id": "e1", "event_type": "proc_to_file", "subject": "proc:p0", "object": "file:f1"}, 1))
    assert seed is not None
    tracker.mark_entity_tainted("file:f1", seed["object_node_id"])

    e2 = g.add_event(
        normalize_event({"event_id": "e2", "event_type": "read", "subject": "proc:p2", "object": "file:f1"}, 2)
    )
    assert e2 is not None
    tracker.on_graph_event(normalize_event({"event_id": "e2", "event_type": "read", "subject": "proc:p2", "object": "file:f1"}, 2), e2)

    assert tracker.is_tainted_entity("proc:p2") is True


def test_taint_tracker_marks_memory_node_on_exec_memory_relation():
    g = ProvenanceGraph()
    tracker = TaintTracker(g)
    event = normalize_event(
        {
            "event_id": "e1",
            "event_type": "mprotect",
            "subject": "proc:p1",
            "object": "mem:100:0x1000:0",
            "semantic_relations": [{"relation": "protect_memory_exec", "src": "proc:p1", "dst": "mem:100:0x1000:0"}],
        },
        1,
    )
    info = g.add_event(event)
    assert info is not None
    tracker.mark_entity_tainted("proc:p1", info["subject_node_id"])

    event2 = normalize_event(
        {
            "event_id": "e2",
            "event_type": "mprotect",
            "subject": "proc:p1",
            "object": "mem:100:0x2000:0",
            "semantic_relations": [{"relation": "protect_memory_exec", "src": "proc:p1", "dst": "mem:100:0x2000:0"}],
        },
        2,
    )
    info2 = g.add_event(event2)
    assert info2 is not None
    tracker.on_graph_event(event2, info2)

    assert tracker.is_tainted_entity("mem:100:0x2000:1") is True


def test_tracker_cleanup_removes_pruned_entities_and_versions():
    g = ProvenanceGraph()
    taint = TaintTracker(g)
    privilege = PrivilegeTracker(g)
    g.register_prune_hook(taint.cleanup)
    g.register_prune_hook(privilege.cleanup)

    info = g.add_event(normalize_event({"event_id": "e1", "ts": "2025-01-01T00:00:00Z", "event_type": "proc_to_file", "subject": "proc:old", "object": "file:old"}, 1))
    assert info is not None
    taint.mark_entity_tainted("proc:old", info["subject_node_id"])
    privilege.mark_entity_root_euid("proc:old", info["subject_node_id"])

    pruned = g.prune_stale_orphaned(
        watermark_ts="2025-03-20T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities=set(),
        protected_version_nodes=set(),
    )

    assert pruned["entities_removed"] >= 1
    assert "proc:old" not in taint.tainted_entities()
    assert "proc:old" not in privilege.privileged_entities()


def test_prerequisite_evaluator_uses_taint_tracker_for_compromised_process():
    g = ProvenanceGraph()
    tracker = TaintTracker(g)
    evaluator = PrerequisiteEvaluator(graph=g, taint_tracker=tracker, resolved_effective_config={"path_thres": 1.0, "path_factor_op": "ge"})

    seed = g.add_event(Event(event_id="e1", ts=None, event_type="proc_to_proc", subject="proc:p0", object="proc:p1", raw={}))
    assert seed is not None
    tracker.mark_entity_tainted("proc:p0", seed["subject_node_id"])
    tracker.mark_entity_tainted("proc:p1", seed["object_node_id"])

    e2 = g.add_event(Event(event_id="e2", ts=None, event_type="proc_to_file", subject="proc:p1", object="file:f1", raw={}))
    assert e2 is not None

    match = TTPMatch(
        match_id="m2",
        rule_id="R_NEXT",
        entities=["file:f1"],
        bindings={"$target_file": "file:f1"},
        binding_node_ids={"$target_file": e2["object_node_id"]},
    )
    rule = Rule(
        rule_id="R_NEXT",
        name="next",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {
                    "type": "path_factor",
                    "source_node": "Compromised_Process",
                    "target_node": "$target_file",
                    "threshold": 1.0,
                    "op": ">=",
                }
            ],
        },
    )

    result = evaluator.evaluate_rule(rule, match, {})

    assert result.satisfied is True


def test_relation_check_requires_matching_typed_semantic_edge():
    g = ProvenanceGraph()
    info = g.add_event(normalize_event({"event_id": "e1", "event_type": "proc_to_file", "subject": "proc:p1", "object": "file:f1"}, 1))
    assert info is not None
    evaluator = PrerequisiteEvaluator(graph=g)
    match = TTPMatch(
        match_id="m1",
        rule_id="R1",
        entities=["proc:p1", "file:f1"],
        bindings={"$current_process": "proc:p1", "$target_file": "file:f1"},
        binding_node_ids={"$current_process": info["subject_node_id"], "$target_file": info["object_node_id"]},
    )

    acts_on_rule = Rule(
        rule_id="R1",
        name="acts_on",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {"type": "relation_check", "relation": "acts_on", "source_node": "$current_process", "target_node": "$target_file"}
            ],
        },
    )
    spawned_by_rule = Rule(
        rule_id="R2",
        name="spawned_by",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {"type": "relation_check", "relation": "spawned_by", "source_node": "$current_process", "target_node": "$target_file"}
            ],
        },
    )

    assert evaluator.evaluate_rule(acts_on_rule, match, {}).satisfied is True
    assert evaluator.evaluate_rule(spawned_by_rule, match, {}).satisfied is False


def test_streaming_engine_attaches_binding_version_nodes():
    engine = StreamingEngine(
        ruleset=type("RuleSetLite", (), {
            "rules": [
                Rule(
                    rule_id="R1",
                    name="init",
                    apt_stage="Initial Compromise",
                    source_types=["process_creation"],
                    match_logic={
                        "engine": "sigma",
                        "condition": {"compiled": {"type": "selector_ref", "selector": "sel"}},
                        "selectors": {
                            "sel": {
                                "type": "object",
                                "items": [
                                    {"type": "field_match", "field": "Image", "modifiers": ["contains"], "value": {"type": "literal", "value": "proc:p1"}}
                                ],
                            }
                        },
                    },
                    entity_bindings=[{"symbol": "$current_process", "entity_type": "Process", "fields": ["Image"]}],
                )
            ],
            "has_scoring_alpha": False,
            "scoring_alpha": 1.0,
        })(),
        use_online_prereq=True,
    )

    engine.process_event(
        Event(
            event_id="e1",
            ts=None,
            event_type="process_creation",
            subject="proc:p1",
            object="file:seed",
            raw={"source_type": "process_creation", "Image": "proc:p1"},
        )
    )

    assert engine.matches
    match = engine.matches[0]
    assert "$current_process" in match.binding_node_ids
    assert match.binding_node_ids["$current_process"] == match.subject_node_id


def test_taint_seed_uses_explicit_rule_bindings_only():
    g = ProvenanceGraph()
    tracker = TaintTracker(g)
    info = g.add_event(normalize_event({"event_id": "e1", "event_type": "proc_to_file", "subject": "proc:p1", "object": "file:f1"}, 1))
    assert info is not None
    rule = Rule(
        rule_id="R_INIT",
        name="init",
        apt_stage="Initial Compromise",
        entity_bindings=[{"symbol": "$current_process", "entity_type": "Process", "fields": ["Image"]}],
    )
    match = TTPMatch(
        match_id="m1",
        rule_id="R_INIT",
        entities=["proc:p1", "file:f1"],
        bindings={"subject": "proc:p1", "object": "file:f1", "$current_process": "proc:p1"},
        binding_node_ids={"$current_process": info["subject_node_id"]},
    )

    tracker.mark_initial_compromise(match, rule)

    assert tracker.is_tainted_entity("proc:p1") is True
    assert tracker.is_tainted_entity("file:f1") is False


def test_streaming_summary_contains_binding_drop_telemetry(tmp_path):
    ruleset = type(
        "RuleSetLite",
        (),
        {
            "rules": [
                Rule(
                    rule_id="R_DROP",
                    name="needs parent",
                    source_types=["process_creation"],
                    match_logic={
                        "engine": "sigma",
                        "condition": {"compiled": {"type": "selector_ref", "selector": "sel"}},
                        "selectors": {
                            "sel": {
                                "type": "object",
                                "items": [
                                    {
                                        "type": "field_match",
                                        "field": "Image",
                                        "modifiers": ["contains"],
                                        "value": {"type": "literal", "value": "proc:p1"},
                                    }
                                ],
                            }
                        },
                    },
                    entity_bindings=[
                        {"symbol": "$current_process", "entity_type": "Process", "fields": ["Image"]},
                        {"symbol": "$parent_process", "entity_type": "Process", "fields": ["ParentImage"]},
                    ],
                )
            ],
            "has_scoring_alpha": False,
            "scoring_alpha": 1.0,
        },
    )()
    telemetry_path = tmp_path / "dropped_matches.jsonl"
    engine = StreamingEngine(
        ruleset=ruleset,
        use_online_prereq=True,
        dropped_match_telemetry_path=telemetry_path,
    )
    engine.process_event(
        Event(
            event_id="e1",
            ts=None,
            event_type="process_creation",
            subject="proc:p1",
            object="file:seed",
            raw={"source_type": "process_creation", "Image": "proc:p1", "ParentImage": "proc:missing-parent"},
        )
    )

    summary = engine.build_result()["summary"]["dropped_match_telemetry"]

    assert summary["binding_drop_count"] == 1
    assert summary["binding_drop_by_rule_id"]["R_DROP"] == 1
    assert summary["path"] == str(telemetry_path)
    lines = telemetry_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "ParentImage" in lines[0]
