from engine.core.graph import ProvenanceGraph
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.matcher import TTPMatch
from engine.core.taint_tracker import TaintTracker
from engine.hsg.builder import build_hsg
from engine.hsg.prerequisite_evaluator import PrerequisiteEvaluator
from engine.io.events import Event, normalize_event
from engine.rules.schema import Rule, RuleSet


def test_prerequisite_evaluator_satisfies_external_path_factor_to_current_process():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(
                event_id="e1",
                ts=None,
                event_type="network_flow",
                subject="ip:203.0.113.10",
                object="proc:alpha",
                raw={},
            )
        ]
    )
    evaluator = PrerequisiteEvaluator(graph=g, resolved_effective_config={"path_thres": 1.0, "path_factor_op": "ge"})
    rule = Rule(
        rule_id="r1",
        name="external->proc",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {
                    "type": "path_factor",
                    "quantifier": "EXISTS",
                    "source_node": "Untrusted_External_Node",
                    "target_node": "$current_process",
                    "threshold": "path_thres",
                }
            ],
        },
    )
    match = TTPMatch(match_id="m1", rule_id="r1", bindings={"$current_process": "proc:alpha"}, entities=["proc:alpha"])

    result = evaluator.evaluate_rule(rule, match, {})

    assert result.satisfied is True


def test_prerequisite_evaluator_satisfies_spawned_by_relation_check():
    g = ProvenanceGraph()
    g.add_events([normalize_event({"event_id": "e1", "event_type": "proc_to_proc", "subject": "proc:parent", "object": "proc:child"}, 1)])
    evaluator = PrerequisiteEvaluator(graph=g)
    rule = Rule(
        rule_id="r1",
        name="spawned by",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {
                    "type": "relation_check",
                    "relation": "spawned_by",
                    "source_node": "$current_process",
                    "target_node": "$parent_process",
                }
            ],
        },
    )
    match = TTPMatch(
        match_id="m1",
        rule_id="r1",
        bindings={"$current_process": "proc:child", "$parent_process": "proc:parent"},
        entities=["proc:child", "proc:parent"],
    )

    result = evaluator.evaluate_rule(rule, match, {})

    assert result.satisfied is True


def test_build_hsg_gates_ast_rule_and_emits_graph_path_edge():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(
                event_id="e1",
                ts=None,
                event_type="proc_to_proc",
                subject="proc:alpha",
                object="proc:beta",
                raw={},
            )
        ]
    )
    left = TTPMatch(
        match_id="m1",
        rule_id="R_A",
        event_ids=["e0"],
        bindings={"$current_process": "proc:alpha"},
        entities=["proc:alpha"],
        sequence=1,
    )
    right = TTPMatch(
        match_id="m2",
        rule_id="R_B",
        event_ids=["e1"],
        bindings={"$current_process": "proc:beta"},
        entities=["proc:beta"],
        sequence=2,
    )
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a"),
            Rule(
                rule_id="R_B",
                name="b",
                prerequisite_ast={
                    "operator": "AND",
                    "conditions": [
                        {
                            "type": "path_factor",
                            "quantifier": "EXISTS",
                            "source_node": "Compromised_Process",
                            "target_node": "$current_process",
                            "threshold": 1.0,
                            "op": ">=",
                        }
                    ],
                },
            ),
        ]
    )
    taint_tracker = TaintTracker(g)
    taint_tracker.mark_entity_tainted("proc:alpha", g.current_version_node("proc:alpha"))

    hsg = build_hsg(
        [left, right],
        g,
        ruleset,
        resolved_effective_config={"path_thres": 1.0, "path_factor_op": "ge"},
        taint_tracker=taint_tracker,
    )

    assert {n.match_id for n in hsg.nodes} == {"m1", "m2"}
    assert any(e.src == "m1" and e.dst == "m2" and e.relation == "graph_path" for e in hsg.edges)


def test_prerequisite_evaluator_checks_elevated_privilege_state():
    g = ProvenanceGraph()
    privilege_tracker = PrivilegeTracker(g)
    event = normalize_event(
        {
            "event_id": "e1",
            "event_type": "token_elevation",
            "subject": "proc:p1",
            "object": "file:x",
            "cdr": {"privilege": {"integrity_level": "system"}},
        },
        1,
    )
    info = g.add_event(event)
    assert info is not None
    privilege_tracker.on_graph_event(event, info)

    evaluator = PrerequisiteEvaluator(graph=g, privilege_tracker=privilege_tracker)
    rule = Rule(
        rule_id="r_priv",
        name="elevated proc",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {
                    "type": "node_state",
                    "target_node": "$current_process",
                    "attribute": "has_elevated_privilege",
                    "expected_value": True,
                }
            ],
        },
    )
    match = TTPMatch(match_id="m1", rule_id="r_priv", bindings={"$current_process": "proc:p1"}, entities=["proc:p1"])

    result = evaluator.evaluate_rule(rule, match, {})

    assert result.satisfied is True


def test_prerequisite_evaluator_checks_root_euid_state():
    g = ProvenanceGraph()
    privilege_tracker = PrivilegeTracker(g)
    event = normalize_event(
        {
            "event_id": "e1",
            "event_type": "setuid",
            "subject": "proc:p2",
            "object": "file:x",
            "cdr": {"privilege": {"euid": 0}},
        },
        1,
    )
    info = g.add_event(event)
    assert info is not None
    privilege_tracker.on_graph_event(event, info)

    evaluator = PrerequisiteEvaluator(graph=g, privilege_tracker=privilege_tracker)
    rule = Rule(
        rule_id="r_root",
        name="root proc",
        prerequisite_ast={
            "operator": "AND",
            "conditions": [
                {
                    "type": "node_state",
                    "target_node": "$current_process",
                    "attribute": "has_root_euid",
                    "expected_value": True,
                }
            ],
        },
    )
    match = TTPMatch(match_id="m2", rule_id="r_root", bindings={"$current_process": "proc:p2"}, entities=["proc:p2"])

    assert evaluator.evaluate_rule(rule, match, {}).satisfied is True
