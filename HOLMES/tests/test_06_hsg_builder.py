from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher, TTPMatch
import engine.hsg.builder as hsg_builder
from engine.hsg.builder import IncrementalHSGBuilder, build_hsg, hsg_to_dict
from engine.io.events import Event, load_events_jsonl
from engine.rules.schema import Rule, RuleSet
from engine.rules.schema import load_rules_yaml


def test_hsg_builder_outputs_nodes_edges_dict():
    g = ProvenanceGraph()
    g.add_events([Event(event_id="e1", ts=None, event_type="x", subject="a", object="b", raw={})])

    matches = [
        TTPMatch(match_id="m1", rule_id="r1", event_ids=["e1"], entities=["a", "b"], bindings={"file": "b"}),
        TTPMatch(match_id="m2", rule_id="r2", event_ids=["e1"], entities=["b"], bindings={"file": "b"}),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="r1", name="left", prerequisites=["shared_entity"]),
            Rule(rule_id="r2", name="right", prerequisites=[]),
        ]
    )

    hsg = build_hsg(matches, g, ruleset)
    data = hsg_to_dict(hsg)

    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["edges"][0]["relation"] == "shared_entity"


def test_hsg_builder_includes_graph_path_relation_with_sample_and_test_rules():
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)
    ruleset = load_rules_yaml(repo_root / "rules" / "test_rules.yaml")
    matches = Matcher().match(g, ruleset, events)

    hsg = build_hsg(matches, g, ruleset)
    relations = {edge.relation for edge in hsg.edges}

    assert "graph_path" in relations


def test_hsg_builder_graph_path_edge_exists_when_max_path_factor_is_zero(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)
    ruleset = load_rules_yaml(repo_root / "rules" / "test_rules.yaml")
    matches = Matcher().match(g, ruleset, events)

    monkeypatch.setattr(
        hsg_builder,
        "PREREQ_CONFIG",
        {"graph_path": {"from_binding": "object", "to_binding": "object", "max_path_factor": "0.0"}},
    )
    hsg = hsg_builder.build_hsg(matches, g, ruleset)
    relations = [edge.relation for edge in hsg.edges]

    assert "graph_path" in relations


def test_hsg_builder_graph_path_edge_missing_when_max_path_factor_is_point_six(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)
    ruleset = load_rules_yaml(repo_root / "rules" / "test_rules.yaml")
    matches = Matcher().match(g, ruleset, events)

    monkeypatch.setattr(
        hsg_builder,
        "PREREQ_CONFIG",
        {"graph_path": {"from_binding": "object", "to_binding": "object", "max_path_factor": "0.6"}},
    )
    hsg = hsg_builder.build_hsg(matches, g, ruleset)
    relations = [edge.relation for edge in hsg.edges]

    assert "graph_path" not in relations


def test_hsg_builder_graph_path_right_rule_override_uses_low_threshold(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)
    ruleset = load_rules_yaml(repo_root / "rules" / "test_rules.yaml")
    matches = Matcher().match(g, ruleset, events)

    monkeypatch.setattr(
        hsg_builder,
        "PREREQ_CONFIG",
        {
            "graph_path": {
                "default": {"from_binding": "object", "to_binding": "object", "max_path_factor": "0.6"},
                "by_right_rule_id": {
                    "TEST_FILE_TO_IP": {"from_binding": "object", "to_binding": "object", "max_path_factor": "0.0"}
                },
                "by_pair": {},
            }
        },
    )

    hsg = hsg_builder.build_hsg(matches, g, ruleset)
    match_rule = {m.match_id: m.rule_id for m in hsg.nodes}
    graph_path_edges = [e for e in hsg.edges if e.relation == "graph_path"]

    assert len(graph_path_edges) == 1
    assert match_rule[graph_path_edges[0].dst] == "TEST_FILE_TO_IP"


def test_hsg_builder_graph_path_only_for_allowed_rule_pair():
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)
    ruleset = load_rules_yaml(repo_root / "rules" / "test_rules.yaml")
    matches = Matcher().match(g, ruleset, events)

    hsg = build_hsg(
        matches,
        g,
        ruleset,
        graph_path_allowlist={("TEST_PROC_TO_FILE", "TEST_FILE_TO_IP")},
    )
    node_rule = {n.match_id: n.rule_id for n in hsg.nodes}
    graph_path_edges = [e for e in hsg.edges if e.relation == "graph_path"]

    assert graph_path_edges
    assert any(
        node_rule[e.src] == "TEST_PROC_TO_FILE" and node_rule[e.dst] == "TEST_FILE_TO_IP"
        for e in graph_path_edges
    )


def test_hsg_builder_graph_path_not_created_for_disallowed_rule_pair():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="proc_to_proc", subject="proc:a", object="proc:b", raw={}),
            Event(event_id="e2", ts=None, event_type="proc_to_file", subject="proc:b", object="file:x", raw={}),
            Event(event_id="e3", ts=None, event_type="file_to_ip", subject="file:x", object="ip:z", raw={}),
        ]
    )
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="TEST_PROC_TO_PROC", name="left", prerequisites=["graph_path"]),
            Rule(rule_id="TEST_FILE_TO_IP", name="right", prerequisites=["graph_path"]),
        ]
    )
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="TEST_PROC_TO_PROC",
            event_ids=["e1"],
            entities=["proc:a", "proc:b"],
            bindings={"subject": "proc:a", "object": "proc:b"},
        ),
        TTPMatch(
            match_id="m2",
            rule_id="TEST_FILE_TO_IP",
            event_ids=["e3"],
            entities=["file:x", "ip:z"],
            bindings={"subject": "file:x", "object": "ip:z"},
        ),
    ]

    hsg = build_hsg(
        matches,
        g,
        ruleset,
        graph_path_allowlist={("TEST_PROC_TO_FILE", "TEST_FILE_TO_IP")},
    )

    assert all(edge.relation != "graph_path" for edge in hsg.edges)


def test_parse_watermark_supports_epoch_ns():
    parsed = IncrementalHSGBuilder._parse_watermark("1523627786654000000")

    assert parsed is not None
    assert parsed.year == 2018
    assert parsed.tzinfo is not None
