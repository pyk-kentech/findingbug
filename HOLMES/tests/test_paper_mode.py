from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.builder import build_hsg
from engine.io.events import Event
from engine.rules.schema import Rule, RuleSet


def test_graph_path_weight_differs_between_hybrid_and_strict_modes():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="proc:B", raw={}))

    matches = [
        TTPMatch(match_id="m1", rule_id="TEST_PROC_TO_FILE", bindings={"object": "proc:A"}),
        TTPMatch(match_id="m2", rule_id="TEST_FILE_TO_IP", bindings={"object": "proc:B"}),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="TEST_PROC_TO_FILE", name="left", prerequisites=["graph_path"]),
            Rule(rule_id="TEST_FILE_TO_IP", name="right", prerequisites=["graph_path"]),
        ]
    )

    h_hybrid = build_hsg(matches, g, ruleset, paper_mode="hybrid")
    h_strict = build_hsg(matches, g, ruleset, paper_mode="strict")

    edge_h = [e for e in h_hybrid.edges if e.relation == "graph_path"][0]
    edge_s = [e for e in h_strict.edges if e.relation == "graph_path"][0]

    assert edge_h.dependency_strength == 1.0
    assert edge_h.path_factor == 1.0
    assert edge_h.weight == 1.0
    assert edge_s.weight == 1.0
    assert edge_s.path_factor == edge_h.path_factor


def test_paper_mode_keeps_same_path_factor_under_unified_mac_model(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    hybrid = run_pipeline(
        str(events_path),
        str(rules_path),
        str(tmp_path / "out_hybrid"),
        scoring_mode="paper",
        paper_mode="hybrid",
    )
    strict = run_pipeline(
        str(events_path),
        str(rules_path),
        str(tmp_path / "out_strict"),
        scoring_mode="paper",
        paper_mode="strict",
    )

    h_weight = [e["weight"] for e in hybrid["hsg"]["edges"] if e["relation"] == "graph_path"][0]
    s_weight = [e["weight"] for e in strict["hsg"]["edges"] if e["relation"] == "graph_path"][0]

    assert s_weight == h_weight
    assert strict["summary"]["top_scenarios"][0]["score"] == hybrid["summary"]["top_scenarios"][0]["score"]
