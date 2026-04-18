from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher, TTPMatch
from engine.hsg.builder import build_hsg
from engine.hsg.prerequisite import is_path_factor_satisfied
from engine.io.events import Event, load_events_jsonl
from engine.rules.schema import PathFactorPrerequisite, Rule, RuleSet, load_rules_yaml


def test_path_factor_threshold_pass_and_block_without_file_io():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="file:A", object="file:X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="file:X", object="file:B", raw={}),
        ]
    )
    left = TTPMatch(match_id="m1", rule_id="L", bindings={"object": "file:A"})
    right = TTPMatch(match_id="m2", rule_id="R", bindings={"object": "file:B"})

    assert g.path_factor(left.bindings["object"], right.bindings["object"]) == 1.0
    assert not is_path_factor_satisfied(g, left.bindings["object"], right.bindings["object"], max_path_factor=0)
    assert is_path_factor_satisfied(g, left.bindings["object"], right.bindings["object"], max_path_factor=1)


def test_rules_yaml_supports_path_factor_prerequisite_dict(tmp_path):
    p = tmp_path / "rules_pf.yaml"
    p.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R1",
                "    name: r1",
                "    prerequisites:",
                "      - graph_path",
                "      - type: path_factor",
                "        max_path_factor: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(p)
    prereqs = ruleset.rules[0].prerequisites

    assert "graph_path" in prereqs
    assert PathFactorPrerequisite(max_path_factor=1) in prereqs


def test_integration_rule_path_factor_threshold_blocks_graph_path_on_sample():
    repo_root = Path(__file__).resolve().parents[1]
    events = load_events_jsonl(repo_root / "experiments" / "sample.jsonl")
    g = ProvenanceGraph()
    g.add_events(events)

    ruleset_base = RuleSet(
        rules=[
            Rule(
                rule_id="TEST_PROC_TO_FILE",
                name="left",
                source_types=["process"],
                target_types=["file"],
                prerequisites=[],
                event_predicate={"event_type": "proc_to_file"},
            ),
            Rule(
                rule_id="TEST_FILE_TO_IP",
                name="right",
                source_types=["file"],
                target_types=["ip"],
                prerequisites=["graph_path"],
                event_predicate={"event_type": "file_to_ip"},
            ),
        ]
    )
    matches_base = Matcher().match(g, ruleset_base, events)
    hsg_base = build_hsg(matches_base, g, ruleset_base)
    assert len([e for e in hsg_base.edges if e.relation == "graph_path"]) == 1

    ruleset_pf = RuleSet(
        rules=[
            Rule(
                rule_id="TEST_PROC_TO_FILE",
                name="left",
                source_types=["process"],
                target_types=["file"],
                prerequisites=[],
                event_predicate={"event_type": "proc_to_file"},
            ),
            Rule(
                rule_id="TEST_FILE_TO_IP",
                name="right",
                source_types=["file"],
                target_types=["ip"],
                prerequisites=["graph_path", PathFactorPrerequisite(max_path_factor=0)],
                event_predicate={"event_type": "file_to_ip"},
            ),
        ]
    )
    matches_pf = Matcher().match(g, ruleset_pf, events)
    hsg_pf = build_hsg(matches_pf, g, ruleset_pf)
    assert [e for e in hsg_pf.edges if e.relation == "graph_path"] == []
