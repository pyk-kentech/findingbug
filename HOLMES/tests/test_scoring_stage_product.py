from engine.hsg.builder import HSG, HSGEdge, HSGNode
from engine.hsg.scorer import rank_hsg_scenarios


def test_stage_coverage_increases_paper_score():
    hsg_stage1 = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    hsg_stage12 = HSG(
        nodes=[HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")],
        edges=[HSGEdge(src="m1", dst="m2", relation="shared_entity")],
    )

    s1 = rank_hsg_scenarios(
        hsg_stage1,
        score_mode="paper",
        rule_stage={"r1": 1},
        rule_cvss={"r1": 6.0},
        top_k=1,
    )[0]["score_paper"]
    s12 = rank_hsg_scenarios(
        hsg_stage12,
        score_mode="paper",
        rule_stage={"r1": 1, "r2": 2},
        rule_cvss={"r1": 6.0, "r2": 6.0},
        top_k=1,
    )[0]["score_paper"]

    assert float(s12) > float(s1)


def test_higher_cvss_in_same_stage_increases_paper_score():
    hsg = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    low = rank_hsg_scenarios(
        hsg,
        score_mode="paper",
        rule_stage={"r1": 3},
        rule_cvss={"r1": 3.0},
        top_k=1,
    )[0]["score_paper"]
    high = rank_hsg_scenarios(
        hsg,
        score_mode="paper",
        rule_stage={"r1": 3},
        rule_cvss={"r1": 8.0},
        top_k=1,
    )[0]["score_paper"]
    assert float(high) > float(low)


def test_scoring_mode_switch_changes_primary_score():
    hsg = HSG(
        nodes=[HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")],
        edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.5)],
    )
    params = {
        "rule_stage": {"r1": 1, "r2": 2},
        "rule_cvss": {"r1": 6.0, "r2": 8.0},
        "rule_severity": {"r1": 1.0, "r2": 1.0},
    }

    legacy = rank_hsg_scenarios(hsg, score_mode="legacy", scoring="weighted", alpha=1.0, top_k=1, **params)[0]
    paper = rank_hsg_scenarios(hsg, score_mode="paper", scoring="weighted", alpha=1.0, top_k=1, **params)[0]

    assert float(legacy["score"]) == float(legacy["score_legacy"])
    assert float(paper["score"]) == float(paper["score_paper"])
    assert float(legacy["score"]) != float(paper["score"])
