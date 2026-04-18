from engine.hsg.builder import HSG, HSGEdge, HSGNode
from engine.hsg.scorer import rank_hsg_scenarios


def test_stage_coverage_increases_score_paper():
    hsg_stage1 = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    hsg_stage1_5 = HSG(
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
    s2 = rank_hsg_scenarios(
        hsg_stage1_5,
        score_mode="paper",
        rule_stage={"r1": 1, "r2": 5},
        rule_cvss={"r1": 6.0, "r2": 8.0},
        top_k=1,
    )[0]["score_paper"]

    assert float(s2) > float(s1)


def test_higher_cvss_in_same_stage_increases_score_paper():
    hsg = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])

    low = rank_hsg_scenarios(
        hsg,
        score_mode="paper",
        rule_stage={"r1": 3},
        rule_cvss={"r1": 2.0},
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


def test_paper_score_stability_bounds():
    empty = rank_hsg_scenarios(HSG(nodes=[], edges=[]), score_mode="paper", top_k=1)[0]
    assert float(empty["score_paper"]) == 1.0

    one_max = rank_hsg_scenarios(
        HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[]),
        score_mode="paper",
        rule_stage={"r1": 4},
        rule_cvss={"r1": 10.0},
        top_k=1,
    )[0]
    assert abs(float(one_max["score_paper"]) - 2.0) <= 1e-9
