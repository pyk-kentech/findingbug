from engine.hsg.builder import HSG, HSGEdge, HSGNode
from engine.hsg.scorer import rank_hsg_scenarios


def test_hsg_scorer_supports_structure_and_severity_scoring():
    hsg = HSG(
        nodes=[
            HSGNode(match_id="m1", rule_id="r1"),
            HSGNode(match_id="m2", rule_id="r2"),
        ],
        edges=[HSGEdge(src="m1", dst="m2", relation="shared_entity")],
    )

    structure_rank = rank_hsg_scenarios(hsg, scoring="structure", top_k=3)
    assert structure_rank[0]["score"] == 2.5
    assert structure_rank[0]["nodes"] == 2
    assert structure_rank[0]["edges"] == 1

    severity_rank = rank_hsg_scenarios(hsg, scoring="severity", rule_severity={"r1": 2.0, "r2": 1.5}, top_k=3)
    assert severity_rank[0]["score"] == 3.5


def test_hsg_weighted_scoring_reflects_edge_weight_magnitude():
    nodes = [HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")]
    hsg_low = HSG(nodes=nodes, edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.25)])
    hsg_high = HSG(nodes=nodes, edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.5)])
    sev = {"r1": 1.0, "r2": 1.0}

    low_score = rank_hsg_scenarios(hsg_low, scoring="weighted", rule_severity=sev, top_k=1)[0]["score"]
    high_score = rank_hsg_scenarios(hsg_high, scoring="weighted", rule_severity=sev, top_k=1)[0]["score"]

    assert high_score > low_score
    assert low_score == 2.25
    assert high_score == 2.5


def test_hsg_weighted_scoring_decreases_when_graph_path_edge_removed():
    nodes = [HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")]
    hsg_with_edge = HSG(nodes=nodes, edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.25)])
    hsg_without_edge = HSG(nodes=nodes, edges=[])
    sev = {"r1": 1.0, "r2": 1.0}

    with_edge = rank_hsg_scenarios(hsg_with_edge, scoring="weighted", rule_severity=sev, top_k=1)[0]["score"]
    without_edge = rank_hsg_scenarios(hsg_without_edge, scoring="weighted", rule_severity=sev, top_k=1)[0]["score"]

    assert with_edge > without_edge
    assert with_edge == 2.25
    assert without_edge == 1.0


def test_hsg_weighted_scoring_alpha_zero_ignores_edge_weight():
    hsg = HSG(
        nodes=[HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")],
        edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.25)],
    )
    score = rank_hsg_scenarios(hsg, scoring="weighted", rule_severity={"r1": 1.0, "r2": 2.0}, alpha=0.0, top_k=1)[0][
        "score"
    ]
    assert score == 3.0


def test_hsg_weighted_scoring_alpha_two_doubles_edge_weight_contribution():
    hsg = HSG(
        nodes=[HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")],
        edges=[HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.25)],
    )
    score = rank_hsg_scenarios(hsg, scoring="weighted", rule_severity={"r1": 1.0, "r2": 2.0}, alpha=2.0, top_k=1)[0][
        "score"
    ]
    assert score == 3.5
