import pytest

from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.hsg.builder import HSG, HSGEdge, HSGNode
from engine.hsg.scorer import rank_hsg_scenarios
from engine.rules.schema import APT_STAGES


def test_scoring_mode_switch_outputs_legacy_and_paper_fields(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    legacy = run_pipeline(str(events_path), str(rules_path), str(tmp_path / "out_legacy"), scoring_mode="legacy")
    paper = run_pipeline(str(events_path), str(rules_path), str(tmp_path / "out_paper"), scoring_mode="paper")

    s_legacy = legacy["summary"]["top_scenarios"][0]
    s_paper = paper["summary"]["top_scenarios"][0]

    for scenario in (s_legacy, s_paper):
        assert "score" in scenario
        assert "score_legacy" in scenario
        assert "score_paper" in scenario
        assert "threat_tuple" in scenario
        assert len(scenario["threat_tuple"]) == 7

    assert float(s_legacy["score"]) == float(s_legacy["score_legacy"])
    assert float(s_paper["score"]) == float(s_paper["score_paper"])


def test_paper_score_monotonicity_with_higher_stage_severity():
    hsg = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    stages = {"r1": 1}

    low = rank_hsg_scenarios(
        hsg,
        rule_severity={"r1": 2.0},
        score_mode="paper",
        rule_stage=stages,
        top_k=1,
    )[0]["score_paper"]
    high = rank_hsg_scenarios(
        hsg,
        rule_severity={"r1": 10.0},
        score_mode="paper",
        rule_stage=stages,
        top_k=1,
    )[0]["score_paper"]

    assert float(high) > float(low)


def test_paper_score_edge_cases_empty_and_single_stage():
    empty = rank_hsg_scenarios(HSG(nodes=[], edges=[]), score_mode="paper", top_k=1)[0]
    assert float(empty["score"]) == 1.0
    assert float(empty["score_paper"]) == 1.0
    assert empty["threat_tuple"] == [0.0] * 7

    hsg = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    one_stage = rank_hsg_scenarios(
        hsg,
        score_mode="paper",
        rule_stage={"r1": 6},
        rule_cvss={"r1": 8.0},
        top_k=1,
    )[0]
    non_zero = [x for x in one_stage["threat_tuple"] if float(x) > 0.0]
    assert len(non_zero) == 1
    assert abs(float(one_stage["score_paper"]) - 1.8) <= 1e-9


def test_paper_score_matches_manual_weighted_product():
    hsg = HSG(
        nodes=[HSGNode(match_id="m1", rule_id="r1"), HSGNode(match_id="m2", rule_id="r2")],
        edges=[HSGEdge(src="m1", dst="m2", relation="shared_entity")],
    )
    stages = {"r1": 1, "r2": 6}
    severities = {"r1": 2.0, "r2": 8.0}
    weights = [1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 1.0]

    score = rank_hsg_scenarios(
        hsg,
        score_mode="paper",
        rule_stage=stages,
        rule_cvss=severities,
        paper_weights=weights,
        top_k=1,
    )[0]["score_paper"]

    expected = (1.0 + 2.0 / 10.0) ** 1.0 * (1.0 + 8.0 / 10.0) ** 2.0
    assert abs(float(score) - expected) <= 1e-9


def test_paper_weights_length_validation_in_scorer():
    hsg = HSG(nodes=[HSGNode(match_id="m1", rule_id="r1")], edges=[])
    try:
        rank_hsg_scenarios(
            hsg,
            score_mode="paper",
            rule_stage={"r1": 1},
            rule_cvss={"r1": 6.0},
            paper_weights=[1.0] * 6,
            top_k=1,
        )
    except ValueError as exc:
        assert str(exc) == "paper_weights must contain exactly 7 values"
    else:
        raise AssertionError("Expected ValueError for invalid paper_weights length")


def test_paper_score_golden_exact_sample_fixture(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    result = run_pipeline(
        str(events_path),
        str(rules_path),
        str(tmp_path / "out_paper_golden"),
        scoring_mode="paper",
        paper_mode="strict",
    )
    assert result["summary"]["top_scenarios"][0]["score_paper"] == pytest.approx(6.8267694320176995)


def test_summary_exposes_paper_scoring_fields(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    result = run_pipeline(
        str(events_path),
        str(rules_path),
        str(tmp_path / "out_paper_fields"),
        scoring_mode="paper",
        paper_mode="strict",
        paper_weights="1.1,1.2,1.3,1.4,1.5,1.6,1.7",
    )
    ps = result["summary"]["paper_scoring"]
    assert "threat_tuple" in ps
    assert "stage_severity" in ps
    assert "paper_weights" in ps
    assert "score_paper" in ps
