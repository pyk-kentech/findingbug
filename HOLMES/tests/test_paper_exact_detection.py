import math

from engine.io.events import Event
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.hsg.paper_exact import IncrementalPaperExactScorer


def test_paper_exact_formula_matches_product():
    scorer = IncrementalPaperExactScorer(weights=[1.0] * 7, tau=None)
    scorer.update(stage=1, raw_severity=2.0, event_time=None, sequence=1)
    scorer.update(stage=2, raw_severity=6.0, event_time=None, sequence=2)
    assert scorer.state.stage_severity == [2.0, 6.0, 1.0, 1.0, 1.0, 1.0, 1.0]
    assert scorer.state.score == 12.0


def test_paper_exact_log_compare_uses_log_tau():
    scorer = IncrementalPaperExactScorer(weights=[1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0], tau=216.0)
    scorer.update(stage=1, raw_severity=6.0, event_time=None, sequence=1)
    scorer.update(stage=2, raw_severity=6.0, event_time=None, sequence=2)
    scorer.update(stage=3, raw_severity=6.0, event_time=None, sequence=3)
    assert abs(scorer.state.score - 216.0) <= 1e-9
    assert scorer.state.log_score >= math.log(216.0)
    assert scorer.state.detected is True


def test_streaming_incremental_tuple_and_tau_trigger(monkeypatch, tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: r1",
                "    name: stage1",
                "    stage: 1",
                "    cvss: 6.0",
                "    event_predicate:",
                "      event_type: e1",
                "  - rule_id: r2",
                "    name: stage2",
                "    stage: 2",
                "    cvss: 6.0",
                "    event_predicate:",
                "      event_type: e2",
                "  - rule_id: r3",
                "    name: stage3",
                "    stage: 3",
                "    cvss: 6.0",
                "    event_predicate:",
                "      event_type: e3",
            ]
        ),
        encoding="utf-8",
    )
    ruleset = load_rules_yaml(rules_path)

    # paper_exact must not depend on full HSG rescoring path.
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("rank_hsg_scenarios must not be called in paper_exact mode")

    monkeypatch.setattr("engine.stream.runner.rank_hsg_scenarios", _boom)

    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper_exact",
        paper_weights=[1.0] * 7,
        tau=216.0,
        paper_mode="strict",
    )
    events = [
        Event(event_id="e1", ts="2026-01-01T00:00:01Z", event_type="e1", subject="proc:a", object="file:a", raw={}),
        Event(event_id="e2", ts="2026-01-01T00:00:02Z", event_type="e2", subject="proc:b", object="file:b", raw={}),
        Event(event_id="e3", ts="2026-01-01T00:00:03Z", event_type="e3", subject="proc:c", object="file:c", raw={}),
    ]
    for ev in events:
        engine.process_event(ev)

    summary = engine.build_result()["summary"]
    ps = summary["paper_scoring"]
    assert ps["threat_tuple"][:3] == [6.0, 6.0, 6.0]
    assert abs(float(ps["score_paper_exact"]) - 216.0) <= 1e-9
    assert ps["apt_detected"] is True
    assert ps["first_detection_sequence"] == 3
    assert [x["stage_index"] for x in ps["first_detection_contributing_stages"]] == [1, 2, 3]
