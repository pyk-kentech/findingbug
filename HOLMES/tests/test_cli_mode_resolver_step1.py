from pathlib import Path

from engine.cli.run_pipeline import _build_parser, run_pipeline


def test_parser_min_path_factor_default_is_none():
    parser = _build_parser()
    args = parser.parse_args(["--events", "x.jsonl", "--rules", "r.yaml", "--out", "out"])
    assert args.min_path_factor is None


def test_paper_mode_resolver_applies_default_path_thres_and_op(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_paper_default"),
        scoring_mode="paper",
        paper_mode="strict",
        min_path_factor=None,
        path_factor_op=None,
        paper_weights="1.1,1.2,1.3,1.4,1.5,1.6,1.7",
    )

    resolved = result["summary"]["resolved_effective_config"]
    assert resolved["path_thres"] == 3.0
    assert resolved["path_factor_op"] == "le"
    assert resolved["scoring"] == "paper"
    assert resolved["paper_mode"] == "strict"
    assert resolved["paper_weights"] == [1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7]


def test_paper_mode_resolver_respects_user_overrides(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_paper_user"),
        scoring_mode="paper",
        paper_mode="strict",
        min_path_factor=5.0,
        path_factor_op="ge",
    )

    resolved = result["summary"]["resolved_effective_config"]
    assert resolved["path_thres"] == 5.0
    assert resolved["path_factor_op"] == "ge"


def test_legacy_mode_default_behavior_matches_explicit_legacy_defaults(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    implicit = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_legacy_implicit"),
        scoring_mode="legacy",
        min_path_factor=None,
        path_factor_op=None,
    )
    explicit = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_legacy_explicit"),
        scoring_mode="legacy",
        min_path_factor=0.0,
        path_factor_op="ge",
    )

    assert implicit["hsg"] == explicit["hsg"]
    assert implicit["matches"] == explicit["matches"]
    assert implicit["summary"]["top_scenarios"] == explicit["summary"]["top_scenarios"]
    assert implicit["summary"]["noise_filter"] == explicit["summary"]["noise_filter"]
    assert implicit["summary"]["events"] == explicit["summary"]["events"]
    assert implicit["summary"]["rules"] == explicit["summary"]["rules"]
    assert implicit["summary"]["matches"] == explicit["summary"]["matches"]
