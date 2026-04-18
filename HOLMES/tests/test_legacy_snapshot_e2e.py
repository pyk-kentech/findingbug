from pathlib import Path

from engine.cli.run_pipeline import run_pipeline


def test_legacy_mode_snapshot_byte_for_byte(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_legacy_snapshot"
    fixture_dir = repo_root / "tests" / "fixtures" / "legacy_snapshot"

    run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_dir),
        scoring_mode="legacy",
    )

    for name in ("summary.json", "result.json", "hsg.json", "matches.json"):
        actual = (out_dir / name).read_text(encoding="utf-8")
        expected = (fixture_dir / name).read_text(encoding="utf-8")
        assert actual == expected, f"legacy snapshot mismatch: {name}"
