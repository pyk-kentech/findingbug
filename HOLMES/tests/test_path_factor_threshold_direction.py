from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.core.graph import path_factor_passes


def test_path_factor_op_ge_behaviour():
    assert path_factor_passes(1.0, 0.9, "ge")
    assert not path_factor_passes(1.0, 1.1, "ge")


def test_path_factor_op_le_behaviour():
    assert path_factor_passes(1.0, 1.1, "le")
    assert not path_factor_passes(2.0, 1.1, "le")


def test_cli_path_factor_op_le_keeps_edges_that_ge_drops(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    ge = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_ge"),
        scoring_mode="paper",
        paper_mode="strict",
        min_path_factor=1.1,
        path_factor_op="ge",
    )
    le = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_le"),
        scoring_mode="paper",
        paper_mode="strict",
        min_path_factor=1.1,
        path_factor_op="le",
    )

    ge_graph_path = [e for e in ge["hsg"]["edges"] if e.get("relation") == "graph_path"]
    le_graph_path = [e for e in le["hsg"]["edges"] if e.get("relation") == "graph_path"]

    assert ge_graph_path == []
    assert len(le_graph_path) >= 1
