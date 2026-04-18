import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline


def test_graph_path_edges_have_integer_path_factor_ge_one(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_pf_inv"),
        scoring_mode="paper",
        paper_mode="strict",
    )

    graph_path_edges = [e for e in result["hsg"]["edges"] if e.get("relation") == "graph_path"]
    assert graph_path_edges
    for edge in graph_path_edges:
        assert "path_factor" in edge
        pf = edge["path_factor"]
        assert isinstance(pf, (int, float))
        assert float(pf) >= 1.0
        assert float(pf).is_integer()


def test_output_json_files_do_not_contain_path_factor_zero(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_scan"

    run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_dir),
        scoring_mode="paper",
        paper_mode="strict",
    )

    for name in ("result.json", "summary.json", "hsg.json", "matches.json"):
        text = (out_dir / name).read_text(encoding="utf-8")
        assert '"path_factor": 0' not in text
        assert '"path_factor": 0.0' not in text

        payload = json.loads(text)

        def _scan(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k == "path_factor":
                        assert v != 0
                        assert v != 0.0
                    _scan(v)
            elif isinstance(value, list):
                for item in value:
                    _scan(item)

        _scan(payload)
