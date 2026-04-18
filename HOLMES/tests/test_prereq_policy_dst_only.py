from pathlib import Path

from engine.cli.run_pipeline import run_pipeline


def _write_rules(path: Path, left_prereqs: str, right_prereqs: str) -> None:
    path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_A",
                "    name: left",
                "    event_predicate:",
                "      event_type: proc_to_file",
                f"    prerequisites: {left_prereqs}",
                "  - rule_id: R_B",
                "    name: right",
                "    event_predicate:",
                "      event_type: file_to_ip",
                f"    prerequisites: {right_prereqs}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _graph_path_edges(result: dict) -> list[dict]:
    return [e for e in result["hsg"]["edges"] if e.get("relation") == "graph_path"]


def test_dst_only_no_graph_path_when_dst_rule_does_not_require_it(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_rules(rules_path, "[]", "[]")

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_dst_none"),
        scoring_mode="paper",
        paper_mode="strict",
        prereq_policy="dst_only",
    )

    assert _graph_path_edges(result) == []


def test_dst_only_graph_path_when_dst_rule_requires_it(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_rules(rules_path, "[]", "[graph_path]")

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_dst_req"),
        scoring_mode="paper",
        paper_mode="strict",
        prereq_policy="dst_only",
    )

    assert len(_graph_path_edges(result)) >= 1


def test_union_policy_preserves_legacy_behavior_vs_dst_only(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_rules(rules_path, "[graph_path]", "[]")

    dst_only = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_dst_only"),
        scoring_mode="paper",
        paper_mode="strict",
        prereq_policy="dst_only",
    )
    union = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out_union"),
        scoring_mode="paper",
        paper_mode="strict",
        prereq_policy="union",
    )

    assert _graph_path_edges(dst_only) == []
    assert len(_graph_path_edges(union)) >= 1
