import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
import engine.hsg.builder as hsg_builder
import engine.noise.filter as noise_filter


def _write_events(path: Path) -> None:
    events = [
        {
            "event_id": "e1",
            "event_type": "proc_to_file",
            "subject": "proc:a",
            "object": "file:x",
        },
        {
            "event_id": "e2",
            "event_type": "file_to_ip",
            "subject": "file:x",
            "object": "ip:10.0.0.1",
        },
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def _write_rules(path: Path, right_prereq_yaml: str) -> None:
    path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_LEFT",
                "    name: left",
                "    source_types: [process]",
                "    target_types: [file]",
                "    prerequisites: []",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "  - rule_id: R_RIGHT",
                "    name: right",
                "    source_types: [file]",
                "    target_types: [ip]",
                "    prerequisites:",
                *[f"      {line}" for line in right_prereq_yaml.splitlines()],
                "    event_predicate:",
                "      event_type: file_to_ip",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_prerequisite_only_calls_prereq_pf_not_pruning_pf(tmp_path, monkeypatch):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_events(events_path)
    _write_rules(
        rules_path,
        "- graph_path\n- type: path_factor\n  max_path_factor: 1",
    )

    counts = {"prereq_pf": 0, "pruning_pf": 0}
    orig_prereq_pf = hsg_builder.is_path_factor_satisfied
    orig_pruning_pf = noise_filter.passes_global_path_factor_pruning

    def _spy_prereq_pf(*args, **kwargs):
        counts["prereq_pf"] += 1
        return orig_prereq_pf(*args, **kwargs)

    def _spy_pruning_pf(*args, **kwargs):
        counts["pruning_pf"] += 1
        return orig_pruning_pf(*args, **kwargs)

    monkeypatch.setattr(hsg_builder, "is_path_factor_satisfied", _spy_prereq_pf)
    monkeypatch.setattr(noise_filter, "passes_global_path_factor_pruning", _spy_pruning_pf)

    run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out"),
        scoring_mode="legacy",
    )

    assert counts["prereq_pf"] == 1
    assert counts["pruning_pf"] == 0


def test_pruning_only_calls_pruning_pf_not_prereq_pf(tmp_path, monkeypatch):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_events(events_path)
    _write_rules(rules_path, "- graph_path")

    counts = {"prereq_pf": 0, "pruning_pf": 0}
    orig_prereq_pf = hsg_builder.is_path_factor_satisfied
    orig_pruning_pf = noise_filter.passes_global_path_factor_pruning

    def _spy_prereq_pf(*args, **kwargs):
        counts["prereq_pf"] += 1
        return orig_prereq_pf(*args, **kwargs)

    def _spy_pruning_pf(*args, **kwargs):
        counts["pruning_pf"] += 1
        return orig_pruning_pf(*args, **kwargs)

    monkeypatch.setattr(hsg_builder, "is_path_factor_satisfied", _spy_prereq_pf)
    monkeypatch.setattr(noise_filter, "passes_global_path_factor_pruning", _spy_pruning_pf)

    run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out"),
        scoring_mode="paper",
        paper_mode="strict",
    )

    assert counts["prereq_pf"] == 0
    assert counts["pruning_pf"] == 1


def test_both_paths_call_once_each_without_duplicate_filtering(tmp_path, monkeypatch):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    _write_events(events_path)
    _write_rules(
        rules_path,
        "- graph_path\n- type: path_factor\n  max_path_factor: 1",
    )

    counts = {"prereq_pf": 0, "pruning_pf": 0}
    orig_prereq_pf = hsg_builder.is_path_factor_satisfied
    orig_pruning_pf = noise_filter.passes_global_path_factor_pruning

    def _spy_prereq_pf(*args, **kwargs):
        counts["prereq_pf"] += 1
        return orig_prereq_pf(*args, **kwargs)

    def _spy_pruning_pf(*args, **kwargs):
        counts["pruning_pf"] += 1
        return orig_pruning_pf(*args, **kwargs)

    monkeypatch.setattr(hsg_builder, "is_path_factor_satisfied", _spy_prereq_pf)
    monkeypatch.setattr(noise_filter, "passes_global_path_factor_pruning", _spy_pruning_pf)

    result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(tmp_path / "out"),
        scoring_mode="paper",
        paper_mode="strict",
    )

    assert counts["prereq_pf"] == 2
    assert counts["pruning_pf"] == 1
    assert any(e.get("relation") == "graph_path" for e in result["hsg"]["edges"])
