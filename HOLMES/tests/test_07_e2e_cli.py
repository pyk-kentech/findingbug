import json
from pathlib import Path

import engine.hsg.builder as hsg_builder
from engine.cli.run_pipeline import run_pipeline


def test_run_pipeline_e2e_empty_rules_creates_output_dir_files(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    out_dir = tmp_path / "out"

    events_path.write_text(
        "\n".join(
            [
                '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}',
                '{"event_id":"e2","event_type":"file_to_ip","subject":"file:x","object":"ip:1.2.3.4"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rules_path.write_text("rules: []\n", encoding="utf-8")

    result = run_pipeline(str(events_path), str(rules_path), str(out_dir))

    assert out_dir.exists() and out_dir.is_dir()

    result_path = out_dir / "result.json"
    summary_path = out_dir / "summary.json"
    matches_path = out_dir / "matches.json"
    hsg_path = out_dir / "hsg.json"
    dropped_path = out_dir / "debug" / "dropped_matches.jsonl"

    assert result_path.exists()
    assert summary_path.exists()
    assert matches_path.exists()
    assert hsg_path.exists()
    assert dropped_path.exists()

    on_disk_result = json.loads(result_path.read_text(encoding="utf-8"))
    on_disk_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    on_disk_matches = json.loads(matches_path.read_text(encoding="utf-8"))
    on_disk_hsg = json.loads(hsg_path.read_text(encoding="utf-8"))

    assert result["summary"]["rules"] == 0
    assert result["summary"]["matches"] == 0
    assert result["hsg"]["nodes"] == []
    assert result["hsg"]["edges"] == []

    assert on_disk_result["summary"]["matches"] == 0
    assert on_disk_summary["matches"] == 0
    assert on_disk_matches == []
    assert on_disk_hsg == {"nodes": [], "edges": []}


def test_run_pipeline_sample_with_test_rules_has_expected_matches_and_hsg_relations(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out"

    result = run_pipeline(str(events_path), str(rules_path), str(out_dir))
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))

    assert result["summary"]["matches"] == 4
    assert summary["matches"] == 4
    assert summary["noise_filter"]["dropped"]["matches"] == 0
    hsg = json.loads((out_dir / "hsg.json").read_text(encoding="utf-8"))
    relations = [edge["relation"] for edge in hsg["edges"]]
    assert relations.count("shared_entity") == 1
    assert relations.count("graph_path") >= 1
    # Unified MAC model: graph_path weight is inverse |MAC|, which is 1.0 on the sample chain.
    assert abs(float(summary["top_scenarios"][0]["score"]) - 4.0) <= 1e-9


def test_graph_path_directionality_by_flipped_binding_config(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = tmp_path / "rules_direction.yaml"
    out_ok = tmp_path / "out_ok"
    out_rev = tmp_path / "out_rev"

    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: TEST_PROC_TO_PROC_GP",
                "    name: direction test left",
                "    source_types: [process]",
                "    target_types: [process]",
                "    prerequisites: [graph_path]",
                "    event_predicate:",
                "      event_type: proc_to_proc",
                "  - rule_id: TEST_FILE_TO_IP_GP",
                "    name: direction test right",
                "    source_types: [file]",
                "    target_types: [ip]",
                "    prerequisites: [graph_path]",
                "    event_predicate:",
                "      event_type: file_to_ip",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        hsg_builder,
        "GRAPH_PATH_ALLOWLIST",
        {("TEST_PROC_TO_PROC_GP", "TEST_FILE_TO_IP_GP")},
    )
    monkeypatch.setattr(
        hsg_builder,
        "PREREQ_CONFIG",
        {"graph_path": {"from_binding": "subject", "to_binding": "object", "max_path_factor": "0.0"}},
    )
    run_pipeline(str(events_path), str(rules_path), str(out_ok))
    hsg_ok = json.loads((out_ok / "hsg.json").read_text(encoding="utf-8"))
    rel_ok = [e["relation"] for e in hsg_ok["edges"]]
    assert "graph_path" in rel_ok

    monkeypatch.setattr(
        hsg_builder,
        "PREREQ_CONFIG",
        {"graph_path": {"from_binding": "object", "to_binding": "subject", "max_path_factor": "0.0"}},
    )
    run_pipeline(str(events_path), str(rules_path), str(out_rev))
    hsg_rev = json.loads((out_rev / "hsg.json").read_text(encoding="utf-8"))
    rel_rev = [e["relation"] for e in hsg_rev["edges"]]
    assert "graph_path" not in rel_rev


def test_graph_path_edge_weight_is_serialized_and_positive(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out"

    run_pipeline(str(events_path), str(rules_path), str(out_dir))
    hsg = json.loads((out_dir / "hsg.json").read_text(encoding="utf-8"))
    nodes = {n["match_id"]: n["rule_id"] for n in hsg["nodes"]}

    target_edges = [
        e
        for e in hsg["edges"]
        if e["relation"] == "graph_path"
        and nodes[e["src"]] == "TEST_PROC_TO_FILE"
        and nodes[e["dst"]] == "TEST_FILE_TO_IP"
    ]
    assert target_edges
    weight = float(target_edges[0]["weight"])
    assert weight > 0.0
    assert abs(weight - 1.0) <= 1e-9


def test_run_pipeline_alpha_changes_top_scenario_score(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out0 = tmp_path / "out0"
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"

    s0 = run_pipeline(str(events_path), str(rules_path), str(out0), alpha=0.0)["summary"]["top_scenarios"][0]["score"]
    s1 = run_pipeline(str(events_path), str(rules_path), str(out1), alpha=1.0)["summary"]["top_scenarios"][0]["score"]
    s2 = run_pipeline(str(events_path), str(rules_path), str(out2), alpha=2.0)["summary"]["top_scenarios"][0]["score"]

    assert abs(float(s0) - 3.0) <= 1e-9
    assert abs(float(s1) - 4.0) <= 1e-9
    assert abs(float(s2) - 5.0) <= 1e-9
