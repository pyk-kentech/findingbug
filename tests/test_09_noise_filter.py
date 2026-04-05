import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.builder import build_hsg
from engine.io.events import Event
from engine.noise.filter import NoiseConfig, apply_noise_filter
from engine.rules.schema import Rule, RuleSet


def test_noise_filter_records_before_after_counts(tmp_path):
    events_path = tmp_path / "events.jsonl"
    rules_path = tmp_path / "rules.yaml"
    noise_path = tmp_path / "noise.yaml"
    out_dir = tmp_path / "out"

    events_path.write_text(
        '{"event_id":"e1","op":"exec","event_type":"exec","subject":"proc:p","object":"file:/bin/x"}\n',
        encoding="utf-8",
    )
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: r_keep_1",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
                "  - rule_id: r_keep_2",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
                "  - rule_id: r_drop",
                "    name: test",
                "    event_predicate:",
                "      op: exec",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    noise_path.write_text(
        "\n".join(
            [
                "drop:",
                "  rule_id: [r_drop]",
                "  prerequisite_type: [shared_entity]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_pipeline(str(events_path), str(rules_path), str(out_dir), noise_path=str(noise_path))
    summary = result["summary"]
    noise = summary["noise_filter"]

    assert noise["before"]["matches"] == 3
    assert noise["before"]["hsg_nodes"] == 3
    assert noise["before"]["hsg_edges"] == 0
    assert noise["after"]["matches"] == 2
    assert noise["after"]["hsg_nodes"] == 2
    assert noise["after"]["hsg_edges"] == 0
    assert noise["dropped"]["matches"] == 1
    assert noise["dropped"]["hsg_edges"] == 0

    on_disk_summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert on_disk_summary["noise_filter"]["after"]["matches"] == 2


def test_noise_filter_drop_rule_ids_affects_final_outputs_with_sample_data(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    noise_path = tmp_path / "noise.yaml"
    out_dir = tmp_path / "out"

    noise_path.write_text("drop_rule_ids: [TEST_PROC_TO_FILE]\n", encoding="utf-8")

    run_pipeline(str(events_path), str(rules_path), str(out_dir), noise_path=str(noise_path))

    matches = json.loads((out_dir / "matches.json").read_text(encoding="utf-8"))
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    result = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))

    assert summary["matches"] == 2
    assert result["summary"]["matches"] == 2
    assert summary["noise_filter"]["before"]["matches"] == 4
    assert summary["noise_filter"]["after"]["matches"] == 2
    assert summary["noise_filter"]["dropped"]["matches"] == 2
    assert len(matches) == 2
    assert [m["rule_id"] for m in matches] == ["TEST_FILE_TO_IP", "TEST_PROC_TO_PROC"]


def test_min_graph_path_weight_drops_graph_path_edges_and_reduces_score(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_base = tmp_path / "out_base"
    out_filtered = tmp_path / "out_filtered"

    baseline = run_pipeline(str(events_path), str(rules_path), str(out_base), alpha=1.0)
    filtered = run_pipeline(
        str(events_path),
        str(rules_path),
        str(out_filtered),
        alpha=1.0,
        min_graph_path_weight=1.1,
    )

    hsg_filtered = json.loads((out_filtered / "hsg.json").read_text(encoding="utf-8"))
    graph_path_edges = [e for e in hsg_filtered["edges"] if e["relation"] == "graph_path"]

    assert graph_path_edges == []
    assert filtered["summary"]["noise_filter"]["before"]["hsg_edges"] > filtered["summary"]["noise_filter"]["after"]["hsg_edges"]
    assert filtered["summary"]["noise_filter"]["dropped"]["hsg_edges"] >= 1
    assert float(filtered["summary"]["top_scenarios"][0]["score"]) < float(baseline["summary"]["top_scenarios"][0]["score"])


def test_min_path_factor_filters_graph_path_edges_on_parallel_paths_without_file_io():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="proc:A", object="proc:X", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="proc:X", object="proc:B", raw={}),
            Event(event_id="e3", ts=None, event_type="flow", subject="proc:A", object="proc:Y", raw={}),
            Event(event_id="e4", ts=None, event_type="flow", subject="proc:Y", object="proc:B", raw={}),
        ]
    )
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="TEST_PROC_TO_FILE", name="left", prerequisites=["graph_path"]),
            Rule(rule_id="TEST_FILE_TO_IP", name="right", prerequisites=["graph_path"]),
        ]
    )
    matches = [
        TTPMatch(match_id="m1", rule_id="TEST_PROC_TO_FILE", bindings={"object": "proc:A"}),
        TTPMatch(match_id="m2", rule_id="TEST_FILE_TO_IP", bindings={"object": "proc:B"}),
    ]
    hsg_before = build_hsg(matches, g, ruleset)
    assert any(e.relation == "graph_path" for e in hsg_before.edges)

    _, hsg_drop = apply_noise_filter(matches, hsg_before, NoiseConfig(min_path_factor=1.1))
    _, hsg_keep = apply_noise_filter(matches, hsg_before, NoiseConfig(min_path_factor=1.0))

    assert all(e.relation != "graph_path" for e in hsg_drop.edges)
    assert any(e.relation == "graph_path" for e in hsg_keep.edges)


def test_min_path_factor_cli_drops_graph_path_and_reduces_score(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_base = tmp_path / "out_base_pf"
    out_filtered = tmp_path / "out_filtered_pf"

    base = run_pipeline(str(events_path), str(rules_path), str(out_base), alpha=1.0)
    filt = run_pipeline(
        str(events_path),
        str(rules_path),
        str(out_filtered),
        alpha=1.0,
        min_path_factor=1.1,
    )

    hsg_filtered = json.loads((out_filtered / "hsg.json").read_text(encoding="utf-8"))
    assert [e for e in hsg_filtered["edges"] if e["relation"] == "graph_path"] == []
    assert float(filt["summary"]["top_scenarios"][0]["score"]) < float(base["summary"]["top_scenarios"][0]["score"])
