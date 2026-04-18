import json
from pathlib import Path

from engine.cli.run_pipeline import run_pipeline
from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.builder import is_graph_path_candidate
from engine.io.events import Event


def test_graph_path_created_without_allowlist_for_general_ruleset(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = tmp_path / "rules.yaml"
    out_dir = tmp_path / "out"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_PROC_FILE",
                "    name: left",
                "    source_types: [process]",
                "    target_types: [file]",
                "    event_predicate:",
                "      event_type: proc_to_file",
                "  - rule_id: R_FILE_IP",
                "    name: right",
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

    run_pipeline(
        str(events_path),
        str(rules_path),
        str(out_dir),
        scoring_mode="paper",
        paper_mode="strict",
    )
    h = json.loads((out_dir / "hsg.json").read_text(encoding="utf-8"))
    assert any(e.get("relation") == "graph_path" for e in h.get("edges", []))


def test_graph_path_candidate_pruning_sanity_for_unrelated_matches():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="flow", subject="proc:a", object="file:x", raw={}),
            Event(event_id="e2", ts=None, event_type="flow", subject="reg:r", object="ip:z", raw={}),
        ]
    )
    left = TTPMatch(match_id="m1", rule_id="r1", entities=["proc:a", "file:x"], bindings={"object": "file:x"})
    right = TTPMatch(match_id="m2", rule_id="r2", entities=["reg:r", "ip:z"], bindings={"object": "ip:z"})
    assert not is_graph_path_candidate(g, left, right)


def test_max_graph_path_candidates_per_match_limits_edges(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_base = tmp_path / "out_base"
    out_limited = tmp_path / "out_limited"

    run_pipeline(
        str(events_path),
        str(rules_path),
        str(out_base),
        scoring_mode="paper",
        paper_mode="strict",
        max_graph_path_candidates_per_match=200,
    )
    base_hsg = json.loads((out_base / "hsg.json").read_text(encoding="utf-8"))
    base_count = len([e for e in base_hsg.get("edges", []) if e.get("relation") == "graph_path"])
    assert base_count >= 1

    run_pipeline(
        str(events_path),
        str(rules_path),
        str(out_limited),
        scoring_mode="paper",
        paper_mode="strict",
        max_graph_path_candidates_per_match=0,
    )
    limited_hsg = json.loads((out_limited / "hsg.json").read_text(encoding="utf-8"))
    limited_count = len([e for e in limited_hsg.get("edges", []) if e.get("relation") == "graph_path"])
    assert limited_count == 0
