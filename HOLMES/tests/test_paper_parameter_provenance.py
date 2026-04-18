from __future__ import annotations

import json

import pytest

from experiments.parameters import load_paper_parameters
from experiments.pipeline import run_experiment


def test_priority_paper_defaults_not_overridden_by_assumptions(tmp_path):
    paper = tmp_path / "paper.yaml"
    ass = tmp_path / "ass.yaml"
    doc = tmp_path / "paper_parameters.md"
    paper.write_text(
        "\n".join(
            [
                "stage_order:",
                "  value: [Initial Compromise, Establish Foothold, Internal Recon, Privilege Escalation, Move Laterally, Exfiltration, Cleanup]",
                "  source: {section: s, page: 8, note: n}",
                "tau:",
                "  value: 999",
                "  source: {section: s, page: 12, note: n}",
                "severity_mapping:",
                "  value: {Low: 2, Medium: 6, High: 8, Critical: 10}",
                "  source: {section: s, page: 8, note: n}",
                "missing_stage_value:",
                "  value: 1",
                "  source: {section: s, page: 8, note: n}",
            ]
        ),
        encoding="utf-8",
    )
    ass.write_text(
        "\n".join(
            [
                "tau:",
                "  value: 123",
                "  WHY: a",
                "  IMPACT: b",
                "fallback_weights:",
                "  value: [1,1,1,1,1,1,1]",
                "  WHY: a",
                "  IMPACT: b",
            ]
        ),
        encoding="utf-8",
    )
    doc.write_text(
        "\n".join(
            [
                "| `key` | x | x | x | x |",
                "|---|---|---|---|---|",
                "| `stage_order` | | | | |",
                "| `tau` | | | | |",
                "| `severity_mapping` | | | | |",
                "| `missing_stage_value` | | | | |",
                "| `fallback_weights` | | | | |",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cannot override"):
        load_paper_parameters(paper_defaults_path=paper, assumptions_path=ass, docs_path=doc)


def test_missing_tau_fails_fast(tmp_path):
    paper = tmp_path / "paper.yaml"
    ass = tmp_path / "ass.yaml"
    doc = tmp_path / "paper_parameters.md"
    paper.write_text(
        "\n".join(
            [
                "stage_order:",
                "  value: [Initial Compromise, Establish Foothold, Internal Recon, Privilege Escalation, Move Laterally, Exfiltration, Cleanup]",
                "  source: {section: s, page: 8, note: n}",
                "severity_mapping:",
                "  value: {Low: 2, Medium: 6, High: 8, Critical: 10}",
                "  source: {section: s, page: 8, note: n}",
                "missing_stage_value:",
                "  value: 1",
                "  source: {section: s, page: 8, note: n}",
            ]
        ),
        encoding="utf-8",
    )
    ass.write_text(
        "\n".join(
            [
                "fallback_weights:",
                "  value: [1,1,1,1,1,1,1]",
                "  WHY: a",
                "  IMPACT: b",
            ]
        ),
        encoding="utf-8",
    )
    doc.write_text(
        "\n".join(
            [
                "| `key` | x | x | x | x |",
                "|---|---|---|---|---|",
                "| `stage_order` | | | | |",
                "| `severity_mapping` | | | | |",
                "| `missing_stage_value` | | | | |",
                "| `fallback_weights` | | | | |",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tau missing"):
        load_paper_parameters(paper_defaults_path=paper, assumptions_path=ass, docs_path=doc)


def test_metrics_include_digests_and_provenance():
    result = run_experiment(
        {
            "seed": 1,
            "scenario_type": "mixed",
            "num_campaigns": 2,
            "campaign_window_events": 20,
            "noise_injection_rate": 0.2,
            "enable_memory_profile": False,
            "paper_defaults_path": "configs/paper_defaults.yaml",
            "assumptions_path": "configs/assumptions.yaml",
            "paper_parameters_doc_path": "docs/paper_parameters.md",
        }
    )
    m = result["metrics"]
    for key in (
        "paper_defaults_path",
        "paper_defaults_digest",
        "assumptions_path",
        "assumptions_digest",
        "stage_order_digest",
        "parameter_provenance",
    ):
        assert key in m
    prov = m["parameter_provenance"]
    assert "tau" in prov and "weights" in prov and "stage_order" in prov
    tau_prov = prov["tau"]
    assert ("page" in tau_prov and "section" in tau_prov) or ("WHY" in tau_prov and "IMPACT" in tau_prov)
