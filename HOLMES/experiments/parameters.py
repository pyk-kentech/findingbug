from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

import yaml

from engine.rules.schema import APT_STAGES


CORE_KEYS = ("stage_order", "tau", "weights")


@dataclass(slots=True)
class ResolvedPaperParameters:
    stage_order: list[str]
    tau: float
    weights: list[float]
    paper_defaults_path: str
    paper_defaults_digest: str
    assumptions_path: str
    assumptions_digest: str
    stage_order_digest: str
    parameter_provenance: dict[str, Any]
    paper_defaults_source: dict[str, Any]


def _load_yaml(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}")
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"YAML root must be object: {p}")
    return payload


def _digest(path: str | Path) -> str:
    blob = Path(path).read_bytes()
    return hashlib.sha256(blob).hexdigest()


def _has_assumption_marker(x: Any) -> bool:
    if isinstance(x, dict):
        if "WHY" in x or "IMPACT" in x:
            return True
        return any(_has_assumption_marker(v) for v in x.values())
    if isinstance(x, list):
        return any(_has_assumption_marker(v) for v in x)
    return False


def _validate_paper_defaults(paper: dict[str, Any]) -> None:
    if _has_assumption_marker(paper):
        raise ValueError("paper_defaults.yaml must not contain WHY/IMPACT (assumptions are forbidden)")
    for key, value in paper.items():
        if key == "meta":
            continue
        if not isinstance(value, dict):
            raise ValueError(f"paper_defaults.{key} must be object with value/source")
        source = value.get("source")
        if not isinstance(source, dict):
            raise ValueError(f"paper_defaults.{key}.source must be object")
        page = source.get("page")
        if not isinstance(page, int):
            raise ValueError(f"paper_defaults.{key}.source.page must be integer")
        if not isinstance(source.get("note"), str) or not source.get("note"):
            raise ValueError(f"paper_defaults.{key}.source.note must be non-empty string")


def _validate_assumptions(ass: dict[str, Any]) -> None:
    for key, value in ass.items():
        if key == "meta":
            continue
        if not isinstance(value, dict):
            raise ValueError(f"assumptions.{key} must be object")
        if not isinstance(value.get("WHY"), str) or not value.get("WHY"):
            raise ValueError(f"assumptions.{key}.WHY must be non-empty string")
        if not isinstance(value.get("IMPACT"), str) or not value.get("IMPACT"):
            raise ValueError(f"assumptions.{key}.IMPACT must be non-empty string")


def _doc_keys(path: str | Path) -> set[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Document not found: {p}")
    keys: set[str] = set()
    pattern = re.compile(r"^\|\s*`([^`]+)`\s*\|")
    for line in p.read_text(encoding="utf-8").splitlines():
        m = pattern.match(line.strip())
        if m:
            key = m.group(1)
            if key == "key":
                continue
            keys.add(key)
    return keys


def _validate_docs_sync(paper: dict[str, Any], ass: dict[str, Any], doc_path: str | Path) -> None:
    expected = {k for k in paper.keys() if k != "meta"} | {k for k in ass.keys() if k != "meta"}
    actual = _doc_keys(doc_path)
    if expected != actual:
        raise ValueError(
            "docs/paper_parameters.md keys mismatch. "
            f"expected={sorted(expected)}, actual={sorted(actual)}"
        )


def _extract_value(obj: dict[str, Any], key: str) -> Any:
    x = obj.get(key)
    if not isinstance(x, dict):
        return None
    return x.get("value")


def load_paper_parameters(
    *,
    paper_defaults_path: str | Path,
    assumptions_path: str | Path,
    docs_path: str | Path,
) -> ResolvedPaperParameters:
    paper = _load_yaml(paper_defaults_path)
    ass = _load_yaml(assumptions_path)
    _validate_paper_defaults(paper)
    _validate_assumptions(ass)
    _validate_docs_sync(paper, ass, docs_path)

    # assumptions must not override explicit paper keys
    for k in CORE_KEYS:
        if k in paper and k in ass:
            raise ValueError(f"assumptions.yaml cannot override paper_defaults key: {k}")

    stage_order = _extract_value(paper, "stage_order")
    if not isinstance(stage_order, list) or any(not isinstance(x, str) for x in stage_order):
        raise ValueError("paper_defaults.stage_order.value must be list[str]")
    if len(stage_order) != len(APT_STAGES):
        raise ValueError("stage_order size mismatch with engine stage count")
    if list(stage_order) != list(APT_STAGES):
        raise ValueError("stage_order must exactly match code stage definition to avoid drift")

    tau_val = _extract_value(paper, "tau")
    tau_prov: dict[str, Any]
    if tau_val is None:
        fallback = ass.get("fallback_tau")
        if not isinstance(fallback, dict) or "value" not in fallback:
            raise ValueError("tau missing in both paper_defaults and assumptions(fallback_tau)")
        tau_val = float(fallback["value"])
        tau_prov = {
            "origin": "assumptions",
            "key": "fallback_tau",
            "WHY": fallback.get("WHY"),
            "IMPACT": fallback.get("IMPACT"),
        }
    else:
        tau_val = float(tau_val)
        src = paper["tau"]["source"]
        tau_prov = {"origin": "paper_defaults", "page": src["page"], "section": src.get("section"), "note": src.get("note")}

    w_val = _extract_value(paper, "weights")
    w_prov: dict[str, Any]
    if w_val is None:
        fallback = ass.get("fallback_weights")
        if not isinstance(fallback, dict) or "value" not in fallback:
            raise ValueError("weights missing in both paper_defaults and assumptions(fallback_weights)")
        w_val = fallback["value"]
        w_prov = {
            "origin": "assumptions",
            "key": "fallback_weights",
            "WHY": fallback.get("WHY"),
            "IMPACT": fallback.get("IMPACT"),
        }
    else:
        src = paper["weights"]["source"]
        w_prov = {"origin": "paper_defaults", "page": src["page"], "section": src.get("section"), "note": src.get("note")}
    if not isinstance(w_val, list) or len(w_val) != len(APT_STAGES):
        raise ValueError("weights must be 7-item list")
    weights = [float(x) for x in w_val]

    stage_src = paper["stage_order"]["source"]
    stage_prov = {
        "origin": "paper_defaults",
        "page": stage_src["page"],
        "section": stage_src.get("section"),
        "note": stage_src.get("note"),
    }
    stage_order_digest = hashlib.sha256(
        json.dumps(stage_order, ensure_ascii=True, sort_keys=False).encode("utf-8")
    ).hexdigest()

    return ResolvedPaperParameters(
        stage_order=list(stage_order),
        tau=float(tau_val),
        weights=weights,
        paper_defaults_path=str(Path(paper_defaults_path).resolve()),
        paper_defaults_digest=_digest(paper_defaults_path),
        assumptions_path=str(Path(assumptions_path).resolve()),
        assumptions_digest=_digest(assumptions_path),
        stage_order_digest=stage_order_digest,
        parameter_provenance={"tau": tau_prov, "weights": w_prov, "stage_order": stage_prov},
        paper_defaults_source={
            "stage_order": stage_prov,
            "severity_mapping": paper.get("severity_mapping", {}).get("source"),
            "missing_stage_value": paper.get("missing_stage_value", {}).get("source"),
        },
    )
