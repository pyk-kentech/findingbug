from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


HOLMES_STAGES: tuple[str, ...] = (
    "Initial Compromise",
    "Establish Foothold",
    "Internal Recon",
    "Privilege Escalation",
    "Move Laterally",
    "Exfiltration",
    "Cleanup",
)

STAGE_MAP: dict[str, str] = {
    "initial compromise": "Initial Compromise",
    "initial_access": "Initial Compromise",
    "execution": "Establish Foothold",
    "establish foothold": "Establish Foothold",
    "persistence": "Establish Foothold",
    "c&c communication": "Establish Foothold",
    "c2": "Establish Foothold",
    "command and control": "Establish Foothold",
    "internal recon": "Internal Recon",
    "discovery": "Internal Recon",
    "credential access": "Internal Recon",
    "collection": "Internal Recon",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Privilege Escalation",
    "lateral movement": "Move Laterally",
    "move laterally": "Move Laterally",
    "exfiltration": "Exfiltration",
    "complete mission": "Cleanup",
    "impact": "Cleanup",
    "cleanup": "Cleanup",
}

RELATION_TO_CDR: dict[str, str] = {
    "SPAWN": "spawn",
    "EXECUTE": "execute",
    "READ": "read",
    "WRITE": "write",
    "CREATE": "create",
    "DELETE": "delete",
    "CONNECT": "connect",
}

KNOWN_MODIFIERS: set[str] = {"contains", "endswith", "startswith", "regex", "re", "windash"}


def _normalize_stage(raw_stage: Any) -> str:
    if not isinstance(raw_stage, str) or not raw_stage.strip():
        return "Initial Compromise"
    key = raw_stage.strip().lower()
    return STAGE_MAP.get(key, "Initial Compromise")


def _relation_selector(relation: str) -> dict[str, Any]:
    mapped = RELATION_TO_CDR.get(relation.upper(), relation.lower())
    return {
        "type": "object",
        "items": [
            {
                "type": "field_match",
                "field": "cdr.semantic_relations{}.relation",
                "value": {"type": "literal", "value": mapped},
                "modifiers": [],
            }
        ],
    }


def _value_to_spec(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        return {
            "type": "list",
            "items": [{"type": "literal", "value": str(v)} for v in value],
        }
    return {"type": "literal", "value": str(value)}


def _wildcard_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
    return f"^{escaped}$"


def _normalize_field_match(field_key: str, raw_value: Any) -> dict[str, Any] | None:
    if not isinstance(field_key, str) or not field_key.strip():
        return None
    if raw_value is None:
        return None

    parts = [p for p in field_key.split("|") if p]
    base_field = parts[0]
    modifiers = [m.lower() for m in parts[1:] if m.lower() in KNOWN_MODIFIERS]

    value = raw_value
    if isinstance(raw_value, str) and ("*" in raw_value or "?" in raw_value):
        if not modifiers:
            if raw_value.startswith("*") and raw_value.endswith("*") and len(raw_value) > 2:
                modifiers = ["contains"]
                value = raw_value[1:-1]
            elif raw_value.startswith("*") and len(raw_value) > 1:
                modifiers = ["endswith"]
                value = raw_value[1:]
            elif raw_value.endswith("*") and len(raw_value) > 1:
                modifiers = ["startswith"]
                value = raw_value[:-1]
            else:
                modifiers = ["regex"]
                value = _wildcard_to_regex(raw_value)
        elif "regex" in modifiers or "re" in modifiers:
            value = _wildcard_to_regex(raw_value)

    return {
        "type": "field_match",
        "field": base_field,
        "modifiers": modifiers,
        "value": _value_to_spec(value),
    }


def _attributes_to_selector_items(attrs: Any) -> list[dict[str, Any]]:
    if not isinstance(attrs, dict):
        return []
    out: list[dict[str, Any]] = []
    for key, value in attrs.items():
        fm = _normalize_field_match(str(key), value)
        if fm is not None:
            out.append(fm)
    return out


def _build_sigma_logic(source_rule: dict[str, Any]) -> dict[str, Any]:
    match_logic = source_rule.get("match_logic")
    if not isinstance(match_logic, dict):
        return {
            "engine": "sigma",
            "condition": {"compiled": {"type": "selector_ref", "selector": "sel_any"}},
            "selectors": {
                "sel_any": {
                    "type": "object",
                    "items": [
                        {
                            "type": "field_match",
                            "field": "event_id",
                            "modifiers": [],
                            "value": {"type": "literal", "value": ""},
                        }
                    ],
                }
            },
        }

    relation = str(match_logic.get("relation", "EXECUTE")).upper()
    subject_attrs = {}
    object_attrs = {}
    if isinstance(match_logic.get("subject"), dict):
        subject_attrs = match_logic["subject"].get("attributes", {}) or {}
    if isinstance(match_logic.get("object"), dict):
        object_attrs = match_logic["object"].get("attributes", {}) or {}

    selectors: dict[str, Any] = {
        "sel_relation": _relation_selector(relation),
    }
    operands: list[dict[str, Any]] = [{"type": "selector_ref", "selector": "sel_relation"}]

    subj_items = _attributes_to_selector_items(subject_attrs)
    if subj_items:
        selectors["sel_subject"] = {"type": "object", "items": subj_items}
        operands.append({"type": "selector_ref", "selector": "sel_subject"})

    obj_items = _attributes_to_selector_items(object_attrs)
    if obj_items:
        selectors["sel_object"] = {"type": "object", "items": obj_items}
        operands.append({"type": "selector_ref", "selector": "sel_object"})

    compiled: dict[str, Any]
    if len(operands) == 1:
        compiled = operands[0]
    else:
        compiled = {
            "type": "logical",
            "operator": "AND",
            "operands": operands,
        }

    return {
        "engine": "sigma",
        "condition": {"compiled": compiled},
        "selectors": selectors,
    }


def _safe_name(rule: dict[str, Any], fallback: str) -> str:
    name = rule.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return fallback


def _safe_severity(rule: dict[str, Any]) -> float:
    raw = rule.get("severity")
    if raw is None:
        raw = rule.get("severity_score")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 5.0


def _safe_prerequisites(rule: dict[str, Any]) -> dict[str, Any]:
    prereq = rule.get("prerequisites")
    if isinstance(prereq, dict):
        return prereq
    return {"operator": "AND", "predicates": []}


def convert_rule(source_rule: dict[str, Any], rule_id: str, source_relpath: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "name": _safe_name(source_rule, fallback=source_relpath),
        "source_types": ["sigma_adapter"],
        "apt_stage": _normalize_stage(source_rule.get("apt_stage")),
        "severity": _safe_severity(source_rule),
        "cvss": _safe_severity(source_rule),
        "match_logic": _build_sigma_logic(source_rule),
        "prerequisites": _safe_prerequisites(source_rule),
        "entity_bindings": [],
        "metadata": {
            "source_rule_path": source_relpath,
            "adapter_version": "1.0",
        },
    }


def load_source_rules(input_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    entries: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(input_dir.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            entries.append((path, payload))
        elif isinstance(payload, list):
            for idx, item in enumerate(payload):
                if isinstance(item, dict):
                    pseudo = path.with_name(f"{path.stem}__idx_{idx}.json")
                    entries.append((pseudo, item))
    return entries


def build_bundle(
    input_dir: Path,
    rule_id_prefix: str = "ADAPT_SIGMA",
) -> dict[str, list[dict[str, Any]]]:
    source_entries = load_source_rules(input_dir)
    converted: list[dict[str, Any]] = []
    for idx, (source_path, source_rule) in enumerate(source_entries, start=1):
        rid = f"{rule_id_prefix}_{idx:06d}"
        relpath = str(source_path.relative_to(input_dir))
        converted.append(convert_rule(source_rule, rid, relpath))
    return {"rules": converted}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert SIGMA_rule_extract HOLMES-format JSON into HOLMES runtime rules bundle."
    )
    parser.add_argument(
        "--input-dir",
        default="/home/work/SIGMA/SIGMA_rule_extract/rules/holmes",
        help="Directory containing translated JSON rules from SIGMA_rule_extract.",
    )
    parser.add_argument(
        "--output",
        default="/home/work/SIGMA/HOLMES/rules/sigma_adapter_rules.json",
        help="Output JSON bundle path under HOLMES/rules.",
    )
    parser.add_argument(
        "--rule-id-prefix",
        default="ADAPT_SIGMA",
        help="Prefix for generated sequential rule_id values.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    input_dir = Path(args.input_dir).resolve()
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    bundle = build_bundle(input_dir=input_dir, rule_id_prefix=str(args.rule_id_prefix))
    output_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"Converted {len(bundle['rules'])} rules\n"
        f"input:  {input_dir}\n"
        f"output: {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
