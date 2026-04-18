import argparse
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


FILE_RELATED_KEYS = {
    "file_path",
    "file_name",
    "filename",
    "path",
    "target_file",
}

NETWORK_RELATED_KEYS = {
    "dst_ip",
    "src_ip",
    "ip_address",
    "remote_ip",
    "local_ip",
    "dst_port",
    "src_port",
    "port",
    "remote_port",
    "local_port",
}

CANONICAL_SUBJECT_KEYS = {
    "commandline",
    "image",
    "parentimage",
    "originalfilename",
    "hashes",
    "user",
    "description",
    "product",
    "company",
    "eventid",
    "provider_name",
    "logname",
    "channel",
}


def _is_blank_or_wildcard(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() in {"", "*"}
    if isinstance(value, Mapping):
        return not value or all(_is_blank_or_wildcard(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return not value or all(_is_blank_or_wildcard(item) for item in value)
    return False


def _load_rule_entries(input_path: Path) -> list[tuple[str, dict[str, Any]]]:
    if input_path.is_dir():
        entries: list[tuple[str, dict[str, Any]]] = []
        for json_file in sorted(input_path.rglob("*.json")):
            entries.extend(_load_rule_entries(json_file))
        return entries

    if input_path.suffix.lower() != ".json":
        raise ValueError(f"Unsupported input type: {input_path}")

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if isinstance(payload, Mapping):
        if "rules" in payload and isinstance(payload["rules"], list):
            return _extract_bundle_entries(input_path, payload["rules"])
        return [(str(input_path), dict(payload))]
    if isinstance(payload, list):
        return _extract_bundle_entries(input_path, payload)

    raise ValueError(f"Unsupported JSON structure in {input_path}")


def _extract_bundle_entries(
    source_path: Path,
    rules: Iterable[Any],
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for index, rule in enumerate(rules):
        if isinstance(rule, Mapping):
            entries.append((f"{source_path}#{index}", dict(rule)))
    return entries


def _rule_name(rule: Mapping[str, Any], source: str) -> str:
    name = rule.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return source


def _collect_thresholds(rule: Mapping[str, Any]) -> list[tuple[str, Any]]:
    prerequisites = rule.get("prerequisites")
    if not isinstance(prerequisites, Mapping):
        return []

    predicates = prerequisites.get("predicates")
    if not isinstance(predicates, list):
        return []

    thresholds: list[tuple[str, Any]] = []
    for index, predicate in enumerate(predicates):
        if isinstance(predicate, Mapping):
            thresholds.append((f"prerequisites.predicates[{index}].threshold", predicate.get("threshold")))
    return thresholds


def lint_rule(rule: Mapping[str, Any], source: str) -> dict[str, list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    match_logic = rule.get("match_logic")
    if not isinstance(match_logic, Mapping):
        errors.append("Missing or invalid 'match_logic' object.")
        return {"errors": errors, "warnings": warnings}

    relation = match_logic.get("relation")
    object_node = match_logic.get("object")
    subject_node = match_logic.get("subject")

    object_attributes = (
        object_node.get("attributes") if isinstance(object_node, Mapping) else None
    )
    subject_attributes = (
        subject_node.get("attributes") if isinstance(subject_node, Mapping) else None
    )

    if not isinstance(subject_attributes, Mapping):
        errors.append("Missing or invalid 'match_logic.subject.attributes'.")
    elif not isinstance(object_attributes, Mapping):
        if _is_blank_or_wildcard(subject_attributes):
            errors.append(
                "Empty match constraint: 'subject_attributes' is empty and "
                "'match_logic.object.attributes' is missing or invalid."
            )
    elif _is_blank_or_wildcard(subject_attributes) and _is_blank_or_wildcard(
        object_attributes
    ):
        errors.append(
            "Empty match constraint: both 'subject_attributes' and "
            "'object_attributes' are empty or only wildcard values."
        )

    if isinstance(object_attributes, Mapping):
        object_keys = set(object_attributes.keys())
        if relation == "CONNECT" and object_keys & FILE_RELATED_KEYS:
            keys = ", ".join(sorted(object_keys & FILE_RELATED_KEYS))
            warnings.append(
                f"Relation-attribute mismatch: CONNECT rule uses file-related object key(s): {keys}."
            )
        if relation in {"READ", "WRITE"} and object_keys & NETWORK_RELATED_KEYS:
            keys = ", ".join(sorted(object_keys & NETWORK_RELATED_KEYS))
            warnings.append(
                f"Relation-attribute mismatch: {relation} rule uses network-related object key(s): {keys}."
            )

    thresholds = _collect_thresholds(rule)
    for path, threshold in thresholds:
        if not isinstance(threshold, int) or isinstance(threshold, bool):
            errors.append(f"Threshold sanity failure: {path} must be an integer, got {threshold!r}.")
        elif threshold <= 0:
            errors.append(f"Threshold sanity failure: {path} must be > 0, got {threshold}.")

    return {"errors": errors, "warnings": warnings}


def lint_rules(input_path: str | Path, report_path: str | Path = "linter_report.log") -> dict[str, Any]:
    input_path = Path(input_path)
    report_path = Path(report_path)

    entries = _load_rule_entries(input_path)
    passed_count = 0
    error_count = 0
    warning_count = 0
    report_lines = [
        f"Rule linter report for: {input_path}",
        f"Scanned rules: {len(entries)}",
        "",
    ]

    for source, rule in entries:
        name = _rule_name(rule, source)
        result = lint_rule(rule, source)
        errors = result["errors"]
        warnings = result["warnings"]

        if not errors and not warnings:
            passed_count += 1
            continue

        if errors:
            error_count += len(errors)
            for reason in errors:
                report_lines.append(f"ERROR | {name} | {reason}")

        if warnings:
            warning_count += len(warnings)
            for reason in warnings:
                report_lines.append(f"WARNING | {name} | {reason}")

    summary_lines = [
        f"Passed rules: {passed_count}",
        f"Error count: {error_count}",
        f"Warning count: {warning_count}",
    ]
    if passed_count == len(entries) and error_count == 0 and warning_count == 0:
        report_lines.append("No issues found.")

    report_text = "\n".join(summary_lines + [""] + report_lines) + "\n"
    print(report_text, end="")
    report_path.write_text(report_text, encoding="utf-8")

    return {
        "scanned_rules": len(entries),
        "passed_rules": passed_count,
        "error_count": error_count,
        "warning_count": warning_count,
        "report_path": str(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint generated HOLMES rules for logical reasonableness.")
    parser.add_argument(
        "input",
        nargs="?",
        default="rules/holmes/",
        help="Input directory of HOLMES JSON files or a bundle JSON file.",
    )
    parser.add_argument(
        "--report",
        default="linter_report.log",
        help="Path to write the linter summary report.",
    )
    args = parser.parse_args()

    result = lint_rules(args.input, args.report)
    return 1 if result["error_count"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
