import argparse
import json
import os
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from tqdm import tqdm


SYSTEM_PROMPT = """You are a strict QA linter for Sigma-to-HOLMES rules. Review the provided JSON rule and reply ONLY with one of the following exact strings. Do not explain.
- PASS (If the rule looks perfectly valid and logical)
- FAIL_CLOUD_MISMATCH (If the rule name implies Cloud/Azure/AWS/M365 but entity type is Process/File)
- FAIL_EMPTY_OBJECT (If object attributes are completely empty {})
- FAIL_NO_PREREQUISITE (If apt_stage is not 'Initial Access' but prerequisites are empty)
- FAIL_OVERFITTING (If specific IPs, emails, or exact test file paths are hardcoded without wildcards)
- FAIL_ARRAY_FLATTENING (If values contain comma-separated strings like "wget, curl" instead of a proper JSON array or regex)
- FAIL_RELATION_MISMATCH (If relation is CONNECT but attributes have file paths, or relation is READ/WRITE but attributes have IPs/ports)
- FAIL_TOO_BROAD (If BOTH subject and object attributes are completely empty or only contain a wildcard "*")"""

VALID_VERDICTS = {
    "PASS",
    "FAIL_CLOUD_MISMATCH",
    "FAIL_EMPTY_OBJECT",
    "FAIL_NO_PREREQUISITE",
    "FAIL_OVERFITTING",
    "FAIL_ARRAY_FLATTENING",
    "FAIL_RELATION_MISMATCH",
    "FAIL_TOO_BROAD",
}
FAIL_VERDICTS = sorted(verdict for verdict in VALID_VERDICTS if verdict != "PASS")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch-review HOLMES rules with a local 14B LLM and write a summary report."
    )
    parser.add_argument(
        "--input-dir",
        default="rules/holmes/",
        help="Directory containing HOLMES rule JSON files.",
    )
    parser.add_argument(
        "--output",
        default="qa_reports/14b_review_summary.json",
        help="Path to write the aggregated review summary JSON.",
    )
    parser.add_argument(
        "--endpoint",
        default=os.getenv("LLM_REVIEW_ENDPOINT", "http://localhost:11434/api/generate"),
        help="Local LLM review endpoint. Defaults to Ollama's /api/generate endpoint.",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("LLM_REVIEW_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")),
        help="Model name for the local reviewer.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="HTTP timeout in seconds for each rule review request.",
    )
    return parser.parse_args()


def _load_rule(rule_path: Path) -> dict[str, Any]:
    payload = json.loads(rule_path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError(f"Rule file must contain a JSON object: {rule_path}")
    return dict(payload)


def _discover_rule_files(input_dir: Path) -> list[Path]:
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    if not input_dir.is_dir():
        raise NotADirectoryError(f"Input path is not a directory: {input_dir}")
    return sorted(input_dir.rglob("*.json"))


def _normalize_verdict(raw_text: str) -> str:
    verdict = raw_text.strip()
    if verdict in VALID_VERDICTS:
        return verdict

    for line in raw_text.splitlines():
        candidate = line.strip()
        if candidate in VALID_VERDICTS:
            return candidate

    raise ValueError(f"Unexpected reviewer verdict: {raw_text!r}")


def _review_rule(
    endpoint: str,
    model: str,
    timeout: float,
    rule_path: Path,
    rule_json: Mapping[str, Any],
) -> str:
    prompt = json.dumps(rule_json, indent=2, ensure_ascii=False)
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "top_p": 0.1,
            "num_ctx": 8192,
        },
    }

    response = requests.post(endpoint, json=payload, timeout=timeout)
    response.raise_for_status()

    data = response.json()
    if not isinstance(data, Mapping):
        raise ValueError(f"Invalid endpoint response for {rule_path}: expected JSON object.")

    generated_text = data.get("response")
    if not isinstance(generated_text, str):
        raise ValueError(
            f"Invalid endpoint response for {rule_path}: missing string 'response' field."
        )

    return _normalize_verdict(generated_text)


def _rule_display_name(rule_path: Path, rule_json: Mapping[str, Any]) -> str:
    name = rule_json.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return str(rule_path)


def _build_summary(
    input_dir: Path,
    endpoint: str,
    model: str,
    total_rules: int,
    verdict_counts: Counter[str],
    fail_samples: Mapping[str, list[str]],
    reviews: list[dict[str, Any]],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    fail_count = sum(count for verdict, count in verdict_counts.items() if verdict != "PASS")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_dir": str(input_dir),
        "endpoint": endpoint,
        "model": model,
        "total_rules": total_rules,
        "pass_count": verdict_counts.get("PASS", 0),
        "fail_count": fail_count,
        "error_count": len(errors),
        "verdict_counts": {verdict: verdict_counts.get(verdict, 0) for verdict in sorted(VALID_VERDICTS)},
        "fail_samples": {verdict: fail_samples.get(verdict, [])[:3] for verdict in FAIL_VERDICTS},
        "reviews": reviews,
        "errors": errors,
    }


def _print_summary(summary: Mapping[str, Any]) -> None:
    print("")
    print("LLM Batch Review Summary")
    print(f"Input dir   : {summary['input_dir']}")
    print(f"Endpoint    : {summary['endpoint']}")
    print(f"Model       : {summary['model']}")
    print(f"Total rules : {summary['total_rules']}")
    print(f"PASS        : {summary['pass_count']}")
    print(f"FAIL        : {summary['fail_count']}")
    print(f"Errors      : {summary['error_count']}")
    print("")
    print("Fail counts and samples")
    for verdict in FAIL_VERDICTS:
        count = summary["verdict_counts"].get(verdict, 0)
        samples = summary["fail_samples"].get(verdict, [])
        sample_text = ", ".join(samples) if samples else "-"
        print(f"- {verdict}: {count}")
        print(f"  samples: {sample_text}")

    if summary["error_count"]:
        print("")
        print("Review errors")
        for error in summary["errors"][:10]:
            print(f"- {error['file']}: {error['error']}")


def main() -> int:
    args = _parse_args()
    input_dir = Path(args.input_dir)
    output_path = Path(args.output)
    rule_files = _discover_rule_files(input_dir)

    verdict_counts: Counter[str] = Counter()
    fail_samples: dict[str, list[str]] = defaultdict(list)
    reviews: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    progress = tqdm(rule_files, desc="Reviewing HOLMES rules", unit="rule")
    for rule_path in progress:
        try:
            rule_json = _load_rule(rule_path)
            verdict = _review_rule(
                endpoint=args.endpoint,
                model=args.model,
                timeout=args.timeout,
                rule_path=rule_path,
                rule_json=rule_json,
            )
            rule_name = _rule_display_name(rule_path, rule_json)
            verdict_counts[verdict] += 1
            if verdict != "PASS" and len(fail_samples[verdict]) < 3:
                fail_samples[verdict].append(rule_name)
            reviews.append(
                {
                    "file": str(rule_path),
                    "name": rule_name,
                    "verdict": verdict,
                }
            )
            progress.set_postfix_str(verdict)
        except Exception as exc:
            errors.append({"file": str(rule_path), "error": str(exc)})
            progress.set_postfix_str("ERROR")

    summary = _build_summary(
        input_dir=input_dir,
        endpoint=args.endpoint,
        model=args.model,
        total_rules=len(rule_files),
        verdict_counts=verdict_counts,
        fail_samples=fail_samples,
        reviews=reviews,
        errors=errors,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    _print_summary(summary)
    print("")
    print(f"Summary JSON written to: {output_path}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
