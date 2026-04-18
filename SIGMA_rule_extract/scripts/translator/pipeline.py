import json
from collections.abc import Mapping
from typing import Any

import yaml

from .builder import build_holmes_rule
from .prompts import HOLMES_SYSTEM_PROMPT
from .sigma_translator import SigmaTranslator
from .validator import ALLOWED_RELATIONS, validate_rule


def _normalize_list_fields(rule_json: dict[str, Any]) -> None:
    prerequisites = rule_json.get("prerequisites")
    if not isinstance(prerequisites, Mapping):
        return

    predicates = prerequisites.get("predicates")
    if isinstance(predicates, list):
        return
    if predicates is None:
        return
    prerequisites["predicates"] = [predicates]


def _autocorrect_rule(rule_json: dict[str, Any]) -> dict[str, Any]:
    match_logic = rule_json.get("match_logic")
    if isinstance(match_logic, Mapping):
        relation = match_logic.get("relation")
        if relation not in ALLOWED_RELATIONS:
            match_logic["relation"] = "EXECUTE"

    _normalize_list_fields(rule_json)
    return rule_json


def _extract_rule_name(yaml_text: str) -> str:
    sigma_dict = _parse_sigma_rule(yaml_text)
    title = sigma_dict.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()

    return "Untitled Rule"


def _parse_sigma_rule(yaml_text: str) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return {}

    if isinstance(parsed, Mapping):
        return dict(parsed)

    return {}


def _translate_extracted_json(
    translator: SigmaTranslator,
    yaml_text: str,
    feedback: str | None = None,
) -> dict[str, Any]:
    prompt = (
        "Translate the following Sigma rule YAML into the required extraction JSON.\n\n"
        "[Sigma Rule YAML]\n"
        f"{yaml_text}"
    )
    if feedback:
        prompt = f"{prompt}\n\n{feedback}"

    llm_response_text = translator.client.generate(
        prompt=prompt,
        system=HOLMES_SYSTEM_PROMPT,
    )

    raw_text = llm_response_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]
    clean_text = raw_text.strip()
    extracted_json = json.loads(clean_text)

    if not isinstance(extracted_json, dict):
        raise ValueError("LLM output must be a JSON object.")

    return extracted_json


def process_single_rule(yaml_text: str, max_retries: int = 3) -> dict:
    translator = SigmaTranslator()
    sigma_dict = _parse_sigma_rule(yaml_text)
    rule_name = _extract_rule_name(yaml_text)
    feedback: str | None = None
    last_error: str | None = None

    for attempt in range(max_retries):
        try:
            extracted_json = _translate_extracted_json(
                translator,
                yaml_text,
                feedback=feedback,
            )
            rule_json = build_holmes_rule(rule_name, extracted_json, sigma_dict)
            rule_json = _autocorrect_rule(rule_json)
        except Exception as exc:
            last_error = f"Translation attempt {attempt + 1} failed: {exc}"
        else:
            validation_error = validate_rule(rule_json)
            if validation_error is None:
                return rule_json
            last_error = validation_error

        feedback = (
            "이전 응답은 다음 이유로 실패했다: "
            f"{last_error}. "
            "지시사항을 다시 읽고 이 오류를 수정하여 단순 추출 JSON만 다시 생성하라"
        )

    raise Exception(
        f"Failed to produce a valid HOLMES rule after {max_retries} attempts: {last_error}"
    )
