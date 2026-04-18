from collections.abc import Mapping
import re
from typing import Any


PROCESS_ONLY_KEYS = {
    "ParentImage",
    "ParentCommandLine",
    "Image",
    "CommandLine",
    "OriginalFileName",
    "Hashes",
    "User",
    "IntegrityLevel",
}

OBJECT_ONLY_KEYS = {
    "TargetFilename",
    "ImageLoaded",
    "ImagePath",
    "ServiceFileName",
    "TargetObject",
    "file_path",
}

ALLOWED_RELATIONS = {
    "SPAWN",
    "EXECUTE",
    "READ",
    "WRITE",
    "CREATE",
    "DELETE",
    "CONNECT",
}

ALLOWED_OPERATORS = {
    "AND",
    "OR",
    "NOT",
}

ALLOWED_NODE_TYPES = {
    "Process",
    "File",
    "Registry",
    "Network",
    "NetFlow",
    "CloudIdentity",
    "CloudResource",
    "Event",
}

PATH_OR_COMMAND_KEYS = {
    "CommandLine",
    "ParentCommandLine",
    "Image",
    "ParentImage",
    "file_path",
    "TargetFilename",
    "ImageLoaded",
    "ImagePath",
    "ServiceFileName",
    "Path",
    "FileName",
}

PROCESS_CONTEXT_FORBIDDEN_KEYS = {
    "cs-method",
    "cs-uri",
    "cs-host",
    "cs-user-agent",
    "Signature",
}

GENERIC_BROAD_VALUES = {
    "success",
    "rds.amazonaws.com",
}

FAILURE_NAME_TOKENS = {"failed", "error", "denied"}
FAILURE_VALUE_TOKENS = {"fail", "failed", "error", "denied", "failure", "unsuccess"}
FILE_VALUE_CONTEXT_SNIPPETS = {"mozilla", "..%", "select *", "drop table"}
NON_STANDARD_CHAR_RE = re.compile(r"[^\x00-\x7F]")


def _base_key(key: str) -> str:
    return str(key).split("|", 1)[0]


def _find_misplaced_key(
    attributes: Mapping[str, Any] | None,
    forbidden_bases: set[str],
) -> str | None:
    if not isinstance(attributes, Mapping):
        return None

    for key in attributes:
        if _base_key(str(key)) in forbidden_bases:
            return str(key)

    return None


def _flatten_string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        values: list[str] = []
        for nested_value in value.values():
            values.extend(_flatten_string_values(nested_value))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_flatten_string_values(item))
        return values
    return []


def _attribute_count(attributes: Mapping[str, Any] | None) -> int:
    if not isinstance(attributes, Mapping):
        return 0
    return len(attributes)


def _has_non_standard_path_value(attributes: Mapping[str, Any] | None) -> bool:
    if not isinstance(attributes, Mapping):
        return False
    for key, value in attributes.items():
        if _base_key(str(key)) not in PATH_OR_COMMAND_KEYS:
            continue
        for item in _flatten_string_values(value):
            if NON_STANDARD_CHAR_RE.search(item):
                return True
    return False


def validate_rule(rule_json: dict[str, Any]) -> str | None:
    if "attributes" in rule_json:
        return "Fail: attributes는 최상단에 올 수 없습니다. 반드시 match_logic 내부에 넣으시오."

    match_logic = rule_json.get("match_logic")
    if not isinstance(match_logic, Mapping):
        return "Invalid rule: 'match_logic' must be an object."

    relation = match_logic.get("relation")
    if relation not in ALLOWED_RELATIONS:
        return (
            "Invalid rule: 'match_logic.relation' must be one of "
            f"{sorted(ALLOWED_RELATIONS)}, got {relation!r}."
        )

    subject = match_logic.get("subject")
    object_ = match_logic.get("object")
    subject_attributes = (
        subject.get("attributes")
        if isinstance(subject, Mapping)
        else None
    )
    object_attributes = (
        object_.get("attributes")
        if isinstance(object_, Mapping)
        else None
    )
    if subject_attributes == {} and object_attributes == {}:
        return (
            "Fail: subject와 object의 attributes가 모두 비어있습니다. "
            "Sigma 룰의 탐지 키워드를 반드시 이 안에 채워 넣으시오."
        )

    subject_type = subject.get("type") if isinstance(subject, Mapping) else None
    object_type = object_.get("type") if isinstance(object_, Mapping) else None

    if subject_type not in ALLOWED_NODE_TYPES:
        return f"Invalid rule: unsupported subject.type {subject_type!r}."
    if object_type not in ALLOWED_NODE_TYPES:
        return f"Invalid rule: unsupported object.type {object_type!r}."

    if relation == "SPAWN" and object_type != "Process":
        return "Invalid rule: SPAWN relation requires object.type == 'Process'."
    if relation == "CONNECT" and object_type not in {"NetFlow", "Network"}:
        return "Invalid rule: CONNECT relation requires object.type == 'NetFlow' or 'Network'."

    if subject_type != "Process":
        misplaced_subject_process_key = _find_misplaced_key(
            subject_attributes,
            PROCESS_ONLY_KEYS,
        )
        if misplaced_subject_process_key is not None:
            return (
                "Invalid rule: process-specific field found on non-Process "
                f"subject: '{misplaced_subject_process_key}'."
            )

    misplaced_subject_object_key = _find_misplaced_key(
        subject_attributes,
        OBJECT_ONLY_KEYS,
    )
    if misplaced_subject_object_key is not None:
        return (
            "Invalid rule: object-specific field found in subject.attributes: "
            f"'{misplaced_subject_object_key}'."
        )

    if object_type != "Process":
        misplaced_object_process_key = _find_misplaced_key(
            object_attributes,
            PROCESS_ONLY_KEYS,
        )
        if misplaced_object_process_key is not None:
            return (
                "Invalid rule: process-specific field found in object.attributes: "
                f"'{misplaced_object_process_key}'."
            )

    if subject_type == "CloudIdentity" and object_type in {"Registry", "File"}:
        return (
            "Invalid rule: CloudIdentity subject cannot directly target "
            f"{object_type}."
        )

    if object_type == "CloudResource":
        cloudresource_file_key = _find_misplaced_key(
            object_attributes,
            {"TargetFilename"},
        )
        if cloudresource_file_key is not None:
            return (
                "Invalid rule: CloudResource object cannot carry file-specific field "
                f"'{cloudresource_file_key}'."
            )

    if _has_non_standard_path_value(subject_attributes) or _has_non_standard_path_value(
        object_attributes
    ):
        return "Invalid rule: non-standard characters found in path/command attributes."

    total_attribute_count = _attribute_count(subject_attributes) + _attribute_count(
        object_attributes
    )
    all_values_lower = {
        value.strip().lower()
        for value in (
            _flatten_string_values(subject_attributes)
            + _flatten_string_values(object_attributes)
        )
        if value.strip()
    }
    if total_attribute_count <= 1 and all_values_lower and all(
        value in GENERIC_BROAD_VALUES for value in all_values_lower
    ):
        return "Invalid rule: overly broad generic indicator set."

    if subject_type == "Process":
        process_context_key = _find_misplaced_key(
            subject_attributes,
            PROCESS_CONTEXT_FORBIDDEN_KEYS,
        )
        if process_context_key is not None:
            return (
                "Invalid rule: web-log or signature field found in Process subject: "
                f"'{process_context_key}'."
            )

    if object_type == "File":
        for value in _flatten_string_values(object_attributes):
            value_lower = value.lower()
            if any(snippet in value_lower for snippet in FILE_VALUE_CONTEXT_SNIPPETS):
                return (
                    "Invalid rule: File object contains web/database log style content."
                )

    rule_name = str(rule_json.get("name", "")).lower()
    if any(token in rule_name for token in FAILURE_NAME_TOKENS):
        if "success" in all_values_lower and not any(
            token in value
            for value in all_values_lower
            for token in FAILURE_VALUE_TOKENS
        ):
            return "Invalid rule: failure/error rule name paired only with Success indicators."

    prerequisites = rule_json.get("prerequisites")
    if not isinstance(prerequisites, Mapping):
        return "Invalid rule: 'prerequisites' must be an object."

    operator = prerequisites.get("operator")
    if operator not in ALLOWED_OPERATORS:
        return (
            "Invalid rule: 'prerequisites.operator' must be one of "
            f"{sorted(ALLOWED_OPERATORS)}, got {operator!r}."
        )

    entity_bindings = match_logic.get("entity_bindings")
    if not isinstance(entity_bindings, Mapping):
        return "Invalid rule: 'match_logic.entity_bindings' must be an object."

    declared_bindings = {
        binding
        for binding in entity_bindings.values()
        if isinstance(binding, str)
    }
    if not declared_bindings:
        return "Invalid rule: 'match_logic.entity_bindings' must declare at least one variable."

    predicates = prerequisites.get("predicates")
    if not isinstance(predicates, list):
        return "Invalid rule: 'prerequisites.predicates' must be an array."

    for index, predicate in enumerate(predicates):
        if not isinstance(predicate, Mapping):
            return f"Invalid rule: 'prerequisites.predicates[{index}]' must be an object."

        predicate_type = predicate.get("type")
        if predicate_type != "stage_path":
            return (
                "Fail: predicates의 type은 오직 'stage_path'만 허용됩니다. "
                "탐지 조건은 match_logic의 attributes로 옮기시오."
            )

        target_node = predicate.get("target_node")
        if not isinstance(target_node, str):
            return (
                "Invalid rule: "
                f"'prerequisites.predicates[{index}].target_node' must be a string."
            )
        if target_node not in declared_bindings:
            return (
                "Invalid rule: hallucinated variable in "
                f"'prerequisites.predicates[{index}].target_node': {target_node!r}. "
                f"Declared bindings are {sorted(declared_bindings)}."
            )

    return None
