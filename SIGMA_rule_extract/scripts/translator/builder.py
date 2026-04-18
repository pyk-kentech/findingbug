from collections.abc import Mapping
from typing import Any

VALID_RELATIONS = {
    "SPAWN",
    "EXECUTE",
    "READ",
    "WRITE",
    "CREATE",
    "DELETE",
    "CONNECT",
}

STAGE_ORDER = [
    "Initial Compromise",
    "Execution",
    "Establish Foothold",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Internal Recon",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Complete Mission",
]

STAGE_MAPPING = {
    "attack.initial_access": ("Initial Compromise", None),
    "attack.execution": ("Execution", "Initial Compromise"),
    "attack.persistence": ("Establish Foothold", "Execution"),
    "attack.privilege_escalation": ("Privilege Escalation", "Establish Foothold"),
    "attack.defense_evasion": ("Defense Evasion", "Privilege Escalation"),
    "attack.credential_access": ("Credential Access", "Privilege Escalation"),
    "attack.discovery": ("Internal Recon", "Establish Foothold"),
    "attack.lateral_movement": ("Lateral Movement", "Internal Recon"),
    "attack.collection": ("Collection", "Lateral Movement"),
    "attack.exfiltration": ("Exfiltration", "Collection"),
    "attack.impact": ("Complete Mission", "Lateral Movement"),
}


NETWORK_KEYS = {
    "dst_ip",
    "src_ip",
    "ip_address",
    "remote_ip",
    "local_ip",
    "DestinationIp",
    "IpAddress|cidr",
    "DestinationPort",
    "DestPort",
    "DestinationHostname|endswith",
    "DestinationHostname|contains",
    "QueryName",
    "QueryName|contains",
    "QueryName|endswith",
    "RemoteName|contains",
    "cs-host|endswith",
    "c-uri|endswith",
}

FILE_KEYS = {
    "file_path",
    "file_path|contains",
    "file_path|endswith",
    "ImagePath",
    "ImagePath|contains",
    "ImagePath|endswith",
    "TargetFilename|contains",
    "TargetFilename|contains|all",
    "TargetFilename",
    "TargetFilename|endswith",
    "TargetFilename|startswith",
    "TargetFilename|re",
    "ImageLoaded",
    "ImageLoaded|contains",
    "ImageLoaded|endswith",
    "ImageLoaded|startswith",
    "FileName|contains",
    "Path|contains",
    "ServiceFileName",
}

REGISTRY_KEYS = {
    "TargetObject",
    "TargetObject|contains",
    "TargetObject|endswith",
    "ObjectName|contains",
    "ObjectName|endswith",
    "RelativeTargetName",
    "RelativeTargetName|endswith",
    "Details",
    "Details|contains",
    "Details|endswith",
    "Details|startswith",
    "Data|contains",
    "Data|contains|all",
    "NewValue",
    "NewValue|contains",
}

PIPE_KEYS = {
    "PipeName",
    "PipeName|contains",
}

PROCESS_KEYS = {
    "Image",
    "Image|contains",
    "Image|contains|all",
    "Image|endswith",
    "Image|startswith",
    "CommandLine",
    "CommandLine|contains",
    "CommandLine|contains|all",
    "CommandLine|endswith",
    "CommandLine|re",
    "ScriptBlockText",
    "ScriptBlockText|contains",
    "ScriptBlockText|contains|all",
    "OriginalFileName",
}

IDENTITY_KEYS = {
    "TargetOutboundUserName",
    "TargetUserName",
    "TargetUserName|contains",
    "TargetUserName|endswith",
    "SubjectUserName",
    "AccountName",
    "ShareName",
}

OBJECT_ONLY_KEYS = {
    "imageloaded",
    "imagepath",
    "servicefilename",
    "targetobject",
    "targetfilename",
    "file_path",
}

PROCESS_SUBJECT_KEYS = {
    "image",
    "commandline",
    "parentimage",
    "parentcommandline",
    "originalfilename",
    "hashes",
    "user",
    "integritylevel",
}


def _is_meaningful_string(value: str) -> bool:
    stripped = value.strip()
    return stripped not in {"", "*"}


def _normalize_detection_value(value: Any) -> str | list[str] | None:
    if isinstance(value, str):
        return value if _is_meaningful_string(value) else None

    if isinstance(value, list):
        cleaned = [
            item
            for item in value
            if isinstance(item, str) and _is_meaningful_string(item)
        ]
        return cleaned or None

    return None


def _flatten_detection_mapping(
    mapping: Mapping[str, Any],
    prefix: str = "",
) -> dict[str, str | list[str]]:
    flattened: dict[str, str | list[str]] = {}

    for key, value in mapping.items():
        key_str = str(key)
        full_key = f"{prefix}.{key_str}" if prefix else key_str

        if isinstance(value, Mapping):
            nested_keys = [str(item) for item in value.keys()]
            if nested_keys and all(item.startswith("|") for item in nested_keys):
                for modifier, modifier_value in value.items():
                    normalized = _normalize_detection_value(modifier_value)
                    if normalized is not None:
                        flattened[f"{full_key}{modifier}"] = normalized
                continue

            flattened.update(_flatten_detection_mapping(value, full_key))
            continue

        normalized = _normalize_detection_value(value)
        if normalized is not None:
            flattened[full_key] = normalized

    return flattened


def _extract_detection_fallback_attributes(
    sigma_dict: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    detection = sigma_dict.get("detection", {})
    if not isinstance(detection, Mapping):
        return {}, {}

    raw_candidates: dict[str, str | list[str]] = {}

    selection = detection.get("selection")
    if isinstance(selection, Mapping):
        raw_candidates.update(_flatten_detection_mapping(selection))
    else:
        for key, value in detection.items():
            key_str = str(key)
            if key_str == "condition" or key_str.startswith("filter_"):
                continue
            if not isinstance(value, Mapping):
                continue
            raw_candidates.update(_flatten_detection_mapping({key_str: value}))

    if not raw_candidates:
        return {}, {}

    values = _logsource_values(sigma_dict)
    event_like_logsource = _is_event_logsource(sigma_dict)
    is_cisco = any("cisco" in value or "bgp" in value for value in values)

    subject_fallback: dict[str, Any] = {}
    object_fallback: dict[str, Any] = {}

    if is_cisco:
        keyword_all_values = [
            value
            for key, value in raw_candidates.items()
            if key.endswith("|all")
        ]
        if keyword_all_values:
            merged: list[str] = []
            for value in keyword_all_values:
                if isinstance(value, str):
                    merged.append(value)
                elif isinstance(value, list):
                    merged.extend(value)
            if merged:
                object_fallback["message|contains|all"] = merged
        else:
            object_fallback.update(raw_candidates)
        return subject_fallback, object_fallback

    if event_like_logsource:
        subject_fallback.update(raw_candidates)
        return subject_fallback, object_fallback

    object_fallback.update(raw_candidates)
    return subject_fallback, object_fallback


def _scrub_attribute_map(attributes: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}

    for key, value in attributes.items():
        if value is None:
            continue
        if isinstance(value, str):
            if value == "":
                continue
            scrubbed[key] = value
            continue
        if isinstance(value, Mapping):
            raise ValueError(
                f"Invalid nested object found in attributes for key '{key}'."
            )
        if isinstance(value, list):
            cleaned_items = [
                item
                for item in value
                if isinstance(item, str) and item != ""
            ]
            if cleaned_items:
                scrubbed[key] = cleaned_items
            continue
        scrubbed[key] = value

    return scrubbed


def _logsource_values(sigma_dict: Mapping[str, Any]) -> list[str]:
    logsource = sigma_dict.get("logsource", {})
    if not isinstance(logsource, Mapping):
        return []
    return [
        str(logsource.get("product", "")).lower(),
        str(logsource.get("category", "")).lower(),
        str(logsource.get("service", "")).lower(),
    ]


def _is_event_logsource(sigma_dict: Mapping[str, Any]) -> bool:
    values = _logsource_values(sigma_dict)
    event_keywords = {
        "audit",
        "activity",
        "signin",
        "bitbucket",
        "github",
        "kubernetes",
        "opencanary",
        "zeek",
        "proxy",
        "dns",
        "fortigate",
    }
    return any(keyword in value for value in values for keyword in event_keywords)


def _infer_subject_type(sigma_dict: Mapping[str, Any]) -> str:
    if _is_cloud_logsource(sigma_dict):
        return "CloudIdentity"
    if _is_event_logsource(sigma_dict):
        return "Event"
    return "Process"


def _infer_object_type(
    object_attributes: Mapping[str, Any],
    sigma_dict: Mapping[str, Any],
    relation: str,
) -> str:
    object_keys = set(object_attributes.keys())

    if object_keys & NETWORK_KEYS:
        return "NetFlow"
    if relation == "CONNECT":
        return "NetFlow"
    if object_keys & IDENTITY_KEYS:
        return "Identity"
    if object_keys & PROCESS_KEYS:
        return "Process"
    if object_keys & REGISTRY_KEYS:
        return "Registry"
    if object_keys & PIPE_KEYS:
        return "NamedPipe"
    if any(key.startswith("objectRef.") for key in object_keys):
        return "CloudResource" if _is_cloud_logsource(sigma_dict) else "Resource"
    if _is_cloud_logsource(sigma_dict):
        return "CloudResource"
    if object_keys & FILE_KEYS or "file_path" in object_attributes:
        return "File"
    if _is_event_logsource(sigma_dict):
        return "Event"
    return "File"


def _is_cloud_logsource(sigma_dict: Mapping[str, Any]) -> bool:
    logsource = sigma_dict.get("logsource", {})
    if not isinstance(logsource, Mapping):
        return False

    cloud_keywords = {
        "azure",
        "aws",
        "gcp",
        "m365",
        "okta",
        "google_workspace",
    }
    logsource_values = [
        str(logsource.get("product", "")).lower(),
        str(logsource.get("category", "")).lower(),
    ]
    return any(
        keyword in value for value in logsource_values for keyword in cloud_keywords
    )


def _resolve_stages(
    sigma_dict: Mapping[str, Any],
    threshold: int,
) -> tuple[str, str, list[dict[str, Any]]]:
    tags = sigma_dict.get("tags", [])
    matched_stages: list[tuple[str, str | None]] = []

    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag in STAGE_MAPPING:
                matched_stages.append(STAGE_MAPPING[tag])

    if matched_stages:
        current_stage = matched_stages[0][0]
    else:
        current_stage = "Execution"

    unique_source_stages: list[str | None] = []
    for _, source_stage in matched_stages:
        if source_stage not in unique_source_stages:
            unique_source_stages.append(source_stage)

    valid_source_stages = [
        source_stage for source_stage in unique_source_stages if source_stage is not None
    ]

    if not valid_source_stages:
        if current_stage == "Initial Compromise":
            valid_source_stages = []
        else:
            try:
                current_stage_index = STAGE_ORDER.index(current_stage)
            except ValueError:
                current_stage_index = -1

            if current_stage_index > 0:
                valid_source_stages = [STAGE_ORDER[current_stage_index - 1]]

    if not unique_source_stages or not valid_source_stages:
        operator = "AND"
        predicates = []
        if len(valid_source_stages) == 1:
            predicates = [
                {
                    "type": "stage_path",
                    "quantifier": "EXISTS",
                    "source_stage": valid_source_stages[0],
                    "target_node": "$subject_node",
                    "threshold": threshold,
                }
            ]
    elif len(valid_source_stages) == 1:
        operator = "AND"
        predicates = [
            {
                "type": "stage_path",
                "quantifier": "EXISTS",
                "source_stage": valid_source_stages[0],
                "target_node": "$subject_node",
                "threshold": threshold,
            }
        ]
    else:
        operator = "OR"
        predicates = []
        for stage in unique_source_stages:
            if stage is not None:
                predicates.append(
                    {
                        "type": "stage_path",
                        "quantifier": "EXISTS",
                        "source_stage": stage,
                        "target_node": "$subject_node",
                        "threshold": threshold,
                    }
                )

    return (current_stage, operator, predicates)


def _normalize_threshold(raw_threshold: Any) -> int:
    try:
        threshold = int(raw_threshold)
    except (TypeError, ValueError):
        return 1
    return max(threshold, 1)


def _relocate_misplaced_attributes(
    subject_attributes: dict[str, Any],
    object_attributes: dict[str, Any],
) -> None:
    # Final safety net for small-model drift: keep process cues on subject and object cues on object.
    for key in list(subject_attributes.keys()):
        key_base = str(key).split("|", 1)[0].lower()
        if key_base in OBJECT_ONLY_KEYS:
            object_attributes.setdefault(key, subject_attributes.pop(key))

    for key in list(object_attributes.keys()):
        key_base = str(key).split("|", 1)[0].lower()
        if key_base in PROCESS_SUBJECT_KEYS:
            subject_attributes.setdefault(key, object_attributes.pop(key))


def _remediate_non_process_subject_attributes(
    subject_attributes: dict[str, Any],
    object_attributes: dict[str, Any],
    sigma_dict: Mapping[str, Any],
) -> None:
    inferred_subject_type = _infer_subject_type(sigma_dict)
    if inferred_subject_type == "Process":
        return

    values = _logsource_values(sigma_dict)
    is_proxy_logsource = any("proxy" in value for value in values)

    for key in list(subject_attributes.keys()):
        key_base = str(key).split("|", 1)[0].lower()
        if key_base not in PROCESS_SUBJECT_KEYS:
            continue

        value = subject_attributes.pop(key)
        if not is_proxy_logsource:
            continue

        normalized = _normalize_detection_value(value)
        if normalized is not None:
            object_attributes.setdefault("c-useragent", normalized)


def _is_empty_or_wildcard(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() in {"", "*"}
    if isinstance(value, Mapping):
        return not value or all(_is_empty_or_wildcard(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return not value or all(_is_empty_or_wildcard(item) for item in value)
    return False


def _is_too_broad(
    subject_attributes: Mapping[str, Any],
    object_attributes: Mapping[str, Any],
) -> bool:
    subject_unconstrained = _is_empty_or_wildcard(subject_attributes)
    object_unconstrained = _is_empty_or_wildcard(object_attributes)
    return subject_unconstrained and object_unconstrained


def build_holmes_rule(
    rule_name: str,
    extracted_json: Mapping[str, Any],
    sigma_dict: Mapping[str, Any],
) -> dict[str, Any]:
    relation = str(extracted_json.get("relation", "EXECUTE")).upper()
    if relation not in VALID_RELATIONS:
        relation = "EXECUTE"

    subject_attributes = extracted_json.get("subject_attributes")
    object_attributes = extracted_json.get("object_attributes")

    if not isinstance(subject_attributes, Mapping):
        subject_attributes = {}
    else:
        subject_attributes = dict(subject_attributes)

    if not isinstance(object_attributes, Mapping):
        object_attributes = {}
    else:
        object_attributes = dict(object_attributes)

    _relocate_misplaced_attributes(subject_attributes, object_attributes)
    _remediate_non_process_subject_attributes(
        subject_attributes,
        object_attributes,
        sigma_dict,
    )
    subject_attributes = _scrub_attribute_map(subject_attributes)
    object_attributes = _scrub_attribute_map(object_attributes)

    if _is_too_broad(subject_attributes, object_attributes):
        fallback_subject, fallback_object = _extract_detection_fallback_attributes(
            sigma_dict
        )
        for key, value in fallback_subject.items():
            subject_attributes.setdefault(key, value)
        for key, value in fallback_object.items():
            object_attributes.setdefault(key, value)
        _relocate_misplaced_attributes(subject_attributes, object_attributes)
        subject_attributes = _scrub_attribute_map(subject_attributes)
        object_attributes = _scrub_attribute_map(object_attributes)

    threshold = _normalize_threshold(extracted_json.get("threshold", 1))
    current_stage, operator, predicates = _resolve_stages(sigma_dict, threshold)
    if _is_too_broad(subject_attributes, object_attributes):
        raise ValueError(
            "Rule is too broad: Subject and Object lack specific constraints."
        )

    return {
        "name": rule_name,
        "apt_stage": current_stage,
        "severity_score": 5.0,
        "match_logic": {
            "relation": relation,
            "subject": {
                "type": _infer_subject_type(sigma_dict),
                "attributes": subject_attributes,
            },
            "object": {
                "type": _infer_object_type(object_attributes, sigma_dict, relation),
                "attributes": object_attributes,
            },
            "entity_bindings": {
                "subject": "$subject_node",
                "object": "$object_node",
            },
        },
        "prerequisites": {
            "operator": operator,
            "predicates": predicates,
        },
    }
