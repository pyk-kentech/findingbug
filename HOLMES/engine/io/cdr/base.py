from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import PurePath
from typing import Any


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def extract_basename(value: Any) -> str:
    text = str(value or "").strip().strip("\"'")
    if not text:
        return ""
    normalized = text.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    return (parts[-1] if parts else normalized).lower()


def infer_process_name(raw: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            base = extract_basename(value)
            if base:
                return base
    for key in ("CommandLine", "commandLine", "cmdLine", "command_line"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            first = value.strip().split()[0]
            base = extract_basename(first)
            if base:
                return base
    for key in ("Image", "exe", "path", "program", "ParentImage", "TargetImage"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            base = extract_basename(value)
            if base:
                return base
    return ""


RELATION_ALIASES = {
    "spawned_by": "spawn",
    "acts_on": "write",
    "modifies": "write",
    "connects_to": "connect",
    "resolves": "resolve",
    "requests": "request",
    "invoked_by": "invoke",
}


def canonical_relation(relation: Any) -> str:
    name = normalize_text(relation)
    return RELATION_ALIASES.get(name, name)


class BaseCDRAdapter(ABC):
    """Adapter that converts raw OS events into a common data representation."""

    name = "base"

    @classmethod
    @abstractmethod
    def can_handle(cls, raw: dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    def to_cdr(self, raw: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def _entity(prefix: str, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        if ":" in text and text.split(":", 1)[0].lower() == prefix.lower():
            return text
        return f"{prefix}:{text}"

    @staticmethod
    def _process_entity_from_ids(
        raw: dict[str, Any],
        *,
        guid_keys: tuple[str, ...],
        pid_keys: tuple[str, ...],
        ts_keys: tuple[str, ...] = ("ts", "timestamp", "UtcTime", "EventTime"),
    ) -> str | None:
        for key in guid_keys:
            value = raw.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return f"proc_guid:{text}"
        pid_value: str | None = None
        for key in pid_keys:
            value = raw.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                pid_value = text
                break
        if not pid_value:
            return None
        timestamp_value = ""
        for key in ts_keys:
            value = raw.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                timestamp_value = text
                break
        if not timestamp_value:
            timestamp_value = "no-ts"
        return f"proc_pid:{pid_value}@{timestamp_value}"

    @staticmethod
    def _finalize(
        raw: dict[str, Any],
        *,
        subject: str | None,
        object_: str | None,
        semantic_relations: list[dict[str, str]],
        source_type: str | None = None,
        logsource: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        mapped = dict(raw)
        if subject is not None:
            mapped["subject"] = subject
        if object_ is not None:
            mapped["object"] = object_
        cdr = dict(mapped.get("cdr", {})) if isinstance(mapped.get("cdr"), dict) else {}
        cdr["semantic_relations"] = [
            {"relation": canonical_relation(item["relation"]), "src": item["src"], "dst": item["dst"]}
            for item in semantic_relations
            if isinstance(item, dict) and {"relation", "src", "dst"} <= set(item)
        ]
        if source_type:
            cdr["source_type"] = source_type.strip().lower()
        if logsource:
            cdr["logsource"] = {str(k): str(v).strip().lower() for k, v in logsource.items() if v is not None}
        mapped["cdr"] = cdr
        return mapped


class GenericCDRAdapter(BaseCDRAdapter):
    name = "generic"

    @classmethod
    def can_handle(cls, raw: dict[str, Any]) -> bool:
        return True

    def to_cdr(self, raw: dict[str, Any]) -> dict[str, Any]:
        subject = str(raw.get("subject")) if raw.get("subject") is not None else None
        object_ = str(raw.get("object")) if raw.get("object") is not None else None
        if isinstance(raw.get("semantic_relations"), list):
            relations = [
                {"relation": canonical_relation(item.get("relation")), "src": str(item.get("src")), "dst": str(item.get("dst"))}
                for item in raw.get("semantic_relations", [])
                if isinstance(item, dict) and isinstance(item.get("relation"), str) and isinstance(item.get("src"), str) and isinstance(item.get("dst"), str)
            ]
        else:
            op = normalize_text(raw.get("op")) or normalize_text(raw.get("event_type") or raw.get("type"))
            relations: list[dict[str, str]] = []

            def add(rel: str, src: str | None, dst: str | None) -> None:
                if src and dst:
                    relations.append({"relation": rel, "src": src, "dst": dst})

            subj_prefix = subject.split(":", 1)[0].lower() if subject else ""
            obj_prefix = object_.split(":", 1)[0].lower() if object_ else ""
            if op in {"proc_to_proc", "fork"} and subj_prefix == "proc" and obj_prefix == "proc":
                add("spawn", subject, object_)
                add("execute", subject, object_)
            if op in {"file_to_proc", "exec", "execute"} and obj_prefix == "proc":
                add("execute", object_, subject)
            if op in {"proc_to_file", "write", "modify"} and subj_prefix == "proc" and obj_prefix == "file":
                add("write", subject, object_)
            if op in {"read"} and subj_prefix == "proc" and obj_prefix == "file":
                add("read", subject, object_)
            if op in {"proc_to_registry"} or (subj_prefix == "proc" and obj_prefix == "reg"):
                add("write", subject, object_)
            if op in {"proc_to_ip", "file_to_ip", "connect", "send", "network_flow"} or obj_prefix == "ip":
                add("connect", subject, object_)
            if op == "dns_query" or obj_prefix == "dns":
                add("resolve", subject, object_)
            if op in {"web_request", "http_request", "proxy"} or obj_prefix == "web":
                add("request", subject, object_)
            if op in {"cloud_api", "cloudtrail"}:
                add("invoke", subject, object_)
            if "inject" in op:
                add("inject", subject, object_)

        source_type = raw.get("source_type")
        return self._finalize(
            raw,
            subject=subject,
            object_=object_,
            semantic_relations=relations,
            source_type=str(source_type) if isinstance(source_type, str) else None,
            logsource=raw.get("logsource") if isinstance(raw.get("logsource"), dict) else None,
        )


def select_cdr_adapter(raw: dict[str, Any]) -> BaseCDRAdapter:
    from engine.io.cdr.auditd import AuditdAdapter
    from engine.io.cdr.darpa_tc import DarpaTCAdapter
    from engine.io.cdr.etw import ETWAdapter

    for adapter_cls in (DarpaTCAdapter, AuditdAdapter, ETWAdapter, GenericCDRAdapter):
        if adapter_cls.can_handle(raw):
            return adapter_cls()
    return GenericCDRAdapter()


def map_raw_event_to_cdr(raw: dict[str, Any]) -> dict[str, Any]:
    return select_cdr_adapter(raw).to_cdr(raw)
