from __future__ import annotations

from typing import Any

from engine.io.cdr.base import BaseCDRAdapter, normalize_text


class ETWAdapter(BaseCDRAdapter):
    name = "etw"

    @classmethod
    def can_handle(cls, raw: dict[str, Any]) -> bool:
        logsource = raw.get("logsource")
        if isinstance(logsource, dict):
            if normalize_text(logsource.get("product")) == "windows":
                return True
            if normalize_text(logsource.get("service")) in {"sysmon", "etw"}:
                return True
        return any(key in raw for key in ("Image", "ParentImage", "TargetFilename", "DestinationIp", "SourceProcessGuid"))

    def _proc(self, raw: dict[str, Any], *, guid_keys: tuple[str, ...], pid_keys: tuple[str, ...]) -> str | None:
        return self._process_entity_from_ids(raw, guid_keys=guid_keys, pid_keys=pid_keys)

    def _file(self, raw: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = raw.get(key)
            entity = self._entity("file", value)
            if entity:
                return entity
        return None

    def _ip(self, raw: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = raw.get(key)
            entity = self._entity("ip", value)
            if entity:
                return entity
        return None

    def to_cdr(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = normalize_text(raw.get("event_type") or raw.get("type") or raw.get("EventType"))
        subject = self._proc(
            raw,
            guid_keys=("SourceProcessGuid", "ProcessGuid"),
            pid_keys=("SourceProcessId", "ProcessId"),
        )
        object_: str | None = None
        relations: list[dict[str, str]] = []

        def add(rel: str, src: str | None, dst: str | None) -> None:
            if src and dst:
                relations.append({"relation": rel, "src": src, "dst": dst})

        if event_type in {"process_creation", "createprocess", "sysmon_process_create"}:
            parent = self._proc(
                {
                    **raw,
                    "ProcessGuid": raw.get("ParentProcessGuid"),
                    "ProcessId": raw.get("ParentProcessId"),
                },
                guid_keys=("ProcessGuid",),
                pid_keys=("ProcessId",),
            )
            child = self._proc(
                raw,
                guid_keys=("ProcessGuid", "SourceProcessGuid"),
                pid_keys=("ProcessId", "SourceProcessId"),
            )
            subject = parent or subject
            object_ = child
            add("execute", subject, object_)
            add("spawn", subject, object_)
        elif event_type in {"image_load", "module_load"}:
            object_ = self._file(raw, "ImageLoaded", "TargetFilename")
            add("read", subject, object_)
        elif event_type in {"file_create", "file_write", "proc_to_file"}:
            object_ = self._file(raw, "TargetFilename", "FileName")
            add("write", subject, object_)
        elif event_type in {"network_connect", "network_connection", "proc_to_ip"}:
            object_ = self._ip(raw, "DestinationIp", "DestIp", "RemoteAddress")
            add("connect", subject, object_)
        elif event_type in {"remote_thread", "process_inject", "inject"}:
            object_ = self._proc(
                {
                    **raw,
                    "ProcessGuid": raw.get("TargetProcessGuid"),
                    "ProcessId": raw.get("TargetProcessId"),
                },
                guid_keys=("ProcessGuid",),
                pid_keys=("ProcessId",),
            )
            add("inject", subject, object_)
        else:
            object_ = self._file(raw, "TargetFilename", "FileName")

        mapped = dict(raw)
        if "event_type" not in mapped and event_type:
            mapped["event_type"] = event_type
        cdr = dict(mapped.get("cdr", {})) if isinstance(mapped.get("cdr"), dict) else {}
        integrity_level = normalize_text(
            raw.get("IntegrityLevel")
            or raw.get("MandatoryLabel")
            or raw.get("ProcessIntegrityLevel")
        )
        if integrity_level:
            if "system" in integrity_level:
                normalized_integrity = "system"
            elif "high" in integrity_level:
                normalized_integrity = "high"
            elif "medium" in integrity_level:
                normalized_integrity = "medium"
            elif "low" in integrity_level:
                normalized_integrity = "low"
            else:
                normalized_integrity = integrity_level
            cdr["privilege"] = {
                "integrity_level": normalized_integrity,
                "token_elevation": bool(raw.get("TokenElevation") or raw.get("token_elevation")),
            }
            mapped["cdr"] = cdr
        return self._finalize(
            mapped,
            subject=subject,
            object_=object_,
            semantic_relations=relations,
            source_type="windows/etw",
            logsource={"product": "windows", "service": "etw"},
        )
