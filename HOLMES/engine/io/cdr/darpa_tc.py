from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from engine.io.cdr.base import BaseCDRAdapter, normalize_text

SUBJECT_CACHE: dict[str, dict[str, str]] = {}
OBJECT_CACHE: dict[str, dict[str, str]] = {}


def _unwrap_scalar(value: Any) -> Any:
    if isinstance(value, list):
        return [_unwrap_scalar(item) for item in value]
    if not isinstance(value, dict):
        return value

    if len(value) == 1:
        key, item = next(iter(value.items()))
        key_text = normalize_text(key)
        if key_text in {"string", "int", "long", "float", "double", "boolean", "bytes", "null"}:
            return _unwrap_scalar(item)
        if key_text == "map" and isinstance(item, dict):
            return {str(k): _unwrap_scalar(v) for k, v in item.items()}
        if key_text == "array" and isinstance(item, list):
            return [_unwrap_scalar(v) for v in item]
        if "com.bbn.tc.schema.avro" in key_text:
            return _unwrap_scalar(item)

    return {str(k): _unwrap_scalar(v) for k, v in value.items()}


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value is not None:
            return _unwrap_scalar(value)
    return None


def _flatten_namespace_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            text = normalize_text(key)
            if text:
                tokens.add(text)
            tokens |= _flatten_namespace_tokens(item)
    elif isinstance(value, list):
        for item in value:
            tokens |= _flatten_namespace_tokens(item)
    elif isinstance(value, str):
        text = normalize_text(value)
        if text:
            tokens.add(text)
    return tokens


def _unwrap_avro_payload(raw: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    namespace_tokens = _flatten_namespace_tokens(raw)
    datum = raw.get("datum")
    if isinstance(datum, dict) and len(datum) == 1:
        namespace, payload = next(iter(datum.items()))
        if isinstance(payload, dict):
            namespace_tokens.add(normalize_text(namespace))
            merged = _unwrap_scalar(payload)
            if not isinstance(merged, dict):
                merged = {"value": merged}
            merged.setdefault("datum_namespace", namespace)
            for key in ("event_id", "event_type", "timestamp", "ts", "hostId", "logsource"):
                if key in raw and key not in merged:
                    merged[key] = _unwrap_scalar(raw[key])
            return merged, namespace_tokens
    normalized = _unwrap_scalar(raw)
    return (normalized if isinstance(normalized, dict) else dict(raw)), namespace_tokens


class _DarpaTA1Parser(ABC):
    name = "generic"

    @classmethod
    @abstractmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        raise NotImplementedError

    @staticmethod
    def _entity(prefix: str, value: Any) -> str | None:
        return BaseCDRAdapter._entity(prefix, value)

    def _entity_from_object(self, raw_obj: Any) -> str | None:
        raw_obj = _unwrap_scalar(raw_obj)
        if isinstance(raw_obj, str):
            text = raw_obj.strip()
            if not text:
                return None
            if ":" in text:
                return text
            return f"entity:{text}"
        if not isinstance(raw_obj, dict):
            return None
        obj_type = normalize_text(
            raw_obj.get("type")
            or raw_obj.get("objectType")
            or raw_obj.get("cdmType")
            or raw_obj.get("kind")
            or raw_obj.get("baseObjectType")
        )
        uuid = _first(raw_obj, "uuid", "UUID", "cid", "id", "subjectUuid", "predicateObjectUuid")
        path = _first(raw_obj, "path", "predicateObjectPath", "name", "filename", "exe")
        host = _first(raw_obj, "hostId", "hostname")
        if obj_type in {"subject", "process", "process_object"}:
            return self._entity("proc_guid", uuid or path)
        if obj_type in {"file", "file_object"}:
            return self._entity("file", path or uuid)
        if obj_type in {"netflow", "ip", "socket"}:
            return self._entity("ip", _first(raw_obj, "remoteAddress", "address", "ip", "dst_ip", "src_ip") or uuid)
        if obj_type in {"memory", "memory_object"}:
            pid = _first(raw_obj, "pid", "processId", "tgid")
            addr = _first(raw_obj, "baseAddress", "address", "vm_start", "start")
            if pid is not None and addr is not None:
                return f"mem:{pid}:{addr}:0"
        if host and uuid:
            return f"entity:{host}:{uuid}"
        return self._entity("entity", uuid or path)

    def subject_entity(self, raw: dict[str, Any]) -> str | None:
        subject = raw.get("subject")
        if isinstance(subject, str):
            cached = SUBJECT_CACHE.get(subject)
            if cached and cached.get("entity"):
                return cached["entity"]
            return self._entity("proc_guid", subject)
        entity = self._entity_from_object(subject)
        if entity:
            return entity
        subject_uuid = _first(raw, "subject_uuid", "subjectUuid", "subjectId", "subject")
        if isinstance(subject_uuid, (str, int)):
            cached = SUBJECT_CACHE.get(str(subject_uuid))
            if cached and cached.get("entity"):
                return cached["entity"]
            return self._entity("proc_guid", subject_uuid)
        return None

    def object_entity(self, raw: dict[str, Any]) -> str | None:
        direct_path = _first(raw, "predicateObjectPath", "predicateObject2Path", "path", "name")
        if isinstance(direct_path, str) and direct_path.strip():
            normalized_path = direct_path.strip()
            if normalized_path.startswith("/"):
                return self._entity("file", normalized_path)
        for key in ("predicateObject", "predicateObject2", "object"):
            candidate = _unwrap_scalar(raw.get(key))
            if isinstance(candidate, str):
                cached = OBJECT_CACHE.get(candidate) or SUBJECT_CACHE.get(candidate)
                if cached and cached.get("entity"):
                    return cached["entity"]
            entity = self._entity_from_object(raw.get(key))
            if entity:
                return entity
        object_uuid = _first(raw, "predicateObjectUuid", "object_uuid", "objectUuid")
        object_path = _first(raw, "predicateObjectPath", "path", "name")
        if isinstance(object_uuid, (str, int)):
            cached = OBJECT_CACHE.get(str(object_uuid)) or SUBJECT_CACHE.get(str(object_uuid))
            if cached and cached.get("entity"):
                return cached["entity"]
        return self._entity("entity", object_uuid or object_path)

    def relation(self, raw: dict[str, Any]) -> str:
        event_type = normalize_text(
            raw.get("event_type")
            or raw.get("type")
            or raw.get("typeName")
            or raw.get("eventType")
            or raw.get("datum")
            or raw.get("predicateObjectType")
        )
        mapping = {
            "event_execve": "execute",
            "execve": "execute",
            "event_clone": "spawn",
            "event_fork": "spawn",
            "clone": "spawn",
            "fork": "spawn",
            "event_open": "read",
            "event_read": "read",
            "read": "read",
            "event_write": "write",
            "write": "write",
            "event_connect": "connect",
            "connect": "connect",
            "event_sendmsg": "write",
            "event_recvmsg": "read",
            "event_execute": "execute",
            "event_accept": "accept",
            "accept": "accept",
            "event_mmap": "make_mem_exec",
            "event_mprotect": "protect_memory_exec",
            "event_sendto": "write",
            "event_recvfrom": "read",
        }
        return mapping.get(event_type, "write")

    def enrich(self, raw: dict[str, Any], mapped: dict[str, Any]) -> dict[str, Any]:
        return mapped

    @staticmethod
    def _extract_cmdline(raw: dict[str, Any]) -> str | None:
        properties = raw.get("properties")
        if isinstance(properties, dict):
            for key in ("cmdLine", "commandLine", "command_line"):
                value = properties.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            for key in ("args", "argv"):
                value = properties.get(key)
                if isinstance(value, list):
                    parts = [str(item).strip() for item in value if str(item).strip()]
                    if parts:
                        return " ".join(parts)
            prop_map = properties.get("map")
            if isinstance(prop_map, dict):
                for key in ("cmdLine", "commandLine", "command_line", "name"):
                    value = prop_map.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
        for key in ("cmdLine", "commandLine", "command_line"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for key in ("args", "argv"):
            value = raw.get(key)
            if isinstance(value, list):
                parts = [str(item).strip() for item in value if str(item).strip()]
                if parts:
                    return " ".join(parts)
        return None

    @staticmethod
    def _extract_image(raw: dict[str, Any]) -> str | None:
        for key in ("path", "exe", "image", "program", "predicateObjectPath"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        properties = raw.get("properties")
        if isinstance(properties, dict):
            prop_map = properties.get("map")
            if isinstance(prop_map, dict):
                for key in ("image", "exe", "path", "name"):
                    value = prop_map.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
        predicate_object = raw.get("predicateObject")
        if isinstance(predicate_object, dict):
            for key in ("path", "exe", "image", "name"):
                value = predicate_object.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return None


class TraceParser(_DarpaTA1Parser):
    name = "trace"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return any("trace" in token for token in namespace_tokens) or normalize_text(raw.get("host")) == "trace"

    def subject_entity(self, raw: dict[str, Any]) -> str | None:
        subject = raw.get("subject")
        if isinstance(subject, dict):
            subject_uuid = _first(subject, "uuid", "subjectUuid", "cid")
            if subject_uuid is not None:
                return self._entity("proc_guid", subject_uuid)
        return super().subject_entity(raw)

    def enrich(self, raw: dict[str, Any], mapped: dict[str, Any]) -> dict[str, Any]:
        out = dict(mapped)
        cmdline = self._extract_cmdline(raw)
        image = self._extract_image(raw)
        if cmdline:
            out["CommandLine"] = cmdline
        if image:
            out["Image"] = image
        return out


class TheiaParser(_DarpaTA1Parser):
    name = "theia"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return any("theia" in token for token in namespace_tokens)

    def subject_entity(self, raw: dict[str, Any]) -> str | None:
        subject = raw.get("subject")
        if isinstance(subject, dict):
            subject_uuid = _first(subject, "uuid", "subjectUuid", "cid")
            if subject_uuid is not None:
                return self._entity("proc_guid", subject_uuid)
        return super().subject_entity(raw)

    def enrich(self, raw: dict[str, Any], mapped: dict[str, Any]) -> dict[str, Any]:
        out = dict(mapped)
        cmdline = self._extract_cmdline(raw)
        image = self._extract_image(raw)
        if cmdline:
            out["CommandLine"] = cmdline
        if image:
            out["Image"] = image
        return out


class FiveDirectionsParser(_DarpaTA1Parser):
    name = "fivedirections"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return any("fivedirections" in token for token in namespace_tokens)


class CadetsParser(_DarpaTA1Parser):
    name = "cadets"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return any("cadets" in token for token in namespace_tokens)


class ClearscopeParser(_DarpaTA1Parser):
    name = "clearscope"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return any("clearscope" in token for token in namespace_tokens)


class GenericDarpaParser(_DarpaTA1Parser):
    name = "generic"

    @classmethod
    def matches(cls, namespace_tokens: set[str], raw: dict[str, Any]) -> bool:
        return True


class DarpaTCAdapter(BaseCDRAdapter):
    name = "darpa_tc"
    PARSERS: tuple[type[_DarpaTA1Parser], ...] = (
        TraceParser,
        TheiaParser,
        FiveDirectionsParser,
        CadetsParser,
        ClearscopeParser,
        GenericDarpaParser,
    )

    @classmethod
    def can_handle(cls, raw: dict[str, Any]) -> bool:
        logsource = raw.get("logsource")
        if isinstance(logsource, dict):
            dataset = normalize_text(logsource.get("dataset"))
            if dataset in {"darpa_tc", "darpa_tc_e3", "darpa"}:
                return True
        namespace_tokens = _flatten_namespace_tokens(raw)
        if any("com.bbn.tc.schema.avro" in token for token in namespace_tokens):
            return True
        return any(key in raw for key in ("hostId", "subject_uuid", "predicateObjectUuid", "datum"))

    def _select_parser(self, namespace_tokens: set[str], raw: dict[str, Any]) -> _DarpaTA1Parser:
        for parser_cls in self.PARSERS:
            if parser_cls.matches(namespace_tokens, raw):
                return parser_cls()
        return GenericDarpaParser()

    @staticmethod
    def _remember_subject(payload: dict[str, Any], parser: _DarpaTA1Parser) -> None:
        uuid = _first(payload, "uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            return
        cmdline = parser._extract_cmdline(payload)
        image = parser._extract_image(payload)
        entity = BaseCDRAdapter._entity("proc_guid", uuid)
        record: dict[str, str] = {"entity": entity or f"proc_guid:{uuid}"}
        if cmdline:
            record["CommandLine"] = cmdline
        if image:
            record["Image"] = image
        elif cmdline:
            record["Image"] = cmdline.split()[0].strip()
        SUBJECT_CACHE[uuid] = record

    @staticmethod
    def _remember_object(payload: dict[str, Any]) -> None:
        uuid = _first(payload, "uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            return
        namespace = normalize_text(payload.get("datum_namespace"))
        base_object = payload.get("baseObject")
        base_properties = {}
        if isinstance(base_object, dict):
            props = base_object.get("properties")
            if isinstance(props, dict):
                prop_map = props.get("map")
                if isinstance(prop_map, dict):
                    base_properties = prop_map

        entity: str | None = None
        image: str | None = None
        if "fileobject" in namespace:
            path = (
                _first(payload, "path", "filename", "name")
                or base_properties.get("path")
            )
            if isinstance(path, str) and path.strip():
                entity = BaseCDRAdapter._entity("file", path.strip())
                image = path.strip()
        elif "netflowobject" in namespace:
            remote = _first(payload, "remoteAddress", "address", "ip")
            if isinstance(remote, str) and remote.strip():
                entity = BaseCDRAdapter._entity("ip", remote.strip())
        elif "memoryobject" in namespace:
            tgid = base_properties.get("tgid") or _first(payload, "tgid", "pid", "processId")
            addr = _first(payload, "memoryAddress", "baseAddress", "address")
            if tgid is not None and addr is not None:
                entity = f"mem:{tgid}:{addr}:0"
        elif "srcsinkobject" in namespace:
            entity = BaseCDRAdapter._entity("entity", uuid)

        if entity:
            record = {"entity": entity}
            if image:
                record["Image"] = image
            OBJECT_CACHE[uuid] = record

    def to_cdr(self, raw: dict[str, Any]) -> dict[str, Any]:
        payload, namespace_tokens = _unwrap_avro_payload(raw)
        parser = self._select_parser(namespace_tokens, payload)
        namespace = normalize_text(payload.get("datum_namespace"))
        if "subject" in namespace and "event" not in namespace:
            self._remember_subject(payload, parser)
        elif any(token in namespace for token in ("fileobject", "netflowobject", "memoryobject", "srcsinkobject")):
            self._remember_object(payload)
        subject = parser.subject_entity(payload)
        object_ = parser.object_entity(payload)
        relation = parser.relation(payload)
        relations: list[dict[str, str]] = []
        if subject and object_:
            relations.append({"relation": relation, "src": subject, "dst": object_})

        mapped = dict(payload)
        if mapped.get("event_id") is None:
            mapped["event_id"] = str(_first(payload, "uuid", "event_uuid", "id", "sequence") or "darpa-event")
        if mapped.get("ts") is None and mapped.get("timestamp") is None:
            ts = _first(payload, "timestampNanos", "timestampMicros", "timestamp", "ts")
            if ts is not None:
                mapped["ts"] = str(ts)
        if mapped.get("event_type") is None:
            mapped["event_type"] = normalize_text(
                payload.get("typeName") or payload.get("eventType") or payload.get("type") or payload.get("datum") or "darpa_event"
            )
        subject_value = _unwrap_scalar(payload.get("subject"))
        if isinstance(subject_value, str):
            cached = SUBJECT_CACHE.get(subject_value)
            if cached:
                mapped.setdefault("Image", cached.get("Image"))
                mapped.setdefault("CommandLine", cached.get("CommandLine"))
        object_value = _unwrap_scalar(payload.get("predicateObject"))
        if isinstance(object_value, str):
            cached_obj = OBJECT_CACHE.get(object_value) or SUBJECT_CACHE.get(object_value)
            if cached_obj:
                mapped.setdefault("TargetImage", cached_obj.get("Image"))
                if not mapped.get("Image") and relation == "execute":
                    mapped["Image"] = cached_obj.get("Image")
        mapped["ta1_parser"] = parser.name
        mapped = parser.enrich(payload, mapped)
        return self._finalize(
            mapped,
            subject=subject,
            object_=object_,
            semantic_relations=relations,
            source_type=f"darpa/tc/{parser.name}",
            logsource={"product": "darpa", "service": "tc", "dataset": "darpa_tc_e3", "ta1": parser.name},
        )
