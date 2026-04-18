from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
from typing import Any

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.io.events import Event, EventMeta
from engine.rules.schema import Rule, infer_rule_stage

BYTE_VALUE_KEYS: tuple[str, ...] = (
    "bytes",
    "size",
    "len",
    "nbytes",
    "byte_count",
    "total_bytes",
    "transfer_bytes",
    "sent_bytes",
    "recv_bytes",
    "write_bytes",
    "read_bytes",
)
BYTE_THRESHOLD_CHOICES: set[str] = {"p50", "p95", "p99", "max"}


@dataclass(slots=True)
class NoiseModel:
    version: int = 1
    benign_signatures: dict[str, dict[str, Any]] = field(default_factory=dict)
    params: dict[str, Any] = field(
        default_factory=lambda: {
            "min_count": 5,
            "bytes_min_count": 20,
            "signature_min_ratio": 0.1,
        }
    )
    byte_volume: dict[str, dict[str, float]] = field(default_factory=dict)
    signature_totals_by_rule: dict[str, int] = field(default_factory=dict)
    dynamic_thresholds: dict[str, Any] = field(default_factory=dict)


def _to_nonneg_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = int(value)
        return n if n >= 0 else None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            n = int(float(v))
        except ValueError:
            return None
        return n if n >= 0 else None
    return None


def _entity_type_and_value(entity: str) -> tuple[str, str]:
    if ":" in entity:
        prefix, value = entity.split(":", 1)
        return prefix.lower(), value
    return "unknown", entity


def _file_shape(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]
    filename = parts[-1] if parts else ""
    dir_parts = parts[:-1]
    ext = PurePosixPath(filename).suffix.lower() or "(none)"
    dir_level = len(dir_parts)
    topdir = dir_parts[0].lower() if dir_parts else "(root)"
    return f"ext={ext};dir_level={dir_level};topdir={topdir}"


def _ip_shape(value: str) -> str:
    raw = value.strip()
    candidate = raw
    if ":" in raw and raw.count(":") == 1 and "." in raw.split(":", 1)[0]:
        candidate = raw.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return "subnet=invalid"
    if ip.version == 4:
        subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
        return f"subnet={subnet.network_address}/24"
    subnet_v6 = ipaddress.ip_network(f"{ip}/64", strict=False)
    return f"subnet={subnet_v6.network_address}/64"


def _registry_shape(value: str) -> str:
    normalized = value.strip().replace("/", "\\")
    parts = [p for p in normalized.split("\\") if p]
    hive = parts[0].upper() if parts else "UNKNOWN"
    key_parts = [p.lower() for p in parts[1:3]]
    key = "\\".join(key_parts) if key_parts else "(root)"
    return f"hive={hive};key={key}"


def extract_entity_shape(entity: str, role: str) -> dict[str, str]:
    entity_type, value = _entity_type_and_value(entity)
    if entity_type == "file":
        shape = _file_shape(value)
    elif entity_type == "ip":
        shape = _ip_shape(value)
    elif entity_type in {"reg", "registry"}:
        shape = _registry_shape(value)
        entity_type = "reg"
    elif entity_type in {"proc", "process"}:
        shape = f"name={value.strip()}"
        entity_type = "proc"
    else:
        shape = f"len={len(value.strip())}"
    return {"role": role, "type": entity_type, "shape": shape}


def _signature_entities(match: TTPMatch) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, str]] = []
    subject = match.bindings.get("subject")
    if isinstance(subject, str) and subject:
        item = extract_entity_shape(subject, role="subject")
        key = (item["role"], item["type"], item["shape"])
        if key not in seen:
            seen.add(key)
            out.append(item)
    object_ = match.bindings.get("object")
    if isinstance(object_, str) and object_:
        item = extract_entity_shape(object_, role="object")
        key = (item["role"], item["type"], item["shape"])
        if key not in seen:
            seen.add(key)
            out.append(item)

    if not out:
        for entity in match.entities:
            if not isinstance(entity, str) or not entity:
                continue
            item = extract_entity_shape(entity, role="entity")
            key = (item["role"], item["type"], item["shape"])
            if key not in seen:
                seen.add(key)
                out.append(item)

    out.sort(key=lambda x: (x["role"], x["type"], x["shape"]))
    return out


def build_signature(match: TTPMatch, rule: Rule | None, graph: ProvenanceGraph | None = None) -> dict[str, Any]:
    del graph
    event_type = None
    if isinstance(match.metadata, dict):
        event_type = match.metadata.get("event_type")
    if event_type is None and rule and isinstance(rule.event_predicate, dict):
        event_type = rule.event_predicate.get("event_type") or rule.event_predicate.get("op")

    stage = infer_rule_stage(rule) if rule is not None else None
    return {
        "rule_id": match.rule_id,
        "stage": stage,
        "event_type": event_type,
        "entity_signature": _signature_entities(match),
    }


def signature_key(signature: dict[str, Any]) -> str:
    return json.dumps(signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _parse_signature_key(key: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(key)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _signature_rule_stage_from_key(key: str) -> tuple[str | None, int | None]:
    payload = _parse_signature_key(key)
    if not isinstance(payload, dict):
        return None, None
    rid = payload.get("rule_id")
    stage = payload.get("stage")
    stage_val = stage if isinstance(stage, int) else None
    return (rid if isinstance(rid, str) else None), stage_val


def _infer_signature_totals_from_benign(benign: dict[str, dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for key, info in benign.items():
        count = _to_nonneg_int(info.get("count")) if isinstance(info, dict) else None
        if count is None:
            continue
        rid = None
        if isinstance(info, dict):
            rid_raw = info.get("rule_id")
            if isinstance(rid_raw, str):
                rid = rid_raw
        if rid is None:
            rid, _ = _signature_rule_stage_from_key(key)
        if rid:
            totals[rid] = totals.get(rid, 0) + int(count)
    return totals


def extract_flow_bytes(event: Event) -> int | None:
    if event.bytes_transferred is not None:
        return int(event.bytes_transferred)

    raw = event.raw
    if not isinstance(raw, dict):
        return None

    sent = _to_nonneg_int(raw.get("sent_bytes"))
    recv = _to_nonneg_int(raw.get("recv_bytes"))
    if sent is not None and recv is not None:
        return sent + recv

    written = _to_nonneg_int(raw.get("write_bytes"))
    read = _to_nonneg_int(raw.get("read_bytes"))
    if written is not None and read is not None:
        return written + read

    for key in BYTE_VALUE_KEYS:
        n = _to_nonneg_int(raw.get(key))
        if n is not None:
            return n
    return None


def _extract_match_bytes(match: TTPMatch, events_by_id: dict[str, Any]) -> float | None:
    values: list[int] = []
    for event_id in match.event_ids:
        event = events_by_id.get(event_id)
        if isinstance(event, (Event, EventMeta)) and event.bytes_transferred is not None:
            values.append(int(event.bytes_transferred))
            continue
        if isinstance(event, Event):
            b = extract_flow_bytes(event)
            if b is not None:
                values.append(b)
        elif event is not None:
            raw = getattr(event, "raw", None)
            if isinstance(raw, dict):
                pseudo = Event(
                    event_id=str(getattr(event, "event_id", event_id)),
                    ts=None,
                    event_type=str(getattr(event, "event_type", "unknown")),
                    subject=None,
                    object=None,
                    raw=raw,
                )
                b = extract_flow_bytes(pseudo)
                if b is not None:
                    values.append(b)
    if not values:
        return None
    return float(sum(values))


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(p * len(ordered)) - 1)
    idx = min(idx, len(ordered) - 1)
    return float(ordered[idx])


def _byte_volume_stats(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "count": float(len(ordered)),
        "p50": _percentile(ordered, 0.50),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
        "max": float(ordered[-1]) if ordered else 0.0,
    }


def _as_int_if_whole(value: float) -> int | float:
    if float(value).is_integer():
        return int(value)
    return float(value)


def _normalize_byte_volume_stats(stats: dict[str, Any]) -> dict[str, float]:
    count = _to_nonneg_int(stats.get("count"))
    p50 = stats.get("p50")
    p95 = stats.get("p95")
    p99 = stats.get("p99")
    mx = stats.get("max")
    return {
        "count": float(count if count is not None else 0),
        "p50": float(p50) if isinstance(p50, (int, float)) else 0.0,
        "p95": float(p95) if isinstance(p95, (int, float)) else 0.0,
        "p99": float(p99) if isinstance(p99, (int, float)) else 0.0,
        "max": float(mx) if isinstance(mx, (int, float)) else 0.0,
    }


def train_noise_model(
    matches: list[TTPMatch],
    rule_by_id: dict[str, Rule],
    min_count: int = 5,
    bytes_min_count: int = 20,
    signature_min_ratio: float = 0.1,
    events_by_id: dict[str, Any] | None = None,
) -> NoiseModel:
    signature_counts: dict[str, int] = {}
    rule_totals: dict[str, int] = {}
    bytes_by_rule: dict[str, list[float]] = {}
    event_map = events_by_id or {}

    for match in matches:
        rule_totals[match.rule_id] = rule_totals.get(match.rule_id, 0) + 1

        sig = build_signature(match, rule_by_id.get(match.rule_id))
        key = signature_key(sig)
        signature_counts[key] = signature_counts.get(key, 0) + 1

        b = _extract_match_bytes(match, event_map)
        if b is not None:
            bytes_by_rule.setdefault(match.rule_id, []).append(b)

    benign: dict[str, dict[str, Any]] = {}
    for key, count in signature_counts.items():
        info: dict[str, Any] = {"count": int(count)}
        rid, stage = _signature_rule_stage_from_key(key)
        if rid is not None:
            info["rule_id"] = rid
        if stage is not None:
            info["stage"] = int(stage)
        benign[key] = info

    byte_volume: dict[str, dict[str, float]] = {}
    for rule_id, vals in bytes_by_rule.items():
        if len(vals) < int(bytes_min_count):
            continue
        byte_volume[rule_id] = _byte_volume_stats(vals)

    ratio = max(0.0, min(1.0, float(signature_min_ratio)))
    return NoiseModel(
        version=1,
        benign_signatures=benign,
        params={
            "min_count": int(min_count),
            "bytes_min_count": int(bytes_min_count),
            "signature_min_ratio": ratio,
        },
        byte_volume=byte_volume,
        signature_totals_by_rule=rule_totals,
    )


def get_benign_drop_ids(
    matches: list[TTPMatch],
    rule_by_id: dict[str, Rule],
    model: NoiseModel,
    events_by_id: dict[str, Any] | None = None,
    bytes_threshold: str = "p95",
    signature_min_ratio: float | None = None,
) -> tuple[set[str], dict[str, Any]]:
    if bytes_threshold not in BYTE_THRESHOLD_CHOICES:
        raise ValueError(f"bytes_threshold must be one of {sorted(BYTE_THRESHOLD_CHOICES)}")

    model_min_count = max(1, int(_to_nonneg_int(model.params.get("min_count")) or 1))
    ratio_default = model.params.get("signature_min_ratio", 0.1)
    min_ratio = float(signature_min_ratio if signature_min_ratio is not None else ratio_default)
    min_ratio = max(0.0, min(1.0, min_ratio))

    drop_ids: set[str] = set()
    by_signature = 0
    by_byte_volume = 0
    by_rule_id: dict[str, int] = {}
    dropped_by_ratio = 0
    event_map = events_by_id or {}
    rule_totals = dict(model.signature_totals_by_rule or {})
    if not rule_totals:
        rule_totals = _infer_signature_totals_from_benign(model.benign_signatures)

    for match in matches:
        sig = build_signature(match, rule_by_id.get(match.rule_id))
        key = signature_key(sig)
        sig_info = model.benign_signatures.get(key)
        if isinstance(sig_info, dict):
            count = int(_to_nonneg_int(sig_info.get("count")) or 0)
            total = int(rule_totals.get(match.rule_id, 0))
            if total <= 0:
                total = count
            ratio = (float(count) / float(total)) if total > 0 else 0.0
            if count >= model_min_count and ratio >= min_ratio:
                drop_ids.add(match.match_id)
                by_signature += 1
                dropped_by_ratio += 1
                continue

        stats = model.byte_volume.get(match.rule_id)
        if isinstance(stats, dict):
            b = _extract_match_bytes(match, event_map)
            thr = stats.get(bytes_threshold)
            if b is not None and isinstance(thr, (int, float)) and b <= float(thr):
                drop_ids.add(match.match_id)
                by_byte_volume += 1
                by_rule_id[match.rule_id] = by_rule_id.get(match.rule_id, 0) + 1

    return drop_ids, {
        "by_signature": by_signature,
        "by_byte_volume": by_byte_volume,
        "byte_volume_by_rule_id": by_rule_id,
        "signature_precision": {
            "total_signatures": len(model.benign_signatures),
            "dropped_by_ratio": dropped_by_ratio,
        },
    }


def load_noise_model(path: str | Path) -> NoiseModel:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Noise model not found: {p}")
    payload = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("noise model root must be an object")

    version = int(payload.get("version", 1))
    benign = payload.get("benign_signatures", {})
    params = payload.get("params", {"min_count": 5, "bytes_min_count": 20, "signature_min_ratio": 0.1})
    byte_volume = payload.get("byte_volume", {})
    signature_totals_by_rule = payload.get("signature_totals_by_rule", {})
    legacy_byte_p95 = payload.get("byte_p95_by_rule", {})
    dynamic_thresholds = payload.get("dynamic_thresholds", {})

    if not isinstance(benign, dict):
        raise ValueError("noise model benign_signatures must be an object")
    if not isinstance(params, dict):
        raise ValueError("noise model params must be an object")
    if not isinstance(byte_volume, dict):
        raise ValueError("noise model byte_volume must be an object")
    if not isinstance(signature_totals_by_rule, dict):
        raise ValueError("noise model signature_totals_by_rule must be an object")
    if not isinstance(legacy_byte_p95, dict):
        raise ValueError("noise model byte_p95_by_rule must be an object")
    if not isinstance(dynamic_thresholds, dict):
        raise ValueError("noise model dynamic_thresholds must be an object")

    min_count = max(1, int(_to_nonneg_int(params.get("min_count")) or 5))
    bytes_min_count = max(1, int(_to_nonneg_int(params.get("bytes_min_count")) or 20))
    ratio_raw = params.get("signature_min_ratio", 0.1)
    try:
        signature_min_ratio = float(ratio_raw)
    except (TypeError, ValueError):
        signature_min_ratio = 0.1
    signature_min_ratio = max(0.0, min(1.0, signature_min_ratio))

    normalized_benign: dict[str, dict[str, Any]] = {}
    for key, value in benign.items():
        info: dict[str, Any] = {}
        if isinstance(value, dict):
            count = _to_nonneg_int(value.get("count"))
            if count is None:
                continue
            info["count"] = int(count)
            rid = value.get("rule_id")
            st = value.get("stage")
            if isinstance(rid, str):
                info["rule_id"] = rid
            if isinstance(st, int):
                info["stage"] = st
        elif isinstance(value, (int, float)):
            count = _to_nonneg_int(value)
            if count is None:
                continue
            info["count"] = int(count)
        else:
            continue

        parsed_rid, parsed_stage = _signature_rule_stage_from_key(str(key))
        if "rule_id" not in info and parsed_rid is not None:
            info["rule_id"] = parsed_rid
        if "stage" not in info and parsed_stage is not None:
            info["stage"] = parsed_stage
        normalized_benign[str(key)] = info

    normalized_byte_volume: dict[str, dict[str, float]] = {}
    for key, value in byte_volume.items():
        if isinstance(value, dict):
            normalized_byte_volume[str(key)] = _normalize_byte_volume_stats(value)

    for key, value in legacy_byte_p95.items():
        if str(key) in normalized_byte_volume:
            continue
        if isinstance(value, (int, float)):
            p95 = float(value)
            normalized_byte_volume[str(key)] = {
                "count": 0.0,
                "p50": p95,
                "p95": p95,
                "p99": p95,
                "max": p95,
            }

    normalized_totals: dict[str, int] = {}
    for key, value in signature_totals_by_rule.items():
        if not isinstance(key, str):
            continue
        count = _to_nonneg_int(value)
        if count is None:
            continue
        normalized_totals[key] = int(count)
    if not normalized_totals:
        normalized_totals = _infer_signature_totals_from_benign(normalized_benign)

    return NoiseModel(
        version=version,
        benign_signatures=normalized_benign,
        params={
            "min_count": min_count,
            "bytes_min_count": bytes_min_count,
            "signature_min_ratio": signature_min_ratio,
        },
        byte_volume=normalized_byte_volume,
        signature_totals_by_rule=normalized_totals,
        dynamic_thresholds=dynamic_thresholds,
    )


def save_noise_model(model: NoiseModel, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": int(model.version),
        "benign_signatures": {
            key: {
                "count": int(_to_nonneg_int(value.get("count")) or 0),
                **({"rule_id": value.get("rule_id")} if isinstance(value.get("rule_id"), str) else {}),
                **({"stage": int(value.get("stage"))} if isinstance(value.get("stage"), int) else {}),
            }
            for key, value in model.benign_signatures.items()
            if isinstance(value, dict)
        },
        "params": {
            "min_count": int(_to_nonneg_int(model.params.get("min_count")) or 5),
            "bytes_min_count": int(_to_nonneg_int(model.params.get("bytes_min_count")) or 20),
            "signature_min_ratio": max(0.0, min(1.0, float(model.params.get("signature_min_ratio", 0.1)))),
        },
        "signature_totals_by_rule": {
            key: int(_to_nonneg_int(value) or 0) for key, value in model.signature_totals_by_rule.items()
        },
    }
    if model.byte_volume:
        payload["byte_volume"] = {
            rid: {
                "count": _as_int_if_whole(v.get("count", 0.0)),
                "p50": float(v.get("p50", 0.0)),
                "p95": float(v.get("p95", 0.0)),
                "p99": float(v.get("p99", 0.0)),
                "max": float(v.get("max", 0.0)),
            }
            for rid, v in model.byte_volume.items()
        }
    if model.dynamic_thresholds:
        payload["dynamic_thresholds"] = model.dynamic_thresholds
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
