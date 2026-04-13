from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
from typing import Any

from engine.io.cdr.base import canonical_relation
from engine.io.cdr.base import map_raw_event_to_cdr

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


def _to_nonneg_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        out = int(value)
        return out if out >= 0 else None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            out = int(float(raw))
        except ValueError:
            return None
        return out if out >= 0 else None
    return None


def extract_event_bytes(raw: dict[str, Any]) -> int | None:
    sent = _to_nonneg_int(raw.get("sent_bytes"))
    recv = _to_nonneg_int(raw.get("recv_bytes"))
    if sent is not None and recv is not None:
        return sent + recv

    written = _to_nonneg_int(raw.get("write_bytes"))
    read = _to_nonneg_int(raw.get("read_bytes"))
    if written is not None and read is not None:
        return written + read

    for key in BYTE_VALUE_KEYS:
        value = _to_nonneg_int(raw.get(key))
        if value is not None:
            return value
    return None


@dataclass(slots=True)
class Event:
    """Normalized event schema used by the MVP pipeline."""

    event_id: str
    ts: str | None
    event_type: str
    subject: str | None
    object: str | None
    bytes_transferred: int | None = None
    parsed_ts: datetime | None = None
    event_type_lower: str = ""
    semantic_relations: tuple[tuple[str, str, str], ...] = ()
    subject_state_change: bool = False
    object_state_change: bool = False
    is_memory_object: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EventMeta:
    """Compact retained event metadata for long-running pipelines."""

    event_id: str
    ts: str | None
    bytes_transferred: int | None = None


class EventSchemaError(ValueError):
    """Raised when an input event cannot be normalized."""


def _is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def _extract_semantic_relations(raw: dict[str, Any]) -> tuple[tuple[str, str, str], ...]:
    cdr = raw.get("cdr")
    if not isinstance(cdr, dict):
        return ()
    relations = cdr.get("semantic_relations")
    if not isinstance(relations, list):
        return ()
    out: list[tuple[str, str, str]] = []
    for item in relations:
        if not isinstance(item, dict):
            continue
        relation = item.get("relation")
        src = item.get("src")
        dst = item.get("dst")
        if isinstance(relation, str) and isinstance(src, str) and isinstance(dst, str):
            out.append((canonical_relation(relation), src, dst))
    return tuple(out)


def _parse_event_ts(value: str | None) -> datetime | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        numeric = float(raw)
        abs_numeric = abs(numeric)
        if abs_numeric >= 1e17:
            numeric /= 1_000_000_000.0
        elif abs_numeric >= 1e14:
            numeric /= 1_000_000.0
        elif abs_numeric >= 1e11:
            numeric /= 1_000.0
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        pass
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def normalize_event(raw: dict[str, Any], index: int) -> Event:
    """Normalize flexible input JSON into the engine Event schema."""
    if not isinstance(raw, dict):
        raise EventSchemaError(f"Event at line {index} is not a JSON object")
    raw = map_raw_event_to_cdr(raw)

    event_id = str(raw.get("event_id") or raw.get("id") or f"evt-{index}")
    ts = raw.get("ts") or raw.get("timestamp")
    if ts is not None:
        ts = str(ts)

    event_type = str(raw.get("event_type") or raw.get("type") or "unknown")
    event_type_lower = event_type.lower()

    subject = raw.get("subject")
    object_ = raw.get("object")
    if subject is not None:
        subject = str(subject)
    if object_ is not None:
        object_ = str(object_)

    return Event(
        event_id=event_id,
        ts=ts,
        event_type=event_type,
        subject=subject,
        object=object_,
        bytes_transferred=extract_event_bytes(raw),
        parsed_ts=_parse_event_ts(ts),
        event_type_lower=event_type_lower,
        semantic_relations=_extract_semantic_relations(raw),
        subject_state_change=_is_truthy(raw.get("subject_state_change")),
        object_state_change=_is_truthy(raw.get("object_state_change")),
        is_memory_object=bool(object_ and object_.startswith("mem:")),
        raw=raw,
    )


def iter_raw_records_jsonl(path: str | Path) -> Iterator[tuple[int, str]]:
    """Stream raw non-empty JSONL records as (line_number, text)."""
    p = Path(path)
    opener = gzip.open if p.suffix.lower() == ".gz" else Path.open
    with opener(p, "rt", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield idx, line


def count_raw_records_jsonl(path: str | Path) -> int:
    """Count non-empty JSONL records."""
    count = 0
    for _idx, _line in iter_raw_records_jsonl(path):
        count += 1
    return count


def load_events_jsonl(path: str | Path) -> Iterator[Event]:
    """Stream events from JSONL and normalize them lazily."""
    for idx, line in iter_raw_records_jsonl(path):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EventSchemaError(f"Invalid JSON at line {idx}: {exc}") from exc

        yield normalize_event(raw, idx)
