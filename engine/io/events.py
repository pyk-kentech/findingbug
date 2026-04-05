from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import json
from pathlib import Path
from typing import Any

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
    raw: dict[str, Any] = field(default_factory=dict)


class EventSchemaError(ValueError):
    """Raised when an input event cannot be normalized."""


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
        raw=raw,
    )


def load_events_jsonl(path: str | Path) -> list[Event]:
    """Load events from JSONL and normalize them to Event schema."""
    events: list[Event] = []
    p = Path(path)

    opener = gzip.open if p.suffix.lower() == ".gz" else Path.open
    with opener(p, "rt", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EventSchemaError(f"Invalid JSON at line {idx}: {exc}") from exc

            events.append(normalize_event(raw, idx))

    return events
