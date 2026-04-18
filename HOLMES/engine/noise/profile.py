from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from collections.abc import Iterable
from typing import Any

from engine.io.events import Event
from engine.io.cdr.base import infer_process_name


def _raw_value(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw:
            return raw[key]
        lowered = key.lower()
        for raw_key, value in raw.items():
            if isinstance(raw_key, str) and raw_key.lower() == lowered:
                return value
    return None


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return str(value).strip() or None


def _normalize_process_image(raw: dict[str, Any], role: str) -> str | None:
    candidates = (
        ("Image", "subject_image", "SubjectImage", "process_path", "exe", "path")
        if role == "subject"
        else ("ObjectImage", "TargetImage", "ParentImage", "object_image", "target_image", "path", "exe", "Image")
    )
    for key in candidates:
        value = _stringify(_raw_value(raw, key))
        if value:
            return value
    fallback = infer_process_name(raw, *(candidates))
    if fallback:
        return fallback
    return None


def _canonical_entity(raw: dict[str, Any], entity: str | None, role: str) -> str | None:
    if not entity:
        return None
    prefix, _, value = entity.partition(":")
    prefix = prefix.lower()
    stable_value = value.strip()
    if prefix in {"proc", "proc_guid", "proc_pid"}:
        image = _normalize_process_image(raw, role)
        return f"process_image:{image}" if image else None
    if prefix in {"file", "reg", "ip", "net", "dns", "web", "cloudapi", "cloudid", "app", "ua", "pipe", "artifact", "entity", "mem"}:
        return f"{prefix}:{stable_value}" if stable_value else None
    if stable_value and prefix not in {"uuid", "pid"}:
        return f"{prefix}:{stable_value}"
    return None


def relation_triplets_for_event(event: Event) -> list[tuple[str, str, str]]:
    raw = event.raw if isinstance(event.raw, dict) else {}
    cdr = raw.get("cdr") if isinstance(raw.get("cdr"), dict) else {}
    relations = cdr.get("semantic_relations")
    if not isinstance(relations, list):
        return []
    out: list[tuple[str, str, str]] = []
    for item in relations:
        if not isinstance(item, dict):
            continue
        relation = item.get("relation")
        src = item.get("src")
        dst = item.get("dst")
        canonical_src = _canonical_entity(raw, src if isinstance(src, str) else event.subject, "subject")
        canonical_dst = _canonical_entity(raw, dst if isinstance(dst, str) else event.object, "object")
        if isinstance(relation, str) and canonical_src and canonical_dst:
            out.append((canonical_src, relation, canonical_dst))
    return out


def profile_key(subject: str, relation: str, object_: str) -> str:
    return json.dumps(
        {"subject": subject, "relation": relation, "object": object_},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


@dataclass(slots=True)
class BenignProfile:
    version: int = 1
    min_count: int = 1
    patterns: dict[str, dict[str, Any]] = field(default_factory=dict)

    def event_is_benign(self, event: Event) -> bool:
        triplets = relation_triplets_for_event(event)
        if not triplets:
            return False
        return all(profile_key(subject, relation, object_) in self.patterns for subject, relation, object_ in triplets)


def train_benign_profile(events: Iterable[Event], min_count: int = 5) -> BenignProfile:
    counts: dict[str, int] = {}
    for event in events:
        for subject, relation, object_ in relation_triplets_for_event(event):
            key = profile_key(subject, relation, object_)
            counts[key] = counts.get(key, 0) + 1
    patterns = {
        key: {"count": int(count)}
        for key, count in counts.items()
        if int(count) >= max(1, int(min_count))
    }
    return BenignProfile(version=1, min_count=max(1, int(min_count)), patterns=patterns)


def save_benign_profile(profile: BenignProfile, path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": int(profile.version),
        "min_count": int(profile.min_count),
        "patterns": dict(profile.patterns),
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_benign_profile(path: str | Path) -> BenignProfile:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("benign profile root must be an object")
    patterns = payload.get("patterns", {})
    if not isinstance(patterns, dict):
        raise ValueError("benign profile patterns must be an object")
    return BenignProfile(
        version=int(payload.get("version", 1)),
        min_count=max(1, int(payload.get("min_count", 1))),
        patterns={str(key): value for key, value in patterns.items() if isinstance(value, dict)},
    )
