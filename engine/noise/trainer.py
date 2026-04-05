from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from engine.core.matcher import TTPMatch
from engine.io.events import Event
from engine.noise.model import NoiseModel, save_noise_model, train_noise_model
from engine.rules.schema import Rule


@dataclass(slots=True)
class DynamicThresholdEntry:
    threshold: float
    max_observed_bytes: float
    samples: int
    subject: str | None = None
    object: str | None = None
    rule_id: str | None = None


def _match_event_order(
    match: TTPMatch,
    event_index_by_id: dict[str, int],
) -> tuple[int, int, str]:
    indices = [event_index_by_id[eid] for eid in match.event_ids if eid in event_index_by_id]
    first = min(indices) if indices else 10**12
    seq = int(match.sequence) if match.sequence is not None else first
    return (seq, first, match.match_id)


def _match_bytes(match: TTPMatch, events_by_id: dict[str, Event]) -> int | None:
    values = [
        int(event.bytes_transferred)
        for event_id in match.event_ids
        for event in [events_by_id.get(event_id)]
        if isinstance(event, Event) and event.bytes_transferred is not None
    ]
    if not values:
        return None
    return sum(values)


def _pair_key(rule_id: str, subject: str, object_: str) -> str:
    return json.dumps(
        {
            "rule_id": rule_id,
            "subject": subject,
            "object": object_,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _threshold_from_max(max_bytes: float, margin_ratio: float, min_margin_bytes: int) -> float:
    margin = max(float(min_margin_bytes), float(max_bytes) * max(0.0, float(margin_ratio)))
    return float(max_bytes) + margin


def build_dynamic_thresholds(
    matches: list[TTPMatch],
    *,
    events_by_id: dict[str, Event],
    margin_ratio: float = 0.25,
    min_margin_bytes: int = 1,
    min_samples: int = 1,
) -> dict[str, Any]:
    event_index_by_id = {event_id: idx for idx, event_id in enumerate(events_by_id, start=1)}
    ordered_matches = sorted(matches, key=lambda match: _match_event_order(match, event_index_by_id))

    pair_cumulative: dict[str, int] = {}
    pair_stats: dict[str, dict[str, Any]] = {}
    rule_cumulative: dict[str, int] = {}
    rule_stats: dict[str, dict[str, Any]] = {}

    for match in ordered_matches:
        subject = match.bindings.get("subject")
        object_ = match.bindings.get("object")
        if not isinstance(subject, str) or not subject:
            continue
        if not isinstance(object_, str) or not object_:
            continue

        match_bytes = _match_bytes(match, events_by_id)
        if match_bytes is None or match_bytes <= 0:
            continue

        key = _pair_key(match.rule_id, subject, object_)
        pair_cumulative[key] = pair_cumulative.get(key, 0) + int(match_bytes)
        pair_info = pair_stats.setdefault(
            key,
            {
                "rule_id": match.rule_id,
                "subject": subject,
                "object": object_,
                "samples": 0,
                "max_observed_bytes": 0.0,
            },
        )
        pair_info["samples"] = int(pair_info["samples"]) + 1
        pair_info["max_observed_bytes"] = max(float(pair_info["max_observed_bytes"]), float(pair_cumulative[key]))

        rule_cumulative[match.rule_id] = rule_cumulative.get(match.rule_id, 0) + int(match_bytes)
        rule_info = rule_stats.setdefault(
            match.rule_id,
            {
                "rule_id": match.rule_id,
                "samples": 0,
                "max_observed_bytes": 0.0,
            },
        )
        rule_info["samples"] = int(rule_info["samples"]) + 1
        rule_info["max_observed_bytes"] = max(float(rule_info["max_observed_bytes"]), float(rule_cumulative[match.rule_id]))

    pair_thresholds = {
        key: {
            **value,
            "threshold": _threshold_from_max(value["max_observed_bytes"], margin_ratio, min_margin_bytes),
        }
        for key, value in pair_stats.items()
        if int(value["samples"]) >= int(min_samples)
    }
    rule_thresholds = {
        rule_id: {
            **value,
            "threshold": _threshold_from_max(value["max_observed_bytes"], margin_ratio, min_margin_bytes),
        }
        for rule_id, value in rule_stats.items()
        if int(value["samples"]) >= int(min_samples)
    }

    return {
        "version": 1,
        "params": {
            "margin_ratio": max(0.0, float(margin_ratio)),
            "min_margin_bytes": max(1, int(min_margin_bytes)),
            "min_samples": max(1, int(min_samples)),
        },
        "pair_thresholds": pair_thresholds,
        "rule_thresholds": rule_thresholds,
    }


def train_benign_noise_model(
    matches: list[TTPMatch],
    *,
    rule_by_id: dict[str, Rule],
    events_by_id: dict[str, Event],
    min_count: int = 5,
    bytes_min_count: int = 20,
    signature_min_ratio: float = 0.1,
    dynamic_margin_ratio: float = 0.25,
    dynamic_min_margin_bytes: int = 1,
    dynamic_min_samples: int = 1,
) -> NoiseModel:
    model = train_noise_model(
        matches,
        rule_by_id=rule_by_id,
        min_count=min_count,
        bytes_min_count=bytes_min_count,
        signature_min_ratio=signature_min_ratio,
        events_by_id=events_by_id,
    )
    model.version = max(2, int(model.version))
    model.dynamic_thresholds = build_dynamic_thresholds(
        matches,
        events_by_id=events_by_id,
        margin_ratio=dynamic_margin_ratio,
        min_margin_bytes=dynamic_min_margin_bytes,
        min_samples=dynamic_min_samples,
    )
    return model


def save_benign_noise_model(model: NoiseModel, path: str | Path) -> None:
    save_noise_model(model, path)

