from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

import yaml

from engine.core.graph import path_factor_passes
from engine.core.matcher import TTPMatch
from engine.hsg.builder import HSG, HSGEdge, HSGNode
from engine.io.events import Event, EventMeta
from engine.noise.model import NoiseModel, load_noise_model


@dataclass(slots=True)
class DynamicNoiseRuntimeState:
    cumulative_pair_bytes: dict[str, int] = field(default_factory=dict)
    cumulative_rule_bytes: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class NoiseConfig:
    drop_rule_ids: set[str] = field(default_factory=set)
    drop_match_ids: set[str] = field(default_factory=set)
    drop_prerequisite_types: set[str] = field(default_factory=set)
    min_graph_path_weight: float = 0.0
    min_path_factor: float = 0.0
    path_factor_op: str = "ge"
    noise_model: NoiseModel | None = None
    noise_bytes_threshold: str = "p95"
    noise_signature_min_ratio: float = 0.1
    dynamic_state: DynamicNoiseRuntimeState = field(default_factory=DynamicNoiseRuntimeState)
    last_trained_noise_stats: dict[str, Any] = field(default_factory=dict)


def load_noise_config(
    path: str | Path | None = None,
    *,
    model_path: str | Path | None = None,
    noise_bytes_threshold: str = "p95",
    noise_signature_min_ratio: float = 0.1,
) -> NoiseConfig:
    config = NoiseConfig(
        noise_bytes_threshold=noise_bytes_threshold,
        noise_signature_min_ratio=max(0.0, min(1.0, float(noise_signature_min_ratio))),
    )
    if model_path:
        config.noise_model = load_noise_model(model_path)

    if path is None:
        return config

    p = Path(path)
    if not p.exists():
        return config

    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return config

    payload = yaml.safe_load(text)
    if payload is None:
        return config
    if not isinstance(payload, dict):
        raise ValueError("noise config root must be a mapping")

    drop = payload.get("drop", payload)
    if not isinstance(drop, dict):
        raise ValueError("noise config 'drop' must be a mapping")

    rule_ids = (
        drop.get("drop_rule_ids")
        or drop.get("rule_ids")
        or drop.get("rule_id")
        or []
    )
    match_ids = drop.get("drop_match_ids") or drop.get("match_ids") or drop.get("match_id") or []
    prerequisite_types = (
        drop.get("drop_prerequisite_types")
        or drop.get("prerequisite_types")
        or drop.get("prerequisite_type")
        or []
    )
    min_graph_path_weight = payload.get("min_graph_path_weight", drop.get("min_graph_path_weight", 0.0))
    min_path_factor = payload.get("min_path_factor", drop.get("min_path_factor", 0.0))
    path_factor_op = str(payload.get("path_factor_op", drop.get("path_factor_op", "ge"))).lower()
    model_override = payload.get("noise_model") or payload.get("noise_model_path")

    if model_override and config.noise_model is None:
        config.noise_model = load_noise_model(model_override)
    if not isinstance(rule_ids, list) or any(not isinstance(x, str) for x in rule_ids):
        raise ValueError("noise.rule_id must be list[str]")
    if not isinstance(match_ids, list) or any(not isinstance(x, str) for x in match_ids):
        raise ValueError("noise.match_id must be list[str]")
    if not isinstance(prerequisite_types, list) or any(not isinstance(x, str) for x in prerequisite_types):
        raise ValueError("noise.prerequisite_type must be list[str]")
    if not isinstance(min_graph_path_weight, (int, float)):
        raise ValueError("noise.min_graph_path_weight must be a number")
    if not isinstance(min_path_factor, (int, float)):
        raise ValueError("noise.min_path_factor must be a number")
    if path_factor_op not in {"ge", "le"}:
        raise ValueError("noise.path_factor_op must be 'ge' or 'le'")

    config.drop_rule_ids = set(rule_ids)
    config.drop_match_ids = set(match_ids)
    config.drop_prerequisite_types = set(prerequisite_types)
    config.min_graph_path_weight = float(min_graph_path_weight)
    config.min_path_factor = float(min_path_factor)
    config.path_factor_op = str(path_factor_op)
    return config


def _match_bytes(match: TTPMatch, events_by_id: dict[str, Event | EventMeta] | None) -> int | None:
    if not events_by_id:
        return None
    values = []
    for event_id in match.event_ids:
        event = events_by_id.get(event_id)
        if isinstance(event, (Event, EventMeta)) and event.bytes_transferred is not None:
            values.append(int(event.bytes_transferred))
    if not values:
        return None
    return sum(values)


def _pair_key(rule_id: str, subject: str, object_: str) -> str:
    return json.dumps(
        {"rule_id": rule_id, "subject": subject, "object": object_},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _match_sort_key(match: TTPMatch, event_order: dict[str, int]) -> tuple[int, int, str]:
    indices = [event_order[eid] for eid in match.event_ids if eid in event_order]
    first_index = min(indices) if indices else 10**12
    sequence = int(match.sequence) if match.sequence is not None else first_index
    return (sequence, first_index, match.match_id)


def _dynamic_threshold_entry(match: TTPMatch, config: NoiseConfig) -> tuple[str | None, dict[str, Any] | None]:
    model = config.noise_model
    if model is None or not model.dynamic_thresholds:
        return None, None

    thresholds = model.dynamic_thresholds
    pair_thresholds = thresholds.get("pair_thresholds", {})
    rule_thresholds = thresholds.get("rule_thresholds", {})
    if not isinstance(pair_thresholds, dict) or not isinstance(rule_thresholds, dict):
        return None, None

    subject = match.bindings.get("subject")
    object_ = match.bindings.get("object")
    if isinstance(subject, str) and subject and isinstance(object_, str) and object_:
        pair_key = _pair_key(match.rule_id, subject, object_)
        pair_entry = pair_thresholds.get(pair_key)
        if isinstance(pair_entry, dict):
            return pair_key, pair_entry

    rule_entry = rule_thresholds.get(match.rule_id)
    if isinstance(rule_entry, dict):
        return match.rule_id, rule_entry
    return None, None


def _should_drop_by_dynamic_threshold(
    match: TTPMatch,
    config: NoiseConfig,
    *,
    events_by_id: dict[str, Event | EventMeta] | None,
    state: DynamicNoiseRuntimeState,
) -> tuple[bool, str | None]:
    key, threshold_entry = _dynamic_threshold_entry(match, config)
    if key is None or threshold_entry is None:
        return False, None

    match_bytes = _match_bytes(match, events_by_id)
    if match_bytes is None or match_bytes <= 0:
        return False, None

    threshold_raw = threshold_entry.get("threshold")
    if not isinstance(threshold_raw, (int, float)):
        return False, None

    subject = match.bindings.get("subject")
    object_ = match.bindings.get("object")
    pair_key = None
    if isinstance(subject, str) and subject and isinstance(object_, str) and object_:
        pair_key = _pair_key(match.rule_id, subject, object_)

    if pair_key is not None and key == pair_key:
        cumulative = state.cumulative_pair_bytes.get(pair_key, 0) + int(match_bytes)
        state.cumulative_pair_bytes[pair_key] = cumulative
    else:
        cumulative = state.cumulative_rule_bytes.get(match.rule_id, 0) + int(match_bytes)
        state.cumulative_rule_bytes[match.rule_id] = cumulative

    return cumulative <= float(threshold_raw), match.rule_id


def filter_matches(
    matches: list[TTPMatch],
    config: NoiseConfig,
    *,
    events_by_id: dict[str, Event | EventMeta] | None = None,
    reset_dynamic_state: bool = True,
) -> list[TTPMatch]:
    if not matches:
        config.last_trained_noise_stats = {"by_dynamic_threshold": 0, "dynamic_threshold_by_rule_id": {}}
        return []

    state = DynamicNoiseRuntimeState() if reset_dynamic_state else config.dynamic_state
    event_order = {event_id: idx for idx, event_id in enumerate(events_by_id or {}, start=1)}
    ordered_matches = sorted(matches, key=lambda match: _match_sort_key(match, event_order))

    kept: list[TTPMatch] = []
    by_dynamic_threshold = 0
    dynamic_threshold_by_rule_id: dict[str, int] = {}
    for match in ordered_matches:
        if match.rule_id in config.drop_rule_ids or match.match_id in config.drop_match_ids:
            continue
        drop_dynamic, rule_id = _should_drop_by_dynamic_threshold(
            match,
            config,
            events_by_id=events_by_id,
            state=state,
        )
        if drop_dynamic:
            by_dynamic_threshold += 1
            if rule_id is not None:
                dynamic_threshold_by_rule_id[rule_id] = dynamic_threshold_by_rule_id.get(rule_id, 0) + 1
            continue
        kept.append(match)

    if not reset_dynamic_state:
        config.dynamic_state = state
    config.last_trained_noise_stats = {
        "by_dynamic_threshold": by_dynamic_threshold,
        "dynamic_threshold_by_rule_id": dynamic_threshold_by_rule_id,
    }
    return kept


def passes_global_path_factor_pruning(edge: HSGEdge, config: NoiseConfig) -> bool:
    return (
        float(edge.weight or 0.0) >= config.min_graph_path_weight
        and path_factor_passes(edge.path_factor, config.min_path_factor, config.path_factor_op)
    )


def filter_hsg(hsg: HSG, config: NoiseConfig) -> HSG:
    edges = [
        e
        for e in hsg.edges
        if e.relation not in config.drop_prerequisite_types
        and (
            e.relation != "graph_path"
            or passes_global_path_factor_pruning(e, config)
        )
    ]
    return HSG(nodes=list(hsg.nodes), edges=edges)


def apply_noise_filter(
    matches_before: list[TTPMatch],
    hsg_before: HSG,
    config: NoiseConfig,
    *,
    events_by_id: dict[str, Event | EventMeta] | None = None,
) -> tuple[list[TTPMatch], HSG]:
    matches_after = filter_matches(matches_before, config, events_by_id=events_by_id, reset_dynamic_state=True)
    keep_ids = {m.match_id for m in matches_after}

    nodes_after: list[HSGNode] = [n for n in hsg_before.nodes if n.match_id in keep_ids]
    edges_subset: list[HSGEdge] = [
        e
        for e in hsg_before.edges
        if e.src in keep_ids
        and e.dst in keep_ids
    ]
    hsg_after = filter_hsg(HSG(nodes=nodes_after, edges=edges_subset), config)
    return matches_after, hsg_after


def build_noise_counts(before_matches: int, before_nodes: int, before_edges: int, after_matches: int, after_nodes: int, after_edges: int) -> dict[str, Any]:
    return {
        "before": {"matches": before_matches, "hsg_nodes": before_nodes, "hsg_edges": before_edges},
        "after": {"matches": after_matches, "hsg_nodes": after_nodes, "hsg_edges": after_edges},
        "dropped": {
            "matches": before_matches - after_matches,
            "hsg_nodes": before_nodes - after_nodes,
            "hsg_edges": before_edges - after_edges,
        },
    }
