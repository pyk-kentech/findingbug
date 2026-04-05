from __future__ import annotations

from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Any

import yaml


def load_yaml_config(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("config root must be a mapping")
    return payload


def config_get(payload: dict[str, Any], *keys: str) -> Any:
    cur: Any = payload
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def apply_config_defaults(
    parser: ArgumentParser,
    args: Namespace,
    config: dict[str, Any],
    mappings: dict[str, tuple[str, ...]],
) -> Namespace:
    for arg_name, path_keys in mappings.items():
        configured = config_get(config, *path_keys)
        if configured is None:
            continue
        current = getattr(args, arg_name)
        default = parser.get_default(arg_name)
        if current == default or current is None:
            setattr(args, arg_name, configured)
    return args


def validate_mode_config(mode: str, args: Namespace, config: dict[str, Any]) -> None:
    if mode == "stream":
        source_count = int(bool(getattr(args, "events", None))) + int(bool(getattr(args, "watch_dir", None))) + int(bool(getattr(args, "kafka_topic", None)))
        if source_count != 1:
            raise ValueError(
                "stream config error: exactly one input source is required across CLI/config "
                "(source.events, source.watch_dir, or kafka.topic)"
            )
        if getattr(args, "kafka_topic", None) and not getattr(args, "kafka_bootstrap_servers", None):
            raise ValueError("stream config error: kafka.bootstrap_servers is required when kafka.topic is set")
    elif mode == "experiments":
        required = {
            "benign_events": "experiments.benign_events",
            "attack_events": "experiments.attack_events",
            "rules": "experiments.rules",
            "ground_truth": "experiments.ground_truth",
            "out": "experiments.out",
        }
        missing = [path for attr, path in required.items() if not getattr(args, attr, None)]
        if missing:
            raise ValueError(f"experiments config error: missing required settings: {', '.join(missing)}")
