from __future__ import annotations

import importlib
import os
from typing import Protocol

from engine.io.events import Event


class NativeEngineBackend(Protocol):
    """
    Narrow backend seam for future Rust/C++ engine migration.

    A native backend may choose to consume a batch end-to-end and return True,
    or return False to let the Python engine handle the batch normally.
    """

    available: bool
    name: str

    def process_events(self, events: list[Event]) -> bool:
        ...

    def flush(self) -> None:
        ...

    def reset_online_index(self) -> None:
        ...

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        ...

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        ...

    def online_index_stats(self) -> tuple[int, int, int, int]:
        ...

    def graph_stats(self) -> tuple[int, int]:
        ...

    def online_contains_match(self, node_id: str, match_id: str) -> bool:
        ...

    def online_node_match_count(self, node_id: str) -> int:
        ...

    def online_mapper_contains_rule(self, node_id: str, rule_id: str) -> bool:
        ...

    def online_mapper_earliest_seq(self, node_id: str, rule_id: str) -> int | None:
        ...

    def online_mapper_min_hops(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> int | None:
        ...

    def online_mapper_match_ids(self, node_id: str) -> set[str]:
        ...


class NoopNativeBackend:
    available = False
    name = "python"

    def process_events(self, events: list[Event]) -> bool:
        return False

    def flush(self) -> None:
        return None

    def reset_online_index(self) -> None:
        return None

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        return None

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        return None

    def online_index_stats(self) -> tuple[int, int, int, int]:
        return (0, 0, 0, 0)

    def graph_stats(self) -> tuple[int, int]:
        return (0, 0)

    def online_contains_match(self, node_id: str, match_id: str) -> bool:
        return False

    def online_node_match_count(self, node_id: str) -> int:
        return 0

    def online_mapper_contains_rule(self, node_id: str, rule_id: str) -> bool:
        return False

    def online_mapper_earliest_seq(self, node_id: str, rule_id: str) -> int | None:
        return None

    def online_mapper_min_hops(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> int | None:
        return None

    def online_mapper_match_ids(self, node_id: str) -> set[str]:
        return set()


class RustNativeBackend:
    available = True
    name = "rust"

    def __init__(self, module) -> None:
        self._module = module
        self._engine = module.NativeBatchEngine()

    @staticmethod
    def _event_to_payload(event: Event) -> dict:
        return {
            "event_id": event.event_id,
            "ts": event.ts,
            "event_type": event.event_type,
            "subject": event.subject,
            "object": event.object,
            "bytes_transferred": event.bytes_transferred,
            "event_type_lower": event.event_type_lower,
            "subject_state_change": event.subject_state_change,
            "object_state_change": event.object_state_change,
            "is_memory_object": event.is_memory_object,
            "semantic_relations": list(event.semantic_relations),
        }

    def process_events(self, events: list[Event]) -> bool:
        payload = [self._event_to_payload(event) for event in events]
        return bool(self._engine.process_batch(payload))

    def flush(self) -> None:
        self._engine.flush()

    def reset_online_index(self) -> None:
        self._engine.reset_online_index()

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        self._engine.add_online_edge(src, dst, edge_type)

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        self._engine.register_online_match(node_id, match_id, rule_id, sequence)

    def online_index_stats(self) -> tuple[int, int, int, int]:
        return tuple(self._engine.online_index_stats())

    def graph_stats(self) -> tuple[int, int]:
        return tuple(self._engine.graph_stats())

    def online_contains_match(self, node_id: str, match_id: str) -> bool:
        return bool(self._engine.online_contains_match(node_id, match_id))

    def online_node_match_count(self, node_id: str) -> int:
        return int(self._engine.online_node_match_count(node_id))

    def online_mapper_contains_rule(self, node_id: str, rule_id: str) -> bool:
        return bool(self._engine.online_mapper_contains_rule(node_id, rule_id))

    def online_mapper_earliest_seq(self, node_id: str, rule_id: str) -> int | None:
        return self._engine.online_mapper_earliest_seq(node_id, rule_id)

    def online_mapper_min_hops(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> int | None:
        return self._engine.online_mapper_min_hops(node_id, match_id, origin_node_id)

    def online_mapper_match_ids(self, node_id: str) -> set[str]:
        return set(self._engine.online_mapper_match_ids(node_id))


def load_native_backend() -> NativeEngineBackend:
    """
    Placeholder loader for future Rust/C++ backends.

    Today we keep behavior identical and fall back to the Python engine.
    """
    backend_name = os.getenv("HOLMES_NATIVE_BACKEND", "python").strip().lower()
    if backend_name in {"", "python", "none"}:
        return NoopNativeBackend()
    if backend_name == "rust":
        try:
            module = importlib.import_module("holmes_native_rs")
            return RustNativeBackend(module)
        except Exception:
            return NoopNativeBackend()
    return NoopNativeBackend()
