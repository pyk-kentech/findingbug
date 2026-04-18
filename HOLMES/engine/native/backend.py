from __future__ import annotations

import importlib
import os
import time
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

    def reset_graph(self) -> None:
        ...

    def record_graph_event(self, event: Event) -> None:
        ...

    def record_graph_events(self, events: list[Event]) -> None:
        ...

    def record_graph_payloads(self, payloads: list[dict]) -> None:
        ...

    def flush(self) -> None:
        ...

    def reset_online_index(self) -> None:
        ...

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        ...

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        ...

    def remove_online_match(self, node_id: str, match_id: str) -> bool:
        ...

    def online_index_stats(self) -> tuple[int, int, int, int]:
        ...

    def graph_stats(self) -> tuple[int, int]:
        ...

    def graph_current_version_node(self, entity_id: str) -> str | None:
        ...

    def graph_prune_preview(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, int]:
        ...

    def graph_prune_apply(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, object]:
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
    graph_record_payload_encode_time_seconds = 0.0
    graph_record_ffi_call_time_seconds = 0.0
    graph_record_event_count = 0
    graph_record_ffi_call_count = 0

    def process_events(self, events: list[Event]) -> bool:
        return False

    def reset_graph(self) -> None:
        return None

    def record_graph_event(self, event: Event) -> None:
        return None

    def record_graph_events(self, events: list[Event]) -> None:
        return None

    def record_graph_payloads(self, payloads: list[dict]) -> None:
        return None

    def flush(self) -> None:
        return None

    def reset_online_index(self) -> None:
        return None

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        return None

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        return None

    def remove_online_match(self, node_id: str, match_id: str) -> bool:
        return False

    def online_index_stats(self) -> tuple[int, int, int, int]:
        return (0, 0, 0, 0)

    def graph_stats(self) -> tuple[int, int]:
        return (0, 0)

    def graph_current_version_node(self, entity_id: str) -> str | None:
        return None

    def graph_prune_preview(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, int]:
        return {"entities_removed": 0, "version_nodes_removed": 0, "edges_removed": 0}

    def graph_prune_apply(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, object]:
        return {
            "entities_removed": 0,
            "version_nodes_removed": 0,
            "edges_removed": 0,
            "removed_entities": [],
            "removed_version_nodes": [],
        }

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
        self.graph_record_payload_encode_time_seconds = 0.0
        self.graph_record_ffi_call_time_seconds = 0.0
        self.graph_record_event_count = 0
        self.graph_record_ffi_call_count = 0

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

    def reset_graph(self) -> None:
        self._engine.reset_graph()

    def record_graph_event(self, event: Event) -> None:
        payload_started = time.perf_counter()
        payload = self._event_to_payload(event)
        self.graph_record_payload_encode_time_seconds += time.perf_counter() - payload_started
        self.record_graph_payloads([payload])

    def record_graph_events(self, events: list[Event]) -> None:
        payload_started = time.perf_counter()
        payload = [self._event_to_payload(event) for event in events]
        self.graph_record_payload_encode_time_seconds += time.perf_counter() - payload_started
        self.record_graph_payloads(payload)

    def record_graph_payloads(self, payloads: list[dict]) -> None:
        if not payloads:
            return
        ffi_started = time.perf_counter()
        self.graph_record_ffi_call_count += 1
        if len(payloads) == 1 and not hasattr(self._engine, "record_graph_events"):
            self._engine.record_graph_event(payloads[0])
        else:
            try:
                self._engine.record_graph_events(payloads)
            except AttributeError:
                for payload in payloads:
                    self._engine.record_graph_event(payload)
        self.graph_record_ffi_call_time_seconds += time.perf_counter() - ffi_started
        self.graph_record_event_count += len(payloads)

    def flush(self) -> None:
        self._engine.flush()

    def reset_online_index(self) -> None:
        self._engine.reset_online_index()

    def add_online_edge(self, src: str, dst: str, edge_type: str) -> None:
        self._engine.add_online_edge(src, dst, edge_type)

    def register_online_match(self, node_id: str, match_id: str, rule_id: str, sequence: int) -> None:
        self._engine.register_online_match(node_id, match_id, rule_id, sequence)

    def remove_online_match(self, node_id: str, match_id: str) -> bool:
        return bool(self._engine.remove_online_match(node_id, match_id))

    def online_index_stats(self) -> tuple[int, int, int, int]:
        return tuple(self._engine.online_index_stats())

    def graph_stats(self) -> tuple[int, int]:
        return tuple(self._engine.graph_stats())

    def graph_current_version_node(self, entity_id: str) -> str | None:
        return self._engine.graph_current_version_node(entity_id)

    def graph_prune_preview(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, int]:
        return dict(
            self._engine.graph_prune_preview(
                watermark_ts or "",
                int(retention_seconds),
                sorted(protected_entities or set()),
                sorted(protected_version_nodes or set()),
                int(max_version_nodes),
                int(max_edges),
                float(cap_low_watermark_ratio),
            )
        )

    def graph_prune_apply(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
        max_version_nodes: int = 0,
        max_edges: int = 0,
        cap_low_watermark_ratio: float = 1.0,
    ) -> dict[str, object]:
        removed_version_nodes, removed_entities, edges_removed = self._engine.graph_prune_apply(
            watermark_ts or "",
            int(retention_seconds),
            sorted(protected_entities or set()),
            sorted(protected_version_nodes or set()),
            int(max_version_nodes),
            int(max_edges),
            float(cap_low_watermark_ratio),
        )
        return {
            "entities_removed": len(removed_entities),
            "version_nodes_removed": len(removed_version_nodes),
            "edges_removed": int(edges_removed),
            "removed_entities": list(removed_entities),
            "removed_version_nodes": list(removed_version_nodes),
        }

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
