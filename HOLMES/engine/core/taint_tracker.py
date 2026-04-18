from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.io.events import Event
from engine.rules.schema import Rule


@dataclass(slots=True)
class TaintState:
    tainted_version_nodes: set[str] = field(default_factory=set)
    tainted_entities: set[str] = field(default_factory=set)
    entity_last_tainted_ts: dict[str, datetime] = field(default_factory=dict)
    version_last_tainted_ts: dict[str, datetime] = field(default_factory=dict)


class TaintTracker:
    """Track compromised entities and propagate taint with relation-aware flow rules."""

    FORWARD_PROPAGATION = {
        "write",
        "execute",
        "spawn",
        "inject",
        "connect",
        "request",
        "invoke",
        "make_mem_exec",
        "protect_memory_exec",
    }
    REVERSE_PROPAGATION = {
        "read",
        "recv",
        "accept",
        "resolve",
    }

    def __init__(self, graph: ProvenanceGraph) -> None:
        self.graph = graph
        self.state = TaintState()

    def is_tainted_entity(self, entity_id: str | None) -> bool:
        return bool(entity_id and entity_id in self.state.tainted_entities)

    def is_tainted_version(self, node_id: str | None) -> bool:
        return bool(node_id and node_id in self.state.tainted_version_nodes)

    def tainted_entities_by_prefix(self, prefix: str) -> set[str]:
        norm = prefix.lower()
        return {entity for entity in self.state.tainted_entities if entity.split(":", 1)[0].lower() == norm}

    def tainted_entities(self) -> set[str]:
        return set(self.state.tainted_entities)

    def tainted_version_nodes(self) -> set[str]:
        return set(self.state.tainted_version_nodes)

    def cleanup(self, removed_entities: set[str], removed_version_nodes: set[str]) -> None:
        if removed_entities:
            self.state.tainted_entities.difference_update(removed_entities)
            for entity_id in removed_entities:
                self.state.entity_last_tainted_ts.pop(entity_id, None)
        if removed_version_nodes:
            self.state.tainted_version_nodes.difference_update(removed_version_nodes)
            for node_id in removed_version_nodes:
                self.state.version_last_tainted_ts.pop(node_id, None)

    def _parse_ts(self, raw_ts: str | None) -> datetime | None:
        if not raw_ts:
            return None
        return self.graph._parse_ts(raw_ts)  # noqa: SLF001

    def mark_entity_tainted(self, entity_id: str | None, node_id: str | None = None, observed_ts: str | None = None) -> None:
        if not entity_id:
            return
        self.state.tainted_entities.add(entity_id)
        observed = self._parse_ts(observed_ts)
        if observed is not None:
            self.state.entity_last_tainted_ts[entity_id] = observed
        version_node = node_id or self.graph.current_version_node(entity_id)
        if version_node:
            self.state.tainted_version_nodes.add(version_node)
            if observed is not None:
                self.state.version_last_tainted_ts[version_node] = observed

    def on_graph_event(self, event: Event, node_info: dict[str, str] | None) -> None:
        if not node_info or not event.subject or not event.object:
            return
        subject_node = node_info.get("subject_node_id")
        object_node = node_info.get("object_node_id")

        # Preserve taint across version transitions for both endpoints.
        for entity, current_node in ((event.subject, subject_node), (event.object, object_node)):
            if self.is_tainted_entity(entity):
                self.mark_entity_tainted(entity, current_node, event.ts)

        raw = event.raw if isinstance(event.raw, dict) else {}
        cdr = raw.get("cdr")
        relations = cdr.get("semantic_relations") if isinstance(cdr, dict) else None
        if not isinstance(relations, list):
            return
        for item in relations:
            if not isinstance(item, dict):
                continue
            relation = str(item.get("relation") or "").strip().lower()
            src = item.get("src")
            dst = item.get("dst")
            if not isinstance(src, str) or not isinstance(dst, str):
                continue
            if relation in self.FORWARD_PROPAGATION and self.is_tainted_entity(src):
                self.mark_entity_tainted(dst, self.graph.current_version_node(dst), event.ts)
            if relation in self.REVERSE_PROPAGATION and self.is_tainted_entity(dst):
                self.mark_entity_tainted(src, self.graph.current_version_node(src), event.ts)

    def mark_initial_compromise(self, match: TTPMatch, rule: Rule | None) -> None:
        if rule is None:
            return
        stage_name = str(rule.apt_stage or "")
        stage_num = int(rule.stage or 0) if rule.stage is not None else 0
        if stage_name != "Initial Compromise" and stage_num not in {0, 1}:
            return
        explicit_symbols = {
            str(binding.get("symbol"))
            for binding in getattr(rule, "entity_bindings", [])
            if isinstance(binding, dict) and isinstance(binding.get("symbol"), str)
        }
        for symbol, entity_id in match.bindings.items():
            if explicit_symbols and symbol not in explicit_symbols:
                continue
            node_id = match.binding_node_ids.get(symbol)
            observed_ts = str(match.metadata.get("event_ts") or match.metadata.get("ts") or match.metadata.get("timestamp") or "")
            self.mark_entity_tainted(entity_id, node_id, observed_ts)

    def evict_stale(
        self,
        *,
        watermark_ts: str | None,
        retention_seconds: int,
        protected_entities: set[str] | None = None,
        protected_version_nodes: set[str] | None = None,
    ) -> dict[str, int]:
        watermark = self._parse_ts(watermark_ts)
        if watermark is None or retention_seconds < 0:
            return {"entities_removed": 0, "version_nodes_removed": 0}
        cutoff = watermark - timedelta(seconds=int(retention_seconds))
        protected_entity_set = set(protected_entities or set())
        protected_version_set = set(protected_version_nodes or set())

        removable_entities = {
            entity_id
            for entity_id in list(self.state.tainted_entities)
            if entity_id not in protected_entity_set
            and self.state.entity_last_tainted_ts.get(entity_id) is not None
            and self.state.entity_last_tainted_ts[entity_id] <= cutoff
        }
        removable_versions = {
            node_id
            for node_id in list(self.state.tainted_version_nodes)
            if node_id not in protected_version_set
            and self.state.version_last_tainted_ts.get(node_id) is not None
            and self.state.version_last_tainted_ts[node_id] <= cutoff
        }
        if removable_entities:
            self.state.tainted_entities.difference_update(removable_entities)
            for entity_id in removable_entities:
                self.state.entity_last_tainted_ts.pop(entity_id, None)
        if removable_versions:
            self.state.tainted_version_nodes.difference_update(removable_versions)
            for node_id in removable_versions:
                self.state.version_last_tainted_ts.pop(node_id, None)
        return {
            "entities_removed": len(removable_entities),
            "version_nodes_removed": len(removable_versions),
        }
