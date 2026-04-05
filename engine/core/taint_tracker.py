from __future__ import annotations

from dataclasses import dataclass, field

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.io.events import Event
from engine.rules.schema import Rule


@dataclass(slots=True)
class TaintState:
    tainted_version_nodes: set[str] = field(default_factory=set)
    tainted_entities: set[str] = field(default_factory=set)


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
        if removed_version_nodes:
            self.state.tainted_version_nodes.difference_update(removed_version_nodes)

    def mark_entity_tainted(self, entity_id: str | None, node_id: str | None = None) -> None:
        if not entity_id:
            return
        self.state.tainted_entities.add(entity_id)
        version_node = node_id or self.graph.current_version_node(entity_id)
        if version_node:
            self.state.tainted_version_nodes.add(version_node)

    def on_graph_event(self, event: Event, node_info: dict[str, str] | None) -> None:
        if not node_info or not event.subject or not event.object:
            return
        subject_node = node_info.get("subject_node_id")
        object_node = node_info.get("object_node_id")

        # Preserve taint across version transitions for both endpoints.
        for entity, current_node in ((event.subject, subject_node), (event.object, object_node)):
            if self.is_tainted_entity(entity):
                self.mark_entity_tainted(entity, current_node)

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
                self.mark_entity_tainted(dst, self.graph.current_version_node(dst))
            if relation in self.REVERSE_PROPAGATION and self.is_tainted_entity(dst):
                self.mark_entity_tainted(src, self.graph.current_version_node(src))

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
            self.mark_entity_tainted(entity_id, node_id)
