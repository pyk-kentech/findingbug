from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from engine.io.events import Event


class IntegrityLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    SYSTEM = 4


@dataclass(slots=True)
class PrivilegeState:
    integrity_by_entity: dict[str, IntegrityLevel] = field(default_factory=dict)
    root_euid_entities: set[str] = field(default_factory=set)
    elevated_version_nodes: set[str] = field(default_factory=set)


class PrivilegeTracker:
    """Track OS privilege state for process entities."""

    def __init__(self, graph) -> None:
        self.graph = graph
        self.state = PrivilegeState()

    def has_elevated_privilege(self, entity_id: str | None) -> bool:
        return self.has_high_integrity(entity_id) or self.has_system_integrity(entity_id) or self.has_root_euid(entity_id)

    def integrity_level(self, entity_id: str | None) -> IntegrityLevel | None:
        if not entity_id:
            return None
        return self.state.integrity_by_entity.get(entity_id)

    def has_system_integrity(self, entity_id: str | None) -> bool:
        return self.integrity_level(entity_id) == IntegrityLevel.SYSTEM

    def has_high_integrity(self, entity_id: str | None) -> bool:
        level = self.integrity_level(entity_id)
        return level is not None and level >= IntegrityLevel.HIGH

    def has_root_euid(self, entity_id: str | None) -> bool:
        return bool(entity_id and entity_id in self.state.root_euid_entities)

    def privileged_entities(self) -> set[str]:
        return set(self.state.integrity_by_entity) | set(self.state.root_euid_entities)

    def elevated_version_nodes(self) -> set[str]:
        return set(self.state.elevated_version_nodes)

    def cleanup(self, removed_entities: set[str], removed_version_nodes: set[str]) -> None:
        if removed_entities:
            for entity_id in removed_entities:
                self.state.integrity_by_entity.pop(entity_id, None)
            self.state.root_euid_entities.difference_update(removed_entities)
        if removed_version_nodes:
            self.state.elevated_version_nodes.difference_update(removed_version_nodes)

    def mark_entity_integrity(self, entity_id: str | None, level: IntegrityLevel, node_id: str | None = None) -> None:
        if not entity_id:
            return
        prev = self.state.integrity_by_entity.get(entity_id)
        if prev is None or level > prev:
            self.state.integrity_by_entity[entity_id] = level
        version_node = node_id or self.graph.current_version_node(entity_id)
        if version_node:
            self.state.elevated_version_nodes.add(version_node)

    def mark_entity_root_euid(self, entity_id: str | None, node_id: str | None = None) -> None:
        if not entity_id:
            return
        self.state.root_euid_entities.add(entity_id)
        version_node = node_id or self.graph.current_version_node(entity_id)
        if version_node:
            self.state.elevated_version_nodes.add(version_node)

    @staticmethod
    def _parse_integrity(value: object) -> IntegrityLevel | None:
        if not isinstance(value, str):
            return None
        lowered = value.strip().lower()
        mapping = {
            "low": IntegrityLevel.LOW,
            "medium": IntegrityLevel.MEDIUM,
            "high": IntegrityLevel.HIGH,
            "system": IntegrityLevel.SYSTEM,
        }
        return mapping.get(lowered)

    @staticmethod
    def _parse_euid(value: object) -> int | None:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except ValueError:
            return None

    def on_graph_event(self, event: Event, node_info: dict[str, str] | None) -> None:
        if not node_info or not event.subject:
            return
        subject_node = node_info.get("subject_node_id")
        object_node = node_info.get("object_node_id")
        existing_integrity = self.integrity_level(event.subject)
        if existing_integrity is not None:
            self.mark_entity_integrity(event.subject, existing_integrity, subject_node)
        if event.object:
            obj_integrity = self.integrity_level(event.object)
            if obj_integrity is not None:
                self.mark_entity_integrity(event.object, obj_integrity, object_node)
        if self.has_root_euid(event.subject):
            self.mark_entity_root_euid(event.subject, subject_node)
        if event.object and self.has_root_euid(event.object):
            self.mark_entity_root_euid(event.object, object_node)

        raw = event.raw if isinstance(event.raw, dict) else {}
        cdr = raw.get("cdr") if isinstance(raw.get("cdr"), dict) else {}
        privilege = cdr.get("privilege") if isinstance(cdr.get("privilege"), dict) else {}
        integrity = self._parse_integrity(privilege.get("integrity_level"))
        if integrity is not None:
            self.mark_entity_integrity(event.subject, integrity, subject_node)
        euid = self._parse_euid(privilege.get("euid") if privilege else raw.get("euid"))
        if euid == 0:
            self.mark_entity_root_euid(event.subject, subject_node)
