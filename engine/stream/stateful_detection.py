from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass(slots=True)
class Node:
    guid: str
    matched_ttps: dict[str, float] = field(default_factory=dict)
    terminated_at: float | None = None
    last_seen: float = 0.0

    def record_ttp(self, ttp: str, timestamp: float) -> bool:
        previous = self.matched_ttps.get(ttp)
        if previous is not None and previous <= timestamp:
            return False
        self.matched_ttps[ttp] = timestamp
        self.last_seen = max(self.last_seen, timestamp)
        return True

    def touch(self, timestamp: float) -> None:
        self.last_seen = max(self.last_seen, timestamp)


@dataclass(slots=True)
class ProcessNode(Node):
    image: str = "<unknown>"
    parent_guid: str | None = None
    consumed_file_guids: set[str] = field(default_factory=set)


@dataclass(slots=True)
class FileNode(Node):
    path: str = "<unknown>"
    creator_guid: str | None = None


@dataclass(slots=True)
class HSG_Edge:
    src_guid: str
    src_ttp: str
    dst_guid: str
    dst_ttp: str
    time_delta: float
    distance: int


class RuleEngine:
    def __init__(self, rule_map: dict[str, set[str]] | None = None) -> None:
        self.rule_map: dict[str, set[str]] = rule_map or {}

    def set_rule(self, current_ttp: str, prerequisite_ttps: set[str]) -> None:
        self.rule_map[current_ttp] = set(prerequisite_ttps)

    def get_prerequisites(self, current_ttp: str) -> set[str]:
        return self.rule_map.get(current_ttp, set())


class StatefulDetectionEngine:
    def __init__(self, rule_engine: RuleEngine) -> None:
        self.rule_engine = rule_engine
        self.node_map: dict[str, Node] = {}
        self.hsg_edges: list[HSG_Edge] = []

    def process_event(
        self,
        timestamp: float,
        guid: str,
        parent_guid: str | None,
        image: str,
        matched_ttp: str | None = None,
    ) -> ProcessNode:
        node = self.node_map.get(guid)
        if node is None:
            process_node = ProcessNode(guid=guid, image=image, parent_guid=parent_guid)
            self.node_map[guid] = process_node
        elif isinstance(node, ProcessNode):
            process_node = node
            process_node.image = image
            process_node.parent_guid = parent_guid
        else:
            raise TypeError(f"GUID '{guid}' is already assigned to a different node type")

        process_node.touch(timestamp)

        if parent_guid and parent_guid not in self.node_map:
            self.node_map[parent_guid] = ProcessNode(guid=parent_guid)

        if matched_ttp:
            recorded = process_node.record_ttp(matched_ttp, timestamp)
            if recorded:
                self.check_prerequisites(process_node, matched_ttp, timestamp)

        return process_node

    def process_file_event(
        self,
        timestamp: float,
        process_guid: str,
        file_guid: str,
        action: str,
    ) -> FileNode | None:
        node = self.node_map.get(process_guid)
        if node is None:
            process_node = ProcessNode(guid=process_guid)
            self.node_map[process_guid] = process_node
        elif isinstance(node, ProcessNode):
            process_node = node
        else:
            raise TypeError(f"GUID '{process_guid}' is already assigned to a different node type")

        process_node.touch(timestamp)

        file_node = self.node_map.get(file_guid)
        if file_node is None:
            file_entity = FileNode(guid=file_guid, path=file_guid)
            self.node_map[file_guid] = file_entity
        elif isinstance(file_node, FileNode):
            file_entity = file_node
        else:
            raise TypeError(f"GUID '{file_guid}' is already assigned to a different node type")

        file_entity.touch(timestamp)

        normalized_action = action.upper()
        if normalized_action == "WRITE":
            file_entity.creator_guid = process_guid
        elif normalized_action == "READ":
            process_node.consumed_file_guids.add(file_guid)
        else:
            raise ValueError(f"Unsupported file action: {action}")

        return file_entity

    def check_prerequisites(self, node: ProcessNode, current_ttp: str, current_time: float) -> HSG_Edge | None:
        prerequisite_ttps = self.rule_engine.get_prerequisites(current_ttp)
        if not prerequisite_ttps:
            return None

        queue: deque[tuple[str, int]] = deque([(node.guid, 0)])
        visited: set[str] = set()

        while queue:
            current_guid, distance = queue.popleft()
            if current_guid in visited:
                continue
            visited.add(current_guid)

            current = self.node_map.get(current_guid)
            if current is None:
                continue

            for prerequisite_ttp in prerequisite_ttps:
                ancestor_time = current.matched_ttps.get(prerequisite_ttp)
                if ancestor_time is None or ancestor_time >= current_time:
                    continue

                edge = HSG_Edge(
                    src_guid=current.guid,
                    src_ttp=prerequisite_ttp,
                    dst_guid=node.guid,
                    dst_ttp=current_ttp,
                    time_delta=current_time - ancestor_time,
                    distance=distance,
                )
                self.hsg_edges.append(edge)
                return edge

            if isinstance(current, ProcessNode):
                if current.parent_guid:
                    queue.append((current.parent_guid, distance + 1))
                for file_guid in current.consumed_file_guids:
                    file_node = self.node_map.get(file_guid)
                    if isinstance(file_node, FileNode) and file_node.creator_guid:
                        queue.append((file_node.creator_guid, distance + 1))

        return None

    def terminate_process(self, guid: str, timestamp: float | None = None) -> bool:
        node = self.node_map.get(guid)
        if not isinstance(node, ProcessNode):
            return False

        if timestamp is not None:
            node.terminated_at = timestamp
            node.touch(timestamp)
        else:
            node.terminated_at = node.last_seen
        return True

    def garbage_collect(self, current_time: float, max_age: float) -> list[str]:
        expired_guids: list[str] = []
        for guid, node in list(self.node_map.items()):
            if node.terminated_at is None:
                continue
            if current_time - node.last_seen < max_age:
                continue
            expired_guids.append(guid)
            del self.node_map[guid]
        return expired_guids


if __name__ == "__main__":
    rules = RuleEngine(
        {
            "attack.t1562.002": {"attack.t1190", "attack.t1059"},
        }
    )
    engine = StatefulDetectionEngine(rule_engine=rules)

    engine.process_event(
        timestamp=1000.0,
        guid="{11111111-1111-1111-1111-111111111111}",
        parent_guid=None,
        image="nginx.exe",
        matched_ttp="attack.t1190",
    )
    engine.process_file_event(
        timestamp=1002.0,
        process_guid="{11111111-1111-1111-1111-111111111111}",
        file_guid=r"C:\temp\malware.exe",
        action="WRITE",
    )
    engine.process_event(
        timestamp=1008.0,
        guid="{22222222-2222-2222-2222-222222222222}",
        parent_guid=None,
        image="explorer.exe",
        matched_ttp=None,
    )
    engine.process_file_event(
        timestamp=1009.0,
        process_guid="{22222222-2222-2222-2222-222222222222}",
        file_guid=r"C:\temp\malware.exe",
        action="READ",
    )
    engine.process_event(
        timestamp=1012.5,
        guid="{22222222-2222-2222-2222-222222222222}",
        parent_guid=None,
        image="explorer.exe",
        matched_ttp="attack.t1562.002",
    )

    for edge in engine.hsg_edges:
        print(
            "HSG Edge Created:",
            edge.src_ttp,
            "->",
            edge.dst_ttp,
            f"(src={edge.src_guid}, dst={edge.dst_guid}, delta={edge.time_delta}, distance={edge.distance})",
        )
