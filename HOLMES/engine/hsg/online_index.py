from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import os
import time

from engine.core.graph import EdgeType


def _seed_merge_bucket_name(size: int) -> str:
    if size <= 1:
        return "1"
    if size <= 4:
        return "2_4"
    if size <= 16:
        return "5_16"
    if size <= 64:
        return "17_64"
    return "65_plus"


@dataclass(slots=True)
class NodeMapper:
    match_ids: set[str] = field(default_factory=set)
    match_ids_by_rule: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    rule_id_by_match: dict[str, str] = field(default_factory=dict)
    earliest_seq_by_rule: dict[str, int] = field(default_factory=dict)
    # match_id -> origin_node_id -> min data-flow hops
    hops_by_match_origin: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(dict))


class OnlineIndex:
    """
    Incremental mapper/index for online prerequisite checks.

    - edge propagate: src mapper -> dst mapper (DATA_FLOW and VERSION_TRANSITION)
    - O(1) checks: required_ttp in node mapper, earliest sequence lookup
    - O(k) retrieval: candidate upstream match ids from mapper buckets
    """

    def __init__(self) -> None:
        depth_raw = os.getenv("HOLMES_ONLINE_INDEX_MAX_PROPAGATION_DEPTH", "5").strip()
        try:
            parsed_depth = int(depth_raw)
        except ValueError:
            parsed_depth = 5
        fanout_raw = os.getenv("HOLMES_ONLINE_INDEX_MAX_FAN_OUT", "1000").strip()
        try:
            parsed_fanout = int(fanout_raw)
        except ValueError:
            parsed_fanout = 1000
        data_flow_precheck_raw = os.getenv("HOLMES_ONLINE_INDEX_ENABLE_DATA_FLOW_PRECHECK", "0").strip().lower()
        self.max_propagation_depth = max(0, parsed_depth)
        self.max_fan_out = max(0, parsed_fanout)
        self.enable_data_flow_precheck = data_flow_precheck_raw not in {"0", "false", "no"}
        self.propagation_depth_cutoff_total = 0
        self.propagation_fanout_cutoff_total = 0
        self._node_mapper: dict[str, NodeMapper] = {}
        # Explicit adjacency cache for propagation engine.
        self.out_edges: dict[str, list[tuple[str, EdgeType | str]]] = defaultdict(list)
        self._out_edge_set: dict[str, set[tuple[str, EdgeType | str]]] = defaultdict(set)
        self.in_edges: dict[str, list[tuple[str, EdgeType | str]]] = defaultdict(list)
        self._in_edge_set: dict[str, set[tuple[str, EdgeType | str]]] = defaultdict(set)
        self._local_matches: dict[str, set[str]] = defaultdict(set)
        self._local_matches_by_rule: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self._local_match_meta: dict[str, dict[str, tuple[str, int, str]]] = defaultdict(dict)
        self._pending_new_edges: list[tuple[str, str, EdgeType | str]] = []
        self.flush_pending_edges_total_time_seconds = 0.0
        self.flush_pending_edges_loop_time_seconds = 0.0
        self.flush_pending_edges_propagate_time_seconds = 0.0
        self.flush_pending_edges_batch_count = 0
        self.flush_pending_edges_edge_count = 0
        self.propagate_across_new_edge_seed_merge_time_seconds = 0.0
        self.propagate_across_new_edge_downstream_time_seconds = 0.0
        self.propagate_delta_time_seconds = 0.0
        self.propagate_delta_queue_pop_count = 0
        self.propagate_delta_edge_visit_count = 0
        self.propagate_delta_changed_enqueue_count = 0
        self.propagate_across_new_edge_changed_match_total = 0
        self.propagate_across_new_edge_scanned_match_total = 0
        self.propagate_across_new_edge_empty_src_count = 0
        self.propagate_across_new_edge_no_change_count = 0
        self.propagate_across_new_edge_seed_merge_time_by_edge_type: dict[str, float] = defaultdict(float)
        self.propagate_across_new_edge_scanned_match_by_edge_type: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_changed_match_by_edge_type: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_count_by_edge_type: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_seed_merge_time_by_bucket: dict[str, float] = defaultdict(float)
        self.propagate_across_new_edge_scanned_match_by_bucket: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_changed_match_by_bucket: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_count_by_bucket: dict[str, int] = defaultdict(int)
        self.propagate_across_new_edge_empty_dst_fast_path_count = 0
        self.propagate_across_new_edge_empty_dst_fast_path_time_seconds = 0.0
        self.propagate_across_new_edge_data_flow_precheck_time_seconds = 0.0
        self.propagate_across_new_edge_data_flow_precheck_count = 0
        self.propagate_across_new_edge_data_flow_precheck_hit_count = 0

    def prune_nodes(self, removed_version_nodes: set[str]) -> None:
        """
        Remove all references to deleted version nodes so Python GC can reclaim memory.
        """
        if not removed_version_nodes:
            return
        removed = set(removed_version_nodes)

        for node_id in removed:
            self._node_mapper.pop(node_id, None)
            self._local_matches.pop(node_id, None)
            self._local_matches_by_rule.pop(node_id, None)
            self._local_match_meta.pop(node_id, None)
            self.out_edges.pop(node_id, None)
            self._out_edge_set.pop(node_id, None)
            self.in_edges.pop(node_id, None)
            self._in_edge_set.pop(node_id, None)

        for src in list(self.out_edges.keys()):
            filtered = [(dst, et) for (dst, et) in self.out_edges[src] if dst not in removed]
            if filtered:
                self.out_edges[src] = filtered
                self._out_edge_set[src] = set(filtered)
            else:
                self.out_edges.pop(src, None)
                self._out_edge_set.pop(src, None)
        for dst in list(self.in_edges.keys()):
            filtered = [(src, et) for (src, et) in self.in_edges[dst] if src not in removed]
            if filtered:
                self.in_edges[dst] = filtered
                self._in_edge_set[dst] = set(filtered)
            else:
                self.in_edges.pop(dst, None)
                self._in_edge_set.pop(dst, None)

        self._pending_new_edges = [
            (src, dst, et)
            for (src, dst, et) in self._pending_new_edges
            if src not in removed and dst not in removed
        ]

    def prune(self, _removed_entities: set[str], removed_version_nodes: set[str]) -> None:
        """
        Graph prune-hook adapter. Keeps the hook signature stable while delegating to node cleanup.
        """
        self.prune_nodes(removed_version_nodes)

    def _mapper(self, node_id: str) -> NodeMapper:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            mapper = NodeMapper()
            self._node_mapper[node_id] = mapper
        return mapper

    @staticmethod
    def _populate_empty_mapper_from_src(dst: NodeMapper, src: NodeMapper, edge_cost: int) -> int:
        if not src.match_ids:
            return 0
        dst.match_ids = set(src.match_ids)
        dst.match_ids_by_rule = defaultdict(set, {rule_id: set(match_ids) for rule_id, match_ids in src.match_ids_by_rule.items()})
        dst.rule_id_by_match = dict(src.rule_id_by_match)
        dst.earliest_seq_by_rule = dict(src.earliest_seq_by_rule)
        if edge_cost == 0:
            dst.hops_by_match_origin = defaultdict(
                dict,
                {match_id: dict(by_origin) for match_id, by_origin in src.hops_by_match_origin.items()},
            )
        else:
            dst.hops_by_match_origin = defaultdict(
                dict,
                {
                    match_id: {origin_node_id: int(hops) + int(edge_cost) for origin_node_id, hops in by_origin.items()}
                    for match_id, by_origin in src.hops_by_match_origin.items()
                },
            )
        return len(dst.match_ids)

    def _merge_match_from_src(
        self,
        dst: NodeMapper,
        src: NodeMapper,
        match_id: str,
        edge_cost: int,
    ) -> bool:
        changed = False
        if match_id not in src.match_ids:
            return False

        if match_id not in dst.match_ids:
            dst.match_ids.add(match_id)
            changed = True

        rule_id = src.rule_id_by_match.get(match_id)
        if rule_id is not None:
            dst_ids = dst.match_ids_by_rule[rule_id]
            if match_id not in dst_ids:
                dst_ids.add(match_id)
                changed = True
            if dst.rule_id_by_match.get(match_id) != rule_id:
                dst.rule_id_by_match[match_id] = rule_id
                changed = True
            src_earliest = src.earliest_seq_by_rule.get(rule_id)
            if src_earliest is None:
                src_earliest = None
            prev = dst.earliest_seq_by_rule.get(rule_id)
            if src_earliest is not None and (prev is None or src_earliest < prev):
                dst.earliest_seq_by_rule[rule_id] = src_earliest
                changed = True

        src_origins = src.hops_by_match_origin.get(match_id, {})
        if src_origins:
            dst_origins = dst.hops_by_match_origin[match_id]
            for origin_node_id, src_hops in src_origins.items():
                cand = int(src_hops) + int(edge_cost)
                prev = dst_origins.get(origin_node_id)
                if prev is None or cand < prev:
                    dst_origins[origin_node_id] = cand
                    changed = True
        return changed

    @staticmethod
    def _would_data_flow_seed_merge_change(dst: NodeMapper, src: NodeMapper) -> bool:
        if not src.match_ids:
            return False
        if not src.match_ids.issubset(dst.match_ids):
            return True
        for rule_id, src_earliest in src.earliest_seq_by_rule.items():
            dst_earliest = dst.earliest_seq_by_rule.get(rule_id)
            if dst_earliest is None or int(src_earliest) < int(dst_earliest):
                return True
        for match_id in src.match_ids:
            if dst.rule_id_by_match.get(match_id) != src.rule_id_by_match.get(match_id):
                return True
            src_origins = src.hops_by_match_origin.get(match_id, {})
            if not src_origins:
                continue
            dst_origins = dst.hops_by_match_origin.get(match_id, {})
            for origin_node_id, src_hops in src_origins.items():
                cand = int(src_hops) + 1
                prev = dst_origins.get(origin_node_id)
                if prev is None or cand < int(prev):
                    return True
        return False

    def _propagate_delta(self, start_node_id: str, delta_match_ids: set[str]) -> None:
        if not delta_match_ids:
            return
        started = time.perf_counter()
        q: deque[tuple[str, set[str], int]] = deque([(start_node_id, set(delta_match_ids), 0)])
        while q:
            self.propagate_delta_queue_pop_count += 1
            src_node_id, delta, current_depth = q.popleft()
            if self.max_propagation_depth > 0 and current_depth >= self.max_propagation_depth:
                self.propagation_depth_cutoff_total += 1
                continue
            out_edges_list = self.out_edges.get(src_node_id, [])
            if self.max_fan_out > 0 and len(out_edges_list) > self.max_fan_out:
                self.propagation_fanout_cutoff_total += 1
                continue
            src_mapper = self._mapper(src_node_id)
            for dst_node_id, edge_type in out_edges_list:
                self.propagate_delta_edge_visit_count += 1
                if edge_type == EdgeType.DATA_FLOW:
                    edge_cost = 1
                elif edge_type == EdgeType.VERSION_TRANSITION:
                    edge_cost = 0
                else:
                    continue
                dst_mapper = self._mapper(dst_node_id)
                changed_for_dst: set[str] = set()
                for match_id in delta:
                    if self._merge_match_from_src(dst_mapper, src_mapper, match_id, edge_cost=edge_cost):
                        changed_for_dst.add(match_id)
                if changed_for_dst:
                    next_depth = current_depth + 1
                    q.append((dst_node_id, changed_for_dst, next_depth))
                    self.propagate_delta_changed_enqueue_count += 1
        self.propagate_delta_time_seconds += time.perf_counter() - started

    def _edge_cost_for(self, edge_type: EdgeType | str) -> int | None:
        if edge_type == EdgeType.DATA_FLOW:
            return 1
        if edge_type == EdgeType.VERSION_TRANSITION:
            return 0
        return None

    def _propagate_across_new_edge(
        self,
        src_node_id: str,
        dst_node_id: str,
        edge_type: EdgeType | str,
    ) -> None:
        edge_cost = self._edge_cost_for(edge_type)
        if edge_cost is None:
            return
        src_mapper = self._mapper(src_node_id)
        if not src_mapper.match_ids:
            self.propagate_across_new_edge_empty_src_count += 1
            return
        edge_type_name = str(getattr(edge_type, "value", edge_type))
        src_match_count = len(src_mapper.match_ids)
        bucket_name = _seed_merge_bucket_name(src_match_count)
        dst_mapper = self._mapper(dst_node_id)
        changed_for_dst: set[str] = set()
        seed_merge_started = time.perf_counter()
        self.propagate_across_new_edge_count_by_edge_type[edge_type_name] += 1
        self.propagate_across_new_edge_count_by_bucket[bucket_name] += 1
        self.propagate_across_new_edge_scanned_match_total += src_match_count
        self.propagate_across_new_edge_scanned_match_by_edge_type[edge_type_name] += src_match_count
        self.propagate_across_new_edge_scanned_match_by_bucket[bucket_name] += src_match_count
        if not dst_mapper.match_ids and not dst_mapper.earliest_seq_by_rule and not dst_mapper.hops_by_match_origin:
            self.propagate_across_new_edge_empty_dst_fast_path_count += 1
            fast_path_started = time.perf_counter()
            changed_count = self._populate_empty_mapper_from_src(dst_mapper, src_mapper, edge_cost=edge_cost)
            self.propagate_across_new_edge_empty_dst_fast_path_time_seconds += time.perf_counter() - fast_path_started
            if changed_count > 0:
                changed_for_dst = set(src_mapper.match_ids)
        else:
            if edge_cost == 1 and self.enable_data_flow_precheck:
                self.propagate_across_new_edge_data_flow_precheck_count += 1
                precheck_started = time.perf_counter()
                should_merge = self._would_data_flow_seed_merge_change(dst_mapper, src_mapper)
                self.propagate_across_new_edge_data_flow_precheck_time_seconds += time.perf_counter() - precheck_started
                if not should_merge:
                    self.propagate_across_new_edge_data_flow_precheck_hit_count += 1
                else:
                    for match_id in src_mapper.match_ids:
                        if self._merge_match_from_src(dst_mapper, src_mapper, match_id, edge_cost=edge_cost):
                            changed_for_dst.add(match_id)
            else:
                for match_id in src_mapper.match_ids:
                    if self._merge_match_from_src(dst_mapper, src_mapper, match_id, edge_cost=edge_cost):
                        changed_for_dst.add(match_id)
        seed_merge_elapsed = time.perf_counter() - seed_merge_started
        self.propagate_across_new_edge_seed_merge_time_seconds += seed_merge_elapsed
        self.propagate_across_new_edge_seed_merge_time_by_edge_type[edge_type_name] += seed_merge_elapsed
        self.propagate_across_new_edge_seed_merge_time_by_bucket[bucket_name] += seed_merge_elapsed
        changed_count = len(changed_for_dst)
        self.propagate_across_new_edge_changed_match_total += changed_count
        self.propagate_across_new_edge_changed_match_by_edge_type[edge_type_name] += changed_count
        self.propagate_across_new_edge_changed_match_by_bucket[bucket_name] += changed_count
        if not changed_for_dst:
            self.propagate_across_new_edge_no_change_count += 1
        if changed_for_dst:
            downstream_started = time.perf_counter()
            self._propagate_delta(dst_node_id, changed_for_dst)
            self.propagate_across_new_edge_downstream_time_seconds += time.perf_counter() - downstream_started

    def _local_mapper_for_node(self, node_id: str) -> NodeMapper:
        mapper = NodeMapper()
        local_meta = self._local_match_meta.get(node_id, {})
        for match_id, (rule_id, sequence, origin_node_id) in local_meta.items():
            mapper.match_ids.add(match_id)
            mapper.match_ids_by_rule[rule_id].add(match_id)
            mapper.rule_id_by_match[match_id] = rule_id
            prev = mapper.earliest_seq_by_rule.get(rule_id)
            if prev is None or sequence < prev:
                mapper.earliest_seq_by_rule[rule_id] = sequence
            mapper.hops_by_match_origin[match_id][origin_node_id] = 0
        return mapper

    def _recompute_mapper_for_node(self, node_id: str) -> bool:
        old_mapper = self._node_mapper.get(node_id)
        new_mapper = self._local_mapper_for_node(node_id)
        for src_node_id, edge_type in self.in_edges.get(node_id, []):
            edge_cost = self._edge_cost_for(edge_type)
            if edge_cost is None:
                continue
            src_mapper = self._node_mapper.get(src_node_id)
            if src_mapper is None:
                continue
            for match_id in src_mapper.match_ids:
                self._merge_match_from_src(new_mapper, src_mapper, match_id, edge_cost=edge_cost)
        if (
            old_mapper is not None
            and old_mapper.match_ids == new_mapper.match_ids
            and old_mapper.earliest_seq_by_rule == new_mapper.earliest_seq_by_rule
            and old_mapper.match_ids_by_rule == new_mapper.match_ids_by_rule
            and old_mapper.rule_id_by_match == new_mapper.rule_id_by_match
            and old_mapper.hops_by_match_origin == new_mapper.hops_by_match_origin
        ):
            return False
        if new_mapper.match_ids or new_mapper.earliest_seq_by_rule or new_mapper.hops_by_match_origin:
            self._node_mapper[node_id] = new_mapper
        else:
            self._node_mapper.pop(node_id, None)
        return True

    def _collect_downstream_nodes(self, start_node_id: str) -> list[str]:
        ordered: list[str] = []
        visited: set[str] = {start_node_id}
        q: deque[tuple[str, int]] = deque([(start_node_id, 0)])
        while q:
            src_node_id, current_depth = q.popleft()
            if self.max_propagation_depth > 0 and current_depth >= self.max_propagation_depth:
                continue
            out_edges_list = self.out_edges.get(src_node_id, [])
            if self.max_fan_out > 0 and len(out_edges_list) > self.max_fan_out:
                continue
            for dst_node_id, edge_type in out_edges_list:
                if self._edge_cost_for(edge_type) is None or dst_node_id in visited:
                    continue
                visited.add(dst_node_id)
                ordered.append(dst_node_id)
                q.append((dst_node_id, current_depth + 1))
        return ordered

    def on_edge_added(
        self,
        src_node_id: str,
        dst_node_id: str,
        edge_type: EdgeType | str,
        *,
        propagate: bool = True,
    ) -> None:
        if isinstance(edge_type, EdgeType):
            et = edge_type
        else:
            raw = str(edge_type).strip().lower()
            if raw in {EdgeType.DATA_FLOW.value, "data_flow"}:
                et = EdgeType.DATA_FLOW
            elif raw in {EdgeType.VERSION_TRANSITION.value, "version_transition", "prev_version"}:
                et = EdgeType.VERSION_TRANSITION
            else:
                et = raw
        edge_tuple = (dst_node_id, et)
        if edge_tuple not in self._out_edge_set[src_node_id]:
            self._out_edge_set[src_node_id].add(edge_tuple)
            self.out_edges[src_node_id].append(edge_tuple)
            reverse_edge_tuple = (src_node_id, et)
            if reverse_edge_tuple not in self._in_edge_set[dst_node_id]:
                self._in_edge_set[dst_node_id].add(reverse_edge_tuple)
                self.in_edges[dst_node_id].append(reverse_edge_tuple)
            self._pending_new_edges.append((src_node_id, dst_node_id, et))

        if propagate:
            self.flush_pending_edges()

    def flush_pending_edges(self) -> None:
        if not self._pending_new_edges:
            return
        flush_started = time.perf_counter()
        pending_edges = self._pending_new_edges
        self._pending_new_edges = []
        self.flush_pending_edges_batch_count += 1
        self.flush_pending_edges_edge_count += len(pending_edges)
        for src_node_id, dst_node_id, edge_type in pending_edges:
            loop_started = time.perf_counter()
            propagate_started = time.perf_counter()
            self._propagate_across_new_edge(src_node_id, dst_node_id, edge_type)
            self.flush_pending_edges_propagate_time_seconds += time.perf_counter() - propagate_started
            self.flush_pending_edges_loop_time_seconds += time.perf_counter() - loop_started
        self.flush_pending_edges_total_time_seconds += time.perf_counter() - flush_started

    def on_match_added(
        self,
        node_id: str,
        ttp_id: str,
        sequence: int,
        rule_id: str | None = None,
        origin_node_id: str | None = None,
    ) -> tuple[bool, float, float, float]:
        effective_rule_id = rule_id if rule_id is not None else ttp_id
        local_update_started = time.perf_counter()
        self._local_matches[node_id].add(ttp_id)
        self._local_matches_by_rule[node_id][effective_rule_id].add(ttp_id)
        origin = origin_node_id if origin_node_id is not None else node_id
        self._local_match_meta[node_id][ttp_id] = (effective_rule_id, int(sequence), origin)
        local_update_elapsed = time.perf_counter() - local_update_started

        mapper_update_started = time.perf_counter()
        mapper = self._mapper(node_id)
        changed = False
        if ttp_id not in mapper.match_ids:
            mapper.match_ids.add(ttp_id)
            mapper.match_ids_by_rule[effective_rule_id].add(ttp_id)
            mapper.rule_id_by_match[ttp_id] = effective_rule_id
            changed = True
        elif mapper.rule_id_by_match.get(ttp_id) != effective_rule_id:
            mapper.rule_id_by_match[ttp_id] = effective_rule_id
            changed = True
        prev_hops = mapper.hops_by_match_origin[ttp_id].get(origin)
        if prev_hops is None or 0 < prev_hops:
            mapper.hops_by_match_origin[ttp_id][origin] = 0
            changed = True
        prev = mapper.earliest_seq_by_rule.get(effective_rule_id)
        if prev is None or sequence < prev:
            mapper.earliest_seq_by_rule[effective_rule_id] = sequence
            changed = True
        mapper_update_elapsed = time.perf_counter() - mapper_update_started

        # Trigger #2: match add must immediately propagate mapper delta along existing edges.
        propagate_elapsed = 0.0
        if changed:
            propagate_started = time.perf_counter()
            self._propagate_delta(node_id, {ttp_id})
            propagate_elapsed = time.perf_counter() - propagate_started
        return changed, local_update_elapsed, mapper_update_elapsed, propagate_elapsed

    def on_match_removed(self, node_id: str, ttp_id: str) -> bool:
        local_set = self._local_matches.get(node_id)
        if not local_set or ttp_id not in local_set:
            return False
        local_set.discard(ttp_id)
        if not local_set:
            self._local_matches.pop(node_id, None)
        meta = self._local_match_meta.get(node_id, {})
        removed_meta = meta.pop(ttp_id, None)
        if not meta:
            self._local_match_meta.pop(node_id, None)
        if removed_meta is not None:
            rule_id = removed_meta[0]
            by_rule = self._local_matches_by_rule.get(node_id, {})
            local_rule_set = by_rule.get(rule_id)
            if local_rule_set is not None:
                local_rule_set.discard(ttp_id)
                if not local_rule_set:
                    by_rule.pop(rule_id, None)
            if not by_rule:
                self._local_matches_by_rule.pop(node_id, None)
        affected = [node_id]
        affected.extend(self._collect_downstream_nodes(node_id))
        changed_any = False
        for affected_node_id in affected:
            changed_any = self._recompute_mapper_for_node(affected_node_id) or changed_any
        return changed_any

    # Backward-compat wrappers
    def on_edge(self, src_node_id: str, dst_node_id: str, edge_cost: int) -> None:
        edge_type = EdgeType.DATA_FLOW if int(edge_cost) > 0 else EdgeType.VERSION_TRANSITION
        self.on_edge_added(src_node_id, dst_node_id, edge_type=edge_type)

    def register_local_match(
        self,
        node_id: str,
        match_id: str,
        rule_id: str,
        sequence: int,
        origin_node_id: str | None = None,
    ) -> None:
        self.on_match_added(
            node_id=node_id,
            ttp_id=match_id,
            rule_id=rule_id,
            sequence=sequence,
            origin_node_id=origin_node_id,
        )

    def mapper_contains_rule(self, node_id: str, rule_id: str) -> bool:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return False
        return bool(mapper.match_ids_by_rule.get(rule_id))

    def mapper_match_ids(self, node_id: str, rule_ids: set[str] | None = None) -> set[str]:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return set()
        if not rule_ids:
            return set(mapper.match_ids)
        out: set[str] = set()
        for rid in rule_ids:
            out |= mapper.match_ids_by_rule.get(rid, set())
        return out

    def mapper_contains_match(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> bool:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return False
        if match_id not in mapper.match_ids:
            return False
        if origin_node_id is None:
            return True
        return origin_node_id in mapper.hops_by_match_origin.get(match_id, {})

    def mapper_min_hops(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> int | None:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return None
        by_origin = mapper.hops_by_match_origin.get(match_id)
        if not by_origin:
            return None
        if origin_node_id is not None:
            return by_origin.get(origin_node_id)
        return min(by_origin.values())

    def mapper_earliest_seq(self, node_id: str, rule_id: str) -> int | None:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return None
        return mapper.earliest_seq_by_rule.get(rule_id)

    def local_match_ids(self, node_id: str, rule_ids: set[str] | None = None) -> set[str]:
        if not rule_ids:
            return set(self._local_matches.get(node_id, set()))
        out: set[str] = set()
        by_rule = self._local_matches_by_rule.get(node_id, {})
        for rid in rule_ids:
            out |= by_rule.get(rid, set())
        return out
