from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.core.graph import ProvenanceGraph, path_factor_passes
from engine.core.matcher import TTPMatch
from engine.core.privilege_tracker import PrivilegeTracker
from engine.core.taint_tracker import TaintTracker
from engine.io.cdr.base import canonical_relation
from engine.rules.schema import Rule


@dataclass(slots=True)
class EvaluatedEdge:
    src_match_id: str
    relation: str
    weight: float | None = None
    path_factor: float | None = None
    dependency_strength: float | None = None


@dataclass(slots=True)
class EvaluationResult:
    satisfied: bool
    edges: list[EvaluatedEdge] = field(default_factory=list)
    resolved_symbols: dict[str, str] = field(default_factory=dict)


class PrerequisiteEvaluator:
    """Evaluate prerequisite ASTs against the provenance graph and prior TTP matches."""

    EXTERNAL_PREFIXES = {"ip", "web", "dns", "url", "cloudapi", "cloudid", "net"}
    EXECUTABLE_SUFFIXES = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".hta", ".com", ".scr")
    ASEP_MARKERS = (
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\services\\",
        "\\image file execution options\\",
        "\\shell folders",
        "\\user shell folders",
        "\\specialaccounts\\userlist",
        "\\winlogon\\",
    )

    def __init__(
        self,
        *,
        graph: ProvenanceGraph,
        taint_tracker: TaintTracker | None = None,
        privilege_tracker: PrivilegeTracker | None = None,
        resolved_effective_config: dict[str, Any] | None = None,
    ) -> None:
        self.graph = graph
        self.taint_tracker = taint_tracker
        self.privilege_tracker = privilege_tracker
        self.resolved_effective_config = dict(resolved_effective_config or {})

    @staticmethod
    def _entity_prefix(entity_id: str | None) -> str:
        if not entity_id:
            return ""
        return entity_id.split(":", 1)[0].lower()

    @staticmethod
    def _entity_payload(entity_id: str | None) -> str:
        if not entity_id or ":" not in entity_id:
            return ""
        return entity_id.split(":", 1)[1]

    @staticmethod
    def _match_entities(match: TTPMatch) -> set[str]:
        entities = {e for e in match.entities if isinstance(e, str) and e}
        for value in match.bindings.values():
            if isinstance(value, str) and value:
                entities.add(value)
        return entities

    def _resolve_runtime_threshold(self, raw_threshold: Any) -> float:
        if isinstance(raw_threshold, (int, float)):
            return float(raw_threshold)
        if isinstance(raw_threshold, str):
            if raw_threshold == "path_thres":
                return float(self.resolved_effective_config.get("path_thres", 0.0))
            try:
                return float(raw_threshold)
            except ValueError:
                return 0.0
        return 0.0

    def _symbol_candidates(
        self,
        symbol: str,
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> list[tuple[str, str | None]]:
        if symbol in match.bindings:
            return [(symbol, match.bindings[symbol])]

        if symbol == "$current_process":
            for key in ("$current_process", "subject", "object"):
                entity = match.bindings.get(key)
                if self._entity_prefix(entity) == "proc":
                    return [(symbol, entity)]
        if symbol in {"$current_process_image", "$current_file", "$target_file"}:
            for key in (symbol, "object", "subject"):
                entity = match.bindings.get(key)
                if self._entity_prefix(entity) == "file":
                    return [(symbol, entity)]
        if symbol == "$target_registry_key":
            for key in (symbol, "object", "subject"):
                entity = match.bindings.get(key)
                if self._entity_prefix(entity) == "reg":
                    return [(symbol, entity)]
        if symbol in {"$remote_ip", "External_IP_Node"}:
            for key in (symbol, "object", "subject"):
                entity = match.bindings.get(key)
                if self._entity_prefix(entity) == "ip":
                    return [(symbol, entity)]
        if symbol == "$parent_process":
            entity = match.bindings.get(symbol)
            return [(symbol, entity)] if entity else []
        if symbol == "$dns_query":
            entity = match.bindings.get(symbol)
            return [(symbol, entity)] if entity else []
        if symbol == "$web_request":
            entity = match.bindings.get(symbol)
            return [(symbol, entity)] if entity else []
        if symbol == "$cloud_api_call":
            entity = match.bindings.get(symbol)
            return [(symbol, entity)] if entity else []
        if symbol == "$cloud_identity":
            entity = match.bindings.get(symbol)
            return [(symbol, entity)] if entity else []
        if symbol == "$current_event_source":
            entity = match.bindings.get(symbol)
            if entity:
                return [(symbol, entity)]
            fallback = match.bindings.get("subject") or match.bindings.get("object")
            return [(symbol, fallback)] if fallback else []
        if symbol == "Compromised_Process":
            if self.taint_tracker is None:
                return []
            out: list[tuple[str, str | None]] = []
            tainted = self.taint_tracker.tainted_entities_by_prefix("proc")
            for prior in prior_matches.values():
                for entity in self._match_entities(prior):
                    if entity in tainted and self._entity_prefix(entity) == "proc":
                        out.append((prior.match_id, entity))
            seen_entities = {entity for _, entity in out}
            for entity in sorted(tainted):
                if entity not in seen_entities:
                    out.append(("taint", entity))
            return out
        if symbol == "Untrusted_External_Node":
            out: list[tuple[str, str | None]] = []
            seen: set[str] = set()
            for prior in prior_matches.values():
                for entity in self._match_entities(prior):
                    if self._entity_prefix(entity) in self.EXTERNAL_PREFIXES and entity not in seen:
                        out.append((prior.match_id, entity))
                        seen.add(entity)
            for entity in sorted(self.graph.nodes):
                if self._entity_prefix(entity) in self.EXTERNAL_PREFIXES and entity not in seen:
                    out.append(("external", entity))
                    seen.add(entity)
            return out
        if symbol == "External_IP_Node":
            out: list[tuple[str, str | None]] = []
            seen: set[str] = set()
            for prior in prior_matches.values():
                for entity in self._match_entities(prior):
                    if self._entity_prefix(entity) == "ip" and entity not in seen:
                        out.append((prior.match_id, entity))
                        seen.add(entity)
            for entity in sorted(self.graph.nodes):
                if self._entity_prefix(entity) == "ip" and entity not in seen:
                    out.append(("external", entity))
                    seen.add(entity)
            return out
        return []

    def _node_state(self, entity_id: str | None, attribute: str, expected_value: Any) -> bool:
        if not entity_id:
            return False
        payload = self._entity_payload(entity_id).lower()
        prefix = self._entity_prefix(entity_id)
        attr = attribute.lower()
        expected = bool(expected_value)
        if attr == "is_executable":
            actual = prefix == "proc" or payload.endswith(self.EXECUTABLE_SUFFIXES)
            return actual is expected
        if attr == "is_asep_key":
            actual = prefix == "reg" and any(marker in payload for marker in self.ASEP_MARKERS)
            return actual is expected
        if attr == "has_elevated_privilege":
            actual = self.privilege_tracker.has_elevated_privilege(entity_id) if self.privilege_tracker is not None else False
            return actual is expected
        if attr == "has_system_integrity":
            actual = self.privilege_tracker.has_system_integrity(entity_id) if self.privilege_tracker is not None else False
            return actual is expected
        if attr == "has_root_euid":
            actual = self.privilege_tracker.has_root_euid(entity_id) if self.privilege_tracker is not None else False
            return actual is expected
        if attr == "has_high_integrity":
            actual = self.privilege_tracker.has_high_integrity(entity_id) if self.privilege_tracker is not None else False
            return actual is expected
        return False

    def _edge_for_path(
        self,
        src_match_id: str,
        src_token: str,
        dst_token: str,
    ) -> EvaluatedEdge | None:
        edge_pf = self.graph.path_factor_for_edge(src_token, dst_token)
        if edge_pf is None or edge_pf <= 0.0:
            return None
        return EvaluatedEdge(
            src_match_id=src_match_id,
            relation="graph_path",
            weight=1.0 / float(edge_pf),
            path_factor=float(edge_pf),
            dependency_strength=1.0 / float(edge_pf),
        )

    def _evaluate_path_factor(
        self,
        condition: dict[str, Any],
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        source_candidates = self._symbol_candidates(str(condition.get("source_node", "")), match, prior_matches)
        target_candidates = self._symbol_candidates(str(condition.get("target_node", "")), match, prior_matches)
        threshold = self._resolve_runtime_threshold(condition.get("threshold"))
        op = str(condition.get("op") or self.resolved_effective_config.get("path_factor_op", "ge")).lower()
        if op == ">=":
            op = "ge"
        elif op == "<=":
            op = "le"

        edges: list[EvaluatedEdge] = []
        resolved: dict[str, str] = {}
        for src_match_id, src_entity in source_candidates:
            if not src_entity:
                continue
            for _, dst_entity in target_candidates:
                if not dst_entity:
                    continue
                src_token = match.binding_node_ids.get(str(condition.get("source_node"))) or src_entity
                dst_token = match.binding_node_ids.get(str(condition.get("target_node"))) or dst_entity
                pf = self.graph.path_factor_for_edge(src_token, dst_token)
                if not path_factor_passes(pf, threshold, op):
                    continue
                resolved[str(condition.get("source_node"))] = src_entity
                resolved[str(condition.get("target_node"))] = dst_entity
                if src_match_id not in {"external", "", "taint"}:
                    edge = self._edge_for_path(src_match_id, src_token, dst_token)
                    if edge is not None:
                        edges.append(edge)
                return EvaluationResult(satisfied=True, edges=edges, resolved_symbols=resolved)
        return EvaluationResult(satisfied=False)

    def _evaluate_relation_check(
        self,
        condition: dict[str, Any],
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        raw_relation = str(condition.get("relation") or "relation_check")
        relation = canonical_relation(raw_relation)
        source_candidates = self._symbol_candidates(str(condition.get("source_node", "")), match, prior_matches)
        target_candidates = self._symbol_candidates(str(condition.get("target_node", "")), match, prior_matches)
        reverse_query = raw_relation.strip().lower() in {"spawned_by"}

        for src_match_id, src_entity in source_candidates:
            if not src_entity:
                continue
            for _, dst_entity in target_candidates:
                if not dst_entity:
                    continue
                src_token = match.binding_node_ids.get(str(condition.get("source_node"))) or src_entity
                dst_token = match.binding_node_ids.get(str(condition.get("target_node"))) or dst_entity
                query_src = dst_token if reverse_query else src_token
                query_dst = src_token if reverse_query else dst_token
                if not self.graph.has_semantic_path(query_src, query_dst, {relation}):
                    continue
                edge = None
                if src_match_id not in {"external", "", "taint"}:
                    edge = EvaluatedEdge(src_match_id=src_match_id, relation=relation)
                return EvaluationResult(
                    satisfied=True,
                    edges=[edge] if edge is not None else [],
                    resolved_symbols={
                        str(condition.get("source_node")): src_entity,
                        str(condition.get("target_node")): dst_entity,
                    },
                )
        return EvaluationResult(satisfied=False)

    def _evaluate_node_state(
        self,
        condition: dict[str, Any],
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        target_candidates = self._symbol_candidates(str(condition.get("target_node", "")), match, prior_matches)
        attribute = str(condition.get("attribute") or "")
        expected = condition.get("expected_value")
        for _, entity in target_candidates:
            if self._node_state(entity, attribute, expected):
                return EvaluationResult(
                    satisfied=True,
                    resolved_symbols={str(condition.get("target_node")): str(entity)},
                )
        return EvaluationResult(satisfied=False)

    def _evaluate_event_existence(
        self,
        condition: dict[str, Any],
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        target_candidates = self._symbol_candidates(str(condition.get("target_node", "")), match, prior_matches)
        return EvaluationResult(satisfied=any(entity for _, entity in target_candidates))

    def _evaluate_condition(
        self,
        condition: dict[str, Any],
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        cond_type = str(condition.get("type") or "").lower()
        if cond_type == "path_factor":
            return self._evaluate_path_factor(condition, match, prior_matches)
        if cond_type == "relation_check":
            return self._evaluate_relation_check(condition, match, prior_matches)
        if cond_type == "node_state":
            return self._evaluate_node_state(condition, match, prior_matches)
        if cond_type == "event_existence":
            return self._evaluate_event_existence(condition, match, prior_matches)
        return EvaluationResult(satisfied=False)

    def evaluate_rule(
        self,
        rule: Rule | None,
        match: TTPMatch,
        prior_matches: dict[str, TTPMatch],
    ) -> EvaluationResult:
        if rule is None or not isinstance(rule.prerequisite_ast, dict):
            return EvaluationResult(satisfied=True)

        operator = str(rule.prerequisite_ast.get("operator", "AND")).upper()
        conditions = rule.prerequisite_ast.get("conditions", [])
        if not isinstance(conditions, list) or not conditions:
            return EvaluationResult(satisfied=True)

        collected_edges: list[EvaluatedEdge] = []
        collected_symbols: dict[str, str] = {}
        child_results = [self._evaluate_condition(cond, match, prior_matches) for cond in conditions if isinstance(cond, dict)]
        if operator == "AND":
            if not child_results or not all(result.satisfied for result in child_results):
                return EvaluationResult(satisfied=False)
        elif operator == "OR":
            if not any(result.satisfied for result in child_results):
                return EvaluationResult(satisfied=False)
            child_results = [result for result in child_results if result.satisfied]
        else:
            return EvaluationResult(satisfied=False)

        for result in child_results:
            collected_edges.extend(result.edges)
            collected_symbols.update(result.resolved_symbols)
        return EvaluationResult(satisfied=True, edges=collected_edges, resolved_symbols=collected_symbols)
