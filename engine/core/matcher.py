from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event
from engine.noise.profile import BenignProfile
from engine.rules.schema import Rule, RuleSet


@dataclass(slots=True)
class TTPMatch:
    """A matched rule instance against one or more events."""

    match_id: str
    rule_id: str
    event_ids: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    binding_node_ids: dict[str, str] = field(default_factory=dict)
    subject_node_id: str | None = None
    object_node_id: str | None = None
    sequence: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _EventMatchContext:
    event: Event
    ev_op: str | None
    ev_event_type: str | None
    source_type: str | None
    target_type: str | None
    event_source_types: set[str]
    ci_lookup_cache: dict[int, dict[str, Any]]


@dataclass(slots=True)
class _CompiledFieldMatch:
    field_name: str
    field_parts: tuple[str, ...]
    match_all: bool
    expected_values: tuple[str, ...]
    matcher_kind: str
    use_windash: bool
    regex_patterns: tuple[re.Pattern[str], ...]


@dataclass(slots=True)
class _CompiledSelector:
    items: tuple[_CompiledFieldMatch, ...]


@dataclass(slots=True)
class _CompiledRule:
    allowed_source_types: set[str]
    allowed_target_types: set[str]
    use_entity_filters: bool
    sigma_selectors: dict[str, _CompiledSelector]
    sigma_condition: dict[str, Any] | None


class Matcher:
    """Placeholder matcher: no rules -> no matches."""

    SIMPLE_ENTITY_TYPES = {"process", "file", "ip", "registry", "artifact"}
    ENTITY_TYPE_PREFIX = {
        "process": "proc",
        "file": "file",
        "registrykey": "reg",
        "registry": "reg",
        "ipaddress": "ip",
        "networkendpoint": "net",
        "artifact": "artifact",
        "dnsquery": "dns",
        "webrequest": "web",
        "cloudapicall": "cloudapi",
        "cloudidentity": "cloudid",
        "application": "app",
        "useragent": "ua",
        "namedpipe": "pipe",
    }

    def __init__(self) -> None:
        self.last_drop_telemetry: list[dict[str, Any]] = []
        self.benign_profile: BenignProfile | None = None
        self.last_benign_profile_drop_count: int = 0
        self._compiled_rule_cache: dict[str, _CompiledRule] = {}

    @staticmethod
    def _entity_type(entity: str | None) -> str | None:
        if not entity:
            return None
        prefix = entity.split(":", 1)[0].lower()
        mapping = {
            "proc": "process",
            "reg": "registry",
        }
        return mapping.get(prefix, prefix)

    @staticmethod
    def _lookup_case_insensitive(
        current: Any,
        key_name: str,
        ci_lookup_cache: dict[int, dict[str, Any]] | None = None,
    ) -> Any:
        if not isinstance(current, dict):
            return None
        if key_name in current:
            return current[key_name]
        lowered_key = key_name.lower()
        if ci_lookup_cache is not None:
            cache_key = id(current)
            lowered_map = ci_lookup_cache.get(cache_key)
            if lowered_map is None:
                lowered_map = {
                    str(key).lower(): value
                    for key, value in current.items()
                    if isinstance(key, str)
                }
                ci_lookup_cache[cache_key] = lowered_map
            return lowered_map.get(lowered_key)
        for key, value in current.items():
            if isinstance(key, str) and key.lower() == lowered_key:
                return value
        return None

    @classmethod
    def _get_field_value(
        cls,
        raw: dict[str, Any],
        field: str,
        ci_lookup_cache: dict[int, dict[str, Any]] | None = None,
    ) -> Any:
        def get_path_value(current: Any, parts: list[str]) -> Any:
            if not parts:
                return current
            if not isinstance(current, dict):
                return None
            part = parts[0]
            rest = parts[1:]

            if part.endswith("{}"):
                list_field = part[:-2]
                list_value = cls._lookup_case_insensitive(current, list_field, ci_lookup_cache)
                if not isinstance(list_value, list):
                    return None
                collected: list[Any] = []
                for item in list_value:
                    resolved = get_path_value(item, rest)
                    if resolved is None:
                        continue
                    if isinstance(resolved, list):
                        collected.extend(resolved)
                    else:
                        collected.append(resolved)
                return collected

            next_value = cls._lookup_case_insensitive(current, part, ci_lookup_cache)
            if next_value is None:
                return None
            return get_path_value(next_value, rest)

        if "." not in field and not field.endswith("{}"):
            return cls._lookup_case_insensitive(raw, field, ci_lookup_cache)
        return get_path_value(raw, field.split("."))

    @classmethod
    def _get_field_value_parts(
        cls,
        raw: dict[str, Any],
        field_parts: tuple[str, ...],
        ci_lookup_cache: dict[int, dict[str, Any]] | None = None,
    ) -> Any:
        def get_path_value(current: Any, parts: tuple[str, ...]) -> Any:
            if not parts:
                return current
            if not isinstance(current, dict):
                return None
            part = parts[0]
            rest = parts[1:]
            if part.endswith("{}"):
                list_field = part[:-2]
                list_value = cls._lookup_case_insensitive(current, list_field, ci_lookup_cache)
                if not isinstance(list_value, list):
                    return None
                collected: list[Any] = []
                for item in list_value:
                    resolved = get_path_value(item, rest)
                    if resolved is None:
                        continue
                    if isinstance(resolved, list):
                        collected.extend(resolved)
                    else:
                        collected.append(resolved)
                return collected
            next_value = cls._lookup_case_insensitive(current, part, ci_lookup_cache)
            if next_value is None:
                return None
            return get_path_value(next_value, rest)

        if len(field_parts) == 1 and not field_parts[0].endswith("{}"):
            return cls._lookup_case_insensitive(raw, field_parts[0], ci_lookup_cache)
        return get_path_value(raw, field_parts)

    @staticmethod
    def _string_values(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                out.extend(Matcher._string_values(item))
            return out
        if isinstance(value, dict):
            out = []
            for item in value.values():
                out.extend(Matcher._string_values(item))
            return out
        return [str(value)]

    @staticmethod
    def _normalize_windash(value: str) -> str:
        return value.replace("/", "-").replace("\u2013", "-").replace("\u2014", "-")

    @classmethod
    def _extract_sigma_values(cls, value_spec: Any) -> list[str]:
        if isinstance(value_spec, dict):
            if not value_spec:
                return []
            spec_type = value_spec.get("type")
            if spec_type == "literal":
                value = value_spec.get("value")
                return [] if value is None else [str(value)]
            if spec_type == "list":
                out: list[str] = []
                for item in value_spec.get("items", []):
                    out.extend(cls._extract_sigma_values(item))
                return out
        if isinstance(value_spec, list):
            out: list[str] = []
            for item in value_spec:
                out.extend(cls._extract_sigma_values(item))
            return out
        if value_spec is None:
            return []
        return [str(value_spec)]

    @classmethod
    def _match_modifier(cls, field_value: str, expected: str, modifiers: list[str]) -> bool:
        actual = field_value
        needle = expected
        if "windash" in modifiers:
            actual = cls._normalize_windash(actual)
            needle = cls._normalize_windash(needle)

        if "contains" in modifiers:
            return needle in actual
        if "endswith" in modifiers:
            return actual.endswith(needle)
        if "startswith" in modifiers:
            return actual.startswith(needle)
        if "regex" in modifiers or "re" in modifiers:
            try:
                return re.search(needle, actual) is not None
            except re.error:
                return False
        return actual == needle

    @classmethod
    def _compile_field_match(cls, predicate: dict[str, Any]) -> _CompiledFieldMatch | None:
        field_name = predicate.get("field")
        if not isinstance(field_name, str) or not field_name:
            return None
        raw_modifiers = predicate.get("modifiers", [])
        modifiers = tuple(
            str(x).lower()
            for x in raw_modifiers
            if isinstance(raw_modifiers, list) and isinstance(x, str)
        )
        matcher_kind = "eq"
        if "regex" in modifiers or "re" in modifiers:
            matcher_kind = "regex"
        elif "contains" in modifiers:
            matcher_kind = "contains"
        elif "endswith" in modifiers:
            matcher_kind = "endswith"
        elif "startswith" in modifiers:
            matcher_kind = "startswith"
        expected_values = tuple(cls._extract_sigma_values(predicate.get("value")))
        regex_patterns: list[re.Pattern[str]] = []
        if matcher_kind == "regex":
            for expected in expected_values:
                try:
                    regex_patterns.append(re.compile(expected))
                except re.error:
                    continue
        return _CompiledFieldMatch(
            field_name=field_name,
            field_parts=tuple(field_name.split(".")) if "." in field_name or field_name.endswith("{}") else (field_name,),
            match_all=predicate.get("value") == {},
            expected_values=expected_values,
            matcher_kind=matcher_kind,
            use_windash="windash" in modifiers,
            regex_patterns=tuple(regex_patterns),
        )

    @classmethod
    def _compile_selector(cls, selector: Any) -> _CompiledSelector | None:
        if not isinstance(selector, dict) or selector.get("type") != "object":
            return None
        items = selector.get("items", [])
        if not isinstance(items, list):
            return None
        compiled_items: list[_CompiledFieldMatch] = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "field_match":
                return None
            compiled = cls._compile_field_match(item)
            if compiled is None:
                return None
            compiled_items.append(compiled)
        return _CompiledSelector(items=tuple(compiled_items))

    def _compiled_rule(self, rule: Rule) -> _CompiledRule:
        cached = self._compiled_rule_cache.get(rule.rule_id)
        if cached is not None:
            return cached
        logic = rule.match_logic if isinstance(rule.match_logic, dict) else {}
        selector_map = logic.get("selectors", {}) if isinstance(logic, dict) else {}
        compiled_selectors: dict[str, _CompiledSelector] = {}
        if isinstance(selector_map, dict):
            for selector_name, selector in selector_map.items():
                if not isinstance(selector_name, str):
                    continue
                compiled = self._compile_selector(selector)
                if compiled is not None:
                    compiled_selectors[selector_name] = compiled
        condition_payload = logic.get("condition", {}) if isinstance(logic, dict) else {}
        sigma_condition = condition_payload.get("compiled") if isinstance(condition_payload, dict) else None
        compiled_rule = _CompiledRule(
            allowed_source_types={x.lower() for x in rule.source_types},
            allowed_target_types={x.lower() for x in rule.target_types},
            use_entity_filters=self._should_use_entity_type_filters(rule),
            sigma_selectors=compiled_selectors,
            sigma_condition=sigma_condition if isinstance(sigma_condition, dict) else None,
        )
        self._compiled_rule_cache[rule.rule_id] = compiled_rule
        return compiled_rule

    @classmethod
    def _evaluate_field_match(cls, event_ctx: _EventMatchContext, predicate: dict[str, Any]) -> bool:
        if not isinstance(event_ctx.event.raw, dict):
            return False
        field_name = predicate.get("field")
        if not isinstance(field_name, str) or not field_name:
            return False
        if predicate.get("value") == {}:
            return True

        modifiers = predicate.get("modifiers", [])
        if not isinstance(modifiers, list) or any(not isinstance(x, str) for x in modifiers):
            modifiers = []

        field_values = cls._string_values(
            cls._get_field_value(event_ctx.event.raw, field_name, event_ctx.ci_lookup_cache)
        )
        expected_values = cls._extract_sigma_values(predicate.get("value"))
        if not field_values or not expected_values:
            return False

        return any(
            cls._match_modifier(field_value, expected, modifiers)
            for field_value in field_values
            for expected in expected_values
        )

    @classmethod
    def _evaluate_compiled_field_match(
        cls,
        event_ctx: _EventMatchContext,
        predicate: _CompiledFieldMatch,
    ) -> bool:
        if not isinstance(event_ctx.event.raw, dict):
            return False
        if predicate.match_all:
            return True
        field_values = cls._string_values(
            cls._get_field_value_parts(event_ctx.event.raw, predicate.field_parts, event_ctx.ci_lookup_cache)
        )
        if not field_values or not predicate.expected_values:
            return False
        if predicate.matcher_kind == "regex":
            if not predicate.regex_patterns:
                return False
            if predicate.use_windash:
                field_values = [cls._normalize_windash(value) for value in field_values]
            return any(pattern.search(field_value) is not None for field_value in field_values for pattern in predicate.regex_patterns)
        if predicate.use_windash:
            field_values = [cls._normalize_windash(value) for value in field_values]
            expected_values = tuple(cls._normalize_windash(value) for value in predicate.expected_values)
        else:
            expected_values = predicate.expected_values
        if predicate.matcher_kind == "contains":
            return any(expected in field_value for field_value in field_values for expected in expected_values)
        if predicate.matcher_kind == "endswith":
            return any(field_value.endswith(expected) for field_value in field_values for expected in expected_values)
        if predicate.matcher_kind == "startswith":
            return any(field_value.startswith(expected) for field_value in field_values for expected in expected_values)
        return any(field_value == expected for field_value in field_values for expected in expected_values)

    @classmethod
    def _evaluate_sigma_selector(cls, event_ctx: _EventMatchContext, selector: _CompiledSelector | None) -> bool:
        if selector is None:
            return False
        for item in selector.items:
            if not cls._evaluate_compiled_field_match(event_ctx, item):
                return False
        return True

    @classmethod
    def _evaluate_sigma_condition(
        cls,
        event_ctx: _EventMatchContext,
        condition: Any,
        selectors: dict[str, Any],
    ) -> bool:
        if not isinstance(condition, dict):
            return False
        node_type = condition.get("type")
        if node_type == "selector_ref":
            selector_name = condition.get("selector")
            if not isinstance(selector_name, str):
                return False
            return cls._evaluate_sigma_selector(event_ctx, selectors.get(selector_name))
        if node_type == "selector_group":
            selector_names = condition.get("selectors", [])
            count = int(condition.get("count", 1))
            if not isinstance(selector_names, list):
                return False
            matched = sum(
                1
                for selector_name in selector_names
                if isinstance(selector_name, str)
                and cls._evaluate_sigma_selector(event_ctx, selectors.get(selector_name))
            )
            quantifier = str(condition.get("quantifier", "COUNT")).upper()
            if quantifier != "COUNT":
                return False
            return matched >= count
        if node_type == "logical":
            operator = str(condition.get("operator", "AND")).upper()
            operands = condition.get("operands", [])
            if not isinstance(operands, list):
                return False
            evaluated = [cls._evaluate_sigma_condition(event_ctx, operand, selectors) for operand in operands]
            if operator == "AND":
                return all(evaluated)
            if operator == "OR":
                return any(evaluated)
            if operator == "NOT":
                return len(evaluated) == 1 and not evaluated[0]
            return False
        return False

    @classmethod
    def _sigma_match(cls, compiled_rule: _CompiledRule, rule: Rule, event_ctx: _EventMatchContext) -> bool:
        logic = rule.match_logic
        if not isinstance(logic, dict):
            return True
        if str(logic.get("engine", "")).lower() != "sigma":
            return False
        if not compiled_rule.sigma_selectors:
            return False
        if compiled_rule.sigma_condition is None:
            return False
        return cls._evaluate_sigma_condition(event_ctx, compiled_rule.sigma_condition, compiled_rule.sigma_selectors)

    @classmethod
    def _event_source_types(cls, event: Event) -> set[str]:
        tokens: set[str] = set()
        if not isinstance(event.raw, dict):
            return tokens

        for key in ("source_type", "log_type", "category", "service", "product"):
            value = event.raw.get(key)
            if isinstance(value, str) and value.strip():
                tokens.add(value.strip().lower())
        logsource = event.raw.get("logsource")
        if isinstance(logsource, dict):
            product = str(logsource.get("product") or "").strip().lower()
            category = str(logsource.get("category") or "").strip().lower()
            service = str(logsource.get("service") or "").strip().lower()
            if product:
                tokens.add(product)
            if category:
                tokens.add(category)
            if service:
                tokens.add(service)
            for suffix in (category, service):
                if product and suffix:
                    tokens.add(f"{product}/{suffix}")
        return tokens

    @classmethod
    def _entity_from_raw_field(
        cls,
        event: Event,
        graph: ProvenanceGraph | None,
        entity_type: str,
        field_names: list[str],
    ) -> tuple[str | None, dict[str, Any] | None]:
        if not isinstance(event.raw, dict):
            return None, {"reason": "binding_field_unresolved", "fields": list(field_names)}
        for field_name in field_names:
            value = cls._get_field_value(event.raw, field_name)
            for string_value in cls._string_values(value):
                normalized = string_value.strip()
                if not normalized:
                    continue
                prefix = cls.ENTITY_TYPE_PREFIX.get(entity_type.lower())
                if prefix is None:
                    continue
                entity_id = f"{prefix}:{normalized}"
                if graph is not None and graph.current_version_node(entity_id) is None:
                    return None, {
                        "reason": "binding_entity_missing_in_graph",
                        "field": field_name,
                        "fields": list(field_names),
                        "entity_type": entity_type,
                        "candidate_entity": entity_id,
                    }
                return entity_id, None
        return None, {
            "reason": "binding_field_unresolved",
            "field": field_names[0] if field_names else None,
            "fields": list(field_names),
            "entity_type": entity_type,
        }

    def _bind_entity_symbols(
        self,
        rule: Rule,
        event: Event,
        graph: ProvenanceGraph | None,
    ) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
        cls = self.__class__
        bindings: dict[str, str] = {}
        subject_type = cls._entity_type(event.subject)
        object_type = cls._entity_type(event.object)

        if event.subject:
            bindings["subject"] = event.subject
        if event.object:
            bindings["object"] = event.object

        for binding in rule.entity_bindings:
            symbol = binding.get("symbol")
            entity_type = str(binding.get("entity_type") or "")
            fields = binding.get("fields", [])
            if not isinstance(symbol, str) or not symbol:
                continue
            if not isinstance(fields, list):
                fields = []

            resolved: str | None = None
            normalized_entity_type = entity_type.lower()
            if normalized_entity_type == "process":
                if symbol in {"$current_process", "$source_process"} and subject_type == "process" and event.subject:
                    resolved = event.subject
                elif symbol in {"$current_process", "$source_process"} and object_type == "process" and event.object:
                    resolved = event.object
                elif symbol == "$parent_process":
                    resolved = None
            elif normalized_entity_type in {"file", "registrykey", "registry", "ipaddress"}:
                candidate_type = {
                    "file": "file",
                    "registrykey": "registry",
                    "registry": "registry",
                    "ipaddress": "ip",
                }[normalized_entity_type]
                if symbol in {"$target_file", "$current_file", "$target_registry_key", "$remote_ip"} and subject_type == candidate_type and event.subject:
                    resolved = event.subject
                elif symbol in {"$target_file", "$current_file", "$target_registry_key", "$remote_ip"} and object_type == candidate_type and event.object:
                    resolved = event.object

            if resolved is None and fields:
                resolved, drop_detail = cls._entity_from_raw_field(
                    event,
                    graph,
                    entity_type,
                    [str(x) for x in fields if isinstance(x, str)],
                )
            else:
                drop_detail = None
            if resolved is not None:
                bindings[symbol] = resolved
            elif isinstance(symbol, str) and symbol.startswith("$"):
                telemetry = {
                    "reason": "binding_symbol_unresolved",
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "event_id": event.event_id,
                    "symbol": symbol,
                    "entity_type": entity_type,
                    "field": fields[0] if fields else None,
                    "fields": [str(x) for x in fields if isinstance(x, str)],
                }
                if isinstance(drop_detail, dict):
                    telemetry.update(drop_detail)
                return None, telemetry
        return bindings, None

    @classmethod
    def _should_use_entity_type_filters(cls, rule: Rule) -> bool:
        if rule.target_types:
            return True
        if not rule.source_types:
            return False
        return all("/" not in item and item.lower() in cls.SIMPLE_ENTITY_TYPES for item in rule.source_types)

    @classmethod
    def _build_event_context(cls, event: Event) -> _EventMatchContext:
        ev_op = None
        if isinstance(event.raw, dict):
            raw_op = event.raw.get("op")
            if raw_op is not None:
                ev_op = str(raw_op)
        ev_event_type = getattr(event, "event_type", None)
        if ev_event_type is None and isinstance(event.raw, dict):
            raw_event_type = event.raw.get("event_type")
            if raw_event_type is not None:
                ev_event_type = str(raw_event_type)
        return _EventMatchContext(
            event=event,
            ev_op=ev_op,
            ev_event_type=ev_event_type,
            source_type=cls._entity_type(event.subject),
            target_type=cls._entity_type(event.object),
            event_source_types=cls._event_source_types(event),
            ci_lookup_cache={},
        )

    def _match_rules(
        self,
        graph: ProvenanceGraph | None,
        rules: list[Rule],
        events: list[Event],
    ) -> list[TTPMatch]:
        self.last_drop_telemetry = []
        self.last_benign_profile_drop_count = 0
        if not rules:
            return []

        matches: list[TTPMatch] = []
        serial = 1
        event_contexts = {event.event_id: self._build_event_context(event) for event in events}
        compiled_rules = {rule.rule_id: self._compiled_rule(rule) for rule in rules}

        for rule in rules:
            compiled_rule = compiled_rules[rule.rule_id]
            allowed_source_types = compiled_rule.allowed_source_types
            allowed_target_types = compiled_rule.allowed_target_types
            use_entity_filters = compiled_rule.use_entity_filters
            for event in events:
                event_ctx = event_contexts[event.event_id]
                if (
                    self.benign_profile is not None
                    and not bool(rule.bypass_benign_filter)
                    and self.benign_profile.event_is_benign(event)
                ):
                    self.last_benign_profile_drop_count += 1
                    self.last_drop_telemetry.append(
                        {
                            "reason": "benign_profile_drop",
                            "rule_id": rule.rule_id,
                            "rule_name": rule.name,
                            "event_id": event.event_id,
                        }
                    )
                    continue
                if rule.event_predicate:
                    expected_op = rule.event_predicate.get("op")
                    expected_event_type = rule.event_predicate.get("event_type")
                    if expected_op is not None and event_ctx.ev_op != expected_op:
                        continue
                    if expected_event_type is not None and event_ctx.ev_event_type != expected_event_type:
                        continue
                elif not self._sigma_match(compiled_rule, rule, event_ctx):
                    continue

                if use_entity_filters:
                    if allowed_source_types and event_ctx.source_type not in allowed_source_types:
                        continue
                    if allowed_target_types and event_ctx.target_type not in allowed_target_types:
                        continue
                elif rule.source_types:
                    if event_ctx.event_source_types and not (allowed_source_types & event_ctx.event_source_types):
                        continue

                bindings, drop_telemetry = self._bind_entity_symbols(rule, event, graph)
                if bindings is None:
                    if drop_telemetry is not None:
                        self.last_drop_telemetry.append(drop_telemetry)
                    continue
                entities = list({x for x in [event.subject, event.object, *bindings.values()] if x})
                matches.append(
                    TTPMatch(
                        match_id=f"m{serial}",
                        rule_id=rule.rule_id,
                        event_ids=[event.event_id],
                        entities=entities,
                        bindings=bindings,
                        metadata={"op": event_ctx.ev_op, "event_type": event_ctx.ev_event_type},
                    )
                )
                serial += 1

        return matches

    def match(self, graph: ProvenanceGraph, ruleset: RuleSet, events: list[Event]) -> list[TTPMatch]:
        return self._match_rules(graph=graph, rules=ruleset.rules, events=events)

    def match_batch(
        self,
        graph: ProvenanceGraph | None,
        rules_subset: list[Rule],
        events_batch: list[Event],
    ) -> list[TTPMatch]:
        return self._match_rules(graph=graph, rules=rules_subset, events=events_batch)
