from __future__ import annotations

from collections import defaultdict, deque
import math

from engine.hsg.builder import HSG
from engine.rules.schema import APT_STAGES


def _connected_components(hsg: HSG) -> list[set[str]]:
    node_ids = {n.match_id for n in hsg.nodes}
    if not node_ids:
        return []

    adj: dict[str, set[str]] = defaultdict(set)
    for edge in hsg.edges:
        if edge.src not in node_ids or edge.dst not in node_ids:
            continue
        adj[edge.src].add(edge.dst)
        adj[edge.dst].add(edge.src)

    seen: set[str] = set()
    components: list[set[str]] = []
    for root in node_ids:
        if root in seen:
            continue
        queue: deque[str] = deque([root])
        comp: set[str] = set()
        seen.add(root)
        while queue:
            cur = queue.popleft()
            comp.add(cur)
            for nxt in adj.get(cur, set()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                queue.append(nxt)
        components.append(comp)
    return components


def _score_component(
    node_ids: set[str],
    edge_count: int,
    edge_score: float,
    rule_id_by_match: dict[str, str],
    scoring: str,
    rule_severity: dict[str, float] | None,
    alpha: float,
) -> float:
    sev = rule_severity or {}
    valid_node_ids = {mid for mid in node_ids if mid in rule_id_by_match}
    if scoring == "structure":
        return float(len(valid_node_ids)) + 0.5 * float(edge_count)
    if scoring == "severity":
        return float(sum(sev.get(rule_id_by_match[mid], 1.0) for mid in valid_node_ids))
    if scoring == "weighted":
        node_score = float(sum(sev.get(rule_id_by_match[mid], 1.0) for mid in valid_node_ids))
        return node_score + float(alpha) * float(edge_score)
    raise ValueError(f"Unsupported scoring mode: {scoring}")


def _component_connectivity(edge_strengths: list[float]) -> float:
    if not edge_strengths:
        return 1.0
    avg_strength = sum(edge_strengths) / float(len(edge_strengths))
    return 1.0 + avg_strength


def _edge_path_factor_multiplier(path_factors: list[float]) -> float:
    if not path_factors:
        return 1.0
    additive = 0.0
    for pf in path_factors:
        if pf <= 0.0:
            continue
        additive += math.log(1.0 + (1.0 / float(pf)))
    return min(2.0, 1.0 + float(additive))


def _to_cvss_severity(value: float | str | None) -> float:
    if value is None:
        return 0.0
    if isinstance(value, str):
        mapping = {
            "low": 2.0,
            "medium": 6.0,
            "high": 8.0,
            "critical": 10.0,
        }
        return float(mapping.get(value.lower(), 0.0))
    return float(value)


def _to_paper_stage_severity(value: float | str | None) -> float:
    if value is None:
        return 2.0
    if isinstance(value, str):
        mapping = {
            "low": 2.0,
            "medium": 6.0,
            "high": 8.0,
            "critical": 10.0,
        }
        return float(mapping.get(value.lower(), 2.0))

    x = float(value)
    if x < 4.0:
        return 2.0
    if x < 7.0:
        return 6.0
    if x < 9.0:
        return 8.0
    return 10.0


def _build_threat_tuple(
    node_ids: set[str],
    rule_id_by_match: dict[str, str],
    rule_cvss: dict[str, float | str] | None,
    rule_stage: dict[str, int] | None,
    rule_severity: dict[str, float | str] | None = None,
) -> list[float]:
    cvss_by_rule = rule_cvss or {}
    sev_by_rule = rule_severity or {}
    stages = rule_stage or {}

    t = [0.0] * len(APT_STAGES)
    for mid in node_ids:
        if mid not in rule_id_by_match:
            continue
        rule_id = rule_id_by_match[mid]
        stage = int(stages.get(rule_id, 1))
        idx = max(1, min(stage, len(APT_STAGES))) - 1
        raw_score = cvss_by_rule.get(rule_id)
        if raw_score is None:
            raw_score = sev_by_rule.get(rule_id, 1.0)
        score = _to_cvss_severity(raw_score)
        if score > t[idx]:
            t[idx] = score
    return t


def _paper_score_from_tuple(threat_tuple: list[float], paper_weights: list[float] | None) -> float:
    weights = list(paper_weights) if paper_weights is not None else [1.0] * len(APT_STAGES)
    if len(weights) != len(APT_STAGES):
        raise ValueError("paper_weights must contain exactly 7 values")

    score = 1.0
    for s_i, w_i in zip(threat_tuple, weights):
        x = max(0.0, min(10.0, float(s_i)))
        base = 1.0 + (x / 10.0)
        score *= base**float(w_i)
    return float(score)


def _build_threat_tuple_exact(
    node_ids: set[str],
    rule_id_by_match: dict[str, str],
    rule_cvss: dict[str, float | str] | None,
    rule_stage: dict[str, int] | None,
    rule_severity: dict[str, float | str] | None = None,
) -> list[float]:
    cvss_by_rule = rule_cvss or {}
    sev_by_rule = rule_severity or {}
    stages = rule_stage or {}

    t = [1.0] * len(APT_STAGES)
    for mid in node_ids:
        if mid not in rule_id_by_match:
            continue
        rule_id = rule_id_by_match[mid]
        stage = int(stages.get(rule_id, 1))
        idx = max(1, min(stage, len(APT_STAGES))) - 1
        raw_score = cvss_by_rule.get(rule_id)
        if raw_score is None:
            raw_score = sev_by_rule.get(rule_id, 1.0)
        score = _to_paper_stage_severity(raw_score)
        if score > t[idx]:
            t[idx] = score
    return t


def _paper_exact_score_from_tuple(threat_tuple: list[float], paper_weights: list[float] | None) -> tuple[float, float]:
    weights = list(paper_weights) if paper_weights is not None else [1.0] * len(APT_STAGES)
    if len(weights) != len(APT_STAGES):
        raise ValueError("paper_weights must contain exactly 7 values")
    log_score = 0.0
    for s_i, w_i in zip(threat_tuple, weights):
        log_score += float(w_i) * math.log(float(s_i))
    return float(math.exp(log_score)), float(log_score)


def _scenario_id_for_component(node_ids: set[str]) -> str:
    if not node_ids:
        return "scenario-empty"
    return f"scenario-{sorted(node_ids)[0]}"


def rank_hsg_scenarios(
    hsg: HSG,
    scoring: str = "weighted",
    rule_severity: dict[str, float] | None = None,
    alpha: float = 1.0,
    top_k: int = 3,
    score_mode: str = "legacy",
    rule_stage: dict[str, int] | None = None,
    rule_cvss: dict[str, float | str] | None = None,
    paper_weights: list[float] | None = None,
) -> list[dict[str, float | int | list[float]]]:
    """
    Build scenario scores from HSG connected components and return top-ranked ones.

    scoring:
      - structure: nodes_count + 0.5 * edges_count
      - severity: sum of node rule severities
      - weighted: sum(rule severities in component) + alpha * sum(edge.weight in component)
    """
    if score_mode not in {"legacy", "paper", "paper_exact"}:
        raise ValueError("score_mode must be 'legacy', 'paper', or 'paper_exact'")
    if paper_weights is not None and len(paper_weights) != len(APT_STAGES):
        raise ValueError("paper_weights must contain exactly 7 values")

    components = _connected_components(hsg)
    rule_id_by_match = {n.match_id: n.rule_id for n in hsg.nodes}

    scenarios: list[dict[str, float | int | list[float]]] = []
    for comp in components:
        component_edges = [e for e in hsg.edges if e.src in comp and e.dst in comp and e.src in rule_id_by_match and e.dst in rule_id_by_match]
        edge_count = len(component_edges)
        edge_path_factors = [
            float(e.path_factor)
            for e in component_edges
            if e.path_factor is not None and float(e.path_factor) > 0.0
        ]
        edge_strengths = [
            float(1.0 / float(e.path_factor))
            for e in component_edges
            if e.path_factor is not None and float(e.path_factor) > 0.0
        ]
        if not edge_strengths:
            edge_strengths = [
                float(e.dependency_strength)
                for e in component_edges
                if e.dependency_strength is not None
            ]
        edge_score = sum(
            float(1.0 / float(e.path_factor))
            for e in component_edges
            if e.path_factor is not None and float(e.path_factor) > 0.0
        )
        if edge_score == 0.0:
            edge_score = sum(
                float(e.dependency_strength if e.dependency_strength is not None else e.weight)
                for e in component_edges
                if (e.dependency_strength is not None or e.weight is not None)
            )
        score_legacy = _score_component(comp, edge_count, edge_score, rule_id_by_match, scoring, rule_severity, alpha)
        threat_tuple = _build_threat_tuple(comp, rule_id_by_match, rule_cvss, rule_stage, rule_severity)
        connectivity_strength = _component_connectivity(edge_strengths)
        edge_multiplier = _edge_path_factor_multiplier(edge_path_factors)
        score_paper = _paper_score_from_tuple(threat_tuple, paper_weights) * edge_multiplier
        threat_tuple_exact = _build_threat_tuple_exact(comp, rule_id_by_match, rule_cvss, rule_stage, rule_severity)
        score_paper_exact, score_paper_exact_log = _paper_exact_score_from_tuple(threat_tuple_exact, paper_weights)
        score_paper_exact *= edge_multiplier
        if edge_multiplier > 0.0:
            score_paper_exact_log += math.log(edge_multiplier)
        if score_mode == "paper":
            score = score_paper
        elif score_mode == "paper_exact":
            score = score_paper_exact
        else:
            score = score_legacy
        stage_severity = {APT_STAGES[i]: float(threat_tuple[i]) for i in range(len(APT_STAGES))}
        stage_severity_exact = {APT_STAGES[i]: float(threat_tuple_exact[i]) for i in range(len(APT_STAGES))}
        scenarios.append(
            (
                {
                "score": float(score),
                "score_legacy": float(score_legacy),
                "score_paper": float(score_paper),
                "threat_tuple": threat_tuple,
                "stage_severity": stage_severity,
                "paper_weights": list(paper_weights) if paper_weights is not None else [1.0] * len(APT_STAGES),
                "connectivity_strength": float(connectivity_strength),
                "edge_path_factor_multiplier": float(edge_multiplier),
                "scenario_id": _scenario_id_for_component(comp),
                "match_ids": sorted(comp),
                "nodes": len(comp),
                "edges": edge_count,
                }
                | (
                    {
                        "score_paper_exact": float(score_paper_exact),
                        "score_paper_exact_log": float(score_paper_exact_log),
                        "threat_tuple_exact": threat_tuple_exact,
                        "stage_severity_exact": stage_severity_exact,
                    }
                    if score_mode == "paper_exact"
                    else {}
                )
            )
        )

    scenarios.sort(key=lambda x: (float(x["score"]), int(x["nodes"]), int(x["edges"])), reverse=True)
    scenarios = scenarios[:top_k]
    while len(scenarios) < top_k:
        score_legacy = 0.0
        score_paper = 1.0
        score_paper_exact = 1.0
        score_paper_exact_log = 0.0
        if score_mode == "paper":
            score = score_paper
        elif score_mode == "paper_exact":
            score = score_paper_exact
        else:
            score = score_legacy
        scenarios.append(
            (
                {
                "score": score,
                "score_legacy": score_legacy,
                "score_paper": score_paper,
                "threat_tuple": [0.0] * len(APT_STAGES),
                "stage_severity": {APT_STAGES[i]: 0.0 for i in range(len(APT_STAGES))},
                "paper_weights": list(paper_weights) if paper_weights is not None else [1.0] * len(APT_STAGES),
                "connectivity_strength": 1.0,
                "scenario_id": _scenario_id_for_component(set()),
                "nodes": 0,
                "edges": 0,
                }
                | (
                    {
                        "score_paper_exact": score_paper_exact,
                        "score_paper_exact_log": score_paper_exact_log,
                        "threat_tuple_exact": [1.0] * len(APT_STAGES),
                        "stage_severity_exact": {APT_STAGES[i]: 1.0 for i in range(len(APT_STAGES))},
                    }
                    if score_mode == "paper_exact"
                    else {}
                )
            )
        )
    return scenarios
