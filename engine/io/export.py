from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from itertools import combinations

from engine.core.graph import Edge, ProvenanceGraph
from engine.hsg.builder import HSG


def _hsg_subgraph(hsg: HSG, match_ids: set[str]) -> dict[str, Any]:
    nodes = []
    for node in hsg.nodes:
        if node.match_id not in match_ids:
            continue
        nodes.append(
            {
                "data": {
                    "id": node.match_id,
                    "kind": "hsg_match",
                    "rule_id": node.rule_id,
                    "event_ids": list(node.event_ids),
                    "entities": list(node.entities),
                }
            }
        )

    edges = []
    for edge in hsg.edges:
        if edge.src not in match_ids or edge.dst not in match_ids:
            continue
        edges.append(
            {
                "data": {
                    "id": f"{edge.src}->{edge.dst}:{edge.relation}",
                    "kind": "hsg_edge",
                    "source": edge.src,
                    "target": edge.dst,
                    "relation": edge.relation,
                    "weight": edge.weight,
                    "path_factor": edge.path_factor,
                }
            }
        )
    return {"nodes": nodes, "edges": edges}


def _provenance_subgraph(
    graph: ProvenanceGraph,
    entities: set[str],
    *,
    tainted_entities: set[str],
    privileged_entities: set[str],
    tainted_version_nodes: set[str],
    elevated_version_nodes: set[str],
) -> dict[str, Any]:
    entity_nodes: set[str] = {entity for entity in entities if entity in graph.nodes}
    version_nodes: set[str] = set()

    protected_entities = entity_nodes | set(tainted_entities) | set(privileged_entities)
    protected_entities = {entity for entity in protected_entities if entity in graph.nodes}
    for entity in protected_entities:
        current = graph.current_version_node(entity)
        if current:
            version_nodes.add(current)

    version_nodes.update(node_id for node_id in tainted_version_nodes if node_id in graph.version_nodes)
    version_nodes.update(node_id for node_id in elevated_version_nodes if node_id in graph.version_nodes)

    for src_entity, dst_entity in combinations(sorted(entity_nodes), 2):
        version_nodes.update(graph.exact_mac_nodes(src_entity, dst_entity))
        version_nodes.update(graph.nodes_on_shortest_version_path(src_entity, dst_entity))
        version_nodes.update(graph.nodes_on_shortest_version_path(dst_entity, src_entity))

    for node_id in list(version_nodes):
        meta = graph.version_nodes.get(node_id)
        if meta is not None:
            entity_nodes.add(meta.entity_id)

    edges: list[Edge] = []
    for edge in graph.edges:
        if edge.src in version_nodes and edge.dst in version_nodes:
            edges.append(edge)
            if edge.src_entity:
                entity_nodes.add(edge.src_entity)
            if edge.dst_entity:
                entity_nodes.add(edge.dst_entity)

    nodes = []
    for entity in sorted(entity_nodes):
        nodes.append(
            {
                "data": {
                    "id": entity,
                    "kind": "entity",
                    "label": entity,
                }
            }
        )
    for node_id in sorted(version_nodes):
        meta = graph.version_nodes.get(node_id)
        if meta is None:
            continue
        nodes.append(
            {
                "data": {
                    "id": node_id,
                    "kind": "version_node",
                    "label": node_id,
                    "entity_id": meta.entity_id,
                    "version": meta.version,
                    "created_at": meta.created_at,
                }
            }
        )

    edge_rows = []
    for edge in edges:
        edge_rows.append(
            {
                "data": {
                    "id": f"{edge.event_id}:{edge.src}->{edge.dst}:{edge.relation}",
                    "kind": "provenance_edge",
                    "source": edge.src,
                    "target": edge.dst,
                    "event_id": edge.event_id,
                    "event_type": edge.event_type,
                    "ts": edge.ts,
                    "edge_type": edge.edge_type.value,
                    "relation": edge.relation,
                    "src_entity": edge.src_entity,
                    "dst_entity": edge.dst_entity,
                }
            }
        )
    return {"nodes": nodes, "edges": edge_rows}


def export_alert_scenario_artifact(
    *,
    graph: ProvenanceGraph,
    hsg: HSG,
    scenario_id: str,
    match_ids: list[str],
    entities: set[str],
    tainted_entities: set[str],
    privileged_entities: set[str],
    tainted_version_nodes: set[str],
    elevated_version_nodes: set[str],
    out_dir: str | Path,
) -> Path:
    artifact_dir = Path(out_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{scenario_id}.cytoscape.json"
    payload = {
        "scenario_id": scenario_id,
        "hsg": _hsg_subgraph(hsg, set(match_ids)),
        "provenance": _provenance_subgraph(
            graph,
            set(entities),
            tainted_entities=set(tainted_entities),
            privileged_entities=set(privileged_entities),
            tainted_version_nodes=set(tainted_version_nodes),
            elevated_version_nodes=set(elevated_version_nodes),
        ),
    }
    artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return artifact_path
