use chrono::DateTime;
use chrono::Utc;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct NativeEventPayload {
    event_id: String,
    ts: Option<String>,
    event_type: String,
    subject: Option<String>,
    object: Option<String>,
    bytes_transferred: Option<i64>,
    event_type_lower: String,
    subject_state_change: bool,
    object_state_change: bool,
    is_memory_object: bool,
}

#[derive(Clone, Debug)]
struct NativeEdge {
    src: u32,
    dst: u32,
    event_type: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct NativeVersionNode {
    node_id: String,
    entity_id: String,
    version: u32,
    observed_ts_micros: Option<i64>,
}

#[derive(Clone, Debug, Default)]
struct NativeMapperNode {
    match_ids: Vec<u32>,
    match_ids_by_rule: HashMap<u32, Vec<u32>>,
    earliest_seq_by_rule: HashMap<u32, usize>,
    hops_by_match_origin: HashMap<(u32, u32), u32>,
}

#[derive(Clone, Debug)]
struct NativeLocalMatchMeta {
    rule_id: u32,
    sequence: usize,
    origin_node_id: u32,
}

#[derive(Default)]
struct StringInterner {
    ids_by_value: HashMap<String, u32>,
    values_by_id: Vec<String>,
}

impl StringInterner {
    fn intern(&mut self, value: &str) -> u32 {
        if let Some(existing) = self.ids_by_value.get(value) {
            return *existing;
        }
        let next_id = self.values_by_id.len() as u32;
        let owned = value.to_string();
        self.values_by_id.push(owned.clone());
        self.ids_by_value.insert(owned, next_id);
        next_id
    }

    fn get(&self, id: u32) -> Option<&str> {
        self.values_by_id.get(id as usize).map(|s| s.as_str())
    }
}

#[derive(Default)]
struct NativeGraphState {
    interner: StringInterner,
    version_nodes: Vec<NativeVersionNode>,
    current_version_by_entity: HashMap<String, String>,
    version_counter_by_entity: HashMap<String, u32>,
    entity_versions: HashMap<String, Vec<String>>,
    edges: Vec<NativeEdge>,
    adj_all: Vec<Vec<u32>>,
    entity_last_seen_ts_micros: HashMap<String, i64>,
    version_last_seen_ts_micros: HashMap<String, i64>,
}

struct NativePrunePlan {
    removed_version_nodes: Vec<String>,
    removed_entities: Vec<String>,
    removed_edges: usize,
}

impl NativeGraphState {
    fn parse_ts_micros(value: Option<&str>) -> Option<i64> {
        let raw = value?.trim();
        if raw.is_empty() {
            return None;
        }
        if let Ok(mut numeric) = raw.parse::<f64>() {
            let abs_numeric = numeric.abs();
            if abs_numeric >= 1e17 {
                numeric /= 1_000_000_000.0;
            } else if abs_numeric >= 1e14 {
                numeric /= 1_000_000.0;
            } else if abs_numeric >= 1e11 {
                numeric /= 1_000.0;
            }
            return Some((numeric * 1_000_000.0) as i64);
        }
        let normalized = raw.replace('Z', "+00:00");
        DateTime::parse_from_rfc3339(&normalized)
            .ok()
            .map(|dt| dt.with_timezone(&Utc).timestamp_micros())
    }

    fn ensure_node_slot(&mut self, node_id: u32) {
        let needed_len = node_id as usize + 1;
        if self.adj_all.len() < needed_len {
            self.adj_all.resize_with(needed_len, Vec::new);
        }
    }

    fn flow_direction<'a>(&self, event: &'a NativeEventPayload) -> (Option<&'a str>, Option<&'a str>) {
        let op = event.event_type_lower.as_str();
        if matches!(op, "write" | "fork" | "connect" | "send") {
            return (event.subject.as_deref(), event.object.as_deref());
        }
        if matches!(op, "read" | "exec" | "recv") {
            return (event.object.as_deref(), event.subject.as_deref());
        }
        (event.subject.as_deref(), event.object.as_deref())
    }

    fn is_process_node(entity_id: &str) -> bool {
        entity_id
            .split_once(':')
            .map(|(prefix, _)| prefix.eq_ignore_ascii_case("proc"))
            .unwrap_or(false)
    }

    fn entities_requiring_new_version(&self, event: &NativeEventPayload) -> Vec<String> {
        let (Some(subject), Some(object)) = (event.subject.as_deref(), event.object.as_deref()) else {
            return Vec::new();
        };
        let op = event.event_type_lower.as_str();
        let mut changed: HashSet<String> = HashSet::new();

        if matches!(
            op,
            "write" | "modify" | "send" | "proc_to_file" | "proc_to_registry" | "proc_to_ip" | "file_to_ip"
        ) {
            changed.insert(object.to_string());
        }
        if matches!(op, "read" | "recv" | "file_to_proc") {
            changed.insert(subject.to_string());
        }
        if matches!(op, "exec" | "execute" | "setuid" | "setgid" | "privilege_change" | "privilege_escalation")
            && Self::is_process_node(subject)
        {
            changed.insert(subject.to_string());
        }
        if event.subject_state_change {
            changed.insert(subject.to_string());
        }
        if event.object_state_change {
            changed.insert(object.to_string());
        }
        if changed.is_empty() {
            changed.insert(object.to_string());
        }

        let mut out: Vec<String> = changed.into_iter().collect();
        out.sort();
        out
    }

    fn new_version_node(&mut self, entity_id: &str, observed_ts_micros: Option<i64>) -> String {
        let next_version = self.version_counter_by_entity.get(entity_id).copied().unwrap_or(0) + 1;
        self.version_counter_by_entity
            .insert(entity_id.to_string(), next_version);
        let node_id = format!("{entity_id}#v{next_version}");
        self.version_nodes.push(NativeVersionNode {
            node_id: node_id.clone(),
            entity_id: entity_id.to_string(),
            version: next_version,
            observed_ts_micros,
        });
        self.entity_versions
            .entry(entity_id.to_string())
            .or_default()
            .push(node_id.clone());
        let interned = self.interner.intern(&node_id);
        self.ensure_node_slot(interned);
        if let Some(ts_micros) = observed_ts_micros {
            self.version_last_seen_ts_micros.insert(node_id.clone(), ts_micros);
            match self.entity_last_seen_ts_micros.get(entity_id).copied() {
                Some(prev) if prev >= ts_micros => {}
                _ => {
                    self.entity_last_seen_ts_micros
                        .insert(entity_id.to_string(), ts_micros);
                }
            }
        }
        node_id
    }

    fn ensure_entity(&mut self, entity_id: &str) -> String {
        if let Some(node_id) = self.current_version_by_entity.get(entity_id) {
            return node_id.clone();
        }
        let node_id = self.new_version_node(entity_id, None);
        self.current_version_by_entity
            .insert(entity_id.to_string(), node_id.clone());
        node_id
    }

    fn link_edge(&mut self, src_node_id: &str, dst_node_id: &str, event_type: &str) {
        let src = self.interner.intern(src_node_id);
        let dst = self.interner.intern(dst_node_id);
        self.ensure_node_slot(src);
        self.ensure_node_slot(dst);
        self.adj_all[src as usize].push(dst);
        self.edges.push(NativeEdge {
            src,
            dst,
            event_type: event_type.to_string(),
        });
    }

    fn bump_entity(&mut self, entity_id: &str, observed_ts_micros: Option<i64>) -> String {
        let prev = self.ensure_entity(entity_id);
        let new_node = self.new_version_node(entity_id, observed_ts_micros);
        self.current_version_by_entity
            .insert(entity_id.to_string(), new_node.clone());
        self.link_edge(&prev, &new_node, "version_transition");
        new_node
    }

    fn add_event(&mut self, event: &NativeEventPayload) {
        if event.subject.is_none() || event.object.is_none() {
            return;
        }
        let (Some(src_entity), Some(dst_entity)) = self.flow_direction(event) else {
            return;
        };

        self.ensure_entity(src_entity);
        self.ensure_entity(dst_entity);

        let pre_src = self
            .current_version_by_entity
            .get(src_entity)
            .cloned()
            .unwrap_or_else(|| self.ensure_entity(src_entity));
        let observed_ts_micros = Self::parse_ts_micros(event.ts.as_deref());

        let mut changed_entities = self.entities_requiring_new_version(event);
        if !changed_entities.iter().any(|entity_id| entity_id == dst_entity) {
            changed_entities.push(dst_entity.to_string());
            changed_entities.sort();
            changed_entities.dedup();
        }

        let mut post_by_entity: HashMap<String, String> = HashMap::new();
        for entity_id in changed_entities {
            let new_node = self.bump_entity(&entity_id, observed_ts_micros);
            post_by_entity.insert(entity_id, new_node);
        }

        let flow_dst = post_by_entity
            .get(dst_entity)
            .cloned()
            .unwrap_or_else(|| {
                self.current_version_by_entity
                    .get(dst_entity)
                    .cloned()
                    .unwrap_or_else(|| self.ensure_entity(dst_entity))
            });
        self.link_edge(&pre_src, &flow_dst, &event.event_type);
    }

    fn node_count(&self) -> usize {
        self.version_nodes.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }

    fn current_version_node(&self, entity_id: &str) -> Option<String> {
        self.current_version_by_entity.get(entity_id).cloned()
    }

    fn compute_prune_plan(
        &self,
        watermark_ts: Option<&str>,
        retention_seconds: i64,
        protected_entities: &[String],
        protected_version_nodes: &[String],
        max_version_nodes: usize,
        max_edges: usize,
        cap_low_watermark_ratio: f64,
    ) -> NativePrunePlan {
        let Some(watermark_micros) = Self::parse_ts_micros(watermark_ts) else {
            return NativePrunePlan {
                removed_version_nodes: Vec::new(),
                removed_entities: Vec::new(),
                removed_edges: 0,
            };
        };
        if retention_seconds < 0 {
            return NativePrunePlan {
                removed_version_nodes: Vec::new(),
                removed_entities: Vec::new(),
                removed_edges: 0,
            };
        }

        let cutoff_micros = watermark_micros - (retention_seconds * 1_000_000);
        let protected_entity_set: HashSet<&str> = protected_entities.iter().map(String::as_str).collect();
        let protected_version_set: HashSet<&str> = protected_version_nodes.iter().map(String::as_str).collect();

        let mut incident_edge_counts_by_version: HashMap<String, usize> = HashMap::new();
        for edge in &self.edges {
            if let Some(src) = self.interner.get(edge.src) {
                *incident_edge_counts_by_version.entry(src.to_string()).or_insert(0) += 1;
            }
            if edge.dst != edge.src {
                if let Some(dst) = self.interner.get(edge.dst) {
                    *incident_edge_counts_by_version.entry(dst.to_string()).or_insert(0) += 1;
                }
            }
        }

        let mut removable_version_nodes: HashSet<String> = HashSet::new();
        let mut eligible_versions: Vec<(i64, String)> = Vec::new();
        for (entity_id, version_ids) in &self.entity_versions {
            let current_node_id = self.current_version_by_entity.get(entity_id);
            for node_id in version_ids {
                let node = node_id.as_str();
                if protected_version_set.contains(node) {
                    continue;
                }
                if current_node_id.map(String::as_str) == Some(node) && protected_entity_set.contains(entity_id.as_str()) {
                    continue;
                }
                let version_ts_micros = self
                    .version_last_seen_ts_micros
                    .get(node)
                    .copied()
                    .or_else(|| self.entity_last_seen_ts_micros.get(entity_id).copied())
                    .or_else(|| {
                        self.version_nodes
                            .iter()
                            .find(|meta| meta.node_id == node)
                            .and_then(|meta| meta.observed_ts_micros)
                    });
                let Some(ts_micros) = version_ts_micros else {
                    continue;
                };
                eligible_versions.push((ts_micros, node.to_string()));
                if ts_micros <= cutoff_micros {
                    removable_version_nodes.insert(node.to_string());
                }
            }
        }

        let current_version_nodes = self.version_nodes.len();
        let current_edges = self.edges.len();
        let mut removable_version_estimate = removable_version_nodes.len();
        let mut removable_edge_estimate = removable_version_nodes
            .iter()
            .map(|node_id| incident_edge_counts_by_version.get(node_id).copied().unwrap_or(0))
            .sum::<usize>();
        let low_watermark_ratio = cap_low_watermark_ratio.clamp(0.0, 1.0);
        let mut target_version_nodes = max_version_nodes;
        let mut target_edges = max_edges;
        if max_version_nodes > 0 && current_version_nodes > max_version_nodes {
            target_version_nodes = ((max_version_nodes as f64) * low_watermark_ratio).floor() as usize;
            target_version_nodes = target_version_nodes.max(1);
        }
        if max_edges > 0 && current_edges > max_edges {
            target_edges = ((max_edges as f64) * low_watermark_ratio).floor() as usize;
            target_edges = target_edges.max(1);
        }

        if max_version_nodes > 0 || max_edges > 0 {
            eligible_versions.sort_by(|a, b| a.cmp(b));
            for (_ts_micros, node_id) in eligible_versions {
                let projected_version_nodes = current_version_nodes.saturating_sub(removable_version_estimate);
                let projected_edges = current_edges.saturating_sub(removable_edge_estimate);
                let version_ok = target_version_nodes == 0 || projected_version_nodes <= target_version_nodes;
                let edge_ok = target_edges == 0 || projected_edges <= target_edges;
                if version_ok && edge_ok {
                    break;
                }
                if removable_version_nodes.contains(node_id.as_str()) {
                    continue;
                }
                removable_version_nodes.insert(node_id.clone());
                removable_version_estimate += 1;
                removable_edge_estimate += incident_edge_counts_by_version.get(node_id.as_str()).copied().unwrap_or(0);
            }
        }

        if removable_version_nodes.is_empty() {
            return NativePrunePlan {
                removed_version_nodes: Vec::new(),
                removed_entities: Vec::new(),
                removed_edges: 0,
            };
        }

        let removable_entities = self
            .entity_versions
            .iter()
            .filter(|(_entity_id, version_ids)| {
                !version_ids.is_empty() && version_ids.iter().all(|node_id| removable_version_nodes.contains(node_id.as_str()))
            })
            .map(|(entity_id, _version_ids)| entity_id.clone())
            .collect::<Vec<_>>();
        let removed_edges = self
            .edges
            .iter()
            .filter(|edge| {
                let src_removed = self
                    .interner
                    .get(edge.src)
                    .map(|node_id| removable_version_nodes.contains(node_id))
                    .unwrap_or(false);
                let dst_removed = self
                    .interner
                    .get(edge.dst)
                    .map(|node_id| removable_version_nodes.contains(node_id))
                    .unwrap_or(false);
                src_removed || dst_removed
            })
            .count();

        let mut removed_version_nodes = removable_version_nodes.into_iter().collect::<Vec<_>>();
        removed_version_nodes.sort();
        let mut removed_entities = removable_entities;
        removed_entities.sort();
        NativePrunePlan {
            removed_version_nodes,
            removed_entities,
            removed_edges,
        }
    }

    fn prune_preview(
        &self,
        watermark_ts: Option<&str>,
        retention_seconds: i64,
        protected_entities: &[String],
        protected_version_nodes: &[String],
        max_version_nodes: usize,
        max_edges: usize,
        cap_low_watermark_ratio: f64,
    ) -> HashMap<String, usize> {
        let plan = self.compute_prune_plan(
            watermark_ts,
            retention_seconds,
            protected_entities,
            protected_version_nodes,
            max_version_nodes,
            max_edges,
            cap_low_watermark_ratio,
        );
        HashMap::from([
            ("entities_removed".to_string(), plan.removed_entities.len()),
            ("version_nodes_removed".to_string(), plan.removed_version_nodes.len()),
            ("edges_removed".to_string(), plan.removed_edges),
        ])
    }

    fn prune_apply(
        &mut self,
        watermark_ts: Option<&str>,
        retention_seconds: i64,
        protected_entities: &[String],
        protected_version_nodes: &[String],
        max_version_nodes: usize,
        max_edges: usize,
        cap_low_watermark_ratio: f64,
    ) -> NativePrunePlan {
        let plan = self.compute_prune_plan(
            watermark_ts,
            retention_seconds,
            protected_entities,
            protected_version_nodes,
            max_version_nodes,
            max_edges,
            cap_low_watermark_ratio,
        );
        if plan.removed_version_nodes.is_empty() {
            return plan;
        }

        let removed_set: HashSet<&str> = plan.removed_version_nodes.iter().map(String::as_str).collect();
        self.edges.retain(|edge| {
            let src_removed = self
                .interner
                .get(edge.src)
                .map(|node_id| removed_set.contains(node_id))
                .unwrap_or(false);
            let dst_removed = self
                .interner
                .get(edge.dst)
                .map(|node_id| removed_set.contains(node_id))
                .unwrap_or(false);
            !(src_removed || dst_removed)
        });
        self.version_nodes
            .retain(|meta| !removed_set.contains(meta.node_id.as_str()));
        for node_id in &plan.removed_version_nodes {
            self.version_last_seen_ts_micros.remove(node_id);
        }

        let entity_ids = self.entity_versions.keys().cloned().collect::<Vec<_>>();
        for entity_id in entity_ids {
            let Some(old_versions) = self.entity_versions.get(&entity_id).cloned() else {
                continue;
            };
            let remaining_versions = old_versions
                .into_iter()
                .filter(|node_id| !removed_set.contains(node_id.as_str()))
                .collect::<Vec<_>>();
            if remaining_versions.is_empty() {
                self.entity_versions.remove(&entity_id);
                self.current_version_by_entity.remove(&entity_id);
                self.version_counter_by_entity.remove(&entity_id);
                self.entity_last_seen_ts_micros.remove(&entity_id);
                continue;
            }
            if self
                .current_version_by_entity
                .get(&entity_id)
                .map(String::as_str)
                .map(|node_id| removed_set.contains(node_id))
                .unwrap_or(false)
            {
                if let Some(last) = remaining_versions.last() {
                    self.current_version_by_entity.insert(entity_id.clone(), last.clone());
                }
            }
            let latest_seen = remaining_versions
                .iter()
                .rev()
                .find_map(|node_id| self.version_last_seen_ts_micros.get(node_id).copied());
            match latest_seen {
                Some(ts_micros) => {
                    self.entity_last_seen_ts_micros.insert(entity_id.clone(), ts_micros);
                }
                None => {
                    self.entity_last_seen_ts_micros.remove(&entity_id);
                }
            }
            self.entity_versions.insert(entity_id, remaining_versions);
        }

        self.adj_all.clear();
        let remaining_edges = self
            .edges
            .iter()
            .map(|edge| (edge.src, edge.dst))
            .collect::<Vec<_>>();
        for (src, dst) in remaining_edges {
            self.ensure_node_slot(src);
            self.ensure_node_slot(dst);
            self.adj_all[src as usize].push(dst);
        }
        plan
    }
}

fn payload_to_native_event(payload: &Bound<'_, PyDict>) -> NativeEventPayload {
    NativeEventPayload {
        event_id: payload
            .get_item("event_id")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok()))
            .unwrap_or_default(),
        ts: payload
            .get_item("ts")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok())),
        event_type: payload
            .get_item("event_type")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok()))
            .unwrap_or_else(|| "unknown".to_string()),
        subject: payload
            .get_item("subject")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok())),
        object: payload
            .get_item("object")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok())),
        bytes_transferred: payload
            .get_item("bytes_transferred")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<i64>().ok())),
        event_type_lower: payload
            .get_item("event_type_lower")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<String>().ok()))
            .unwrap_or_default(),
        subject_state_change: payload
            .get_item("subject_state_change")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<bool>().ok()))
            .unwrap_or(false),
        object_state_change: payload
            .get_item("object_state_change")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<bool>().ok()))
            .unwrap_or(false),
        is_memory_object: payload
            .get_item("is_memory_object")
            .ok()
            .and_then(|v| v.and_then(|x| x.extract::<bool>().ok()))
            .unwrap_or(false),
    }
}

#[derive(Default)]
struct NativeOnlineIndexState {
    mapper_by_node: Vec<NativeMapperNode>,
    out_edges: Vec<Vec<(u32, u8)>>,
    out_edge_set: Vec<HashSet<(u32, u8)>>,
    in_edges: Vec<Vec<(u32, u8)>>,
    in_edge_set: Vec<HashSet<(u32, u8)>>,
    local_match_meta_by_node: Vec<HashMap<u32, NativeLocalMatchMeta>>,
    pending_new_edges: Vec<(u32, u32, u8)>,
    rule_by_match: HashMap<u32, u32>,
    sequence_by_match: HashMap<u32, usize>,
    max_depth: usize,
    max_fan_out: usize,
    depth_cutoff_total: usize,
    fan_out_cutoff_total: usize,
}

impl NativeOnlineIndexState {
    fn new(max_depth: usize, max_fan_out: usize) -> Self {
        Self {
            mapper_by_node: Vec::new(),
            out_edges: Vec::new(),
            out_edge_set: Vec::new(),
            in_edges: Vec::new(),
            in_edge_set: Vec::new(),
            local_match_meta_by_node: Vec::new(),
            pending_new_edges: Vec::new(),
            rule_by_match: HashMap::new(),
            sequence_by_match: HashMap::new(),
            max_depth,
            max_fan_out,
            depth_cutoff_total: 0,
            fan_out_cutoff_total: 0,
        }
    }

    fn ensure_node_slot(&mut self, node_id: u32) {
        let needed_len = node_id as usize + 1;
        if self.mapper_by_node.len() < needed_len {
            self.mapper_by_node
                .resize_with(needed_len, NativeMapperNode::default);
        }
        if self.out_edges.len() < needed_len {
            self.out_edges.resize_with(needed_len, Vec::new);
        }
        if self.out_edge_set.len() < needed_len {
            self.out_edge_set.resize_with(needed_len, HashSet::new);
        }
        if self.in_edges.len() < needed_len {
            self.in_edges.resize_with(needed_len, Vec::new);
        }
        if self.in_edge_set.len() < needed_len {
            self.in_edge_set.resize_with(needed_len, HashSet::new);
        }
        if self.local_match_meta_by_node.len() < needed_len {
            self.local_match_meta_by_node.resize_with(needed_len, HashMap::new);
        }
    }

    fn add_edge(&mut self, src: u32, dst: u32, edge_cost: u8) {
        self.ensure_node_slot(src);
        self.ensure_node_slot(dst);
        let edge = (dst, edge_cost);
        if self.out_edge_set[src as usize].insert(edge) {
            self.out_edges[src as usize].push(edge);
            let reverse_edge = (src, edge_cost);
            if self.in_edge_set[dst as usize].insert(reverse_edge) {
                self.in_edges[dst as usize].push(reverse_edge);
            }
            self.pending_new_edges.push((src, dst, edge_cost));
        }
    }

    fn propagate_across_new_edge(&mut self, src_node_id: u32, dst_node_id: u32, edge_cost: u8) {
        let Some(src_mapper) = self.mapper_by_node.get(src_node_id as usize).cloned() else {
            return;
        };
        if src_mapper.match_ids.is_empty() {
            return;
        }
        self.ensure_node_slot(dst_node_id);
        let dst_mapper = &mut self.mapper_by_node[dst_node_id as usize];
        let mut changed_for_dst: Vec<u32> = Vec::new();
        for match_id in &src_mapper.match_ids {
            let Some(rule_id) = self.rule_by_match.get(match_id).copied() else {
                continue;
            };
            let mut changed = false;
            if !dst_mapper.match_ids.contains(match_id) {
                dst_mapper.match_ids.push(*match_id);
                changed = true;
            }
            let dst_rule_ids = dst_mapper.match_ids_by_rule.entry(rule_id).or_default();
            if !dst_rule_ids.contains(match_id) {
                dst_rule_ids.push(*match_id);
                changed = true;
            }
            if let Some(sequence) = self.sequence_by_match.get(match_id).copied() {
                match dst_mapper.earliest_seq_by_rule.get(&rule_id).copied() {
                    Some(prev) if prev <= sequence => {}
                    _ => {
                        dst_mapper.earliest_seq_by_rule.insert(rule_id, sequence);
                        changed = true;
                    }
                }
            }
            for ((src_match_id, origin_node_id), hops) in &src_mapper.hops_by_match_origin {
                if src_match_id != match_id {
                    continue;
                }
                let key = (*src_match_id, *origin_node_id);
                let candidate_hops = *hops + u32::from(edge_cost);
                match dst_mapper.hops_by_match_origin.get(&key) {
                    Some(prev_hops) if *prev_hops <= candidate_hops => {}
                    _ => {
                        dst_mapper.hops_by_match_origin.insert(key, candidate_hops);
                        changed = true;
                    }
                }
            }
            if changed && !changed_for_dst.contains(match_id) {
                changed_for_dst.push(*match_id);
            }
        }
        if !changed_for_dst.is_empty() {
            self.propagate_delta(dst_node_id, changed_for_dst);
        }
    }

    fn flush_pending_edges(&mut self) {
        if self.pending_new_edges.is_empty() {
            return;
        }
        let pending_edges = std::mem::take(&mut self.pending_new_edges);
        for (src_node_id, dst_node_id, edge_cost) in pending_edges {
            self.propagate_across_new_edge(src_node_id, dst_node_id, edge_cost);
        }
    }

    fn register_match(&mut self, node_id: u32, match_id: u32, origin_node_id: u32, rule_id: u32, sequence: usize) {
        self.ensure_node_slot(node_id);
        self.rule_by_match.insert(match_id, rule_id);
        self.sequence_by_match.insert(match_id, sequence);
        self.local_match_meta_by_node[node_id as usize].insert(
            match_id,
            NativeLocalMatchMeta {
                rule_id,
                sequence,
                origin_node_id,
            },
        );
        let mapper = &mut self.mapper_by_node[node_id as usize];
        let mut changed = false;
        if !mapper.match_ids.contains(&match_id) {
            mapper.match_ids.push(match_id);
            changed = true;
        }
        let by_rule = mapper.match_ids_by_rule.entry(rule_id).or_default();
        if !by_rule.contains(&match_id) {
            by_rule.push(match_id);
            changed = true;
        }
        match mapper.earliest_seq_by_rule.get(&rule_id).copied() {
            Some(prev) if prev <= sequence => {}
            _ => {
                mapper.earliest_seq_by_rule.insert(rule_id, sequence);
                changed = true;
            }
        }
        match mapper.hops_by_match_origin.get(&(match_id, origin_node_id)).copied() {
            Some(prev) if prev <= 0 => {}
            _ => {
                mapper.hops_by_match_origin.insert((match_id, origin_node_id), 0);
                changed = true;
            }
        }
        if changed {
            self.propagate_delta(node_id, vec![match_id]);
        }
    }

    fn local_mapper_for_node(&self, node_id: u32) -> NativeMapperNode {
        let mut mapper = NativeMapperNode::default();
        let Some(local_meta) = self.local_match_meta_by_node.get(node_id as usize) else {
            return mapper;
        };
        for (match_id, meta) in local_meta {
            mapper.match_ids.push(*match_id);
            mapper.match_ids_by_rule.entry(meta.rule_id).or_default().push(*match_id);
            match mapper.earliest_seq_by_rule.get(&meta.rule_id).copied() {
                Some(prev) if prev <= meta.sequence => {}
                _ => {
                    mapper.earliest_seq_by_rule.insert(meta.rule_id, meta.sequence);
                }
            }
            mapper.hops_by_match_origin.insert((*match_id, meta.origin_node_id), 0);
        }
        mapper
    }

    fn recompute_mapper_for_node(&mut self, node_id: u32) -> bool {
        self.ensure_node_slot(node_id);
        let old_mapper = self
            .mapper_by_node
            .get(node_id as usize)
            .cloned()
            .unwrap_or_default();
        let mut new_mapper = self.local_mapper_for_node(node_id);
        let in_edges = self.in_edges.get(node_id as usize).cloned().unwrap_or_default();
        for (src_node_id, edge_cost) in in_edges {
            let Some(src_mapper) = self.mapper_by_node.get(src_node_id as usize).cloned() else {
                continue;
            };
            for match_id in &src_mapper.match_ids {
                Self::merge_match_from_src(&mut new_mapper, &src_mapper, *match_id, edge_cost);
            }
        }
        let changed = old_mapper.match_ids != new_mapper.match_ids
            || old_mapper.match_ids_by_rule != new_mapper.match_ids_by_rule
            || old_mapper.earliest_seq_by_rule != new_mapper.earliest_seq_by_rule
            || old_mapper.hops_by_match_origin != new_mapper.hops_by_match_origin;
        if changed {
            self.mapper_by_node[node_id as usize] = new_mapper;
        }
        changed
    }

    fn collect_downstream_nodes(&mut self, start_node_id: u32) -> Vec<u32> {
        self.ensure_node_slot(start_node_id);
        let mut ordered: Vec<u32> = Vec::new();
        let mut visited: HashSet<u32> = HashSet::from([start_node_id]);
        let mut queue: VecDeque<(u32, usize)> = VecDeque::from([(start_node_id, 0)]);
        while let Some((src_node_id, current_depth)) = queue.pop_front() {
            if self.max_depth > 0 && current_depth >= self.max_depth {
                continue;
            }
            let out_edges = self
                .out_edges
                .get(src_node_id as usize)
                .cloned()
                .unwrap_or_default();
            if self.max_fan_out > 0 && out_edges.len() > self.max_fan_out {
                continue;
            }
            for (dst_node_id, edge_cost) in out_edges {
                if !matches!(edge_cost, 0 | 1) || visited.contains(&dst_node_id) {
                    continue;
                }
                visited.insert(dst_node_id);
                ordered.push(dst_node_id);
                queue.push_back((dst_node_id, current_depth + 1));
            }
        }
        ordered
    }

    fn remove_match(&mut self, node_id: u32, match_id: u32) -> bool {
        self.ensure_node_slot(node_id);
        let Some(local_meta) = self.local_match_meta_by_node.get_mut(node_id as usize) else {
            return false;
        };
        if local_meta.remove(&match_id).is_none() {
            return false;
        }
        let mut changed_any = false;
        let mut affected = vec![node_id];
        affected.extend(self.collect_downstream_nodes(node_id));
        for affected_node_id in affected {
            changed_any = self.recompute_mapper_for_node(affected_node_id) || changed_any;
        }
        changed_any
    }

    fn merge_match_from_src(
        dst_mapper: &mut NativeMapperNode,
        src_mapper: &NativeMapperNode,
        match_id: u32,
        edge_cost: u8,
    ) -> bool {
        let mut changed = false;
        if !src_mapper.match_ids.contains(&match_id) {
            return false;
        }
        if !dst_mapper.match_ids.contains(&match_id) {
            dst_mapper.match_ids.push(match_id);
            changed = true;
        }
        for (rule_id, src_ids) in &src_mapper.match_ids_by_rule {
            if !src_ids.contains(&match_id) {
                continue;
            }
            let dst_rule_ids = dst_mapper.match_ids_by_rule.entry(*rule_id).or_default();
            if !dst_rule_ids.contains(&match_id) {
                dst_rule_ids.push(match_id);
                changed = true;
            }
            let src_earliest = src_mapper.earliest_seq_by_rule.get(rule_id).copied();
            if let Some(sequence) = src_earliest {
                match dst_mapper.earliest_seq_by_rule.get(rule_id).copied() {
                    Some(prev) if prev <= sequence => {}
                    _ => {
                        dst_mapper.earliest_seq_by_rule.insert(*rule_id, sequence);
                        changed = true;
                    }
                }
            }
        }
        for ((src_match_id, origin_node_id), hops) in &src_mapper.hops_by_match_origin {
            if *src_match_id != match_id {
                continue;
            }
            let key = (*src_match_id, *origin_node_id);
            let candidate_hops = *hops + u32::from(edge_cost);
            match dst_mapper.hops_by_match_origin.get(&key) {
                Some(prev_hops) if *prev_hops <= candidate_hops => {}
                _ => {
                    dst_mapper.hops_by_match_origin.insert(key, candidate_hops);
                    changed = true;
                }
            }
        }
        changed
    }

    fn propagate_delta(&mut self, start_node_id: u32, delta_match_ids: Vec<u32>) {
        if delta_match_ids.is_empty() {
            return;
        }
        let mut queue: VecDeque<(u32, Vec<u32>, usize)> =
            VecDeque::from([(start_node_id, delta_match_ids, 0)]);
        while let Some((src_node_id, delta, current_depth)) = queue.pop_front() {
            if self.max_depth > 0 && current_depth >= self.max_depth {
                self.depth_cutoff_total += 1;
                continue;
            }
            let out_edges = self
                .out_edges
                .get(src_node_id as usize)
                .cloned()
                .unwrap_or_default();
            if self.max_fan_out > 0 && out_edges.len() > self.max_fan_out {
                self.fan_out_cutoff_total += 1;
                continue;
            }
            let src_mapper = self
                .mapper_by_node
                .get(src_node_id as usize)
                .cloned()
                .unwrap_or_default();
            for (dst_node_id, edge_cost) in out_edges {
                self.ensure_node_slot(dst_node_id);
                let dst_mapper = &mut self.mapper_by_node[dst_node_id as usize];
                let mut changed_for_dst: Vec<u32> = Vec::new();
                for match_id in &delta {
                    if !src_mapper.match_ids.contains(match_id) {
                        continue;
                    }
                    let changed = Self::merge_match_from_src(dst_mapper, &src_mapper, *match_id, edge_cost);
                    if changed && !changed_for_dst.contains(match_id) {
                        changed_for_dst.push(*match_id);
                    }
                }
                if !changed_for_dst.is_empty() {
                    queue.push_back((dst_node_id, changed_for_dst, current_depth + 1));
                }
            }
        }
    }

    fn node_count(&self) -> usize {
        self.mapper_by_node.len()
    }
}

#[pyclass]
struct NativeBatchEngine {
    processed_batches: usize,
    processed_events: usize,
    graph: NativeGraphState,
    online_index: NativeOnlineIndexState,
    match_interner: StringInterner,
}

#[pymethods]
impl NativeBatchEngine {
    #[new]
    fn new() -> Self {
        Self {
            processed_batches: 0,
            processed_events: 0,
            graph: NativeGraphState::default(),
            online_index: NativeOnlineIndexState::new(5, 1000),
            match_interner: StringInterner::default(),
        }
    }

    fn process_batch(&mut self, batch: &Bound<'_, PyAny>) -> PyResult<bool> {
        let py_list = batch
            .downcast::<PyList>()
            .map_err(|_| PyRuntimeError::new_err("process_batch expects a list of event payload dicts"))?;
        for item in py_list.iter() {
            let payload = item
                .downcast::<PyDict>()
                .map_err(|_| PyRuntimeError::new_err("event payload must be a dict"))?;
            let _event = payload_to_native_event(payload);
            self.processed_events += 1;
        }
        self.processed_batches += 1;
        // Keep Python as the source of truth until graph/query semantics are ported.
        Ok(false)
    }

    fn reset_graph(&mut self) {
        self.graph = NativeGraphState::default();
    }

    fn record_graph_event(&mut self, payload: &Bound<'_, PyAny>) -> PyResult<()> {
        let py_dict = payload
            .downcast::<PyDict>()
            .map_err(|_| PyRuntimeError::new_err("record_graph_event expects an event payload dict"))?;
        let event = payload_to_native_event(py_dict);
        self.graph.add_event(&event);
        Ok(())
    }

    fn record_graph_events(&mut self, batch: &Bound<'_, PyAny>) -> PyResult<()> {
        let py_list = batch
            .downcast::<PyList>()
            .map_err(|_| PyRuntimeError::new_err("record_graph_events expects a list of event payload dicts"))?;
        for item in py_list.iter() {
            let py_dict = item
                .downcast::<PyDict>()
                .map_err(|_| PyRuntimeError::new_err("event payload must be a dict"))?;
            let event = payload_to_native_event(py_dict);
            self.graph.add_event(&event);
        }
        Ok(())
    }

    fn flush(&mut self) {
        self.online_index.flush_pending_edges();
    }

    fn stats(&self) -> (usize, usize) {
        (self.processed_batches, self.processed_events)
    }

    fn graph_stats(&self) -> (usize, usize) {
        (self.graph.node_count(), self.graph.edge_count())
    }

    fn graph_current_version_node(&self, entity_id: &str) -> Option<String> {
        self.graph.current_version_node(entity_id)
    }

    fn graph_prune_preview(
        &self,
        watermark_ts: String,
        retention_seconds: i64,
        protected_entities: Vec<String>,
        protected_version_nodes: Vec<String>,
        max_version_nodes: usize,
        max_edges: usize,
        cap_low_watermark_ratio: f64,
    ) -> HashMap<String, usize> {
        self.graph.prune_preview(
            (!watermark_ts.trim().is_empty()).then_some(watermark_ts.as_str()),
            retention_seconds,
            &protected_entities,
            &protected_version_nodes,
            max_version_nodes,
            max_edges,
            cap_low_watermark_ratio,
        )
    }

    fn graph_prune_apply(
        &mut self,
        watermark_ts: String,
        retention_seconds: i64,
        protected_entities: Vec<String>,
        protected_version_nodes: Vec<String>,
        max_version_nodes: usize,
        max_edges: usize,
        cap_low_watermark_ratio: f64,
    ) -> (Vec<String>, Vec<String>, usize) {
        let plan = self.graph.prune_apply(
            (!watermark_ts.trim().is_empty()).then_some(watermark_ts.as_str()),
            retention_seconds,
            &protected_entities,
            &protected_version_nodes,
            max_version_nodes,
            max_edges,
            cap_low_watermark_ratio,
        );
        (plan.removed_version_nodes, plan.removed_entities, plan.removed_edges)
    }

    fn online_index_stats(&self) -> (usize, usize, usize, usize) {
        (
            self.online_index.node_count(),
            self.online_index.depth_cutoff_total,
            self.online_index.fan_out_cutoff_total,
            self.online_index.max_depth,
        )
    }

    fn reset_online_index(&mut self) {
        let max_depth = self.online_index.max_depth;
        let max_fan_out = self.online_index.max_fan_out;
        self.online_index = NativeOnlineIndexState::new(max_depth, max_fan_out);
    }

    fn add_online_edge(&mut self, src: &str, dst: &str, edge_type: &str) {
        let src_id = self.graph.interner.intern(src);
        let dst_id = self.graph.interner.intern(dst);
        let normalized = edge_type.trim().to_ascii_lowercase();
        let edge_cost = match normalized.as_str() {
            "data_flow" => Some(1_u8),
            "version_transition" | "prev_version" => Some(0_u8),
            _ => None,
        };
        if let Some(cost) = edge_cost {
            self.online_index.add_edge(src_id, dst_id, cost);
        }
    }

    fn register_online_match(&mut self, node_id: &str, match_id: &str, _rule_id: &str, _sequence: usize) {
        let node_u32 = self.graph.interner.intern(node_id);
        let match_u32 = self.match_interner.intern(match_id);
        let rule_u32 = self.match_interner.intern(_rule_id);
        self.online_index
            .register_match(node_u32, match_u32, node_u32, rule_u32, _sequence);
    }

    fn remove_online_match(&mut self, node_id: &str, match_id: &str) -> bool {
        let Some(node_u32) = self.graph.interner.ids_by_value.get(node_id).copied() else {
            return false;
        };
        let Some(match_u32) = self.match_interner.ids_by_value.get(match_id).copied() else {
            return false;
        };
        self.online_index.remove_match(node_u32, match_u32)
    }

    fn online_contains_match(&self, node_id: &str, match_id: &str) -> bool {
        let Some(node_u32) = self.graph.interner.ids_by_value.get(node_id).copied() else {
            return false;
        };
        let Some(match_u32) = self.match_interner.ids_by_value.get(match_id).copied() else {
            return false;
        };
        self.online_index
            .mapper_by_node
            .get(node_u32 as usize)
            .map(|mapper| mapper.match_ids.contains(&match_u32))
            .unwrap_or(false)
    }

    fn online_node_match_count(&self, node_id: &str) -> usize {
        let Some(node_u32) = self.graph.interner.ids_by_value.get(node_id).copied() else {
            return 0;
        };
        self.online_index
            .mapper_by_node
            .get(node_u32 as usize)
            .map(|mapper| mapper.match_ids.len())
            .unwrap_or(0)
    }

    fn online_mapper_contains_rule(&self, node_id: &str, rule_id: &str) -> bool {
        let Some(node_u32) = self.graph.interner.ids_by_value.get(node_id).copied() else {
            return false;
        };
        let Some(rule_u32) = self.match_interner.ids_by_value.get(rule_id).copied() else {
            return false;
        };
        self.online_index
            .mapper_by_node
            .get(node_u32 as usize)
            .and_then(|mapper| mapper.match_ids_by_rule.get(&rule_u32))
            .map(|ids| !ids.is_empty())
            .unwrap_or(false)
    }

    fn online_mapper_earliest_seq(&self, node_id: &str, rule_id: &str) -> Option<usize> {
        let node_u32 = self.graph.interner.ids_by_value.get(node_id).copied()?;
        let rule_u32 = self.match_interner.ids_by_value.get(rule_id).copied()?;
        self.online_index
            .mapper_by_node
            .get(node_u32 as usize)
            .and_then(|mapper| mapper.earliest_seq_by_rule.get(&rule_u32).copied())
    }

    #[pyo3(signature = (node_id, match_id, origin_node_id = None))]
    fn online_mapper_min_hops(&self, node_id: &str, match_id: &str, origin_node_id: Option<String>) -> Option<usize> {
        let node_u32 = self.graph.interner.ids_by_value.get(node_id).copied()?;
        let match_u32 = self.match_interner.ids_by_value.get(match_id).copied()?;
        let mapper = self.online_index.mapper_by_node.get(node_u32 as usize)?;
        if let Some(origin) = origin_node_id.as_deref() {
            let origin_u32 = self.graph.interner.ids_by_value.get(origin).copied()?;
            return mapper
                .hops_by_match_origin
                .get(&(match_u32, origin_u32))
                .copied()
                .map(|v| v as usize);
        }
        mapper
            .hops_by_match_origin
            .iter()
            .filter_map(|((mid, _origin), hops)| (*mid == match_u32).then_some(*hops as usize))
            .min()
    }

    fn online_mapper_match_ids(&self, node_id: &str) -> Vec<String> {
        let Some(node_u32) = self.graph.interner.ids_by_value.get(node_id).copied() else {
            return Vec::new();
        };
        let Some(mapper) = self.online_index.mapper_by_node.get(node_u32 as usize) else {
            return Vec::new();
        };
        mapper
            .match_ids
            .iter()
            .filter_map(|match_u32| self.match_interner.get(*match_u32).map(|s| s.to_string()))
            .collect()
    }

    fn sample_edge(&self) -> Option<(String, String, String)> {
        let edge = self.graph.edges.last()?;
        let src = self.graph.interner.get(edge.src)?.to_string();
        let dst = self.graph.interner.get(edge.dst)?.to_string();
        Some((src, dst, edge.event_type.clone()))
    }
}

#[pymodule]
fn holmes_native_rs(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeBatchEngine>()?;
    Ok(())
}
