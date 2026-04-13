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

#[derive(Clone, Debug, Default)]
struct NativeMapperNode {
    match_ids: Vec<u32>,
    match_ids_by_rule: HashMap<u32, Vec<u32>>,
    earliest_seq_by_rule: HashMap<u32, usize>,
    hops_by_match_origin: HashMap<(u32, u32), u32>,
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

    fn len(&self) -> usize {
        self.values_by_id.len()
    }
}

#[derive(Default)]
struct NativeGraphState {
    interner: StringInterner,
    edges: Vec<NativeEdge>,
    adj_data_flow: Vec<Vec<u32>>,
    event_type_counts: HashMap<String, usize>,
}

impl NativeGraphState {
    fn ensure_node_slot(&mut self, node_id: u32) {
        let needed_len = node_id as usize + 1;
        if self.adj_data_flow.len() < needed_len {
            self.adj_data_flow.resize_with(needed_len, Vec::new);
        }
    }

    fn add_event(&mut self, event: &NativeEventPayload) {
        let Some(subject) = event.subject.as_deref() else {
            return;
        };
        let Some(object) = event.object.as_deref() else {
            return;
        };

        let src = self.interner.intern(subject);
        let dst = self.interner.intern(object);
        self.ensure_node_slot(src);
        self.ensure_node_slot(dst);
        self.adj_data_flow[src as usize].push(dst);
        self.edges.push(NativeEdge {
            src,
            dst,
            event_type: event.event_type.clone(),
        });
        *self
            .event_type_counts
            .entry(event.event_type.clone())
            .or_insert(0) += 1;
    }

    fn node_count(&self) -> usize {
        self.interner.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[derive(Default)]
struct NativeOnlineIndexState {
    mapper_by_node: Vec<NativeMapperNode>,
    out_edges: Vec<Vec<(u32, u8)>>,
    out_edge_set: Vec<HashSet<(u32, u8)>>,
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
    }

    fn add_edge(&mut self, src: u32, dst: u32, edge_cost: u8) {
        self.ensure_node_slot(src);
        self.ensure_node_slot(dst);
        let edge = (dst, edge_cost);
        if self.out_edge_set[src as usize].insert(edge) {
            self.out_edges[src as usize].push(edge);
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
            let event = NativeEventPayload {
                event_id: payload
                    .get_item("event_id")?
                    .and_then(|v| v.extract::<String>().ok())
                    .unwrap_or_default(),
                ts: payload.get_item("ts")?.and_then(|v| v.extract::<String>().ok()),
                event_type: payload
                    .get_item("event_type")?
                    .and_then(|v| v.extract::<String>().ok())
                    .unwrap_or_else(|| "unknown".to_string()),
                subject: payload.get_item("subject")?.and_then(|v| v.extract::<String>().ok()),
                object: payload.get_item("object")?.and_then(|v| v.extract::<String>().ok()),
                bytes_transferred: payload
                    .get_item("bytes_transferred")?
                    .and_then(|v| v.extract::<i64>().ok()),
                event_type_lower: payload
                    .get_item("event_type_lower")?
                    .and_then(|v| v.extract::<String>().ok())
                    .unwrap_or_default(),
                subject_state_change: payload
                    .get_item("subject_state_change")?
                    .and_then(|v| v.extract::<bool>().ok())
                    .unwrap_or(false),
                object_state_change: payload
                    .get_item("object_state_change")?
                    .and_then(|v| v.extract::<bool>().ok())
                    .unwrap_or(false),
                is_memory_object: payload
                    .get_item("is_memory_object")?
                    .and_then(|v| v.extract::<bool>().ok())
                    .unwrap_or(false),
            };
            self.graph.add_event(&event);
            self.processed_events += 1;
        }
        self.processed_batches += 1;
        // Keep Python as the source of truth until graph/query semantics are ported.
        Ok(false)
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

    #[pyo3(signature = (node_id, match_id, origin_node_id=None))]
    fn online_mapper_min_hops(&self, node_id: &str, match_id: &str, origin_node_id: Option<&str>) -> Option<usize> {
        let node_u32 = self.graph.interner.ids_by_value.get(node_id).copied()?;
        let match_u32 = self.match_interner.ids_by_value.get(match_id).copied()?;
        let mapper = self.online_index.mapper_by_node.get(node_u32 as usize)?;
        if let Some(origin) = origin_node_id {
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
