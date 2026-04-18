import pytest

from engine.io.events import Event
from engine.core.graph import ProvenanceGraph
from engine.hsg.online_index import OnlineIndex
from engine.native.backend import NoopNativeBackend, RustNativeBackend


class _FakeNativeBatchEngine:
    def __init__(self) -> None:
        self.reset_graph_calls = 0
        self.recorded_graph_events = []
        self.removed_online_matches = []
        self.flushed = 0
        self.current_versions = {}
        self.version_counters = {}
        self.prune_preview_result = {"entities_removed": 0, "version_nodes_removed": 0, "edges_removed": 0}
        self.prune_apply_result = {
            "removed_entities": [],
            "removed_version_nodes": [],
            "edges_removed": 0,
        }

    def _ensure_entity(self, entity_id):
        if entity_id not in self.current_versions:
            next_version = self.version_counters.get(entity_id, 0) + 1
            self.version_counters[entity_id] = next_version
            self.current_versions[entity_id] = f"{entity_id}#v{next_version}"

    def _bump_entity(self, entity_id):
        self._ensure_entity(entity_id)
        next_version = self.version_counters.get(entity_id, 0) + 1
        self.version_counters[entity_id] = next_version
        self.current_versions[entity_id] = f"{entity_id}#v{next_version}"

    def process_batch(self, payload):
        return False

    def reset_graph(self):
        self.reset_graph_calls += 1

    def record_graph_event(self, payload):
        self.recorded_graph_events.append(payload)
        subject = payload.get("subject")
        object_ = payload.get("object")
        if not subject or not object_:
            return
        self._ensure_entity(subject)
        self._ensure_entity(object_)
        event_type_lower = (payload.get("event_type_lower") or "").lower()
        changed = set()
        if event_type_lower in {"write", "modify", "send", "proc_to_file", "proc_to_registry", "proc_to_ip", "file_to_ip"}:
            changed.add(object_)
        if event_type_lower in {"read", "recv", "file_to_proc"}:
            changed.add(subject)
        if event_type_lower in {"exec", "execute", "setuid", "setgid", "privilege_change", "privilege_escalation"} and subject.startswith("proc:"):
            changed.add(subject)
        if payload.get("subject_state_change"):
            changed.add(subject)
        if payload.get("object_state_change"):
            changed.add(object_)
        if object_ not in changed:
            changed.add(object_)
        for entity_id in sorted(changed):
            self._bump_entity(entity_id)

    def flush(self):
        self.flushed += 1

    def reset_online_index(self):
        return None

    def add_online_edge(self, src, dst, edge_type):
        return None

    def register_online_match(self, node_id, match_id, rule_id, sequence):
        return None

    def remove_online_match(self, node_id, match_id):
        self.removed_online_matches.append((node_id, match_id))
        return True

    def online_index_stats(self):
        return (0, 0, 0, 0)

    def graph_stats(self):
        return (0, 0)

    def graph_current_version_node(self, entity_id):
        return self.current_versions.get(entity_id)

    def graph_prune_preview(
        self,
        watermark_ts,
        retention_seconds,
        protected_entities,
        protected_version_nodes,
        max_version_nodes,
        max_edges,
        cap_low_watermark_ratio,
    ):
        return dict(self.prune_preview_result)

    def graph_prune_apply(
        self,
        watermark_ts,
        retention_seconds,
        protected_entities,
        protected_version_nodes,
        max_version_nodes,
        max_edges,
        cap_low_watermark_ratio,
    ):
        result = dict(self.prune_apply_result)
        return (
            list(result.get("removed_version_nodes", [])),
            list(result.get("removed_entities", [])),
            int(result.get("edges_removed", 0)),
        )

    def online_contains_match(self, node_id, match_id):
        return False

    def online_node_match_count(self, node_id):
        return 0

    def online_mapper_contains_rule(self, node_id, rule_id):
        return False

    def online_mapper_earliest_seq(self, node_id, rule_id):
        return None

    def online_mapper_min_hops(self, node_id, match_id, origin_node_id=None):
        return None

    def online_mapper_match_ids(self, node_id):
        return []


class _FakeRustModule:
    NativeBatchEngine = _FakeNativeBatchEngine


def _assert_online_mapper_equivalent(
    python_index: OnlineIndex,
    rust_backend: RustNativeBackend,
    *,
    node_ids: list[str],
    rule_ids: list[str],
    match_specs: list[tuple[str, str, str]],
) -> None:
    for node_id in node_ids:
        assert rust_backend.online_node_match_count(node_id) == len(python_index.mapper_match_ids(node_id))
        assert rust_backend.online_mapper_match_ids(node_id) == python_index.mapper_match_ids(node_id)
        for rule_id in rule_ids:
            assert rust_backend.online_mapper_contains_rule(node_id, rule_id) is python_index.mapper_contains_rule(
                node_id, rule_id
            )
            assert rust_backend.online_mapper_earliest_seq(node_id, rule_id) == python_index.mapper_earliest_seq(
                node_id, rule_id
            )
        for match_id, _rule_id, origin_node_id in match_specs:
            assert rust_backend.online_contains_match(node_id, match_id) is python_index.mapper_contains_match(
                node_id, match_id
            )
            assert rust_backend.online_mapper_min_hops(node_id, match_id) == python_index.mapper_min_hops(
                node_id, match_id
            )
            assert rust_backend.online_mapper_min_hops(
                node_id, match_id, origin_node_id=origin_node_id
            ) == python_index.mapper_min_hops(node_id, match_id, origin_node_id=origin_node_id)


def test_noop_native_backend_graph_seam_is_safe():
    backend = NoopNativeBackend()
    backend.reset_graph()
    backend.record_graph_event(
        Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:p1", object="file:f1", raw={})
    )


def test_rust_native_backend_forwards_graph_seam():
    backend = RustNativeBackend(_FakeRustModule())
    event = Event(
        event_id="e1",
        ts="2025-01-01T00:00:00Z",
        event_type="proc_to_file",
        subject="proc:p1",
        object="file:f1",
        raw={},
    )

    backend.reset_graph()
    backend.record_graph_event(event)

    assert backend._engine.reset_graph_calls == 1  # noqa: SLF001
    assert len(backend._engine.recorded_graph_events) == 1  # noqa: SLF001
    payload = backend._engine.recorded_graph_events[0]  # noqa: SLF001
    assert payload["event_id"] == "e1"
    assert payload["subject"] == "proc:p1"
    assert payload["object"] == "file:f1"
    assert backend.graph_current_version_node("proc:p1") == "proc:p1#v1"


def test_rust_native_backend_forwards_online_match_remove_seam():
    backend = RustNativeBackend(_FakeRustModule())

    assert backend.remove_online_match("proc:p1#v1", "m1") is True
    assert backend._engine.removed_online_matches == [("proc:p1#v1", "m1")]  # noqa: SLF001


def test_provenance_graph_forwards_events_to_native_backend_seam():
    backend = RustNativeBackend(_FakeRustModule())
    graph = ProvenanceGraph(native_backend=backend)

    graph.add_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )

    assert backend._engine.reset_graph_calls == 1  # noqa: SLF001
    assert len(backend._engine.recorded_graph_events) == 0  # noqa: SLF001
    graph.flush_pending_native_graph_shadow()
    assert len(backend._engine.recorded_graph_events) == 1  # noqa: SLF001
    assert backend.graph_current_version_node("file:f1") == graph.current_version["file:f1"]


def test_provenance_graph_stops_forwarding_after_backend_swap_to_noop():
    backend = RustNativeBackend(_FakeRustModule())
    graph = ProvenanceGraph(native_backend=backend)
    graph.set_native_backend(NoopNativeBackend())

    graph.add_event(
        Event(
            event_id="e2",
            ts="2025-01-02T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p2",
            object="file:f2",
            raw={},
        )
    )

    assert backend._engine.reset_graph_calls == 1  # noqa: SLF001
    assert len(backend._engine.recorded_graph_events) == 0  # noqa: SLF001


def test_provenance_graph_current_version_shadow_check_counts_match(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_SHADOW_CHECK", "1")
    backend = RustNativeBackend(_FakeRustModule())
    graph = ProvenanceGraph(native_backend=backend)
    graph.add_event(
        Event(
            event_id="e3",
            ts="2025-01-03T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p3",
            object="file:f3",
            raw={},
        )
    )

    expected = graph.current_version["file:f3"]
    assert graph.current_version_node("file:f3") == expected
    current_total, current_mismatch, prune_total, prune_mismatch = graph.native_graph_shadow_stats()
    assert current_total >= 1
    assert current_mismatch == 0
    assert prune_total == 0
    assert prune_mismatch == 0


def test_rust_native_backend_forwards_graph_prune_preview_seam():
    backend = RustNativeBackend(_FakeRustModule())

    preview = backend.graph_prune_preview(
        watermark_ts="2025-01-05T00:00:00Z",
        retention_seconds=3600,
        protected_entities={"proc:p1"},
        protected_version_nodes={"proc:p1#v2"},
        max_version_nodes=123,
        max_edges=456,
        cap_low_watermark_ratio=0.85,
    )

    assert preview["entities_removed"] == 0
    assert preview["version_nodes_removed"] == 0
    assert preview["edges_removed"] == 0


def test_rust_native_backend_forwards_graph_prune_apply_seam():
    backend = RustNativeBackend(_FakeRustModule())
    backend._engine.prune_apply_result = {  # noqa: SLF001
        "removed_entities": ["proc:p1"],
        "removed_version_nodes": ["proc:p1#v1"],
        "edges_removed": 2,
    }

    applied = backend.graph_prune_apply(
        watermark_ts="2025-01-05T00:00:00Z",
        retention_seconds=3600,
        protected_entities=set(),
        protected_version_nodes=set(),
        max_version_nodes=123,
        max_edges=456,
        cap_low_watermark_ratio=0.85,
    )

    assert applied["entities_removed"] == 1
    assert applied["version_nodes_removed"] == 1
    assert applied["edges_removed"] == 2
    assert applied["removed_entities"] == ["proc:p1"]
    assert applied["removed_version_nodes"] == ["proc:p1#v1"]


def test_provenance_graph_prune_preview_shadow_check_counts_match(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_SHADOW_CHECK", "1")
    backend = RustNativeBackend(_FakeRustModule())
    backend._engine.prune_preview_result = {"entities_removed": 0, "version_nodes_removed": 1, "edges_removed": 1}  # noqa: SLF001
    backend._engine.prune_apply_result = {  # noqa: SLF001
        "removed_entities": [],
        "removed_version_nodes": ["file:f4#v1"],
        "edges_removed": 1,
    }
    graph = ProvenanceGraph(native_backend=backend)
    graph.add_event(
        Event(
            event_id="e4",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p4",
            object="file:f4",
            raw={},
        )
    )

    prune_result = graph.prune_stale_orphaned(
        watermark_ts="2025-03-20T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities=set(),
        protected_version_nodes=set(),
    )

    assert prune_result["version_nodes_removed"] >= 1
    current_total, current_mismatch, prune_total, prune_mismatch = graph.native_graph_shadow_stats()
    assert current_total >= 0
    assert current_mismatch == 0
    assert prune_total == 1
    assert prune_mismatch == 0


def test_provenance_graph_prune_preview_shadow_check_counts_mismatch(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_SHADOW_CHECK", "1")
    backend = RustNativeBackend(_FakeRustModule())
    backend._engine.prune_preview_result = {"entities_removed": 99, "version_nodes_removed": 88, "edges_removed": 77}  # noqa: SLF001
    backend._engine.prune_apply_result = {  # noqa: SLF001
        "removed_entities": [],
        "removed_version_nodes": ["file:f5#v1"],
        "edges_removed": 2,
    }
    graph = ProvenanceGraph(native_backend=backend)
    graph.add_event(
        Event(
            event_id="e5",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p5",
            object="file:f5",
            raw={},
        )
    )

    graph.prune_stale_orphaned(
        watermark_ts="2025-03-20T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities=set(),
        protected_version_nodes=set(),
    )

    _current_total, _current_mismatch, prune_total, prune_mismatch = graph.native_graph_shadow_stats()
    assert prune_total == 1
    assert prune_mismatch == 1


def test_provenance_graph_uses_native_prune_apply_when_available():
    backend = RustNativeBackend(_FakeRustModule())
    graph = ProvenanceGraph(native_backend=backend)
    graph.add_event(
        Event(
            event_id="e6",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p6",
            object="file:f6",
            raw={},
        )
    )
    backend._engine.prune_apply_result = {  # noqa: SLF001
        "removed_entities": [],
        "removed_version_nodes": ["file:f6#v1"],
        "edges_removed": 0,
    }

    result = graph.prune_stale_orphaned(
        watermark_ts="2025-03-20T00:00:00Z",
        retention_seconds=30 * 24 * 60 * 60,
        protected_entities=set(),
        protected_version_nodes=set(),
    )

    assert result["version_nodes_removed"] == 1
    assert "file:f6#v1" not in graph.version_nodes


def test_rust_native_backend_online_mapper_matches_python_online_index():
    module = pytest.importorskip("holmes_native_rs")
    backend = RustNativeBackend(module)
    python_index = OnlineIndex()

    node_ids = ["u", "v", "w", "x", "z"]
    rule_ids = ["R1", "R2", "R3"]
    match_specs = [
        ("m1", "R1", "u"),
        ("m2", "R2", "x"),
        ("m3", "R3", "w"),
    ]

    for src, dst, edge_type in [
        ("u", "v", "data_flow"),
        ("v", "w", "version_transition"),
        ("x", "v", "data_flow"),
    ]:
        python_index.on_edge_added(src, dst, edge_type, propagate=False)
        backend.add_online_edge(src, dst, edge_type)

    python_index.on_match_added("u", "m1", sequence=3, rule_id="R1", origin_node_id="u")
    backend.register_online_match("u", "m1", "R1", 3)
    python_index.flush_pending_edges()
    backend.flush()
    _assert_online_mapper_equivalent(
        python_index,
        backend,
        node_ids=node_ids,
        rule_ids=rule_ids,
        match_specs=match_specs,
    )

    python_index.on_match_added("x", "m2", sequence=7, rule_id="R2", origin_node_id="x")
    backend.register_online_match("x", "m2", "R2", 7)
    python_index.on_match_added("w", "m3", sequence=2, rule_id="R3", origin_node_id="w")
    backend.register_online_match("w", "m3", "R3", 2)
    _assert_online_mapper_equivalent(
        python_index,
        backend,
        node_ids=node_ids,
        rule_ids=rule_ids,
        match_specs=match_specs,
    )

    python_index.on_edge_added("w", "z", "data_flow", propagate=False)
    backend.add_online_edge("w", "z", "data_flow")
    python_index.flush_pending_edges()
    backend.flush()
    _assert_online_mapper_equivalent(
        python_index,
        backend,
        node_ids=node_ids,
        rule_ids=rule_ids,
        match_specs=match_specs,
    )

    assert python_index.on_match_removed("u", "m1") is True
    assert backend.remove_online_match("u", "m1") is True
    _assert_online_mapper_equivalent(
        python_index,
        backend,
        node_ids=node_ids,
        rule_ids=rule_ids,
        match_specs=match_specs,
    )
