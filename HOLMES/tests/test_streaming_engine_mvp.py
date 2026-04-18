import gzip
import json
from pathlib import Path

from engine.cli import run_stream
from engine.core.matcher import TTPMatch
from engine.cli.run_pipeline import run_pipeline
from engine.hsg.builder import HSGEdge
from engine.hsg.online_index import OnlineIndex
from engine.io.events import Event
from engine.native.backend import RustNativeBackend
from engine.rules.schema import Rule, RuleSet
from engine.rules.schema import load_rules_yaml
from engine.stream.runner import StreamingEngine
from engine.stream.source import DirectoryWatcherSource, FileJsonlSource, FileRawLineSource, RawStringPreFilter
from engine.stream.workers import iter_parsed_events_parallel


class _FakeNativeBatchEngine:
    def __init__(self) -> None:
        self.reset_graph_calls = 0
        self.reset_online_index_calls = 0
        self.removed_online_matches = []
        self.flushed = 0
        self.added_online_edges = []
        self.online_index = OnlineIndex()
        self.fail_add_online_edge = False
        self.fail_register_online_match = False
        self.fail_remove_online_match = False

    def process_batch(self, payload):
        return False

    def reset_graph(self):
        self.reset_graph_calls += 1

    def record_graph_event(self, payload):
        return None

    def flush(self):
        self.flushed += 1
        self.online_index.flush_pending_edges()

    def reset_online_index(self):
        self.reset_online_index_calls += 1
        self.online_index = OnlineIndex()

    def add_online_edge(self, src, dst, edge_type):
        if self.fail_add_online_edge:
            raise RuntimeError("boom:add_online_edge")
        self.added_online_edges.append((src, dst, edge_type))
        self.online_index.on_edge_added(src, dst, edge_type, propagate=False)

    def register_online_match(self, node_id, match_id, rule_id, sequence):
        if self.fail_register_online_match:
            raise RuntimeError("boom:register_online_match")
        self.online_index.on_match_added(
            node_id=node_id,
            ttp_id=match_id,
            rule_id=rule_id,
            sequence=int(sequence),
            origin_node_id=node_id,
        )

    def remove_online_match(self, node_id, match_id):
        if self.fail_remove_online_match:
            raise RuntimeError("boom:remove_online_match")
        self.removed_online_matches.append((node_id, match_id))
        removed = self.online_index.on_match_removed(node_id, match_id)
        return True if removed is False else removed

    def online_index_stats(self):
        return (
            len(self.online_index._node_mapper),  # noqa: SLF001
            int(getattr(self.online_index, "propagation_depth_cutoff_total", 0)),
            int(getattr(self.online_index, "propagation_fanout_cutoff_total", 0)),
            int(getattr(self.online_index, "max_propagation_depth", 0)),
        )

    def graph_stats(self):
        return (0, 0)

    def graph_current_version_node(self, entity_id):
        return None

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
        return {"entities_removed": 0, "version_nodes_removed": 0, "edges_removed": 0}

    def online_contains_match(self, node_id, match_id):
        return self.online_index.mapper_contains_match(node_id, match_id)

    def online_node_match_count(self, node_id):
        return len(self.online_index.mapper_match_ids(node_id))

    def online_mapper_contains_rule(self, node_id, rule_id):
        return self.online_index.mapper_contains_rule(node_id, rule_id)

    def online_mapper_earliest_seq(self, node_id, rule_id):
        return self.online_index.mapper_earliest_seq(node_id, rule_id)

    def online_mapper_min_hops(self, node_id, match_id, origin_node_id=None):
        return self.online_index.mapper_min_hops(node_id, match_id, origin_node_id=origin_node_id)

    def online_mapper_match_ids(self, node_id):
        return sorted(self.online_index.mapper_match_ids(node_id))


class _FakeRustModule:
    NativeBatchEngine = _FakeNativeBatchEngine


def test_streaming_engine_file_source_builds_hsg_and_matches_batch_summary(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_stream = tmp_path / "out_stream"
    out_batch = tmp_path / "out_batch"

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_weights=[1.0] * 7,
        paper_mode="strict",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    stream_result = engine.write_snapshot(out_stream)

    batch_result = run_pipeline(
        events_path=str(events_path),
        rules_path=str(rules_path),
        output_path=str(out_batch),
        scoring_mode="paper",
        paper_mode="strict",
    )

    hsg = json.loads((out_stream / "hsg.json").read_text(encoding="utf-8"))
    assert any(e.get("relation") == "graph_path" for e in hsg.get("edges", []))
    assert stream_result["summary"]["events"] == batch_result["summary"]["events"]
    assert stream_result["summary"]["matches"] == batch_result["summary"]["matches"]
    assert stream_result["summary"]["hsg_edges"] == batch_result["summary"]["hsg_edges"]


def test_file_jsonl_source_reads_gzip_stream_without_extracting(tmp_path):
    gz_path = tmp_path / "events.jsonl.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        fh.write('{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}\n')
        fh.write('{"event_id":"e2","event_type":"file_to_ip","subject":"file:x","object":"ip:1.2.3.4"}\n')

    events = list(FileJsonlSource(gz_path, follow=False))

    assert [event.event_id for event in events] == ["e1", "e2"]


def test_directory_watcher_source_reads_new_lines_from_watched_directory(tmp_path):
    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    log_path = watch_dir / "events.jsonl"
    log_path.write_text("", encoding="utf-8")

    source = DirectoryWatcherSource(watch_dir, poll_interval_sec=0.01)
    iterator = iter(source)

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write('{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}\n')
        fh.flush()

    event = next(iterator)
    assert event.event_id == "e1"


def test_raw_string_prefilter_skips_benign_line_without_json_parse(tmp_path):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        '\n'.join(
            [
                '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:/var/log/auth.log","Image":"/usr/sbin/sshd"}',
                '{"event_id":"e2","event_type":"proc_to_file","subject":"proc:b","object":"file:/etc/shadow","Image":"/usr/bin/cat"}',
            ]
        ),
        encoding="utf-8",
    )
    prefilter = RawStringPreFilter(
        benign_markers={"/var/log/auth.log", "sshd"},
        threat_keywords={"/etc/shadow", "shadow"},
    )

    records = list(FileRawLineSource(events_path, prefilter=prefilter))

    assert len(records) == 1
    assert '"event_id":"e2"' in records[0][1]


def test_raw_string_prefilter_does_not_skip_darpa_relational_line():
    prefilter = RawStringPreFilter(
        benign_markers={"firefox", "/usr/local/firefox-54.0.1"},
        threat_keywords={"shadow"},
    )
    darpa_line = '{"datum":{"com.bbn.tc.schema.avro.cdm18.Subject":{"uuid":"abc","cmdLine":{"string":"firefox"}}},"CDMVersion":"18"}'

    assert prefilter.should_skip(darpa_line) is False


def test_parser_workers_preserve_order_for_raw_records():
    records = [
        (1, '{"event_id":"e1","event_type":"proc_to_file","subject":"proc:a","object":"file:x"}'),
        (2, '{"event_id":"e2","event_type":"file_to_ip","subject":"file:x","object":"ip:1.2.3.4"}'),
    ]
    telemetry = {}

    events = list(iter_parsed_events_parallel(records, worker_count=2, queue_size=4, max_reorder_buffer=2, telemetry=telemetry))

    assert [event.event_id for event in events] == ["e1", "e2"]
    assert telemetry["max_observed_out_of_order_distance"] >= 0
    assert telemetry["reorder_buffer_saturation_count"] >= 0
    assert telemetry["stall_duration_seconds"] >= 0.0


def test_run_stream_writes_resolved_effective_config(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_cli"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--paper-weights",
            "1.1,1.2,1.3,1.4,1.5,1.6,1.7",
            "--snapshot-every",
            "1000",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    resolved = summary["resolved_effective_config"]
    assert resolved == {
        "path_thres": 3.0,
        "path_factor_op": "le",
        "scoring": "paper",
        "paper_mode": "strict",
        "paper_weights": [1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7],
    }
    ps = summary["paper_scoring"]
    assert "threat_tuple" in ps
    assert "stage_severity" in ps
    assert "paper_weights" in ps
    assert "score_paper" in ps


def test_graph_gc_backs_off_after_noop_cycle():
    ruleset = RuleSet(rules=[])
    engine = StreamingEngine(
        ruleset=ruleset,
        graph_retention_days=3,
        graph_gc_every_events=5,
    )

    engine.stats.events = 5
    engine._run_graph_deep_gc("2025-01-10T00:00:00Z")

    assert engine._current_graph_gc_every_events == 10
    assert engine._graph_gc_cap_trigger_total == 0


def test_graph_gc_ignores_interval_when_graph_cap_pressure_hits(monkeypatch):
    monkeypatch.setenv("HOLMES_GRAPH_MAX_VERSION_NODES", "2")

    ruleset = RuleSet(rules=[])
    engine = StreamingEngine(
        ruleset=ruleset,
        graph_retention_days=30,
        graph_gc_every_events=1000,
    )

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-10T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )

    assert len(engine.graph.version_nodes) >= 2
    assert engine._graph_gc_cap_trigger_total == 1
    assert engine._last_graph_gc_events == 1
    assert engine._current_graph_gc_every_events == engine.graph_gc_every_events


def test_graph_gc_skips_deep_prune_before_retention_window(monkeypatch):
    ruleset = RuleSet(rules=[])
    engine = StreamingEngine(
        ruleset=ruleset,
        graph_retention_days=30,
        graph_gc_every_events=1,
    )

    def _unexpected_prune(*args, **kwargs):
        raise AssertionError("deep prune should be skipped before retention window elapses")

    monkeypatch.setattr(engine.taint_tracker, "evict_stale", _unexpected_prune)
    monkeypatch.setattr(engine.graph, "prune_stale_orphaned", _unexpected_prune)

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-10T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )

    assert engine._last_graph_gc_events == 1
    assert engine._current_graph_gc_every_events == 2


def test_protected_graph_entities_stays_narrow_but_current_match_nodes_are_protected():
    engine = StreamingEngine(ruleset=RuleSet(rules=[]))
    info1 = engine.graph.add_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )
    info2 = engine.graph.add_event(
        Event(
            event_id="e2",
            ts="2025-01-02T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:p1",
            object="file:f1",
            raw={},
        )
    )
    engine.matches.append(
        TTPMatch(
            match_id="m1",
            rule_id="R1",
            entities=["proc:p1", "file:f1"],
            bindings={"$current_process": "proc:p1", "$target_file": "file:f1"},
            binding_node_ids={"$current_process": info1["subject_node_id"], "$target_file": info2["object_node_id"]},
            subject_node_id=info1["subject_node_id"],
            object_node_id=info2["object_node_id"],
        )
    )

    protected_entities = engine._protected_graph_entities()
    protected_versions = engine._protected_graph_version_nodes()

    assert "proc:p1" not in protected_entities
    assert "file:f1" not in protected_entities
    assert info2["object_node_id"] in protected_versions
    assert engine.graph.current_version_node("file:f1") in protected_versions


def test_local_eviction_disables_only_native_online_shadow_not_graph_shadow():
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = True

    assert engine.native_backend.available is True
    assert engine.graph._native_graph_shadow_enabled is True  # noqa: SLF001
    assert engine._native_online_shadow_enabled() is True  # noqa: SLF001

    removed = engine._remove_active_matches_from_online_state({"missing-match"})  # noqa: SLF001
    assert removed == 0

    engine._disable_native_backend_shadowing()  # noqa: SLF001

    assert engine.native_backend.available is True
    assert engine.graph._native_graph_shadow_enabled is True  # noqa: SLF001
    assert engine.native_online_read_primary_enabled is False
    assert engine.native_shadow_check_enabled is False
    assert engine._native_online_shadow_enabled() is False  # noqa: SLF001


def test_metrics_keep_native_graph_shadow_enabled_after_online_shadow_disable():
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = True
    engine._disable_native_backend_shadowing()  # noqa: SLF001

    metrics = engine._build_performance_metrics()  # noqa: SLF001

    assert metrics["native_backend_enabled"] == 1
    assert metrics["native_graph_shadow_enabled"] == 1
    assert metrics["native_online_shadow_enabled"] == 0


def test_native_authoritative_online_flush_skips_python_flush(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = False
    engine._pending_online_graph_edges = [("proc:p1#v1", "file:f1#v1", "data_flow")]  # noqa: SLF001

    flush_calls = 0

    def tracked_flush() -> None:
        nonlocal flush_calls
        flush_calls += 1

    monkeypatch.setattr(engine.online_index, "flush_pending_edges", tracked_flush)

    engine._flush_pending_online_graph_edges()  # noqa: SLF001

    assert flush_calls == 0
    assert backend._engine.added_online_edges == [("proc:p1#v1", "file:f1#v1", "data_flow")]  # noqa: SLF001
    assert backend._engine.flushed == 1  # noqa: SLF001
    assert engine._online_graph_edge_flush_native_authoritative_count == 1  # noqa: SLF001


def test_native_authoritative_online_flush_keeps_python_flush_when_shadow_check_enabled(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = True
    engine._pending_online_graph_edges = [("proc:p1#v1", "file:f1#v1", "data_flow")]  # noqa: SLF001

    flush_calls = 0
    original_flush = engine.online_index.flush_pending_edges

    def tracked_flush() -> None:
        nonlocal flush_calls
        flush_calls += 1
        original_flush()

    monkeypatch.setattr(engine.online_index, "flush_pending_edges", tracked_flush)

    engine._flush_pending_online_graph_edges()  # noqa: SLF001

    assert flush_calls == 1
    assert backend._engine.flushed == 1  # noqa: SLF001
    assert engine._online_graph_edge_flush_native_authoritative_count == 0  # noqa: SLF001


def test_native_authoritative_match_add_skips_python_online_index(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = False

    match = TTPMatch(
        match_id="m1",
        rule_id="R1",
        entities=["proc:p1#v1", "file:f1#v1"],
        bindings={},
        binding_node_ids={},
        subject_node_id="proc:p1#v1",
        object_node_id="file:f1#v1",
        sequence=1,
    )
    add_calls = 0

    def tracked_add(*args, **kwargs):
        nonlocal add_calls
        add_calls += 1
        return (True, 0.0, 0.0, 0.0)

    monkeypatch.setattr(engine.online_index, "on_match_added", tracked_add)

    added = engine._add_active_match_to_online_state(match, add_to_online_index=True)  # noqa: SLF001

    assert added is True
    assert add_calls == 0
    assert engine._online_match_add_native_authoritative_count == 2  # noqa: SLF001
    assert engine._online_mapper_contains_match("proc:p1#v1", "m1") is True  # noqa: SLF001
    assert engine._online_mapper_contains_match("file:f1#v1", "m1") is True  # noqa: SLF001


def test_native_authoritative_match_remove_skips_python_online_index(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = False

    match = TTPMatch(
        match_id="m1",
        rule_id="R1",
        entities=["proc:p1#v1", "file:f1#v1"],
        bindings={},
        binding_node_ids={},
        subject_node_id="proc:p1#v1",
        object_node_id="file:f1#v1",
        sequence=1,
    )
    engine._add_active_match_to_online_state(match, add_to_online_index=True)  # noqa: SLF001
    remove_calls = 0

    def tracked_remove(*args, **kwargs):
        nonlocal remove_calls
        remove_calls += 1
        return True

    monkeypatch.setattr(engine.online_index, "on_match_removed", tracked_remove)

    removed = engine._remove_active_matches_from_online_state({"m1"})  # noqa: SLF001

    assert removed == 1
    assert remove_calls == 0
    assert engine._online_match_remove_native_authoritative_count == 2  # noqa: SLF001
    assert engine._online_mapper_contains_match("proc:p1#v1", "m1") is False  # noqa: SLF001
    assert engine._online_mapper_contains_match("file:f1#v1", "m1") is False  # noqa: SLF001


def test_native_authoritative_match_add_failure_falls_back_and_rebuilds(monkeypatch):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    backend = RustNativeBackend(_FakeRustModule())
    backend._engine.fail_register_online_match = True  # noqa: SLF001
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = False

    match = TTPMatch(
        match_id="m1",
        rule_id="R1",
        entities=["proc:p1#v1", "file:f1#v1"],
        bindings={},
        binding_node_ids={},
        subject_node_id="proc:p1#v1",
        object_node_id="file:f1#v1",
        sequence=1,
    )

    added = engine._add_active_match_to_online_state(match, add_to_online_index=True)  # noqa: SLF001

    assert added is True
    assert engine.native_online_read_primary_enabled is False
    assert engine.native_shadow_check_enabled is False
    assert engine.native_online_flush_authoritative_enabled is False
    assert engine._online_mapper_contains_match("proc:p1#v1", "m1") is True  # noqa: SLF001
    assert engine._online_mapper_contains_match("file:f1#v1", "m1") is True  # noqa: SLF001
    assert engine._native_online_fallback_activation_total == 1  # noqa: SLF001
    assert engine._native_online_fallback_mutation_failure_total == 1  # noqa: SLF001
    assert engine._native_online_fallback_first_reason == "mutation_failure:register_online_match"  # noqa: SLF001


def test_native_read_mismatch_disables_primary(monkeypatch):
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = True
    engine.online_index.on_match_added("proc:p1#v1", "m1", rule_id="R1", sequence=1, origin_node_id="proc:p1#v1")

    value = engine._online_mapper_contains_rule("proc:p1#v1", "R1")  # noqa: SLF001

    assert value is True
    assert engine.native_online_read_primary_enabled is False
    assert engine.native_shadow_check_enabled is False
    assert engine.native_online_flush_authoritative_enabled is False
    assert engine._native_online_read_fallback_total == 1  # noqa: SLF001
    assert engine._native_online_fallback_activation_total == 1  # noqa: SLF001
    assert engine._native_online_fallback_read_mismatch_total == 1  # noqa: SLF001
    assert engine._native_online_fallback_first_reason == "read_mismatch:contains_rule"  # noqa: SLF001


def test_native_authoritative_online_flush_smoke_has_no_read_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("HOLMES_NATIVE_ONLINE_FLUSH_AUTHORITATIVE", "1")
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=load_rules_yaml(rules_path), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = False

    for event in FileJsonlSource(events_path, follow=False):
        engine.process_event(event)

    result = engine.write_snapshot(tmp_path / "out_native_authoritative_smoke")
    perf = result["summary"]["performance_metrics"]

    assert perf["native_online_read_primary_enabled"] == 1
    assert perf["native_online_flush_authoritative_enabled"] == 1
    assert perf["online_graph_edge_flush_native_authoritative_count"] > 0
    assert perf["online_match_add_native_authoritative_count"] > 0
    assert perf["native_online_read_fallback_total"] == 0


def test_local_eviction_keeps_native_online_shadow_when_native_delete_succeeds():
    backend = RustNativeBackend(_FakeRustModule())
    engine = StreamingEngine(ruleset=RuleSet(rules=[]), native_backend=backend)
    engine.native_online_read_primary_enabled = True
    engine.native_shadow_check_enabled = True

    match = TTPMatch(
        match_id="m1",
        rule_id="R1",
        entities=["proc:p1", "file:f1"],
        bindings={},
        binding_node_ids={},
        subject_node_id="proc:p1#v1",
        object_node_id="file:f1#v1",
        sequence=1,
    )
    engine.matches = [match]
    engine.match_by_id[match.match_id] = match
    engine.match_to_entities[match.match_id] = {"proc:p1#v1", "file:f1#v1"}
    engine.node_to_matches["proc:p1#v1"] = {"m1"}
    engine.node_to_matches["file:f1#v1"] = {"m1"}
    engine.entity_to_hsg_node["proc:p1#v1"] = {"m1"}
    engine.entity_to_hsg_node["file:f1#v1"] = {"m1"}
    engine.online_index.on_match_added("proc:p1#v1", "m1", rule_id="R1", sequence=1, origin_node_id="proc:p1#v1")
    engine.online_index.on_match_added("file:f1#v1", "m1", rule_id="R1", sequence=1, origin_node_id="file:f1#v1")

    removed = engine._remove_active_matches_from_online_state({"m1"})  # noqa: SLF001

    assert removed == 1
    assert engine.native_online_read_primary_enabled is True
    assert engine.native_shadow_check_enabled is True
    assert engine._native_online_shadow_enabled() is True  # noqa: SLF001
    assert backend._engine.removed_online_matches == [("proc:p1#v1", "m1"), ("file:f1#v1", "m1")]  # noqa: SLF001


def test_local_hsg_edge_eviction_updates_seen_edges_and_graph_path_count():
    engine = StreamingEngine(ruleset=RuleSet(rules=[]))
    edge1 = HSGEdge(src="m1", dst="m2", relation="graph_path", weight=0.5)
    edge2 = HSGEdge(src="m2", dst="m3", relation="prereq")
    engine.hsg_edges = [edge1, edge2]
    engine.seen_edges = {
        (edge1.src, edge1.dst, edge1.relation),
        (edge2.src, edge2.dst, edge2.relation),
    }
    engine._graph_path_edges_count = 1  # noqa: SLF001

    removed = engine._remove_hsg_edges_from_online_state([edge1])  # noqa: SLF001

    assert removed == 1
    assert engine.hsg_edges == [edge2]
    assert engine.seen_edges == {(edge2.src, edge2.dst, edge2.relation)}
    assert engine._graph_path_edges_count == 0  # noqa: SLF001


def test_run_stream_loads_pipeline_config(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_cfg"
    cfg_path = tmp_path / "pipeline.yaml"
    events_text = str(events_path).replace("\\", "/")
    cfg_path.write_text(
        "\n".join(
            [
                "source:",
                f"  events: \"{events_text}\"",
                "performance:",
                "  snapshot_every: 1000",
                "  parser_workers: 0",
                "engine:",
                "  apt_alert_threshold: 12.0",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--config",
            str(cfg_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["alerts"]["threshold"] == 12.0
    assert "stall_duration_seconds" in summary["performance_metrics"]
    metrics_lines = (out_dir / "metrics.jsonl").read_text(encoding="utf-8").splitlines()
    assert metrics_lines


def test_run_experiments_pipeline_loads_shared_config(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    benign_events = repo_root / "experiments" / "sample.jsonl"
    attack_events = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    gt_path = tmp_path / "gt.json"
    gt_path.write_text('{"scenarios":[]}', encoding="utf-8")
    cfg_path = tmp_path / "pipeline.yaml"
    out_dir = tmp_path / "pipeline_out"
    benign_text = str(benign_events).replace("\\", "/")
    attack_text = str(attack_events).replace("\\", "/")
    rules_text = str(rules_path).replace("\\", "/")
    gt_text = str(gt_path).replace("\\", "/")
    out_text = str(out_dir).replace("\\", "/")
    cfg_path.write_text(
        "\n".join(
            [
                "experiments:",
                f"  benign_events: \"{benign_text}\"",
                f"  attack_events: \"{attack_text}\"",
                f"  rules: \"{rules_text}\"",
                f"  ground_truth: \"{gt_text}\"",
                f"  out: \"{out_text}\"",
                "  max_path_factors: \"2\"",
                "  alert_thresholds: \"1.0\"",
                "  top_k: 1",
            ]
        ),
        encoding="utf-8",
    )

    rc = __import__("subprocess").run(
        [
            "python",
            str(repo_root / "scripts" / "run_experiments_pipeline.py"),
            "--config",
            str(cfg_path),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(repo_root)},
        timeout=120,
    )

    assert rc.returncode == 0, rc.stderr
    assert (out_dir / "output" / "pipeline_report.json").exists()


def test_global_refine_off_default_keeps_streaming_baseline(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_refine_off"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--snapshot-every",
            "2",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    gf = summary["streaming"]["global_refine"]
    assert gf["mode"] == "off"
    assert gf["ran_at_snapshots_count"] == 0
    assert gf["ran_at_events_count"] == 0
    assert "resolved_effective_config" in summary
    assert "paper_scoring" in summary


def test_global_refine_snapshot_runs_and_preserves_pf_zero_invariant(monkeypatch, tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    out_dir = tmp_path / "out_stream_refine_snapshot"

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_stream.py",
            "--events",
            str(events_path),
            "--rules",
            str(rules_path),
            "--out",
            str(out_dir),
            "--scoring",
            "paper",
            "--paper-mode",
            "strict",
            "--snapshot-every",
            "2",
            "--global-refine",
            "snapshot",
        ],
    )
    rc = run_stream.main()
    assert rc == 0

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    gf = summary["streaming"]["global_refine"]
    assert gf["mode"] == "snapshot"
    assert gf["ran_at_snapshots_count"] >= 1

    for name in ("result.json", "summary.json", "hsg.json", "matches.json"):
        text = (out_dir / name).read_text(encoding="utf-8")
        assert '"path_factor": 0' not in text
        assert '"path_factor": 0.0' not in text


def test_stream_summary_exposes_pending_eviction_telemetry(tmp_path):
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[], event_predicate={"event_type": "proc_to_file"}),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"], event_predicate={"event_type": "file_to_ip"}),
        ]
    )
    engine = StreamingEngine(ruleset=ruleset)
    engine.hsg_builder.pending_ttl_seconds = 24 * 60 * 60

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="file_to_ip",
            subject="file:stale",
            object="ip:1.2.3.4",
            raw={},
        )
    )
    engine.process_event(
        Event(
            event_id="e2",
            ts="2025-01-03T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:new",
            object="file:new",
            raw={},
        )
    )

    result = engine.write_snapshot(tmp_path / "out_stream_eviction")
    telemetry = result["summary"]["pending_eviction_telemetry"]

    assert telemetry["pending_evicted_count"] == 1
    assert telemetry["pending_evicted_by_rule_id"] == {"R_B": 1}
    assert telemetry["pending_ttl_seconds"] == 24 * 60 * 60


def test_stream_emits_alerts_jsonl_when_threshold_is_crossed(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"

    ruleset = load_rules_yaml(rules_path)
    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_mode="strict",
        apt_alert_threshold=2.0,
        alerts_path=tmp_path / "alerts.jsonl",
    )
    for ev in FileJsonlSource(events_path, follow=False):
        engine.process_event(ev)
    result = engine.write_snapshot(tmp_path / "out_stream_alerts")

    summary = result["summary"]["alerts"]
    alerts_path = tmp_path / "alerts.jsonl"
    lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    assert summary["count"] >= 1
    assert summary["threshold"] == 2.0
    assert summary["path"] == str(alerts_path)
    assert lines
    assert "severity_score" in lines[0]
    assert "kill_chain_stages" in lines[0]
    assert "core_entities" in lines[0]
    assert "scenario_id" in lines[0]
    assert "achieved_stages" in lines[0]
    assert "tainted_entities" in lines[0]
    assert "root_entities" in lines[0]
    assert "graph_artifact_path" in lines[0]
    assert Path(lines[0]["graph_artifact_path"]).exists()

    artifact = json.loads(Path(lines[0]["graph_artifact_path"]).read_text(encoding="utf-8"))
    assert artifact["scenario_id"] == lines[0]["scenario_id"]
    assert "hsg" in artifact
    assert "provenance" in artifact


def test_alert_suppression_emits_update_only_on_new_stage_and_not_on_repeat_snapshot(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    events_path = repo_root / "experiments" / "sample.jsonl"
    rules_path = repo_root / "rules" / "test_rules.yaml"
    ruleset = load_rules_yaml(rules_path)
    alerts_path = tmp_path / "alerts_updates.jsonl"

    engine = StreamingEngine(
        ruleset=ruleset,
        scoring_mode="paper",
        paper_mode="strict",
        apt_alert_threshold=1.0,
        alerts_path=alerts_path,
    )
    events = list(FileJsonlSource(events_path, follow=False))

    engine.process_event(events[0])
    engine.write_snapshot(tmp_path / "out_alert_step1")
    first_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(first_lines) == 1

    engine.process_event(events[1])
    engine.write_snapshot(tmp_path / "out_alert_step2")
    second_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(second_lines) == 2
    assert second_lines[0]["scenario_id"] == second_lines[1]["scenario_id"]
    assert set(second_lines[1]["achieved_stages"]) > set(second_lines[0]["achieved_stages"])

    engine.write_snapshot(tmp_path / "out_alert_step3")
    third_lines = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(third_lines) == 2


def test_stream_summary_exposes_performance_metrics_and_dormant_gc(tmp_path):
    ruleset = RuleSet(rules=[Rule(rule_id="R_A", name="a", prerequisites=[], event_predicate={"event_type": "proc_to_file"})])
    engine = StreamingEngine(
        ruleset=ruleset,
        scenario_dormancy_days=1,
        alerts_path=tmp_path / "alerts.jsonl",
    )

    engine.process_event(
        Event(
            event_id="e1",
            ts="2025-01-01T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:a",
            object="file:x",
            raw={},
        )
    )
    engine.process_event(
        Event(
            event_id="e2",
            ts="2025-01-03T00:00:00Z",
            event_type="proc_to_file",
            subject="proc:b",
            object="file:y",
            raw={},
        )
    )

    result = engine.write_snapshot(tmp_path / "out_stream_metrics")
    perf = result["summary"]["performance_metrics"]
    gc = result["summary"]["dormant_scenario_telemetry"]
    graph_gc = result["summary"]["graph_gc_telemetry"]

    assert perf["events_per_second"] > 0.0
    assert perf["rolling_events_per_second_60s"] > 0.0
    assert perf["rolling_events_per_second_300s"] > 0.0
    assert perf["matcher_time_seconds"] >= 0.0
    assert perf["hsg_update_time_seconds"] >= 0.0
    assert perf["hsg_update_call_count"] == 2
    assert perf["hsg_update_changed_match_count"] >= 2
    assert perf["hsg_update_changed_edge_count"] >= 0
    assert perf["graph_add_semantic_time_seconds"] >= 0.0
    assert perf["graph_add_entity_identity_time_seconds"] >= 0.0
    assert perf["graph_add_versioning_time_seconds"] >= 0.0
    assert perf["graph_add_edge_bookkeeping_time_seconds"] >= 0.0
    assert perf["graph_add_accounted_time_seconds"] >= 0.0
    assert perf["graph_add_residual_time_seconds"] >= 0.0
    assert perf["graph_add_accounted_share"] >= 0.0
    assert perf["graph_add_residual_share"] >= 0.0
    assert perf["graph_gc_time_seconds"] >= 0.0
    assert perf["process_current_rss_bytes"] >= 0
    assert perf["process_current_rss_mb"] >= 0.0
    assert perf["process_peak_rss_bytes"] >= perf["process_current_rss_bytes"]
    assert perf["process_peak_rss_mb"] >= 0.0
    assert perf["graph_entity_count"] >= 2
    assert "graph_version_node_count" in perf
    assert "closed_scenarios_count" in gc
    assert "closed_matches_count" in gc
    assert gc["scenario_dormancy_seconds"] == 24 * 60 * 60
    assert graph_gc["retention_days"] == 60
