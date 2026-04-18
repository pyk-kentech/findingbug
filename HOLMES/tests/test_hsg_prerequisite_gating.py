from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.builder import IncrementalHSGBuilder, build_hsg
from engine.io.events import Event
from engine.rules.schema import Rule, RuleSet


def test_prerequisite_empty_rule_is_immediately_active_in_hsg():
    g = ProvenanceGraph()
    g.add_event(Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:x", raw={}))
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:x"],
            bindings={"subject": "proc:a", "object": "file:x"},
        )
    ]
    ruleset = RuleSet(rules=[Rule(rule_id="R_A", name="a", prerequisites=[])])

    hsg = build_hsg(matches, g, ruleset)

    assert [n.match_id for n in hsg.nodes] == ["m1"]


def test_graph_path_prerequisite_stays_pending_without_connectivity():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:a", raw={}),
            Event(event_id="e2", ts=None, event_type="file_to_ip", subject="file:b", object="ip:1.2.3.4", raw={}),
        ]
    )
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:a"],
            bindings={"subject": "proc:a", "object": "file:a"},
        ),
        TTPMatch(
            match_id="m2",
            rule_id="R_B",
            event_ids=["e2"],
            entities=["file:b", "ip:1.2.3.4"],
            bindings={"subject": "file:b", "object": "ip:1.2.3.4"},
        ),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[]),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"]),
        ]
    )

    hsg = build_hsg(matches, g, ruleset)
    node_ids = {n.match_id for n in hsg.nodes}

    assert "m1" in node_ids
    assert "m2" not in node_ids
    assert all(e.relation != "graph_path" for e in hsg.edges)


def test_graph_path_prerequisite_promotes_pending_match_when_satisfied():
    g = ProvenanceGraph()
    g.add_events(
        [
            Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:x", raw={}),
            Event(event_id="e2", ts=None, event_type="file_to_ip", subject="file:x", object="ip:z", raw={}),
        ]
    )
    matches = [
        TTPMatch(
            match_id="m1",
            rule_id="R_A",
            event_ids=["e1"],
            entities=["proc:a", "file:x"],
            bindings={"subject": "proc:a", "object": "file:x"},
        ),
        TTPMatch(
            match_id="m2",
            rule_id="R_B",
            event_ids=["e2"],
            entities=["file:x", "ip:z"],
            bindings={"subject": "file:x", "object": "ip:z"},
        ),
    ]
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[]),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"]),
        ]
    )

    hsg = build_hsg(matches, g, ruleset)
    node_ids = {n.match_id for n in hsg.nodes}

    assert "m1" in node_ids
    assert "m2" in node_ids
    assert any(e.relation == "graph_path" and e.src == "m1" and e.dst == "m2" for e in hsg.edges)


def test_pending_match_is_evicted_when_watermark_exceeds_ttl():
    g = ProvenanceGraph()
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=[]),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"]),
        ]
    )
    builder = IncrementalHSGBuilder(graph=g, ruleset=ruleset, pending_ttl_seconds=24 * 60 * 60)

    pending = TTPMatch(
        match_id="m1",
        rule_id="R_B",
        event_ids=["e1"],
        entities=["file:old", "ip:1.2.3.4"],
        bindings={"subject": "file:old", "object": "ip:1.2.3.4"},
        metadata={"event_ts": "2025-01-01T00:00:00Z"},
    )
    accepted, _ = builder.add_match(pending, watermark_ts="2025-01-01T00:00:00Z")
    assert not accepted
    assert "m1" in builder.pending_matches_by_id

    active = TTPMatch(
        match_id="m2",
        rule_id="R_A",
        event_ids=["e2"],
        entities=["proc:new", "file:new"],
        bindings={"subject": "proc:new", "object": "file:new"},
        metadata={"event_ts": "2025-01-03T00:00:00Z"},
    )
    accepted, _ = builder.add_match(active, watermark_ts="2025-01-03T00:00:00Z")
    assert accepted
    assert "m1" not in builder.pending_matches_by_id
    assert builder.pending_evicted_count == 1


def test_pending_capacity_limit_preserves_higher_stage_and_evicts_lower_stage():
    g = ProvenanceGraph()
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_LOW", name="low", prerequisites=["graph_path"], stage=1, apt_stage="Initial Compromise"),
            Rule(rule_id="R_HIGH", name="high", prerequisites=["graph_path"], stage=6, apt_stage="Exfiltration"),
        ]
    )
    builder = IncrementalHSGBuilder(graph=g, ruleset=ruleset, max_pending_matches=1, pending_ttl_seconds=None)

    first = TTPMatch(
        match_id="m1",
        rule_id="R_HIGH",
        entities=["file:old", "ip:1.1.1.1"],
        bindings={"subject": "file:old", "object": "ip:1.1.1.1"},
        metadata={"event_ts": "2025-01-01T00:00:00Z"},
    )
    second = TTPMatch(
        match_id="m2",
        rule_id="R_LOW",
        entities=["file:new", "ip:2.2.2.2"],
        bindings={"subject": "file:new", "object": "ip:2.2.2.2"},
        metadata={"event_ts": "2025-01-02T00:00:00Z"},
    )

    accepted, _ = builder.add_match(first, watermark_ts="2025-01-01T00:00:00Z")
    assert not accepted
    accepted, _ = builder.add_match(second, watermark_ts="2025-01-02T00:00:00Z")
    assert not accepted

    assert "m1" in builder.pending_matches_by_id
    assert "m2" not in builder.pending_matches_by_id
    assert builder.pending_evicted_capacity_count == 1
    assert builder.pending_evicted_by_rule_id["R_LOW"] == 1


def test_pending_capacity_limit_prefers_recently_touched_pending_with_same_stage():
    g = ProvenanceGraph()
    ruleset = RuleSet(
        rules=[
            Rule(rule_id="R_A", name="a", prerequisites=["graph_path"], stage=3, apt_stage="Execution"),
            Rule(rule_id="R_B", name="b", prerequisites=["graph_path"], stage=3, apt_stage="Execution"),
        ]
    )
    builder = IncrementalHSGBuilder(graph=g, ruleset=ruleset, max_pending_matches=2, pending_ttl_seconds=None)

    older = TTPMatch(
        match_id="m1",
        rule_id="R_A",
        entities=["file:old", "ip:1.1.1.1"],
        bindings={"subject": "file:old", "object": "ip:1.1.1.1"},
        metadata={"event_ts": "2025-01-01T00:00:00Z"},
    )
    newer = TTPMatch(
        match_id="m2",
        rule_id="R_B",
        entities=["file:new", "ip:2.2.2.2"],
        bindings={"subject": "file:new", "object": "ip:2.2.2.2"},
        metadata={"event_ts": "2025-01-02T00:00:00Z"},
    )

    accepted, _ = builder.add_match(older, watermark_ts="2025-01-01T00:00:00Z")
    assert not accepted
    accepted, _ = builder.add_match(newer, watermark_ts="2025-01-02T00:00:00Z")
    assert not accepted

    builder.pending_match_last_activity_ts["m1"] = builder._parse_watermark("2025-01-03T00:00:00Z")  # noqa: SLF001
    builder.max_pending_matches = 1
    builder._evict_capacity_pending()  # noqa: SLF001

    assert "m1" in builder.pending_matches_by_id
    assert "m2" not in builder.pending_matches_by_id
    assert builder.pending_evicted_capacity_count == 1
    assert builder.pending_evicted_by_rule_id["R_B"] == 1


def test_dormant_scenario_is_closed_when_watermark_exceeds_threshold():
    g = ProvenanceGraph()
    ruleset = RuleSet(rules=[Rule(rule_id="R_A", name="a", prerequisites=[])])
    builder = IncrementalHSGBuilder(
        graph=g,
        ruleset=ruleset,
        pending_ttl_seconds=None,
        scenario_dormancy_seconds=24 * 60 * 60,
    )

    active = TTPMatch(
        match_id="m1",
        rule_id="R_A",
        event_ids=["e1"],
        entities=["proc:a", "file:x"],
        bindings={"subject": "proc:a", "object": "file:x"},
        metadata={"event_ts": "2025-01-01T00:00:00Z"},
    )
    accepted, _ = builder.add_match(active, watermark_ts="2025-01-01T00:00:00Z")
    assert accepted
    assert "m1" in builder.matches_by_id

    closed = builder.gc_dormant_scenarios("2025-01-03T00:00:00Z")

    assert closed == ["m1"]
    assert "m1" not in builder.matches_by_id
    assert builder.closed_scenarios_count == 1
    assert builder.closed_matches_count == 1
    assert builder.closed_scenarios_by_id["scenario-m1"] == 1
