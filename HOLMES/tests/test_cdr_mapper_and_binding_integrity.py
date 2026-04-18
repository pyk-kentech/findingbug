from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher
from engine.io.cdr.auditd import AuditdAdapter
from engine.io.cdr.darpa_tc import DarpaTCAdapter
from engine.io.cdr.etw import ETWAdapter
from engine.io.events import Event, normalize_event
from engine.rules.schema import Rule, RuleSet


def test_normalize_event_populates_cdr_semantic_relations():
    event = normalize_event(
        {
            "event_id": "e1",
            "event_type": "proc_to_file",
            "subject": "proc:p1",
            "object": "file:f1",
        },
        1,
    )

    assert event.raw["cdr"]["semantic_relations"]
    assert {"relation": "write", "src": "proc:p1", "dst": "file:f1"} in event.raw["cdr"]["semantic_relations"]


def test_graph_semantic_edges_use_cdr_relations_only():
    g = ProvenanceGraph()
    event = normalize_event(
        {
            "event_id": "e1",
            "event_type": "proc_to_file",
            "subject": "proc:p1",
            "object": "file:f1",
            "semantic_relations": [{"relation": "inject", "src": "proc:p1", "dst": "file:f1"}],
        },
        1,
    )
    g.add_event(event)

    assert g.has_semantic_path("proc:p1", "file:f1", {"inject"}) is True
    assert g.has_semantic_path("proc:p1", "file:f1", {"write"}) is False


def test_matcher_drops_rule_when_explicit_binding_entity_is_missing_from_graph():
    g = ProvenanceGraph()
    event = Event(
        event_id="e1",
        ts=None,
        event_type="process_creation",
        subject="proc:p1",
        object="file:seed",
        raw={"source_type": "process_creation", "Image": "proc:p1", "ParentImage": "proc:parent-missing"},
    )
    g.add_event(event)
    ruleset = RuleSet(
        rules=[
            Rule(
                rule_id="r1",
                name="needs parent",
                source_types=["process_creation"],
                match_logic={
                    "engine": "sigma",
                    "condition": {"compiled": {"type": "selector_ref", "selector": "sel"}},
                    "selectors": {
                        "sel": {
                            "type": "object",
                            "items": [
                                {
                                    "type": "field_match",
                                    "field": "Image",
                                    "modifiers": ["contains"],
                                    "value": {"type": "literal", "value": "proc:p1"},
                                }
                            ],
                        }
                    },
                },
                entity_bindings=[
                    {"symbol": "$current_process", "entity_type": "Process", "fields": ["Image"]},
                    {"symbol": "$parent_process", "entity_type": "Process", "fields": ["ParentImage"]},
                ],
            )
        ]
    )

    matches = Matcher().match(g, ruleset, [event])

    assert matches == []


def test_etw_adapter_maps_subject_object_and_semantic_relations():
    raw = {
        "event_type": "process_creation",
        "ProcessGuid": "{child-guid}",
        "ParentProcessGuid": "{parent-guid}",
        "logsource": {"product": "windows"},
    }

    mapped = ETWAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_guid:{parent-guid}"
    assert mapped["object"] == "proc_guid:{child-guid}"
    assert {"relation": "execute", "src": mapped["subject"], "dst": mapped["object"]} in mapped["cdr"]["semantic_relations"]
    assert {"relation": "spawn", "src": mapped["subject"], "dst": mapped["object"]} in mapped["cdr"]["semantic_relations"]


def test_etw_adapter_falls_back_to_pid_and_timestamp_when_guid_missing():
    raw = {
        "event_type": "process_creation",
        "ProcessId": 300,
        "ParentProcessId": 200,
        "ts": "2025-01-01T00:00:00Z",
        "logsource": {"product": "windows"},
    }

    mapped = ETWAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_pid:200@2025-01-01T00:00:00Z"
    assert mapped["object"] == "proc_pid:300@2025-01-01T00:00:00Z"


def test_etw_adapter_does_not_use_provider_guid_as_process_identity():
    raw = {
        "event_type": "process_creation",
        "ProviderGuid": "{provider-guid}",
        "ProcessId": 300,
        "ParentProcessId": 200,
        "ts": "2025-01-01T00:00:00Z",
        "logsource": {"product": "windows"},
    }

    mapped = ETWAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_pid:200@2025-01-01T00:00:00Z"
    assert mapped["object"] == "proc_pid:300@2025-01-01T00:00:00Z"


def test_auditd_exec_protection_maps_to_memory_exec_relation_only():
    raw = {
        "syscall": "mprotect",
        "pid": 4242,
        "addr": "0x1000",
        "prot": "PROT_READ|PROT_EXEC",
        "ts": "2025-01-01T00:00:00Z",
        "logsource": {"product": "linux", "service": "auditd"},
    }

    mapped = AuditdAdapter().to_cdr(raw)

    assert mapped["object"] == "mem:4242:0x1000:0"
    assert {"relation": "protect_memory_exec", "src": "proc_pid:4242@2025-01-01T00:00:00Z", "dst": "mem:4242:0x1000:0"} in mapped["cdr"]["semantic_relations"]


def test_auditd_adapter_maps_subject_object_and_semantic_relations():
    raw = {
        "syscall": "openat",
        "pid": 4242,
        "ts": "2025-01-01T00:00:00Z",
        "path": "/tmp/test.txt",
        "logsource": {"product": "linux", "service": "auditd"},
    }

    mapped = AuditdAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_pid:4242@2025-01-01T00:00:00Z"
    assert mapped["object"] == "file:/tmp/test.txt"
    assert {"relation": "read", "src": "proc_pid:4242@2025-01-01T00:00:00Z", "dst": "file:/tmp/test.txt"} in mapped["cdr"]["semantic_relations"]


def test_darpa_tc_adapter_maps_subject_object_and_relation():
    raw = {
        "event_id": "darpa-1",
        "typeName": "EVENT_EXECVE",
        "timestamp": "2025-01-01T00:00:00Z",
        "subject": {"type": "SUBJECT", "uuid": "proc-1"},
        "predicateObject": {"type": "FILE_OBJECT", "path": "/bin/bash"},
        "hostId": "ta1-host",
    }

    mapped = DarpaTCAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_guid:proc-1"
    assert mapped["object"] == "file:/bin/bash"
    assert {"relation": "execute", "src": "proc_guid:proc-1", "dst": "file:/bin/bash"} in mapped["cdr"]["semantic_relations"]


def test_darpa_tc_adapter_routes_parser_from_namespace_probe():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.theia.Event": {
                "uuid": "evt-1",
                "typeName": "EVENT_WRITE",
                "subject": {"type": "SUBJECT", "uuid": "proc-1"},
                "predicateObject": {"type": "FILE_OBJECT", "path": "/tmp/a"},
            }
        }
    }

    mapped = DarpaTCAdapter().to_cdr(raw)

    assert mapped["ta1_parser"] == "theia"
    assert mapped["cdr"]["logsource"]["ta1"] == "theia"


def test_darpa_tc_trace_parser_calibrates_subject_uuid_and_cmdline():
    raw = {
        "datum": {
            "com.bbn.tc.schema.avro.trace.Event": {
                "uuid": "evt-2",
                "typeName": "EVENT_EXECVE",
                "subject": {"type": "SUBJECT", "uuid": "proc-trace-1"},
                "predicateObject": {"type": "FILE_OBJECT", "path": "/usr/bin/bash"},
                "properties": {"cmdLine": "/usr/bin/bash -c whoami"},
            }
        }
    }

    mapped = DarpaTCAdapter().to_cdr(raw)

    assert mapped["subject"] == "proc_guid:proc-trace-1"
    assert mapped["CommandLine"] == "/usr/bin/bash -c whoami"
    assert mapped["Image"] == "/usr/bin/bash"
