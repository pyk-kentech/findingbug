from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher
from engine.io.events import Event
from engine.rules.schema import RuleSet, load_rules_json, load_rules_yaml


def test_matcher_returns_zero_when_no_rules():
    events = [Event(event_id="e1", ts=None, event_type="x", subject="a", object="b", raw={})]
    graph = ProvenanceGraph()
    graph.add_events(events)

    matches = Matcher().match(graph=graph, ruleset=RuleSet(), events=events)

    assert matches == []


def test_matcher_generates_one_match_for_exec_event_predicate_rule():
    events = [
        Event(
            event_id="e1",
            ts=None,
            event_type="file_to_proc",
            subject="file:/bin/x",
            object="proc:new",
            raw={"op": "exec"},
        ),
        Event(
            event_id="e2",
            ts=None,
            event_type="read",
            subject="proc:new",
            object="file:/tmp/y",
            raw={"op": "read"},
        ),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = Path(__file__).resolve().parents[1] / "experiments" / "rules_test.yaml"
    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "test-op-exec"
    assert matches[0].event_ids == ["e1"]


def test_matcher_generates_one_match_for_event_type_predicate_rule(tmp_path):
    events = [
        Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:a", object="file:x", raw={}),
        Event(event_id="e2", ts=None, event_type="read", subject="proc:a", object="file:y", raw={}),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = tmp_path / "rules_event_type.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: test-event-type",
                "    name: test only",
                "    event_predicate:",
                "      event_type: proc_to_file",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "test-event-type"
    assert matches[0].event_ids == ["e1"]


def test_matcher_test_rules_yaml_generates_four_matches_on_sample_events():
    events = [
        Event(event_id="e1", ts=None, event_type="proc_to_file", subject="proc:alpha", object="file:/tmp/a.txt", raw={}),
        Event(event_id="e2", ts=None, event_type="file_to_ip", subject="file:/tmp/a.txt", object="ip:203.0.113.10", raw={}),
        Event(event_id="e3", ts=None, event_type="proc_to_proc", subject="proc:alpha", object="proc:beta", raw={}),
        Event(event_id="e4", ts=None, event_type="proc_to_registry", subject="proc:beta", object="reg:HKCU\\Software\\Demo", raw={}),
        Event(event_id="e5", ts=None, event_type="proc_to_file", subject="proc:gamma", object="file:/var/log/demo.log", raw={}),
        Event(event_id="e6", ts=None, event_type="file_to_proc", subject="file:/var/log/demo.log", object="proc:delta", raw={}),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = Path(__file__).resolve().parents[1] / "rules" / "test_rules.yaml"
    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 4
    assert [m.event_ids[0] for m in matches] == ["e1", "e5", "e2", "e3"]


def test_matcher_generates_match_for_sigma_json_rule(tmp_path):
    events = [
        Event(
            event_id="e1",
            ts=None,
            event_type="process_creation",
            subject="proc:alpha",
            object=None,
            raw={
                "source_type": "windows/process_creation",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "CommandLine": "reg query HKLM\\Software /v Version",
            },
        ),
        Event(
            event_id="e2",
            ts=None,
            event_type="process_creation",
            subject="proc:beta",
            object=None,
            raw={
                "source_type": "windows/process_creation",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd /c echo hi",
            },
        ),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        "\n".join(
            [
                "[",
                "  {",
                '    "rule_id": "sigma-reg-query",',
                '    "name": "Sigma reg query",',
                '    "source_types": ["windows/process_creation", "process_creation"],',
                '    "apt_stage": "Internal Recon",',
                '    "severity_score": 3.0,',
                '    "match_logic": {',
                '      "engine": "sigma",',
                '      "condition": {',
                '        "compiled": {',
                '          "type": "logical",',
                '          "operator": "AND",',
                '          "operands": [',
                '            {"type": "selector_group", "quantifier": "COUNT", "selectors": ["selection_cmd_reg", "selection_cmd_powershell"], "count": 1},',
                '            {"type": "selector_ref", "selector": "selection_keys"}',
                "          ]",
                "        }",
                "      },",
                '      "selectors": {',
                '        "selection_cmd_reg": {',
                '          "type": "object",',
                '          "items": [',
                '            {"type": "field_match", "field": "Image", "modifiers": ["endswith"], "value": {"type": "literal", "value": "\\\\reg.exe"}},',
                '            {"type": "field_match", "field": "CommandLine", "modifiers": ["contains"], "value": {"type": "literal", "value": "query"}},',
                '            {"type": "field_match", "field": "CommandLine", "modifiers": ["contains", "windash"], "value": {"type": "literal", "value": "-v"}}',
                "          ]",
                "        },",
                '        "selection_cmd_powershell": {',
                '          "type": "object",',
                '          "items": [',
                '            {"type": "field_match", "field": "Image", "modifiers": ["endswith"], "value": {"type": "literal", "value": "\\\\powershell.exe"}}',
                "          ]",
                "        },",
                '        "selection_keys": {',
                '          "type": "object",',
                '          "items": [',
                '            {"type": "field_match", "field": "CommandLine", "modifiers": ["contains"], "value": {"type": "literal", "value": "HKLM\\\\Software"}}',
                "          ]",
                "        }",
                "      }",
                "    }",
                "  }",
                "]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_json(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "sigma-reg-query"
    assert matches[0].event_ids == ["e1"]


def test_matcher_treats_empty_dict_value_as_wildcard(tmp_path):
    events = [
        Event(
            event_id="e1",
            ts=None,
            event_type="process_creation",
            subject="proc:alpha",
            object=None,
            raw={
                "source_type": "test",
                "Image": "C:\\Windows\\System32\\cmd.exe",
            },
        ),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = tmp_path / "rules_empty_dict.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: sigma-empty-dict",
                "    name: Sigma empty dict wildcard",
                "    source_types: [test]",
                "    prerequisites: []",
                "    match_logic:",
                "      engine: sigma",
                "      condition:",
                "        compiled:",
                "          type: selector_ref",
                "          selector: selection",
                "      selectors:",
                "        selection:",
                "          type: object",
                "          items:",
                "            - type: field_match",
                "              field: Image",
                "              modifiers: [endswith]",
                "              value: {}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "sigma-empty-dict"


def test_matcher_supports_array_traversal_field_brace_subfield(tmp_path):
    events = [
        Event(
            event_id="e1",
            ts=None,
            event_type="azure_activity",
            subject="proc:alpha",
            object=None,
            raw={
                "source_type": "azure/activity_logs",
                "Operation": "Add member to role.",
                "Workload": "AzureActiveDirectory",
                "ModifiedProperties": [
                    {"NewValue": "User Administrator"},
                    {"NewValue": "Global Administrator"},
                ],
            },
        ),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = tmp_path / "rules_brace_field.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: sigma-brace-field",
                "    name: Sigma array traversal",
                "    source_types: [azure/activity_logs]",
                "    prerequisites: []",
                "    match_logic:",
                "      engine: sigma",
                "      condition:",
                "        compiled:",
                "          type: selector_ref",
                "          selector: selection",
                "      selectors:",
                "        selection:",
                "          type: object",
                "          items:",
                "            - type: field_match",
                "              field: Operation",
                "              modifiers: []",
                "              value:",
                "                type: literal",
                "                value: Add member to role.",
                "            - type: field_match",
                "              field: ModifiedProperties{}.NewValue",
                "              modifiers: [endswith]",
                "              value:",
                "                - type: literal",
                "                  value: Administrator",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "sigma-brace-field"


def test_matcher_supports_list_leaf_field_lookup(tmp_path):
    events = [
        Event(
            event_id="e1",
            ts=None,
            event_type="event_sendmsg",
            subject="proc:alpha",
            object="file:/tmp/demo",
            raw={
                "object": "file:/tmp/demo",
                "cdr": {
                    "semantic_relations": [
                        {"relation": "write", "src": "proc:alpha", "dst": "file:/tmp/demo"},
                    ]
                },
            },
        ),
    ]
    graph = ProvenanceGraph()
    graph.add_events(events)

    rules_path = tmp_path / "rules_list_leaf.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: sigma-list-leaf",
                "    name: Sigma list leaf selector",
                "    prerequisites: []",
                "    match_logic:",
                "      engine: sigma",
                "      condition:",
                "        compiled:",
                "          type: logical",
                "          operator: AND",
                "          operands:",
                "            - type: selector_ref",
                "              selector: rel_write",
                "            - type: selector_ref",
                "              selector: target_tmp",
                "      selectors:",
                "        rel_write:",
                "          type: object",
                "          items:",
                "            - type: field_match",
                "              field: cdr.semantic_relations",
                "              modifiers: [contains]",
                "              value:",
                "                type: literal",
                "                value: write",
                "        target_tmp:",
                "          type: object",
                "          items:",
                "            - type: field_match",
                "              field: object",
                "              modifiers: [contains]",
                "              value:",
                "                type: literal",
                "                value: file:/tmp/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(rules_path)
    matches = Matcher().match(graph=graph, ruleset=ruleset, events=events)

    assert len(matches) == 1
    assert matches[0].rule_id == "sigma-list-leaf"
