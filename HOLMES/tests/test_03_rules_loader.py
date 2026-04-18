from pathlib import Path

from engine.rules.schema import RuleValidationError, load_rules_json, load_rules_yaml


def test_empty_ruleset_is_valid(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("rules: []\n", encoding="utf-8")

    ruleset = load_rules_yaml(p)

    assert ruleset.rules == []


def test_duplicate_rule_id_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: one
  - rule_id: r1
    name: two
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError:
        pass


def test_event_predicate_op_and_event_type_together_rejected(tmp_path):
    p = tmp_path / "bad_predicate.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: bad
    event_predicate:
      op: exec
      event_type: proc_to_file
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError as exc:
        assert str(exc) == "event_predicate supports exactly one key: op or event_type"


def test_event_predicate_invalid_key_rejected(tmp_path):
    p = tmp_path / "bad_predicate_key.yaml"
    p.write_text(
        """
rules:
  - rule_id: r1
    name: bad
    event_predicate:
      foo: bar
""".strip(),
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError as exc:
        assert str(exc) == "event_predicate supports exactly one key: op or event_type"


def test_json_rules_loader_accepts_sigma_rule_bundle(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(
        """
[
  {
    "rule_id": "sigma-1",
    "name": "sigma rule",
    "source_types": ["windows/process_creation", "process_creation"],
    "apt_stage": "Internal Recon",
    "severity_score": 3.0,
    "match_logic": {
      "engine": "sigma",
      "condition": {
        "compiled": {
          "type": "selector_ref",
          "selector": "selection"
        }
      },
      "selectors": {
        "selection": {
          "type": "object",
          "items": [
            {
              "type": "field_match",
              "field": "Image",
              "modifiers": ["endswith"],
              "value": {"type": "literal", "value": "\\\\reg.exe"}
            }
          ]
        }
      }
    },
    "prerequisites": {
      "operator": "AND",
      "conditions": [
        {
          "type": "path_factor",
          "quantifier": "EXISTS",
          "source_node": "Untrusted_External_Node",
          "target_node": "$current_process",
          "threshold": "path_thres"
        }
      ]
    }
  }
]
""".strip(),
        encoding="utf-8",
    )

    ruleset = load_rules_json(p)

    assert len(ruleset.rules) == 1
    assert ruleset.rules[0].rule_id == "sigma-1"
    assert ruleset.rules[0].match_logic is not None
    assert ruleset.rules[0].prerequisite_ast is not None
    assert ruleset.rules[0].severity == 3.0


def test_json_stage_alias_cc_communication_maps_to_establish_foothold(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(
        """
[{"rule_id":"r1","name":"x","source_types":["proxy"],"apt_stage":"C&C Communication"}]
""".strip(),
        encoding="utf-8",
    )

    ruleset = load_rules_json(p)

    assert ruleset.rules[0].apt_stage == "Establish Foothold"


def test_rules_yaml_supports_max_path_factor_prerequisite_dict(tmp_path):
    p = tmp_path / "rules_pf.yaml"
    p.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R1",
                "    name: r1",
                "    prerequisites:",
                "      - graph_path",
                "      - type: path_factor",
                "        max_path_factor: 1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(p)
    assert ruleset.rules[0].prerequisites[1].max_path_factor == 1


def test_rules_yaml_rejects_path_factor_op_override(tmp_path):
    p = tmp_path / "rules_pf_bad.yaml"
    p.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R1",
                "    name: r1",
                "    prerequisites:",
                "      - type: path_factor",
                "        max_path_factor: 1",
                "        op: \">=\"",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    try:
        load_rules_yaml(p)
        assert False, "expected RuleValidationError"
    except RuleValidationError as exc:
        assert "op is not supported" in str(exc)


def test_rules_yaml_supports_match_logic_and_entity_bindings(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: R_SIGMA",
                "    name: sigma in yaml",
                "    prerequisites: []",
                "    match_logic:",
                "      engine: sigma",
                "      condition:",
                "        compiled:",
                "          type: selector_ref",
                "          selector: sel",
                "      selectors:",
                "        sel:",
                "          type: object",
                "          items:",
                "            - type: field_match",
                "              field: CommandLine",
                "              modifiers: [contains]",
                "              value:",
                "                type: literal",
                "                value: bash",
                "    entity_bindings:",
                "      - symbol: $current_process",
                "        entity_type: Process",
                "        fields: [subject]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ruleset = load_rules_yaml(rules_path)

    assert ruleset.rules[0].match_logic is not None
    assert ruleset.rules[0].entity_bindings[0]["symbol"] == "$current_process"


def test_darpa_tc_e3_ruleset_loads(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    ruleset = load_rules_yaml(repo_root / "rules" / "darpa_tc_e3_rules.yaml")

    assert len(ruleset.rules) >= 5
    assert any(rule.rule_id == "DARPA_EXFIL_REMOTE_CONNECT" for rule in ruleset.rules)
    exfil_rule = next(rule for rule in ruleset.rules if rule.rule_id == "DARPA_EXFIL_REMOTE_CONNECT")
    assert exfil_rule.bypass_benign_filter is True
