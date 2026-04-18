from pathlib import Path

content = """rules:
  - id: TEST_PROC_TO_FILE
    event_type: proc_to_file
    prerequisites:
      - graph_path
      - type: path_factor
        threshold: 1.1
        op: ">="
"""

Path("rules/test_rules_pf_1_1.yaml").write_text(content, encoding="utf-8")
print("created rules/test_rules_pf_1_1.yaml")
