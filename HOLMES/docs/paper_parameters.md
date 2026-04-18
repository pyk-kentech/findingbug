# Paper Parameter Anchors

| `key` | Paper Explicit? | Implementation Value | Source | Notes |
|---|---|---|---|---|
| `stage_order` | Yes | 7-stage order in code/config | p.8, TTP/APT-stage table | Paper-anchored |
| `severity_mapping` | Yes | Low=2, Medium=6, High=8, Critical=10 | p.8, NIST severity table | Paper-anchored |
| `missing_stage_value` | Yes | S_i=1 when stage has no evidence | p.8, Eq.1 description | Paper-anchored |
| `fallback_tau` | No (global default) | 1378.0 | Assumption | WHY/IMPACT tracked in `assumptions.yaml` |
| `fallback_weights` | No (global default) | [1,1,1,1,1,1,1] | Assumption | WHY/IMPACT tracked in `assumptions.yaml` |
| `stage_severity_assignment_rule` | No (global rule) | synthetic medium default | Assumption | WHY/IMPACT tracked in `assumptions.yaml` |
| `synthetic_stage_templates` | No | stage marker template | Assumption | WHY/IMPACT tracked in `assumptions.yaml` |

