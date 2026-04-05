# HOLMES-style APT Detection MVP

## Run tests

```bash
pytest -q
```

## Run pipeline

`--out` is an output directory, not a file path.
The pipeline creates these files inside the directory:
- `result.json`
- `summary.json`
- `matches.json`
- `hsg.json`

```bash
python -m engine.cli.run_pipeline \
  --events experiments/sample.jsonl \
  --rules rules/empty.yaml \
  --out out
```

## Paper mode recommended command

```bash
python -m engine.cli.run_pipeline \
  --events <events.jsonl> \
  --rules <rules.yaml> \
  --out out \
  --paper-mode strict \
  --path-factor-op le \
  --min-path-factor 3 \
  --prereq-policy dst_only \
  --scoring paper \
  --paper-weights 1.1,1.2,1.3,1.4,1.5,1.6,1.7 \
  --noise-model noise_model.json \
  --noise-bytes-threshold p95
```

## Reproducible experiment run (Step 5)

Single command:

```bash
python -m experiments.run --config experiments/config_example.yaml
```

The experiment runner always uses `paper_exact` scoring and produces:
- `results/<config_hash>/metrics.json`
- `results/<config_hash>/detections.csv`
- `results/<config_hash>/campaigns.json`
- `results/<config_hash>/config_used.json`

`metrics.json` includes campaign-level metrics (`precision/recall/f1`, TP/FP/TN/FN), early-detection context, latency/throughput, peak memory (when enabled), and config metadata (`config_hash`, `config_path`, `seed`, `tau`, `weights`).

`detections.csv` has one row per campaign window with:
- `campaign_id`, `label`
- `campaign_start_event`, `campaign_end_event`
- `detected`, `detect_event`, `score_at_detect`
- `Stage-to-Detect`, `Events-to-Detect`
- `tuple_snapshot_at_detect`, `contributing_stages_at_detect`

Memory profiling is separated from latency/throughput measurement via an independent runner pass.

## Paper Anchors (Step 6)

`paper_exact` experiments now resolve parameters from:
- `configs/paper_defaults.yaml`: only values explicitly stated in paper (with page/section source)
- `configs/assumptions.yaml`: only non-explicit fallback assumptions with `WHY`/`IMPACT`
- `docs/paper_parameters.md`: drift guard table for paper/assumption keys

Guardrails (fail-fast):
- assumptions cannot override explicit paper defaults (`tau`, `weights`, `stage_order`)
- missing `tau` or `weights` in both layers fails
- `paper_defaults` entries require `source.page` and cannot include `WHY`/`IMPACT`
- stage order must match code stage definition exactly
- docs key table must match YAML keys

`metrics.json` includes provenance metadata:
- `paper_defaults_path`, `paper_defaults_digest`
- `assumptions_path`, `assumptions_digest`
- `stage_order_digest`
- `parameter_provenance` (structured, with paper page/section or assumption WHY/IMPACT)

## Rule schema

`event_predicate` supports exactly one of:

```yaml
event_predicate:
  op: "exec"
```

```yaml
event_predicate:
  event_type: "proc_to_file"
```

## Dependency strength

`dependency_strength(from_entity, to_entity)` is directed and uses shortest path attenuation.
If no directed path exists, strength is `0.0`.
Let `L = shortest_path_len(from_entity, to_entity)` in edge count; then strength is `1.0 / (1.0 + L)`.
If `from_entity == to_entity`, `L = 0` and strength is `1.0`.  # (코드에 맞게 조정)
Examples: 1-hop -> `0.5`, 2-hop -> `1/3`, 3-hop -> `0.25`.
In the HSG output (`out/hsg.json`), `graph_path` edges store this value in the `weight` field.

## Scenario scoring (MVP)

Scenario score = sum(rule severities in the scenario) + alpha * sum(edge weights in the scenario).
Edges without a `weight` field contribute 0.

## Path factor (MAC MVP)

Default `path_factor(from_entity, to_entity)` follows paper-style incremental propagation.
If no directed path exists, path_factor is undefined (`None`), and `path_factor(src, src) = 1.0`.
When unreachable, `graph_path` edges are not created.
Process-node transitions without common ancestor with `src` increase path_factor by 1; non-process transitions keep it.
When multiple paths exist, the minimum propagated value is used.
Legacy MAC approximation remains available as `path_factor_legacy_mac(...)`.
For threshold filtering, `--path-factor-op ge` means keep edges with `path_factor >= threshold` (legacy behavior).
`--path-factor-op le` means keep edges with `path_factor <= threshold` (paper-style max allowed path_factor).
In paper mode, `--min-path-factor` is interpreted as `path_thres` (the option name is kept for compatibility).
Default `path_thres=3` is applied only by the mode resolver when scoring mode is `paper` and the option is omitted.
`--path-factor-op` default is also resolved by mode: `paper -> le`, `legacy -> ge`.

## Summary fields

`summary.json` includes:
- `resolved_effective_config`: resolved runtime config values after mode resolver (`path_thres`, `path_factor_op`, `scoring`, `paper_mode`, `paper_weights`)
- `paper_scoring`: paper scoring visibility fields (`threat_tuple`, `stage_severity`, `paper_weights`, `score_paper`)

## DARPA TC E3 datasets used

Dataset manifest:
- `configs/darpa_manifest.yaml`

Ground truth used in repository:
- `configs/darpa_e3_ground_truth.json`
- `configs/darpa_e3_ground_truth_trace.json`

Mapped Google Drive datasets:
- `trace_e3_benign_day`
  - file id: `1sfIbavsUFwmB-irSGY1TZZ0Sq1dZqF9G`
  - filename: `ta1-trace-e3-official.json.tar.gz`
- `trace_e3_attack_day1`
  - file id: `1GG1aUnPjjzzdbxznVTN8X6oVfA-K4oIV`
  - filename: `ta1-trace-e3-official-1.json.tar.gz`
- `theia_e3_attack_day1`
  - file id: `1Kadc6CUTb4opVSDE4x6RFFnEy0P1cRp0`
  - filename: `ta1-theia-e3-official-6r.json.tar.gz`

Data actually used during local benchmark work:
- benign slice: `D:/DARPA_TC_E3/benchmark/trace_benign_10k.jsonl`
- attack slice: `D:/DARPA_TC_E3/benchmark/trace_attack_5k.jsonl`
- benchmark output example: `output/darpa_trace_real_benchmark_5k/`

Notes:
- the repository keeps dataset addresses, manifests, and ground-truth metadata only
- large raw DARPA archives and generated benchmark outputs are not committed
