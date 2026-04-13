# Full Run Timeout + 6-Core Optimization Plan

## 1) Immediate Operating Rule (Current Job)

- Current long-running command:
  - `python -m engine.cli.run_pipeline --events /home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_full.jsonl --rules /home/work/SIGMA/HOLMES/rules/darpa_tc_e3_rules.yaml --out /home/work/SIGMA/HOLMES/output/darpa_trace_attack_full_smoke`
- Policy:
  - Wait up to **2 more hours**.
  - If not finished, **stop** and switch to optimized run path.

### Monitor (every 30s)

```bash
watch -n 30 'PID=$(pgrep -f "python -m engine.cli.run_pipeline --events /home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_full.jsonl" | head -n 1); if [ -z "$PID" ]; then echo DONE; else ps -p "$PID" -o pid,etime,%cpu,%mem,cmd --no-headers; fi'
```

### Stop if still running after 2 hours

```bash
PID=$(pgrep -f "python -m engine.cli.run_pipeline --events /home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_full.jsonl" | head -n 1)
[ -n "$PID" ] && kill -TERM "$PID"
sleep 5
ps -p "$PID" >/dev/null && kill -KILL "$PID"
```

---

## 2) Optimization Goal

- Target: use **6 CPU workers** for heavy match stage.
- Keep correctness identical on small benchmark (`5k`) before full rerun.
- Avoid changing `SIGMA_rule_extract`; optimize inside `HOLMES` only.

---

## 3) Code Changes to Implement

## A. Add parallel matcher controls to pipeline CLI

- File: [engine/cli/run_pipeline.py](/home/work/SIGMA/HOLMES/engine/cli/run_pipeline.py)
- Add arguments:
  - `--matcher-workers` (default `1`)
  - `--matcher-batch-size` (default `50000`)

## B. Introduce multiprocessing matcher executor

- New file: `engine/core/match_workers.py`
- Responsibility:
  - Split rules into shards by worker count.
  - Process event batches in `multiprocessing.Pool`.
  - Return match objects + minimal telemetry.
- Safety rule:
  - Parallelize only rule matching.
  - Keep graph/HSG mutation in main process (single writer).

## C. Convert matcher hot path into batch API

- File: [engine/core/matcher.py](/home/work/SIGMA/HOLMES/engine/core/matcher.py)
- Add:
  - `match_batch(graph, rules_subset, events_batch)` helper
  - Precompute normalized rule data once per shard (selector cache / field lookup cache).

## D. Use batch loop in pipeline

- File: [engine/cli/run_pipeline.py](/home/work/SIGMA/HOLMES/engine/cli/run_pipeline.py)
- Replace monolithic full-event loop with:
  - batch load iteration
  - parallel match per batch
  - sequential `engine` update with merged matches

## E. Optional low-risk speedups

- Reuse lowered field names map once per event.
- Skip expensive predicate branches when `event_predicate` quick-check fails.
- Reduce debug telemetry writes during full run unless explicitly enabled.

---

## 4) Validation Gate (Must Pass)

## A. Correctness on small sample

```bash
cd /home/work/SIGMA/HOLMES
python -m engine.cli.run_pipeline \
  --events /home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_5k.jsonl \
  --rules /home/work/SIGMA/HOLMES/rules/darpa_tc_e3_rules.yaml \
  --out /home/work/SIGMA/HOLMES/output/darpa_trace_attack_5k_parallel_test
```

- Compare with baseline:
  - `matches` count
  - top scenario score
  - no crash / no schema drift

## B. Throughput check

- Verify `performance_metrics.events_per_second` increased materially vs single-core baseline.

---

## 5) Full Rerun After Optimization

```bash
cd /home/work/SIGMA/HOLMES
python -m engine.cli.run_pipeline \
  --events /home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_full.jsonl \
  --rules /home/work/SIGMA/HOLMES/rules/darpa_tc_e3_rules.yaml \
  --out /home/work/SIGMA/HOLMES/output/darpa_trace_attack_full_parallel \
  --matcher-workers 6 \
  --matcher-batch-size 50000
```

---

## 6) Rollback / Safety

- If parallel path causes mismatch:
  - rerun with `--matcher-workers 1`
  - keep old output directory untouched for diff
- Never overwrite prior baseline outputs; use new `--out` path each run.

