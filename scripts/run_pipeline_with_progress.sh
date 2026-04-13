#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  cat <<'USAGE'
Usage:
  scripts/run_pipeline_with_progress.sh [run_pipeline args...]

Example:
  scripts/run_pipeline_with_progress.sh \
    --events /path/to/events.jsonl \
    --rules /path/to/rules.yaml \
    --out /path/to/output \
    --use-online-prereq --ancestor-index-mode lazy
USAGE
  exit 1
fi

EVENTS_PATH=""
OUT_DIR=""

for ((i=1; i<=$#; i++)); do
  arg="${!i}"
  next_index=$((i+1))
  next_val="${!next_index-}"
  case "$arg" in
    --events)
      EVENTS_PATH="$next_val"
      ;;
    --events=*)
      EVENTS_PATH="${arg#--events=}"
      ;;
    --out)
      OUT_DIR="$next_val"
      ;;
    --out=*)
      OUT_DIR="${arg#--out=}"
      ;;
  esac
done

if [[ -z "$OUT_DIR" ]]; then
  echo "[progress] --out is required in arguments" >&2
  exit 2
fi

TOTAL_EVENTS=""
if [[ -n "${TOTAL_EVENTS_OVERRIDE:-}" && "${TOTAL_EVENTS_OVERRIDE}" =~ ^[0-9]+$ && "${TOTAL_EVENTS_OVERRIDE}" -gt 0 ]]; then
  TOTAL_EVENTS="$TOTAL_EVENTS_OVERRIDE"
elif [[ -n "$EVENTS_PATH" && -f "$EVENTS_PATH" ]]; then
  TOTAL_EVENTS="$(
    python - "$EVENTS_PATH" <<'PY'
from engine.io.events import count_raw_records_jsonl
import sys

print(count_raw_records_jsonl(sys.argv[1]))
PY
  )"
fi

METRICS_PATH="$OUT_DIR/debug/metrics.jsonl"
mkdir -p "$OUT_DIR/debug"

echo "[progress] starting pipeline"
if [[ -n "$TOTAL_EVENTS" ]]; then
  echo "[progress] total events: $TOTAL_EVENTS"
else
  echo "[progress] total events: unknown (set TOTAL_EVENTS_OVERRIDE to force)"
fi

time python -m engine.cli.run_pipeline "$@" &
PIPE_PID=$!

print_progress() {
  if [[ ! -s "$METRICS_PATH" ]]; then
    echo "[progress] waiting for metrics..."
    return
  fi

  python - "$METRICS_PATH" "$TOTAL_EVENTS" <<'PY'
import datetime as dt
import json
import math
import sys

metrics_path = sys.argv[1]
total_raw = sys.argv[2]

total = int(total_raw) if total_raw else None
line = ""
with open(metrics_path, "r", encoding="utf-8") as f:
    for line in f:
        pass

if not line:
    print("[progress] waiting for metrics...")
    raise SystemExit(0)

obj = json.loads(line)
events = int(obj.get("events_processed", 0))
pm = obj.get("performance_metrics", {}) or {}
eps = float(pm.get("events_per_second", 0.0) or 0.0)
ts = obj.get("ts", "")

if total and total > 0:
    display_total = max(total, events)
    pct = (events / display_total) * 100.0
    rem = max(display_total - events, 0)
    eta_sec = (rem / eps) if eps > 0 else math.inf
    if math.isfinite(eta_sec):
        eta = str(dt.timedelta(seconds=int(eta_sec)))
    else:
        eta = "unknown"
    suffix = " [total-adjusted]" if display_total != total else ""
    print(f"[progress] {ts} events={events}/{display_total} ({pct:.2f}%) eps={eps:.1f} eta={eta}{suffix}")
else:
    print(f"[progress] {ts} events={events} eps={eps:.1f}")
PY
}

while kill -0 "$PIPE_PID" 2>/dev/null; do
  print_progress
  sleep 10
done

wait "$PIPE_PID"
EXIT_CODE=$?

echo "[progress] pipeline finished with exit=$EXIT_CODE"
if [[ -s "$METRICS_PATH" ]]; then
  echo "[progress] final metrics:"
  tail -n 1 "$METRICS_PATH"
fi

exit "$EXIT_CODE"
