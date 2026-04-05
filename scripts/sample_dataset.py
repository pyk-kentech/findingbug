from __future__ import annotations

import argparse
import json
from pathlib import Path


def _extract_ts(raw: dict) -> str | None:
    for key in ("ts", "timestamp", "timestampNanos", "timestampMicros"):
        value = raw.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def sample_jsonl(
    *,
    input_path: str | Path,
    output_path: str | Path,
    max_lines: int | None,
    start_ts: str | None,
    end_ts: str | None,
) -> int:
    src = Path(input_path)
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with src.open("r", encoding="utf-8") as fin, dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            raw_line = line.strip()
            if not raw_line:
                continue
            raw = json.loads(raw_line)
            if not isinstance(raw, dict):
                continue
            ts = _extract_ts(raw)
            if start_ts is not None and ts is not None and ts < start_ts:
                continue
            if end_ts is not None and ts is not None and ts > end_ts:
                continue
            fout.write(raw_line + "\n")
            written += 1
            if max_lines is not None and written >= max_lines:
                break
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Stream-sample a large JSONL dataset without loading it into memory.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-lines", type=int, default=100000)
    parser.add_argument("--start-ts")
    parser.add_argument("--end-ts")
    args = parser.parse_args()

    written = sample_jsonl(
        input_path=args.input,
        output_path=args.output,
        max_lines=args.max_lines,
        start_ts=args.start_ts,
        end_ts=args.end_ts,
    )
    print(json.dumps({"written": written, "output": str(Path(args.output))}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
