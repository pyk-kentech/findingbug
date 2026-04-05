from __future__ import annotations

import argparse
import json
from pathlib import Path

from engine.noise.profile import save_benign_profile, train_benign_profile
from engine.stream.source import FileJsonlSource


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a benign whitelist profile from clean JSONL/gz events.")
    parser.add_argument("--events", required=True, help="Path to benign events JSONL or JSONL.GZ")
    parser.add_argument("--out", required=True, help="Path to benign_profile.json")
    parser.add_argument("--min-count", type=int, default=5, help="Minimum occurrence count for a pattern to enter the whitelist.")
    args = parser.parse_args()

    event_count = sum(1 for _ in FileJsonlSource(args.events, follow=False))
    profile = train_benign_profile(FileJsonlSource(args.events, follow=False), min_count=max(1, int(args.min_count)))
    save_benign_profile(profile, args.out)
    print(
        json.dumps(
            {
                "events": event_count,
                "patterns": len(profile.patterns),
                "output": str(Path(args.out)),
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
