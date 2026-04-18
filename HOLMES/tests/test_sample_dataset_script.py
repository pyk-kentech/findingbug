import json
from pathlib import Path
import subprocess
import sys


def test_sample_dataset_script_stream_copies_limited_lines(tmp_path):
    src = tmp_path / "large.jsonl"
    dst = tmp_path / "sample.jsonl"
    src.write_text(
        "\n".join(
            json.dumps({"event_id": f"e{i}", "ts": f"2025-01-0{i}T00:00:00Z"})
            for i in range(1, 6)
        )
        + "\n",
        encoding="utf-8",
    )
    script = Path(__file__).resolve().parents[1] / "scripts" / "sample_dataset.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--input",
            str(src),
            "--output",
            str(dst),
            "--max-lines",
            "2",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout.strip())
    assert payload["written"] == 2
    assert len(dst.read_text(encoding="utf-8").splitlines()) == 2
