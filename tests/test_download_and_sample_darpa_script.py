import gzip
import json
from pathlib import Path
import subprocess
import sys


def test_download_and_sample_darpa_script_uses_existing_gzip_input(tmp_path):
    src = tmp_path / "trace.json.gz"
    out = tmp_path / "sample.jsonl"
    with gzip.open(src, "wt", encoding="utf-8") as fh:
        fh.write('{"event_id":"e1","typeName":"EVENT_EXECVE"}\n')
        fh.write('{"event_id":"e2","typeName":"EVENT_WRITE"}\n')
        fh.write('{"event_id":"e3","typeName":"EVENT_READ"}\n')

    script = Path(__file__).resolve().parents[1] / "scripts" / "download_and_sample_darpa.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--input-gz",
            str(src),
            "--sample-output",
            str(out),
            "--max-lines",
            "2",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout.strip())
    assert payload["written"] == 2
    assert out.exists()
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2
