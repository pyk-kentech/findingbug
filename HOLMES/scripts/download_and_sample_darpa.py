from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import time

import yaml


DEFAULT_OUTPUT_DIR = Path(os.environ.get("HOLMES_DATA_ROOT", "/home/work/SIGMA/datasets")) / "darpa_tc_e3"
DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "configs" / "darpa_manifest.yaml"


def download_single_gdrive_file(
    *,
    file_id: str,
    output_dir: Path,
    output_name: str | None = None,
    max_retries: int = 3,
) -> Path:
    try:
        import gdown
    except ImportError as exc:
        raise RuntimeError("gdown is required for download_and_sample_darpa.py") from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / (output_name or f"{file_id}.json.gz")
    last_error: Exception | None = None
    for attempt in range(1, max(1, int(max_retries)) + 1):
        try:
            downloaded = gdown.download(
                id=str(file_id).strip(),
                output=str(output_path),
                quiet=False,
                fuzzy=True,
            )
            if not downloaded:
                raise RuntimeError(f"Failed to download file id: {file_id}")
            return Path(downloaded)
        except Exception as exc:  # pragma: no cover - retry surface
            last_error = exc
            if attempt >= max_retries:
                break
            time.sleep(float(2 ** (attempt - 1)))
    raise RuntimeError(f"Failed to download file id after {max_retries} attempts: {file_id}") from last_error


def load_manifest(path: str | Path) -> dict:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("DARPA manifest root must be a mapping")
    return payload


def resolve_dataset_entry(manifest_path: str | Path, dataset_name: str) -> dict:
    manifest = load_manifest(manifest_path)
    datasets = manifest.get("datasets", {})
    if not isinstance(datasets, dict):
        raise ValueError("DARPA manifest datasets must be a mapping")
    entry = datasets.get(dataset_name)
    if not isinstance(entry, dict):
        raise KeyError(f"Dataset alias not found in manifest: {dataset_name}")
    return entry


def stream_sample_gzip(
    *,
    input_path: Path,
    output_path: Path,
    max_lines: int,
) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with gzip.open(input_path, "rt", encoding="utf-8") as fin, output_path.open("w", encoding="utf-8") as fout:
        while True:
            line = fin.readline()
            if not line:
                break
            raw = line.strip()
            if not raw:
                continue
            fout.write(raw + "\n")
            written += 1
            if written >= max_lines:
                break
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Download DARPA TC gzip logs and create an on-the-fly streamed sample.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--dataset", help="Dataset alias from darpa_manifest.yaml, e.g. trace_e3_day1.")
    parser.add_argument("--file-id", help="Google Drive file id for a single .json.gz DARPA TC file.")
    parser.add_argument("--output-name", help="Optional output filename for the downloaded .json.gz file.")
    parser.add_argument("--input-gz", help="Use an already downloaded .json.gz file instead of downloading.")
    parser.add_argument("--max-lines", type=int, default=500000)
    parser.add_argument("--sample-output", default=str(DEFAULT_OUTPUT_DIR / "sample.jsonl"))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if args.input_gz:
        gz_path = Path(args.input_gz)
    else:
        resolved_file_id = args.file_id
        resolved_output_name = args.output_name
        if args.dataset:
            entry = resolve_dataset_entry(args.manifest, args.dataset)
            resolved_file_id = str(entry.get("file_id") or "").strip()
            if not resolved_output_name:
                resolved_output_name = str(entry.get("filename") or "").strip() or None
        if not resolved_file_id:
            raise RuntimeError("--file-id or --dataset is required unless --input-gz is provided")
        gz_path = download_single_gdrive_file(
            file_id=resolved_file_id,
            output_dir=output_dir,
            output_name=resolved_output_name,
        )

    written = stream_sample_gzip(
        input_path=gz_path,
        output_path=Path(args.sample_output),
        max_lines=max(1, int(args.max_lines)),
    )
    print(
        json.dumps(
            {
                "downloaded_gz": str(gz_path),
                "sample_output": str(Path(args.sample_output)),
                "written": written,
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
