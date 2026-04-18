from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import yaml


def load_manifest(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("Manifest root must be a mapping")
    return payload


def cleanup_gdown_parts(target: Path) -> None:
    # gdown may leave temp files like "<target>.part" or "<target><random>.part"
    for p in target.parent.glob(target.name + "*.part"):
        try:
            p.unlink()
        except OSError:
            pass


def download_with_retries(*, file_id: str, out_path: Path, max_retries: int) -> Path:
    try:
        import gdown
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("gdown is required") from exc

    last_exc: Exception | None = None
    for attempt in range(1, max(1, int(max_retries)) + 1):
        try:
            downloaded = gdown.download(id=file_id, output=str(out_path), quiet=False, fuzzy=True)
            if not downloaded:
                raise RuntimeError("gdown returned empty path")
            return Path(downloaded)
        except Exception as exc:  # pragma: no cover - network/drive behavior
            last_exc = exc
            sleep_s = min(300.0, 2.0 ** (attempt - 1))
            print(f"RETRY attempt={attempt} sleep={sleep_s:.1f}s err={exc}")
            time.sleep(sleep_s)
    raise RuntimeError(f"Failed after {max_retries} retries: {file_id}") from last_exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Download DARPA TC E3 raw archives listed in configs/darpa_manifest.yaml")
    parser.add_argument("--manifest", default=str(Path(__file__).resolve().parents[1] / "configs" / "darpa_manifest.yaml"))
    default_root = Path(os.environ.get("HOLMES_DATA_ROOT", "/home/work/SIGMA/datasets"))
    parser.add_argument("--out-dir", default=str(default_root / "darpa_tc_e3" / "raw"))
    parser.add_argument("--max-retries", type=int, default=10)
    parser.add_argument("--only", action="append", default=[], help="Download only these dataset aliases (repeatable).")
    parser.add_argument("--skip", action="append", default=[], help="Skip these dataset aliases (repeatable).")
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Keep retrying until all datasets are downloaded (useful for Google Drive quota windows).",
    )
    parser.add_argument("--loop-sleep-seconds", type=int, default=3600)
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(manifest_path)
    datasets = manifest.get("datasets", {})
    if not isinstance(datasets, dict):
        raise ValueError("manifest.datasets must be a mapping")

    only = {str(x).strip() for x in (args.only or []) if str(x).strip()}
    skip = {str(x).strip() for x in (args.skip or []) if str(x).strip()}

    def all_present() -> bool:
        for name, entry in datasets.items():
            if only and name not in only:
                continue
            if name in skip:
                continue
            if not isinstance(entry, dict):
                continue
            filename = str(entry.get("filename") or "").strip()
            if not filename:
                continue
            p = out_dir / filename
            if not (p.exists() and p.stat().st_size > 0):
                return False
        return True

    while True:
        for name, entry in datasets.items():
            if only and name not in only:
                continue
            if name in skip:
                continue
            if not isinstance(entry, dict):
                print(f"SKIP {name}: invalid entry type {type(entry)}")
                continue
            file_id = str(entry.get("file_id") or "").strip()
            filename = str(entry.get("filename") or "").strip() or f"{name}.tar.gz"
            if not file_id:
                print(f"SKIP {name}: missing file_id")
                continue
            out_path = out_dir / filename

            if out_path.exists() and out_path.stat().st_size > 0:
                print(f"SKIP {name}: exists {out_path} size={out_path.stat().st_size}")
                continue

            cleanup_gdown_parts(out_path)
            print(f"DOWN {name}: id={file_id} -> {out_path}")
            try:
                downloaded = download_with_retries(file_id=file_id, out_path=out_path, max_retries=args.max_retries)
                print(f"OK {name}: {downloaded} size={downloaded.stat().st_size}")
            except Exception as exc:
                print(f"FAIL {name}: {exc}")
                if not args.loop:
                    raise

        if all_present():
            print("DONE all datasets")
            return 0
        if not args.loop:
            raise RuntimeError("Some datasets are missing after download attempt(s).")
        sleep_s = max(60, int(args.loop_sleep_seconds))
        print(f"WAIT loop_sleep_seconds={sleep_s}")
        time.sleep(float(sleep_s))


if __name__ == "__main__":
    raise SystemExit(main())
