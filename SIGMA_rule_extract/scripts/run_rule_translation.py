import argparse
import glob
import json
import logging
import os
from pathlib import Path
import sys

from tqdm import tqdm

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.translator.pipeline import process_single_rule
from scripts.qa.rule_linter import lint_rules


def iter_rule_files(input_dir: Path) -> list[Path]:
    return sorted(
        [
            Path(path)
            for pattern in ("**/*.yml", "**/*.yaml")
            for path in glob.glob(str(input_dir / pattern), recursive=True)
            if Path(path).is_file()
        ]
    )


def build_output_path(input_file: Path, input_root: Path, output_root: Path) -> Path:
    relative_path = input_file.relative_to(input_root)
    path_parts = relative_path.parts

    if len(path_parts) > 1:
        top_level_dir = path_parts[0]
        nested_parent = Path(*path_parts[1:-1]) if len(path_parts) > 2 else Path()
        output_dir = output_root / f"hholmes_{top_level_dir}" / nested_parent
    else:
        output_dir = output_root / "hholmes_misc"

    os.makedirs(output_dir, exist_ok=True)
    return output_dir / f"{input_file.stem}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Translate Sigma YAML rules into HOLMES JSON.")
    parser.add_argument("--input", default="rules/sigma/", help="Input directory containing Sigma YAML rules.")
    parser.add_argument("--output", default="rules/holmes/", help="Output directory for HOLMES JSON rules.")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)
    os.makedirs(output_dir, exist_ok=True)

    logging.basicConfig(
        filename="translation_errors.log",
        level=logging.ERROR,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    rule_files = iter_rule_files(input_dir)
    success_count = 0
    failure_count = 0
    too_broad_count = 0

    progress = tqdm(rule_files, desc="Translating rules", unit="file")
    for rule_file in progress:
        try:
            yaml_text = rule_file.read_text(encoding="utf-8")
            rule_json = process_single_rule(yaml_text)
            output_path = build_output_path(rule_file, input_dir, output_dir)
            output_path.write_text(
                json.dumps(rule_json, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            success_count += 1
        except Exception as exc:
            if "too broad" in str(exc).lower():
                too_broad_count += 1
            else:
                failure_count += 1
            logging.error("Failed to process %s: %s", rule_file, exc, exc_info=True)
            continue
        finally:
            progress.set_postfix(
                success=success_count,
                too_broad=too_broad_count,
                failed=failure_count,
            )

    linter_result = lint_rules(output_dir, PROJECT_ROOT / "linter_report.log")
    linter_has_errors = linter_result["error_count"] > 0

    print(
        "\nTranslation summary:\n"
        f"- Total input rules: {len(rule_files)}\n"
        f"- HOLMES JSON generated: {success_count}\n"
        f"- Dropped by Too Broad filter: {too_broad_count}\n"
        f"- Other translation failures: {failure_count}\n"
    )

    return 0 if failure_count == 0 and not linter_has_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
