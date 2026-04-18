from __future__ import annotations

import argparse
import json

from experiments.pipeline import load_experiment_config, run_experiment


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="HOLMES experiment runner")
    p.add_argument("--config", required=True, help="Path to experiment YAML/JSON config")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    cfg, cfg_path = load_experiment_config(args.config)
    result = run_experiment(cfg, config_path=cfg_path)
    metrics = result["metrics"]
    summary = {
        "output_dir": result["output_dir"],
        "parameter_provenance": metrics.get("parameter_provenance"),
        "paper_defaults_path": metrics.get("paper_defaults_path"),
        "assumptions_path": metrics.get("assumptions_path"),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
