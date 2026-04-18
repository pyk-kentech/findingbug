#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="$ROOT_DIR/native-rust"

if ! command -v maturin >/dev/null 2>&1; then
  echo "[build] maturin not found"
  echo "[build] install with: pip install maturin"
  exit 1
fi

if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
  echo "[build] rust toolchain not found"
  echo "[build] install via rustup before building native-rust"
  exit 1
fi

cd "$RUST_DIR"
echo "[build] building holmes_native_rs via maturin"
maturin build --release
WHEEL_PATH="$(find "$RUST_DIR/target/wheels" -maxdepth 1 -type f -name 'holmes_native_rs-*.whl' | sort | tail -n 1)"
if [[ -z "${WHEEL_PATH:-}" ]]; then
  echo "[build] wheel not found after maturin build"
  exit 1
fi
echo "[build] installing wheel: $WHEEL_PATH"
python -m pip install --user --force-reinstall "$WHEEL_PATH"
echo "[build] done"
