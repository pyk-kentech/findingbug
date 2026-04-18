#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
EXT_SUFFIX="$($PYTHON_BIN -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')"
INCLUDE_DIR="$($PYTHON_BIN -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')"

SRC="engine/core/_acmin_native.c"
OUT="engine/core/_acmin_native${EXT_SUFFIX}"

echo "[build] compiling ${SRC} -> ${OUT}"
if gcc -O3 -fPIC -shared -fopenmp -I"${INCLUDE_DIR}" "${SRC}" -o "${OUT}" >/dev/null 2>&1; then
  echo "[build] OpenMP enabled"
else
  echo "[build] OpenMP compile failed, fallback to non-OpenMP"
  gcc -O3 -fPIC -shared -I"${INCLUDE_DIR}" "${SRC}" -o "${OUT}"
fi
echo "[build] done: ${OUT}"
