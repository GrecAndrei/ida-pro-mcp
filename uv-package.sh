#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Running schema integrity check"
python scripts/check_schema_integrity.py

echo "[2/5] Running test suite"
python -m pytest -q

echo "[3/5] Building distribution artifacts"
rm -rf dist
uv build

echo "[4/5] Smoke-testing wheel install in temporary virtualenv"
TMP_DIR="$(mktemp -d)"
python -m venv "$TMP_DIR/.venv"
"$TMP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$TMP_DIR/.venv/bin/python" -m pip install dist/*.whl
"$TMP_DIR/.venv/bin/python" -c "import ida_pro_mcp.host.server, ida_pro_mcp.cli; print('wheel smoke-test ok')"
rm -rf "$TMP_DIR"

echo "[5/5] Publishing package"
uv publish
