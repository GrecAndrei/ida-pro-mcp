#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[1/6] Running schema integrity check"
python scripts/check_schema_integrity.py

echo "[2/6] Regenerating tool docs/skills and checking drift"
python scripts/generate_tool_skills.py
git diff --exit-code -- .agents/skills .agents/tool-docs

echo "[3/6] Running test suite"
python -m pytest -q

echo "[4/6] Building distribution artifacts"
rm -rf dist
uv build

echo "[5/6] Smoke-testing wheel install in temporary virtualenv"
TMP_DIR="$(mktemp -d)"
python -m venv "$TMP_DIR/.venv"
"$TMP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$TMP_DIR/.venv/bin/python" -m pip install dist/*.whl
"$TMP_DIR/.venv/bin/python" -c "import ida_pro_mcp.host.server, ida_pro_mcp.cli; print('wheel smoke-test ok')"
rm -rf "$TMP_DIR"

echo "[6/6] Publishing package"
uv publish
