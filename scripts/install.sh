#!/usr/bin/env bash
# ==============================================================================
# IDA Pro MCP — Universal One-Line / Click-to-Run Auto-Installer (Linux & macOS)
# ==============================================================================
set -euo pipefail

REPO="GrecAndrei/ida-pro-mcp"
VERSION="${IDA_PRO_MCP_VERSION:-1.0.0a1}"
TAG="v${VERSION#v}"
WHEEL_URL="https://github.com/${REPO}/releases/download/${TAG}/ida_pro_mcp-${VERSION}-py3-none-any.whl"

echo "========================================================"
echo "          IDA Pro MCP Auto-Installer (${TAG})          "
echo "========================================================"

# 1. Locate suitable Python (3.11+)
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Error: Python 3.11 or newer is required but was not found on PATH." >&2
    echo "    Please install Python 3.11+ and re-run." >&2
    exit 1
fi

echo "[*] Using Python: $($PYTHON_BIN --version) ($PYTHON_BIN)"

# 2. Determine install root
INSTALL_ROOT="${IDA_PRO_MCP_HOME:-$HOME/.local/share/ida-pro-mcp}"
echo "[*] Install root: ${INSTALL_ROOT}"
mkdir -p "${INSTALL_ROOT}"

# 3. Create or verify managed virtual environment
VENV_DIR="${INSTALL_ROOT}/.venv"
VENV_PY="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

if [ ! -x "${VENV_PY}" ]; then
    echo "[*] Creating isolated virtual environment in ${VENV_DIR}..."
    "$PYTHON_BIN" -m venv "${VENV_DIR}"
fi

# 4. Install / Upgrade IDA Pro MCP from release wheel
echo "[*] Installing/updating IDA Pro MCP (${VERSION})..."
"${VENV_PY}" -m pip install --upgrade pip --quiet
"${VENV_PIP}" install --upgrade "${WHEEL_URL}" --quiet

# 5. Execute automated configuration
echo "[*] Auto-detecting IDA Pro installations, configuring MCP clients, and installing skills..."
"${VENV_PY}" -m ida_pro_mcp.installer.main --auto "$@"

echo ""
echo "========================================================"
echo "[✓] IDA Pro MCP successfully installed and configured!"
echo "========================================================"
