"""Tests for scripts/mcp_client.py path resolution.

The stdio entrypoint ``ida_mcp_stdio.py`` lives at the repo root, not
alongside the client in ``scripts/``. The MCPClient must find it without
the caller passing ``server_cmd`` explicitly.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_resolve_server_script_finds_repo_root():
    """Even though the client is in scripts/, ida_mcp_stdio.py must resolve
    to the repo root, not scripts/ida_mcp_stdio.py.
    """
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    # Import after sys.path update because the script doesn't import sanely otherwise
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_mcp_client_under_test",
        os.path.join(REPO_ROOT, "scripts", "mcp_client.py"),
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    resolved = mod._resolve_server_script()
    assert os.path.isfile(resolved), f"{resolved} does not exist"
    assert resolved.endswith("ida_mcp_stdio.py")
    # And critically, NOT in scripts/
    assert os.path.dirname(resolved) != os.path.join(REPO_ROOT, "scripts")
