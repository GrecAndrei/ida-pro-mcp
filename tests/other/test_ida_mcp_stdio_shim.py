"""Unit tests for ida_mcp_stdio.py — the stdio MCP shim.

The shim has two responsibilities that, if broken, cause the
"server hangs" problem on Windows stdio transports:

  1. Stream isolation: the real ``sys.stdout`` must be saved before
     anything else swaps it for ``sys.stderr``. If we save stderr
     instead, every JSON-RPC reply goes to stderr (invisible to most
     clients) and stdin pipes receive nothing — the result looks
     like a hang.

  2. Module injection: ``_real_stdout`` must be rebound on
     ``ida_pro_mcp.host.server.server`` (the submodule where
     ``IDAMCPServer.run`` references it). The package-level rebind is
     belt-and-braces only; the submodule rebind is mandatory.

These tests are intentionally standalone — they do NOT spin up the
real IDAMCPServer. They exercise the shim's import-time side effects
in a subprocess so we can introspect the post-import state.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run_in_subprocess(snippet: str) -> dict:
    """Run a Python snippet in a fresh subprocess that first imports
    the shim, then executes ``snippet``. Returns the parsed JSON of the
    snippet's last expression. Stderr is captured separately.
    """
    boot_path = os.path.join(REPO_ROOT, "ida_mcp_stdio.py")
    driver = (
        "import sys, runpy, json;"
        f"sys.argv = ['ida_mcp_stdio.py'];"
        f"runpy.run_path({boot_path!r}, run_name='__main__');"
        "result = ("
        f"{snippet}"
        ");"
        "sys.stderr.write('___RESULT_JSON_START___');"
        "sys.stderr.write(json.dumps(result, default=lambda o: repr(o)));"
        "sys.stderr.write('___RESULT_JSON_END___');"
    )
    proc = subprocess.run(
        [sys.executable, "-c", driver],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (
        f"subprocess exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    out = proc.stderr  # the shim redirects stdout to stderr
    start = out.find("___RESULT_JSON_START___")
    end = out.find("___RESULT_JSON_END___")
    assert start >= 0 and end > start, f"no result marker in:\n{out}"
    payload = out[start + len("___RESULT_JSON_START___"):end]
    return json.loads(payload)


class TestStreamIsolation:
    """The hang fix relied on saving the *real* stdout, not stderr."""

    def test_real_stdout_saved_not_stderr(self):
        """After the shim imports, sys.stdout should equal sys.stderr
        (so JSON-RPC replies don't leak to our real stdout). The
        earlier 'hang' bug was caused by saving stderr instead of
        stdout and accidentally swapping them the other way around.
        """
        boot_path = os.path.join(REPO_ROOT, "ida_mcp_stdio.py")
        driver = (
            "import sys, runpy, json\n"
            "_orig_stdout_id = id(sys.stdout)\n"
            f"runpy.run_path({boot_path!r}, run_name='__main__')\n"
            "result = {\n"
            "  'pre_stdout_id': _orig_stdout_id,\n"
            "  'post_stdout_is_stderr': sys.stdout is sys.stderr,\n"
            "  'post_stdout_id': id(sys.stdout),\n"
            "}\n"
            "sys.stderr.write('___' + json.dumps(result) + '___')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", driver],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        start = proc.stderr.find("___") + 3
        end = proc.stderr.rfind("___")
        info = json.loads(proc.stderr[start:end])
        assert info["post_stdout_is_stderr"], (
            f"sys.stdout should be sys.stderr after shim import, got: "
            f"pre_id={info['pre_stdout_id']} post_id={info['post_stdout_id']}"
        )

    def test_shim_does_not_exit_on_import(self):
        """Importing the shim without __main__ side effects shouldn't
        crash anything."""
        boot_path = os.path.join(REPO_ROOT, "ida_mcp_stdio.py")
        driver = (
            "import sys, runpy, json\n"
            f"runpy.run_path({boot_path!r}, run_name='__not_main__')\n"
            "result = 'ok'\n"
            "sys.stderr.write('___' + json.dumps(result) + '___')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", driver],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, f"stderr=\n{proc.stderr}"
        assert "___" + json.dumps("ok") + "___" in proc.stderr


class TestModuleInjection:
    """The hang fix required rebinding _real_stdout on the submodule."""

    def test_real_stdout_rebound_on_submodule(self):
        """After the shim imports, ida_pro_mcp.host.server.server must
        have _real_stdout pointing at the *original* sys.stdout, not
        at sys.stderr."""
        boot_path = os.path.join(REPO_ROOT, "ida_mcp_stdio.py")
        driver = (
            "import sys, runpy, json\n"
            f"_orig_id = id(sys.stdout)\n"
            f"runpy.run_path({boot_path!r}, run_name='__main__')\n"
            "from ida_pro_mcp.host.server import server as srv_mod\n"
            "submodule_real_stdout_id = id(srv_mod._real_stdout)\n"
            "result = {\n"
            "  'pre_stdout_id': _orig_id,\n"
            "  'submodule_real_stdout_id': submodule_real_stdout_id,\n"
            "  'match': _orig_id == submodule_real_stdout_id,\n"
            "  'is_stderr': srv_mod._real_stdout is sys.stderr,\n"
            "}\n"
            "sys.stderr.write('___' + json.dumps(result) + '___')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", driver],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, f"stderr=\n{proc.stderr}"
        start = proc.stderr.find("___") + 3
        end = proc.stderr.rfind("___")
        info = json.loads(proc.stderr[start:end])
        assert info["match"], (
            f"_real_stdout on server.py submodule was not the original "
            f"stdout (would cause the hang). Info: {info}"
        )
        assert not info["is_stderr"], (
            f"_real_stdout pointed at sys.stderr instead of stdout "
            f"(would swallow every JSON-RPC reply). Info: {info}"
        )

    def test_re_exports_resolve_through_shim(self):
        """All public names should be importable through the shim
        namespace so legacy callers keep working."""
        boot_path = os.path.join(REPO_ROOT, "ida_mcp_stdio.py")
        driver = (
            "import sys, runpy, json\n"
            f"runpy.run_path({boot_path!r}, run_name='__main__')\n"
            "import ida_mcp_stdio as shim\n"
            "expected = [\n"
            "  'IDAMCPServer', 'MCPError', 'make_error',\n"
            "  'log_rpc', 'CACHE_DIR', '_normalize_session_id',\n"
            "  '_resolve_tool_alias', 'SessionManager', 'BookmarkManager',\n"
            "  'compile_smart_pattern', '_coerce_bool',\n"
            "]\n"
            "missing = [n for n in expected if not hasattr(shim, n)]\n"
            "result = {'missing': missing}\n"
            "sys.stderr.write('___' + json.dumps(result) + '___')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", driver],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, f"stderr=\n{proc.stderr}"
        start = proc.stderr.find("___") + 3
        end = proc.stderr.rfind("___")
        info = json.loads(proc.stderr[start:end])
        assert info["missing"] == [], (
            f"shim no longer re-exports: {info['missing']}"
        )
