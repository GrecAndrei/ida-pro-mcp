"""AST + helper tests for the RPC hang-sentinel.

Three layers of defense against the "forever-wait for analysis" hang:

  (A) Hard cap on the socket recv timeout so no caller can pin the
      dispatcher open. The cap is read from ``IDA_MCP_RPC_MAX_RECV_TIMEOUT``
      (default 600s) and applied to the long-running whitelist.

  (B) Module-level ``LONG_RUNNING_ACTIONS`` whitelist that extends the
      socket recv timeout for full-program walks (analysis/*,
      summarize.binary, intelligence.index_batch, search.semantic,
      firmware_view.*, funcs.metrics, ...).

  (C) Wall-clock watchdog: total time spent in call_tool (RPC + retries
      + IDA compute) cannot exceed ``IDA_MCP_RPC_HARD_WALLCLOCK_SEC``
      (default 900s). Past the cap, the dispatcher terminates the IDA
      process and returns ``MCPError.IDA_TIMEOUT, recoverable=True``.

These tests are AST-driven because the production code touches
host-process state and subprocess lifecycle.
"""

import importlib
import os
import sys
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"


def _read(rel: Path) -> str:
    return rel.read_text()


def _import(name: str):
    if str(REPO / "src") not in sys.path:
        sys.path.insert(0, str(REPO / "src"))
    return importlib.import_module(name)


DISPATCH = (
    REPO / "src" / "ida_pro_mcp" / "host" / "server" / "server_dispatch.py"
)


# ---------------------------------------------------------------------------
# Module-level whitelist
# ---------------------------------------------------------------------------


def test_long_running_actions_constant_exists_at_module_level():
    src = _read(DISPATCH)
    assert "LONG_RUNNING_ACTIONS: set[tuple[str, str]]" in src
    # The whitelist is at module scope, not inside call_tool, so it's
    # inspectable and growable from a single place.
    assert src.index("LONG_RUNNING_ACTIONS:") < src.index("class ServerDispatchMixin")


def test_long_running_actions_includes_analysis_analyze():
    src = _read(DISPATCH)
    assert '("analysis", "analyze")' in src


def test_long_running_actions_includes_summarize_binary():
    src = _read(DISPATCH)
    assert '("summarize", "binary")' in src


def test_long_running_actions_includes_intelligence_index_batch():
    src = _read(DISPATCH)
    assert '("intelligence", "index_batch")' in src


def test_long_running_actions_includes_firmware_smart_carve():
    src = _read(DISPATCH)
    assert '("firmware_view", "smart_carve")' in src


def test_long_running_actions_includes_session_idle_purge():
    src = _read(DISPATCH)
    assert '("session", "idle_purge")' in src


# ---------------------------------------------------------------------------
# Helper: timeout computation
# ---------------------------------------------------------------------------


def test_helper_returns_minus_one_for_short_calls():
    """Anything not in the whitelist returns -1 (= default)."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "120"}, clear=False):
        out = mod._long_running_sock_timeout("code", {"action": "decompile"})
    assert out == -1


def test_helper_returns_120_minimum_for_whitelist_actions():
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "999999"}, clear=False):
        out = mod._long_running_sock_timeout("summarize", {"action": "binary"})
    assert out == 120


def test_helper_includes_caller_supplied_timeout_with_30s_buffer():
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "999999"}, clear=False):
        out = mod._long_running_sock_timeout(
            "analysis", {"action": "reanalyze", "timeout": 300}
        )
    # 300 + 30 = 330 (and 330 > 120 floor)
    assert out == 330


def test_helper_clamps_to_env_cap():
    """Caller asks for 9_999s; cap is 200; we must clamp."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "200"}, clear=False):
        out = mod._long_running_sock_timeout(
            "analysis", {"action": "reanalyze", "timeout": 9999}
        )
    assert out == 200


def test_helper_cap_floor_at_30s():
    """Even if env is set absurd-low, never go below 30s."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "0"}, clear=False):
        out = mod._long_running_sock_timeout("summarize", {"action": "binary"})
    # cap floor is 30, but whitelist floor is 120 → wins
    assert out == 30


def test_helper_handles_nonnumeric_timeout_arg():
    """A garbage timeout arg shouldn't kill the dispatcher."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "999999"}, clear=False):
        out = mod._long_running_sock_timeout(
            "analysis", {"action": "reanalyze", "timeout": "soon-ish"}
        )
    assert out == 120


def test_helper_reads_timeout_via_fallback_keys():
    """max_wait and poll_timeout are equivalent spellings. Caller-supplied
    timeout must clear the 120s floor when caller value + 30 > 120."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "999999"}, clear=False):
        out_a = mod._long_running_sock_timeout(
            "background", {"action": "wait", "max_wait": 200}
        )
        out_b = mod._long_running_sock_timeout(
            "firmware_view", {"action": "campaign", "poll_timeout": 90}
        )
    # 200 + 30 = 230
    assert out_a == 230
    # 90 + 30 = 120, which equals the 120s floor — still wins.
    assert out_b == 120


def test_helper_uses_floored_120_when_no_caller_timeout():
    """Default whitelist entry → 120s lower bound, even without env cap."""
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    with patch.dict(
        os.environ, {"IDA_MCP_RPC_MAX_RECV_TIMEOUT": "120"}, clear=False
    ):
        out = mod._long_running_sock_timeout(
            "intelligence", {"action": "index_batch"}
        )
    assert out == 120


# ---------------------------------------------------------------------------
# Wall-clock watchdog
# ---------------------------------------------------------------------------


def test_call_tool_pins_to_wallclock_cap():
    """After the cap, we surface IDA_TIMEOUT, recoverable=True."""
    src = _read(DISPATCH)
    # Source must reference the cap env var.
    assert "IDA_MCP_RPC_HARD_WALLCLOCK_SEC" in src
    # and the cap floor at 30s
    assert "_wallclock_cap = max(_wallclock_cap, 30.0)" in src
    # Must return IDA_TIMEOUT (not crash, not RPC_CONNECTION_ERROR).
    watchdog_idx = src.index("_wallclock_cap = max(_wallclock_cap, 30.0)")
    next_def = src.index("res = truncate_response", watchdog_idx)
    body = src[watchdog_idx:next_def]
    assert "MCPError.IDA_TIMEOUT" in body
    assert "recoverable=True" in body


def test_watchdog_attempts_to_terminate_ida_process():
    src = _read(DISPATCH)
    # Pin: the watchdog path uses proc.terminate with a 2s wait,
    # then escalates to proc.kill.
    watchdog_idx = src.index("# Wall-clock watchdog:")
    end = src.index("# Other socket errors", watchdog_idx)
    body = src[watchdog_idx:end]
    assert "proc.terminate()" in body
    assert "proc.wait(timeout=2.0)" in body
    assert "proc.kill()" in body


def test_watchdog_detail_includes_elapsed_and_cap():
    src = _read(DISPATCH)
    watchdog_idx = src.index("# Wall-clock watchdog:")
    end = src.index("# Other socket errors", watchdog_idx)
    body = src[watchdog_idx:end]
    assert "wallclock_cap_sec" in body
    assert "elapsed_sec" in body
    assert "tool" in body


# ---------------------------------------------------------------------------
# Recap: meta-test — the original concern was "the forever wait for
# analysis". That tuple must sit in the whitelist.
# ---------------------------------------------------------------------------


def test_analysis_analyze_is_the_canonical_hang_tuple():
    """The (analysis, analyze) tuple must be present in the
    LONG_RUNNING_ACTIONS whitelist — if a future refactor drops it,
    this test fires.
    """
    mod = _import("ida_pro_mcp.host.server.server_dispatch")
    assert ("analysis", "analyze") in mod.LONG_RUNNING_ACTIONS


def test_call_tool_uses_helper_not_local_constant():
    """If someone reintroduces a local _LONG_RUNNING_ACTIONS dict the
    helper-based path stops being used. Pin: only the module constant
    is wired in.
    """
    src = _read(DISPATCH)
    # Helper call site
    assert "_long_running_sock_timeout(tool_name, rpc_args)" in src
    # No remaining local _LONG_RUNNING_ACTIONS inside call_tool.
    # (Pattern check: the literal string "_LONG_RUNNING_ACTIONS = {" must
    # not exist anywhere in the file.)
    assert "_LONG_RUNNING_ACTIONS = {" not in src
