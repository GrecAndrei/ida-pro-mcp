"""Regression tests for `analysis(action='plugin_run')` routing.

Bug: the host dispatcher shim `_handle_analysis_plugin_run` forwarded
`"tool": "analysis"` to the IDA runtime with `"action": "plugin_run"`,
but `analysis` Literal in `ida_mcp/tools/analysis.py` does NOT include
`plugin_run` — only `misc` does. The zeromcp RPC validator rejects
unknown Literal values, so callers would silently 500.

Fix: forward to `misc` (where `plugin_run` lives in the Literal set).
"""

import os
import re
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def _build_dispatcher():
    from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin

    class FakeDispatcher(ServerDispatchMixin):
        def __init__(self):
            self._rpc_calls = []

        # Override the static method as instance method for testing
        def _runtime_alive(self, runtime):  # type: ignore[override]
            return bool(runtime)

        def _send_rpc_raw(self, payload, port):
            self._rpc_calls.append((payload, port))
            return {"ok": True, "echo": payload}

    return FakeDispatcher()


def _make_session_ctx():
    """Wire the `current_session` + `session_runtimes` slot used by plugin_run."""
    from unittest.mock import Mock

    dispatch = _build_dispatcher()
    dispatch.current_session = Mock(session_id="A1B2C3D4")
    dispatch.session_runtimes = {
        "A1B2C3D4": {"port": 31337, "pid": 9999, "process": Mock(returncode=None)}
    }
    return dispatch


def test_plugin_run_routes_to_misc_not_analysis():
    """Dispatch must go to `misc(action='plugin_run')` because that's the
    only tool whose Literal set includes `plugin_run`."""
    dispatch = _make_session_ctx()
    result = dispatch._handle_analysis_plugin_run({"name": "MyPlugin", "arg": 0})
    assert result["ok"] is True
    assert result["echo"] == {
        "tool": "misc", "args": {"action": "plugin_run", "name": "MyPlugin", "arg": 0}
    }
    # The response self-identifies the session the plugin ran in, so a call
    # aimed at the wrong session on a shared connection is visible instead of
    # silently attributed to the shared active session.
    assert result["_executed_in"]["session_id"] == "A1B2C3D4"


def test_plugin_run_resolves_idb_target():
    """An explicit idb ref must target that session (with ownership) rather
    than silently running in the shared active session."""
    from unittest.mock import Mock

    dispatch = _build_dispatcher()
    dispatch.current_session = Mock(session_id="ACTIVE")
    dispatch.session_runtimes = {
        "ACTIVE": {"port": 31337, "pid": 9999, "process": Mock(returncode=None)},
        "TARGET": {"port": 31338, "pid": 9998, "process": Mock(returncode=None)},
    }
    # Ownership: TARGET is recorded as owned by this connection, so the guard
    # passes and the plugin runs there.
    state = dispatch._client_request_state()
    state.owned_session_ids.add("TARGET")
    dispatch._resolve_session_from_idb_ref = lambda ref: (
        Mock(session_id="TARGET", idb_path="/tmp/target.i64")
        if ref == "TARGET"
        else None
    )
    result = dispatch._handle_analysis_plugin_run(
        {"name": "MyPlugin", "idb": "TARGET"}
    )
    assert result.get("ok") is True
    assert result["_executed_in"]["session_id"] == "TARGET"


def test_plugin_run_rejects_unowned_idb_target():
    """An explicit idb ref pointing at a session this connection does not own
    must be refused before any plugin code runs."""
    from unittest.mock import Mock

    dispatch = _build_dispatcher()
    dispatch.current_session = Mock(session_id="ACTIVE")
    dispatch.session_runtimes = {
        "ACTIVE": {"port": 31337, "pid": 9999, "process": Mock(returncode=None)},
        "TARGET": {"port": 31338, "pid": 9998, "process": Mock(returncode=None)},
    }
    dispatch._resolve_session_from_idb_ref = lambda ref: (
        Mock(session_id="TARGET", idb_path="/tmp/target.i64")
        if ref == "TARGET"
        else None
    )
    # TARGET has a live runtime held by another connection -> FILE_LOCKED.
    # Provide the full ownership-report shape: the FILE_LOCKED error copies
    # specific keys verbatim (report[k], not report.get(k)).
    dispatch._session_ownership_report = lambda sid: {
        "locked": True,
        "holder": "another connection on this server",
        "owner_id": None,
        "owner_pid": None,
        "owner_alive": None,
        "idat_pid": 9998,
        "lease_age_seconds": 12.0,
        "lease_updated_at": None,
    }
    result = dispatch._handle_analysis_plugin_run(
        {"name": "MyPlugin", "idb": "TARGET"}
    )
    assert result.get("ok") is not True
    assert result.get("code") == "FILE_LOCKED"


def test_plugin_run_validates_name():
    dispatch = _make_session_ctx()
    err = dispatch._handle_analysis_plugin_run({"name": "", "arg": 0})
    assert err.get("code") == "INVALID_ARGS"
    assert "name" in err.get("message", "").lower()


def test_plugin_run_arg_must_be_int():
    dispatch = _make_session_ctx()
    err = dispatch._handle_analysis_plugin_run({"name": "MyPlugin", "arg": "not-an-int"})
    assert err.get("code") == "INVALID_ARGS"


def test_plugin_run_requires_live_runtime():
    dispatch = _build_dispatcher()
    from unittest.mock import Mock

    dispatch.current_session = Mock(session_id="A1B2C3D4")
    dispatch.session_runtimes = {}
    err = dispatch._handle_analysis_plugin_run({"name": "MyPlugin"})
    assert err.get("code") == "IDA_CRASHED"


def test_plugin_run_literal_lives_only_on_misc():
    """The Literal source-of-truth — both `analysis` and `misc` files —
    must agree with the dispatcher routing. Use AST parsing so the test
    does not require the full `ida_mcp` package to import (which needs
    `zeromcp`, unavailable in headless test environments)."""

    tools_dir = Path(ROOT) / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"
    analysis_src = (tools_dir / "analysis.py").read_text()
    misc_src = (tools_dir / "misc.py").read_text()

    # Extract first Literal[...] block following `action:` (covers both
    # `action: Annotated[Literal[...], ...]` and bare `action: Literal[...]`).
    def literal(src: str) -> list[str]:
        m = re.search(r"action\s*:\s*(?:Annotated\s*\[\s*)?Literal\s*\[([^\]]+)\]", src)
        if not m:
            return []
        return [s.strip().strip('"\'') for s in m.group(1).split(",")]  # noqa: W291

    analysis_actions = literal(analysis_src)
    misc_actions = literal(misc_src)

    assert "plugin_run" in misc_actions, (
        f"misc Literal must include plugin_run; got {misc_actions!r}"
    )
    assert "plugin_run" not in analysis_actions, (
        f"analysis Literal must NOT include plugin_run "
        f"(that's the bug — RPC would reject). Got {analysis_actions!r}"
    )


def test_plugin_run_dispatch_payload_text():
    """Final ship-shape check: the host's dispatch payload, as a literal
    JSON string, would be accepted by the IDA runtime. Assert this at the
    AST level to avoid importing zeromcp."""
    import ast

    dispatch_src = Path(ROOT, "src", "ida_pro_mcp", "host", "server", "server_dispatch.py").read_text()
    tree = ast.parse(dispatch_src)

    found_handler = False
    found_tool_misc = False
    found_tool_analysis = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name != "_handle_analysis_plugin_run":
            continue
        found_handler = True
        for child in ast.walk(node):
            if not isinstance(child, ast.Dict):
                continue
            for k in (child.keys or []):
                if not isinstance(k, ast.Constant) or k.value != "tool":
                    continue
                for v in child.values:
                    if isinstance(v, ast.Constant):
                        if v.value == "misc":
                            found_tool_misc = True
                        if v.value == "analysis":
                            found_tool_analysis = True

    assert found_handler, "Could not find _handle_analysis_plugin_run"
    assert found_tool_misc, (
        "Dispatcher must send payload to misc (where plugin_run is valid)"
    )
    assert not found_tool_analysis, (
        "Dispatcher must NOT send payload to analysis "
        "(plugin_run is not in its Literal set — would be rejected)"
    )
