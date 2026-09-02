"""Swarm s1: bridge lifecycle — listener-up-during-analysis + real shutdown handler.

Pins the s05-h02-bridge work order against ``server_script.py`` (the IDA-side
RPC bridge) WITHOUT a live IDA (``_FakeIda``-style fakes for ida_loader /
ida_auto / the tool layer):

- ``__main__`` starts ``run_server()`` on a dedicated thread BEFORE startup
  auto-analysis, so the host's liveness probe succeeds while an opaque raw
  blob (e.g. a RISC-V firmware .bin) is still being analyzed. Ping is
  auth-free, answers during analysis, reports ``analyzing: true``, and carries
  the real bound port (ephemeral-port self-heal: the port file is published
  and ping echoes ``_BOUND_PORT``).
- Tool calls that arrive during the analysis window are gated with
  ANALYSIS_INCOMPLETE (``recoverable=True``); once ``_STARTUP_DONE`` is set the
  same listener thread serves them (verified over a real socket against an
  opaque RISC-V raw-blob scenario where the canonical parser resolves bare
  hex inside the image window).
- A real ``type=="shutdown"`` handler exists (previously a no-op / INVALID_REQUEST
  that abandoned the unpacked .id0/.id1 sidecars): it is authenticated, is
  handled BEFORE the startup gate (a session can be torn down mid-analysis),
  sets ``_SHUTDOWN_EVENT`` so ``run_server``'s accept loop exits, and
  best-effort ``save_database``s the IDB at ``IDA_MCP_IDB_PATH`` once startup
  is done. A failing save never crashes the bridge.
- ``_run_startup_analysis`` skips reanalysis + save when shutdown arrived
  during auto_wait (no wasted I/O racing the kill).

The keep=true host-side contract
``test_swarm_f04_runtime.py::test_cleanup_sends_shutdown_before_popping_runtime``
pins that the host still sends ``{"type": "shutdown"}`` before removing the
runtime; this file pins the bridge half of that exchange.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import socket
import sys
import threading
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "ida_pro_mcp"
SRC_SERVER_SCRIPT = SRC / "server_script.py"
IDA_MCP = SRC / "ida_mcp"


# ===========================================================================
# Standalone loader (fake IDA modules, no idat.exe required)
# ===========================================================================

def _load_module(name: str, relpath: str):
    """Load a source module standalone (no package __init__) and return it."""
    path = Path(relpath)
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _register_ida_mcp_stub_packages():
    """Register ``ida_pro_mcp`` / ``ida_pro_mcp.ida_mcp`` stub packages so
    ``from ida_pro_mcp.ida_mcp.error_handling import ...`` resolves to the
    standalone-loaded module instead of the real (IDA-dependent) package."""
    pkg = sys.modules.get("ida_pro_mcp") or types.ModuleType("ida_pro_mcp")
    pkg.__path__ = [str(SRC)]
    sys.modules["ida_pro_mcp"] = pkg
    sub = sys.modules.get("ida_pro_mcp.ida_mcp") or types.ModuleType("ida_pro_mcp.ida_mcp")
    sub.__path__ = [str(IDA_MCP)]
    sys.modules["ida_pro_mcp.ida_mcp"] = sub


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    """Load server_script.py standalone with fake IDA modules. The autouse
    ``_isolate_sys_modules`` fixture restores sys.modules after each test, so
    every test gets a freshly-executed module (fresh events/globals)."""
    monkeypatch.setenv("IDA_MCP_SESSION_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("IDA_MCP_SESSION_TOKEN", "secret")
    monkeypatch.delenv("IDA_MCP_IDB_PATH", raising=False)
    monkeypatch.delenv("IDA_MCP_PORT", raising=False)
    monkeypatch.delenv("IDA_MCP_PORT_FILE", raising=False)
    monkeypatch.delenv("IDA_MCP_USE_EXISTING_IDB", raising=False)
    _register_ida_mcp_stub_packages()
    eh = _load_module("s1_error_handling_ut", str(IDA_MCP / "error_handling.py"))
    sys.modules["ida_pro_mcp.ida_mcp.error_handling"] = eh
    # Replace (not setdefault): a prior test may have mutated the shared `idc`
    # stub in place (e.g. `idc.get_name_ea_simple = ...`), and
    # `_restore_sys_modules` only reverts module identity, not attribute
    # mutation. Reusing that polluted module makes `parse_address_canonical`
    # resolve a bare hex token via the symbol branch instead of the image-window
    # digit path. A fresh empty module keeps the bridge deterministic.
    for name in ("ida_segment", "idautils", "idc"):
        sys.modules[name] = types.ModuleType(name)
    mod = _load_module("s1_server_script_ut", str(SRC_SERVER_SCRIPT))
    mod._eh = eh  # expose the shared error factory for tools in tests
    return mod


class _FakeIdaLoader:
    """Recording stand-in for ida_loader.save_database."""

    def __init__(self):
        self.saved = []

    def save_database(self, path="", flags=0):
        self.saved.append(path)
        return True


def _inject_ida_loader(monkeypatch, loader):
    monkeypatch.setitem(sys.modules, "ida_loader", loader)


# ===========================================================================
# Real-socket helpers (the accept loop runs on a real thread)
# ===========================================================================

def _recv_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(min(length - len(data), 65536))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _rpc_roundtrip(port, payload):
    """Send one length-prefixed JSON request over a fresh connection and read
    the length-prefixed response. The server's protocol is one request per
    connection (run_server closes the conn after answering), so each round
    trip needs a new socket."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sock.sendall(len(data).to_bytes(4, "big") + data)
        raw_len = _recv_exact(sock, 4)
        assert raw_len is not None, "server closed the socket mid-response"
        body = _recv_exact(sock, int.from_bytes(raw_len, "big"))
        assert body is not None, "server closed the socket mid-response"
        return json.loads(body.decode("utf-8"))


@contextlib.contextmanager
def _running_bridge(mod, tmp_path, monkeypatch):
    """Run the real RPC accept loop on a thread against an ephemeral port.

    Mirrors the production topology exactly: the accept loop lives on the
    'listener' thread, while a separate 'main' thread drains ``_TOOL_QUEUE``
    (the real main thread does that in ``__main__`` after startup analysis).
    Tool bodies therefore execute on the drainer thread — the same handoff the
    runtime uses to keep IDA 9.x main-thread-only APIs on the main thread.
    """
    port_file = tmp_path / "bridge.port"
    monkeypatch.setenv("IDA_MCP_PORT", "0")
    monkeypatch.setenv("IDA_MCP_PORT_FILE", str(port_file))
    thread = threading.Thread(target=mod.run_server, name="s1-test-listener", daemon=True)
    thread.start()
    stop_drainer = threading.Event()

    def _drain_loop():
        while not stop_drainer.is_set():
            mod._drain_tool_queue()
            stop_drainer.wait(timeout=0.02)

    drainer = threading.Thread(target=_drain_loop, name="s1-test-main", daemon=True)
    drainer.start()
    assert mod._SERVER_READY.wait(timeout=10.0), "run_server never became ready"
    assert port_file.exists(), "run_server never published the port file"
    port = int(port_file.read_text(encoding="ascii").strip())
    assert port == mod._BOUND_PORT, "reported port must match the bound port"
    try:
        yield port, thread
    finally:
        stop_drainer.set()
        mod._SHUTDOWN_EVENT.set()
        drainer.join(timeout=5)
        thread.join(timeout=5)
        assert not thread.is_alive(), "listener thread did not stop after _SHUTDOWN_EVENT"


# ===========================================================================
# Startup ping decoupled from analysis duration
# ===========================================================================

def test_standalone_defaults_never_gate_or_shutdown(bridge):
    """Outside ``__main__`` (standalone/test invocations) the bridge must be
    start-of-day usable: startup analysis is considered done (no gate) and no
    shutdown is pending."""
    assert bridge._STARTUP_DONE.is_set() is True
    assert bridge._SHUTDOWN_EVENT.is_set() is False


def test_ping_answers_during_analysis_and_reports_analyzing(bridge):
    """The startup ping is auth-free, answers while startup analysis is in
    flight, and flips to ``analyzing: false`` once the gate lifts — the
    host's liveness probe is decoupled from the analysis duration."""
    bridge._STARTUP_DONE.clear()
    try:
        ping = bridge.process_single({"type": "ping"})
        assert ping["pong"] is True
        assert ping["analyzing"] is True
        assert ping.get("startup_error") is None
    finally:
        bridge._STARTUP_DONE.set()
    ping = bridge.process_single({"type": "ping"})
    assert ping["pong"] is True
    assert ping["analyzing"] is False


def test_tool_calls_gated_while_analyzing_then_served(bridge):
    """Mirror of the host-side safe_mode gate: tool calls during the analysis
    window are ANALYSIS_INCOMPLETE (recoverable), and run once the gate lifts."""
    calls = []
    bridge.TOOLS = {"analysis": lambda action="status", **kwargs: calls.append(action) or {"ok": True}}
    bridge._STARTUP_DONE.clear()
    try:
        res = bridge.process_single(
            {"tool": "analysis", "args": {"action": "state"}, "session_token": "secret"}
        )
        assert res["error"] is True
        assert res["code"] == "ANALYSIS_INCOMPLETE"
        assert res["recoverable"] is True
        assert calls == [], "tool must not run while startup analysis is in flight"
    finally:
        bridge._STARTUP_DONE.set()
    res = bridge.process_single(
        {"tool": "analysis", "args": {"action": "state"}, "session_token": "secret"}
    )
    assert res["ok"] is True
    assert calls == ["state"]


# ===========================================================================
# Main-thread dispatch handoff
# ===========================================================================

def test_rpc_routing_pings_inline_and_tools_queued(bridge):
    """Pings — and anything before the startup gate — are answered inline on
    the listener thread. Once the gate lifts, every non-ping request (tool
    calls AND shutdown, whose save_database is main-thread-only) is queued to
    _TOOL_QUEUE for the main thread's drain loop."""
    # Pre-startup: every request is answered inline, nothing queued.
    bridge._STARTUP_DONE.clear()
    try:
        assert bridge._rpc_handled_inline({"type": "ping"}) is True
        assert bridge._rpc_handled_inline({"tool": "analysis", "args": {}}) is True
        assert bridge._rpc_handled_inline({"type": "shutdown"}) is True
    finally:
        bridge._STARTUP_DONE.set()
    assert bridge._TOOL_QUEUE.empty()

    # Post-startup: ping stays inline; tool calls and shutdown are queued.
    assert bridge._rpc_handled_inline({"type": "ping"}) is True
    assert bridge._rpc_handled_inline({"tool": "analysis", "args": {}}) is False
    assert bridge._rpc_handled_inline({"type": "shutdown"}) is False


def test_dispatch_executes_on_drainer_thread(bridge):
    """_dispatch_on_main_thread blocks until the drainer (the main thread in
    production) runs process_single — the tool body must never run on the RPC
    caller's thread — and the caller receives the tool's exact result."""
    ran_on = []
    bridge.TOOLS = {
        "analysis": lambda action="status", **kwargs: ran_on.append(
            threading.current_thread()
        )
        or {"ok": True, "action": action}
    }
    result_box = {}
    queued = threading.Event()
    real_queue = bridge._TOOL_QUEUE

    class _QueueProxy:
        def put(self, item):
            real_queue.put(item)
            queued.set()

        def get_nowait(self):
            return real_queue.get_nowait()

        def empty(self):
            return real_queue.empty()

    bridge._TOOL_QUEUE = _QueueProxy()

    def _caller():
        result_box["res"] = bridge._dispatch_on_main_thread(
            {"tool": "analysis", "args": {"action": "state"}, "session_token": "secret"}
        )

    t = threading.Thread(target=_caller, name="rpc-caller", daemon=True)
    t.start()
    assert queued.wait(timeout=2), "caller never enqueued the request"
    bridge._drain_tool_queue()
    t.join(timeout=5)
    assert not t.is_alive(), "caller must be unblocked once the main thread drains"
    assert result_box["res"] == {"ok": True, "action": "state"}
    assert len(ran_on) == 1
    assert ran_on[0] is threading.current_thread(), "tool body must run on the draining thread, not the caller"


# ===========================================================================
# Real shutdown handler
# ===========================================================================

def test_shutdown_requires_auth_and_leaves_event_clear(bridge):
    """Shutdown is authenticated like every non-ping message; a missing or bad
    token is UNAUTHORIZED and must not set the shutdown event."""
    res = bridge.process_single({"type": "shutdown"})
    assert res["error"] is True
    assert res["code"] == "UNAUTHORIZED"
    assert bridge._SHUTDOWN_EVENT.is_set() is False

    res2 = bridge.process_single({"type": "shutdown", "session_token": "wrong"})
    assert res2["error"] is True
    assert res2["code"] == "UNAUTHORIZED"
    assert bridge._SHUTDOWN_EVENT.is_set() is False


def test_shutdown_after_startup_saves_idb(bridge, monkeypatch, tmp_path):
    """A real shutdown after startup analysis: best-effort save_database merges
    the unpacked .id0/.id1 sidecars into the .i64 at the canonical session
    path (the host then kills the tree, so the save must already be done)."""
    loader = _FakeIdaLoader()
    _inject_ida_loader(monkeypatch, loader)
    idb = tmp_path / "SID_ABCD1234_sample.bin.i64"
    monkeypatch.setenv("IDA_MCP_IDB_PATH", str(idb))

    res = bridge.process_single({"type": "shutdown", "session_token": "secret"})

    assert res == {"ok": True, "shutdown": True, "saved": True, "analysis_complete": True}
    assert loader.saved == [str(idb)]
    assert bridge._SHUTDOWN_EVENT.is_set() is True


def test_shutdown_during_startup_is_honored_before_gate_and_skips_save(bridge, monkeypatch):
    """A session can be torn down mid-startup-analysis: the shutdown branch
    runs BEFORE the ANALYSIS_INCOMPLETE gate, and save_database is skipped so
    it never races the main thread's auto_wait (which owns the IDB)."""
    loader = _FakeIdaLoader()
    _inject_ida_loader(monkeypatch, loader)
    bridge._STARTUP_DONE.clear()

    res = bridge.process_single({"type": "shutdown", "session_token": "secret"})

    assert res["ok"] is True
    assert res["shutdown"] is True
    assert res["saved"] is False
    assert res["analysis_complete"] is False
    assert loader.saved == [], "save_database must not race the main-thread startup analysis"
    assert bridge._SHUTDOWN_EVENT.is_set() is True


def test_shutdown_save_failure_is_best_effort(bridge, monkeypatch):
    """A failing save_database (ENOSPC, read-only FS) must never crash the
    bridge or block the accept-loop stop — ``saved: false``, ``ok`` still
    true, event still set."""
    loader = _FakeIdaLoader()

    def _boom(path="", flags=0):
        raise RuntimeError("No space left on device")

    loader.save_database = _boom
    _inject_ida_loader(monkeypatch, loader)

    res = bridge.process_single({"type": "shutdown", "session_token": "secret"})

    assert res["ok"] is True
    assert res["shutdown"] is True
    assert res["saved"] is False
    assert bridge._SHUTDOWN_EVENT.is_set() is True


def test_shutdown_save_false_reported_not_ok(bridge, monkeypatch):
    """save_database returning False means the save did not happen — the bridge
    reports ``saved: false`` instead of claiming success."""
    loader = _FakeIdaLoader()
    loader.save_database = lambda path="", flags=0: False
    _inject_ida_loader(monkeypatch, loader)

    res = bridge.process_single({"type": "shutdown", "session_token": "secret"})

    assert res["ok"] is True
    assert res["saved"] is False
    assert res["analysis_complete"] is True


def test_startup_skips_reanalysis_and_save_when_shutdown_requested(bridge, monkeypatch):
    """If the host tears the session down while auto_wait is still running,
    ``_run_startup_analysis`` must NOT spend I/O on reanalysis + save that
    races the imminent kill — but must still lift the gate so a late shutdown
    saves once the main thread is idle."""
    class _FakeAuto:
        AU_NONE = -1

        def auto_wait(self):
            return None

        def get_auto_state(self):
            return -1  # AU_NONE: analysis queue idle

    monkeypatch.setitem(sys.modules, "ida_auto", _FakeAuto())
    loader = _FakeIdaLoader()
    _inject_ida_loader(monkeypatch, loader)

    bridge._SHUTDOWN_EVENT.set()
    bridge._run_startup_analysis()

    assert bridge._STARTUP_DONE.is_set() is True
    assert loader.saved == [], "no save_database may run while a shutdown is pending"


# ===========================================================================
# Real accept loop: listener up during analysis, shutdown stops it
# ===========================================================================

def test_listener_up_during_opaque_riscv_analysis_then_unblocks(bridge, tmp_path, monkeypatch):
    """The real accept loop answers pings and gates tool calls while an opaque
    RISC-V raw blob's startup analysis is still running; once the main thread
    finishes analysis the same listener serves the RISC-V gadget lookup (bare
    hex inside the image window resolves; an unmapped token is refused)."""
    eh = bridge._eh
    monkeypatch.setattr(eh, "_image_min_ea", lambda: 0x800)
    monkeypatch.setattr(eh, "_image_max_ea", lambda: 0x1000)

    def riscv_gadget(address, **kwargs):
        addr, err = eh.parse_address_canonical(address)
        if err:
            return err
        return {"ok": True, "gadget": f"gadget@0x{addr:x}"}

    bridge.TOOLS = {"gadgets": riscv_gadget}
    bridge._STARTUP_DONE.clear()  # opaque RISC-V raw blob, still analyzing

    with _running_bridge(bridge, tmp_path, monkeypatch) as (port, _thread):
        ping = _rpc_roundtrip(port, {"type": "ping"})
        assert ping["pong"] is True
        assert ping["analyzing"] is True
        assert ping["port"] == port

        gated = _rpc_roundtrip(
            port, {"tool": "gadgets", "args": {"address": "900"}, "session_token": "secret"}
        )
        assert gated["error"] is True
        assert gated["code"] == "ANALYSIS_INCOMPLETE"
        assert gated["recoverable"] is True

        # The main thread finishes startup analysis -> gate lifts.
        bridge._STARTUP_DONE.set()
        ok = _rpc_roundtrip(
            port, {"tool": "gadgets", "args": {"address": "900"}, "session_token": "secret"}
        )
        assert ok["ok"] is True
        assert ok["gadget"] == "gadget@0x900"

        unmapped = _rpc_roundtrip(
            port, {"tool": "gadgets", "args": {"address": "401000"}, "session_token": "secret"}
        )
        assert unmapped["error"] is True
        assert unmapped["code"] == "ADDRESS_INVALID"
        assert "0x prefix" in unmapped.get("hint", "")


def test_shutdown_over_wire_stops_accept_loop(bridge, tmp_path, monkeypatch):
    """A real shutdown request over the RPC socket answers, sets the event, and
    makes ``run_server``'s accept loop exit on its own. The process then winds
    down with the sidecar-merged .i64 in place instead of being killed with
    the .id0/.id1 abandoned."""
    # Gate open (startup in flight) so _handle_shutdown takes the skip-save
    # branch: the response is deterministic and needs no ida_loader.
    bridge._STARTUP_DONE.clear()

    with _running_bridge(bridge, tmp_path, monkeypatch) as (port, thread):
        res = _rpc_roundtrip(port, {"type": "shutdown", "session_token": "secret"})
        assert res["ok"] is True
        assert res["shutdown"] is True
        assert res["saved"] is False
        assert bridge._SHUTDOWN_EVENT.is_set() is True
        thread.join(timeout=5)
        assert not thread.is_alive(), "accept loop must stop once shutdown is handled"
