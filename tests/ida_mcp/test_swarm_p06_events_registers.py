"""Regression tests for WO-S5 (p06): idb events/registers + IDA event hooks.

Each test maps to a directive in the WO-S5 / p06 work order. All tests run
standalone with _FakeIda-style fakes — no live IDA, no MCP server:

- support/events.py: an IDB_Hooks subclass records ``auto_analysis_finished``
  and ``function_created`` into a bounded 500-entry event ring, invalidates the
  shared tool-result cache, and best-effort pushes an SSE notification; every
  hook body is wrapped so a recording failure never breaks analysis.
- idb(action='events'): reads the ring back ({type, address, name, timestamp}),
  newest first, honoring ``limit`` (capped at the ring size).
- idb(action='registers'): read-only enumeration of the processor register
  classes + CSRs via ida_idp (ph.reg_names / register index ranges; RISC-V CSR
  list where available), with per-class filtering.
- The opaque RISC-V raw-blob scenario: a headerless blob whose processor is
  riscv exposes a ``csr`` register class so an LLM can reason about
  ecall/mret/CSR handlers without hallucinating register names.
"""
import builtins
import inspect
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import (
    install_common_stub,
    load_ida_module,
    load_support_module,
    load_tool_module,
)

# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------

class _FakeIdbHooksBase:
    """Minimal stand-in for ``ida_idp.IDB_Hooks`` (hook/unhook bookkeeping)."""

    def __init__(self):
        self.hooked = False

    def hook(self):
        self.hooked = True

    def unhook(self):
        self.hooked = False


def _make_ph(reg_names, first_ireg=0, last_ireg=None, first_sreg=-1, last_sreg=-1):
    """Build a fake ``ida_idp.ph`` with the register table + index ranges."""
    ph = types.SimpleNamespace()
    ph.reg_names = list(reg_names)
    ph.reg_first_ireg = first_ireg
    ph.reg_last_ireg = len(reg_names) - 1 if last_ireg is None else last_ireg
    ph.reg_first_sreg = first_sreg
    ph.reg_last_sreg = last_sreg
    return ph


# 23-entry x86-64-ish table: 16 GPRs, rflags, then 6 segment registers.
_X86_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rflags", "cs", "ds", "es", "fs", "gs", "ss",
]

# RISC-V raw-blob register table: 32 GPRs + a couple of module-provided CSR
# names (the documented static CSR list must dedupe against these).
_RISCV_REGS = [f"x{i}" for i in range(32)] + ["csr_mstatus", "csr_mepc", "fflags"]


def _load_events_standalone():
    """Load support/events.py standalone with no-op sync/rpc neighbours.

    Registering blank sync/rpc modules keeps ``_invalidate_tool_cache`` and
    ``_sse_emit`` on the fast path instead of attempting to import the real
    host modules. No ``ida_idp`` stub is installed, so events.py uses its
    standalone fallback ``EventHooks`` and does not wire hooks.
    """
    install_common_stub()
    sys.modules["ida_pro_mcp.ida_mcp.sync"] = types.ModuleType("ida_pro_mcp.ida_mcp.sync")
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    return load_support_module("events")


def _load_idb(ph, proc_name="riscv"):
    """Load the idb tool module with a fake ida_idp + required ida_* stubs."""
    install_common_stub()
    ida_idp = types.ModuleType("ida_idp")
    ida_idp.IDB_Hooks = _FakeIdbHooksBase
    ida_idp.ph = ph
    sys.modules["ida_idp"] = ida_idp
    sys.modules["ida_entry"] = types.ModuleType("ida_entry")
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_cc_id = lambda: 0
    sys.modules["ida_ida"] = ida_ida
    mod = load_tool_module("idb")
    # `import *` skips underscore names when the stub has no __all__; inject the
    # processor-name reader the registers action needs (mirrors t08's pattern).
    mod._inf_procname = lambda: proc_name
    return mod


# ---------------------------------------------------------------------------
# support/events.py: event ring recording
# ---------------------------------------------------------------------------

def test_record_event_fills_ring_and_readable():
    events = _load_events_standalone()
    events.EVENT_RING.clear()
    ev = events.record_event("function_created", 0x401000, "sub_401000")
    assert ev["type"] == "function_created"
    assert ev["address"] == "0x401000"
    assert ev["name"] == "sub_401000"
    assert "timestamp" in ev
    result, total = events.read_events(50)
    assert total == 1
    assert result == [ev]


def test_event_ring_bounded_at_max():
    events = _load_events_standalone()
    events.EVENT_RING.clear()
    for i in range(510):
        events.record_event("function_created", 0x1000 + i, f"sub_{i}")
    assert len(events.EVENT_RING) == events.EVENT_RING_MAX == 500
    result, total = events.read_events(50)
    assert total == 500
    assert len(result) == 50
    # Newest first: the last recorded event leads, the window's oldest trails.
    assert result[0]["address"] == hex(0x1000 + 509)
    assert result[-1]["address"] == hex(0x1000 + 460)


def test_read_events_honors_limit_and_newest_first():
    events = _load_events_standalone()
    events.EVENT_RING.clear()
    for i in range(10):
        events.record_event("function_created", 0x1000 + i, f"sub_{i}")
    result, total = events.read_events(3)
    assert len(result) == 3
    assert total == 10
    assert result[0]["address"] == hex(0x1000 + 9)
    assert result[2]["address"] == hex(0x1000 + 7)
    # limit=0 returns nothing; a bad limit falls back to 50.
    assert events.read_events(0)[0] == []
    assert len(events.read_events("banana")[0]) == 10


# ---------------------------------------------------------------------------
# support/events.py: hook behaviour
# ---------------------------------------------------------------------------

def test_hook_methods_record_events():
    events = _load_events_standalone()
    events.EVENT_RING.clear()
    sys.modules["idc"].get_func_name = lambda ea: "sub_401000" if ea == 0x401000 else None
    hooks = events.EventHooks()
    hooks.auto_empty_finally()
    hooks.func_created(0x401000)
    result, total = events.read_events(10)
    assert total == 2
    assert result[0]["type"] == "function_created"
    assert result[0]["address"] == "0x401000"
    assert result[0]["name"] == "sub_401000"
    assert result[1]["type"] == "auto_analysis_finished"
    assert result[1]["address"] == ""


def test_hook_body_failure_never_breaks_analysis():
    events = _load_events_standalone()
    events.EVENT_RING.clear()
    hooks = events.EventHooks()

    def boom(*args, **kwargs):
        raise RuntimeError("recording exploded")

    original = events.record_event
    events.record_event = boom
    try:
        hooks.auto_empty_finally()   # must swallow, not raise
        hooks.func_created(0x401000)
    finally:
        events.record_event = original
    assert len(events.EVENT_RING) == 0  # nothing recorded while record() raised


def test_install_hooks_idempotent_and_unhook():
    install_common_stub()
    ida_idp = types.ModuleType("ida_idp")
    ida_idp.IDB_Hooks = _FakeIdbHooksBase
    sys.modules["ida_idp"] = ida_idp
    events = load_support_module("events")
    inst1 = events.install_hooks()
    assert inst1 is not None
    assert inst1.hooked is True
    assert events.install_hooks() is inst1  # idempotent
    sys.modules["idc"].get_func_name = lambda _ea: "created_func"
    inst1.auto_empty_finally()
    inst1.func_created(0x401000)
    events.unhook_hooks()
    assert inst1.hooked is False
    # Re-install after unhook yields a fresh, hooked instance.
    inst2 = events.install_hooks()
    assert inst2 is not inst1
    assert inst2.hooked is True
    events.unhook_hooks()


def test_install_hooks_guarded_outside_ida():
    events = _load_events_standalone()  # no ida_idp -> no hook wiring
    assert events.install_hooks() is None


def test_events_function_name_fallback_and_hook_cleanup_failures(monkeypatch):
    events = _load_events_standalone()
    idc = sys.modules["idc"]
    idaapi = types.ModuleType("idaapi")
    idaapi.get_func_name = lambda _ea: "idaapi_name"
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "", raising=False)
    assert events._func_name(0x401000) == "idaapi_name"

    class _BadHooks:
        def hook(self):
            raise RuntimeError("hook failed")

        def unhook(self):
            raise RuntimeError("unhook failed")

    events._IDB_HOOKS_BASE = _BadHooks
    events.EventHooks = _BadHooks
    events._INSTALLED_HOOKS = None
    assert events.install_hooks() is None
    events._INSTALLED_HOOKS = _BadHooks()
    events.unhook_hooks()


# ---------------------------------------------------------------------------
# support/events.py: cache invalidation + SSE best-effort push
# ---------------------------------------------------------------------------

def test_record_event_invalidates_shared_tool_cache():
    install_common_stub()
    cache = load_ida_module("cache")
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    load_ida_module("sync")  # registers ida_pro_mcp.ida_mcp.sync
    cache.TOOL_CACHE.put("code", {"x": 1}, {"a": 1})
    cache.TOOL_CACHE.put("code", {"x": 2}, {"a": 2})
    assert cache.TOOL_CACHE.stats()["entries"] == 2
    events = load_support_module("events")
    events.EVENT_RING.clear()
    events.record_event("function_created", 0x401000, "sub_401000")
    # The hook invalidated the exact cache singleton @idaread/@idawrite use.
    assert cache.TOOL_CACHE.stats()["entries"] == 0


def test_sse_emit_pushes_to_live_connections():
    install_common_stub()
    sent = []

    class _FakeConn:
        def send_event(self, event_type, data):
            sent.append((event_type, data))

    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.MCP_SERVER = types.SimpleNamespace(
        _sse_connections={"a": _FakeConn(), "b": _FakeConn()}
    )
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    events = load_support_module("events")
    events.EVENT_RING.clear()
    events.record_event("auto_analysis_finished", None, "")
    assert len(sent) == 2
    assert sent[0][0] == "analysis"
    assert sent[0][1]["type"] == "auto_analysis_finished"
    assert len(events.EVENT_RING) == 1  # still recorded alongside the push


def test_sse_emit_no_server_is_record_only():
    install_common_stub()
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.MCP_SERVER = None
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub
    events = load_support_module("events")
    events.EVENT_RING.clear()
    events.record_event("function_created", 0x401000, "")
    # Record-only when no SSE server/connections are reachable; no crash.
    assert len(events.EVENT_RING) == 1
    assert events.EVENT_RING[0]["type"] == "function_created"


def test_events_defensive_address_resolution_and_sse_connection_failures(monkeypatch):
    events = _load_events_standalone()
    assert events._fmt_addr(None) == ""
    assert events._fmt_addr(-1) == ""
    assert events._fmt_addr("not-an-address") == ""

    real_import = builtins.__import__

    def blocked_event_import(name, *args, **kwargs):
        if name in {"ida_pro_mcp.ida_mcp.rpc", "ida_mcp.rpc", "rpc"}:
            raise ImportError("rpc unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_event_import)
    assert events._resolve_mcp_server() is None
    events._invalidate_tool_cache()

    monkeypatch.undo()
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")

    class _DeadConnection:
        def send_event(self, *_args):
            raise RuntimeError("socket closed")

    rpc_stub.MCP_SERVER = types.SimpleNamespace(_sse_connections=[_DeadConnection()])
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.rpc", rpc_stub)
    events._sse_emit({"type": "test"})
    rpc_stub.MCP_SERVER = types.SimpleNamespace(_sse_connections={"dead": _DeadConnection()})
    events._sse_emit({"type": "test"})


# ---------------------------------------------------------------------------
# idb(action='events'): the ring read side through the tool dispatch
# ---------------------------------------------------------------------------

def test_idb_events_action_reads_ring():
    mod = _load_idb(_make_ph(_X86_REGS, first_ireg=0, last_ireg=15), proc_name="x86_64")
    events = sys.modules["ida_pro_mcp.ida_mcp.support.events"]
    events.EVENT_RING.clear()
    events.record_event("function_created", 0x401000, "sub_401000")
    events.record_event("auto_analysis_finished", None, "")
    res = mod.idb(action="events")
    assert res["ok"] is True, res
    assert res["count"] == 2
    assert res["total"] == 2
    assert res["events"][0]["type"] == "auto_analysis_finished"
    assert res["events"][0]["address"] == ""
    assert res["events"][1]["type"] == "function_created"
    assert res["events"][1]["address"] == "0x401000"
    assert res["events"][1]["name"] == "sub_401000"


def test_idb_events_action_honors_limit_capped_at_ring_size():
    mod = _load_idb(_make_ph(_X86_REGS, first_ireg=0, last_ireg=15), proc_name="x86_64")
    events = sys.modules["ida_pro_mcp.ida_mcp.support.events"]
    events.EVENT_RING.clear()
    for i in range(10):
        events.record_event("function_created", 0x1000 + i, f"sub_{i}")
    res = mod.idb(action="events", limit=3)
    assert res["ok"] is True, res
    assert res["count"] == 3
    assert res["limit"] == 3
    assert res["events"][0]["address"] == hex(0x1000 + 9)
    # Requests above the ring capacity clamp to the ring max.
    big = mod.idb(action="events", limit=9999)
    assert big["count"] == 10
    assert big["limit"] == 500


# ---------------------------------------------------------------------------
# idb(action='registers'): processor register classes + CSRs
# ---------------------------------------------------------------------------

def test_idb_registers_riscv_raw_blob_exposes_csr_class():
    """Opaque RISC-V blob: registers returns GPR + CSR classes so an LLM can
    reason about ecall/mret/CSR handlers without hallucinating names."""
    ph = _make_ph(_RISCV_REGS, first_ireg=0, last_ireg=31)
    mod = _load_idb(ph, proc_name="riscv")
    res = mod.idb(action="registers")
    assert res["ok"] is True, res
    assert res["processor"] == "riscv"
    assert res["reg_class"] == "all"
    classes = {c["reg_class"]: c["registers"] for c in res["classes"]}
    assert "gpr" in classes
    assert "x0" in classes["gpr"]
    assert "x31" in classes["gpr"]
    assert "csr" in classes
    assert "mstatus" in classes["csr"]
    # fflags is module-provided (in "other"); the static CSR list dedupes it.
    assert "fflags" in classes["other"]
    assert "fflags" not in classes["csr"]
    # The flat union carries both the GPR and CSR names.
    assert "x0" in res["registers"]
    assert "mstatus" in res["registers"]
    assert res["count"] >= 32


def test_idb_registers_x86_classes():
    ph = _make_ph(_X86_REGS, first_ireg=0, last_ireg=15, first_sreg=17, last_sreg=22)
    mod = _load_idb(ph, proc_name="metapc")
    res = mod.idb(action="registers")
    assert res["ok"] is True, res
    classes = {c["reg_class"]: c["registers"] for c in res["classes"]}
    assert classes["gpr"] == _X86_REGS[0:16]
    assert classes["segment"] == _X86_REGS[17:23]
    assert classes["other"] == ["rflags"]
    assert res["count"] == len(_X86_REGS)


def test_idb_registers_class_filter_and_unknown_class():
    ph = _make_ph(_RISCV_REGS, first_ireg=0, last_ireg=31)
    mod = _load_idb(ph, proc_name="riscv")
    res = mod.idb(action="registers", reg_class="csr")
    assert res["ok"] is True, res
    assert res["reg_class"] == "csr"
    assert "mstatus" in res["registers"]
    assert "x0" not in res["registers"]
    bad = mod.idb(action="registers", reg_class="nope")
    assert bad["ok"] is False
    assert bad["code"] == "INVALID_ARGS"


def test_idb_registers_unavailable_without_ida_idp():
    """When ida_idp cannot resolve (no live IDA runtime) the action degrades
    to an error envelope instead of crashing the tool."""
    install_common_stub()
    sys.modules["ida_entry"] = types.ModuleType("ida_entry")
    sys.modules["ida_ida"] = types.ModuleType("ida_ida")
    sys.modules.pop("ida_idp", None)
    mod = load_tool_module("idb")
    mod._inf_procname = lambda: "riscv"
    res = mod.idb(action="registers")
    assert res["ok"] is False
    assert res["code"] == "IDA_ERROR"


def test_idb_registers_synthesizes_sparse_processor_table(monkeypatch):
    """IDA 9.x may expose names only through get_reg_name()."""
    ph = _make_ph([], first_ireg=0, last_ireg=1)
    mod = _load_idb(ph, proc_name="riscv")
    ida_idp = sys.modules["ida_idp"]
    names = {(0, 8): "x0", (1, 8): "x1", (2, 8): "pc"}
    monkeypatch.setattr(ida_idp, "get_reg_name", lambda reg, width: names.get((reg, width)), raising=False)
    monkeypatch.setattr(ida_idp, "ph_get_reg_first_sreg", lambda: 2, raising=False)
    monkeypatch.setattr(ida_idp, "ph_get_reg_last_sreg", lambda: 2, raising=False)
    result = mod.idb(action="registers")
    assert result["ok"] is True, result
    classes = {item["reg_class"]: item["registers"] for item in result["classes"]}
    assert classes["gpr"] == ["x0"]
    assert classes["segment"] == ["pc"]
    assert classes["other"] == ["x1"]
    assert classes["segment"] == ["pc"]
    assert "mstatus" in classes["csr"]


def test_idb_state_composes_active_audit_raw_blob_and_debugger_modes(monkeypatch, tmp_path):
    mod = _load_idb(_make_ph(_X86_REGS, first_ireg=0, last_ireg=15), proc_name="metapc")
    idb_path = tmp_path / "state.i64"
    input_path = tmp_path / "opaque.bin"
    idb_path.write_bytes(b"idb")
    input_path.write_bytes(b"opaque binary")
    audit_day = tmp_path / "audit" / "2026-09"
    audit_day.mkdir(parents=True)
    (audit_day / "audit_2026-09-01.jsonl").write_text(
        '{"ts":"now","tool":"idb","action":"state","latency_ms":2}\n'
        "not-json\n"
        "[1]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(mod.idaapi, "get_idb_path", lambda: str(idb_path), raising=False)
    monkeypatch.setattr(mod.idaapi, "get_input_file_path", lambda: str(input_path), raising=False)
    monkeypatch.setattr(mod.idaapi, "auto_state", lambda: 4, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_auto_display", lambda: "Analyzing", raising=False)
    monkeypatch.setattr(mod.idaapi, "auto_is_ok", lambda: False, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_func_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_strlist_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.idaapi, "is_debugger_on", lambda: True, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_process_state", lambda: 2, raising=False)
    monkeypatch.setattr(mod.ida_nalt, "get_import_module_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.ida_entry, "get_entry_qty", lambda: 0, raising=False)
    monkeypatch.setattr(mod.ida_kernwin, "get_cursor_ea", lambda: 0x401000, raising=False)
    state = mod.idb_state(audit_tail=5)
    assert state["ok"] is True
    assert state["analysis"] == {
        "state": "FINAL_IDB", "state_id": 4, "display": "Analyzing",
        "is_ok": False, "active": True,
    }
    assert state["database"]["input_size"] == len(b"opaque binary")
    assert state["inventory"]["functions_qty"] == 0
    assert state["ui"]["cursor_ea"] == "0x401000"
    assert state["debugger"] == {"active": True, "process_state": "PROCESS_RUNNING"}
    assert len(state["audit_tail"]) == 1
    assert state["audit_tail"][0]["ok"] is True
    assert state["indicators"]["raw_blob"] is True
    assert state["indicators"]["arch_unverified"] is True
    assert state["indicators"]["needs_packer_check"] is True


# ---------------------------------------------------------------------------
# idb action surface advertises the new actions
# ---------------------------------------------------------------------------

def test_idb_advertises_events_and_registers_actions():
    mod = _load_idb(_make_ph(_X86_REGS, first_ireg=0, last_ireg=15), proc_name="x86_64")
    anno = str(inspect.signature(mod.idb).parameters["action"].annotation)
    assert "events" in anno
    assert "registers" in anno
