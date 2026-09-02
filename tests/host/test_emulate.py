"""Host-side unit tests for the ``emulate`` tool (ida_dbg-backed emulation).

These tests mock the IDA side and must pass WITHOUT a live IDA. A fake
``ida_dbg`` module (plus the arch/error helpers the tool pulls from
``_common``) is installed in ``sys.modules`` BEFORE
``load_tool_module("emulate", common_overrides={"ida_dbg": fake_dbg})`` loads
the real tool source from ``src/ida_pro_mcp/ida_mcp/tools/emulate.py``.

The autouse ``_isolate_sys_modules`` conftest fixture (which already tracks
``ida_dbg`` in ``_SHARED_STUB_MODULES`` and purges
``ida_pro_mcp.ida_mcp.tools.*`` submodules per test) gives per-test isolation
for free: every test rebuilds a fresh fake + reloads the tool module.

Because the tool caches ``_BACKEND``/``_BACKEND_REASON``/``_PROCESS_STARTED``
as module globals, ``setUp`` resets them after every load.
"""

from __future__ import annotations

import ctypes
import sys
import types
import unittest
from unittest import mock

from tests._isolated_repo_loader import load_tool_module


# ---------------------------------------------------------------------------
# _common overrides the emulate module imports via `from ._common import *`
# ---------------------------------------------------------------------------
class _MCPError:
    """MCPError codes the emulate tool references (subset of the real set)."""

    UNKNOWN = "UNKNOWN_ERROR"
    INVALID_ARGS = "INVALID_ARGS"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_FOUND = "NOT_FOUND"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    MISSING_REQUIRED_ARG = "MISSING_REQUIRED_ARG"
    INVALID_ARG_VALUE = "INVALID_ARG_VALUE"
    INVALID_ARG_COMBINATION = "INVALID_ARG_COMBINATION"
    IDA_ERROR = "IDA_ERROR"
    ADDRESS_INVALID = "ADDRESS_INVALID"
    ADDRESS_NOT_MAPPED = "ADDRESS_NOT_MAPPED"
    FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
    DEBUGGER_NOT_RUNNING = "DEBUGGER_NOT_RUNNING"
    DEBUGGER_ACTIVE = "DEBUGGER_ACTIVE"
    DEBUGGER_MEMORY_ERROR = "DEBUGGER_MEMORY_ERROR"
    DEBUGGER_REGISTER_ERROR = "DEBUGGER_REGISTER_ERROR"
    DEBUGGER_STEP_ERROR = "DEBUGGER_STEP_ERROR"
    DEBUGGER_PROCESS_ERROR = "DEBUGGER_PROCESS_ERROR"
    EMULATION_ERROR = "EMULATION_ERROR"
    EMULATION_TIMEOUT = "EMULATION_TIMEOUT"
    GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    TIMEOUT = "TIMEOUT"


_TIMEOUT_CODES = frozenset({_MCPError.EMULATION_TIMEOUT, _MCPError.TIMEOUT})


def _make_error(code, message, hint=None, details=None, recoverable=False, **kwargs):
    """Real-shaped make_error envelope (mirrors ida_mcp.error_handling.make_error).

    Timeout codes are always recoverable, matching the production
    ``_TIMEOUT_CODES`` treatment, so the EMULATION_TIMEOUT tests hold even when
    the tool omits the explicit ``recoverable=True`` kwarg.
    """
    if code in _TIMEOUT_CODES:
        recoverable = True
    result = {
        "error": True,
        "code": code,
        "message": message,
        "recoverable": bool(recoverable),
    }
    if hint:
        result["hint"] = hint
    if details:
        result["details"] = details
    result.update(kwargs)
    return result


def _handle_error(e, context=None):
    msg = str(e) if not context else f"[{context}] {e}"
    return _make_error(_MCPError.IDA_ERROR, msg)


# Normalized get_arch() for a metapc/64 IDB is "x64"; the arch-family helpers
# mirror arch_utils.is_*_family so the tool's register fallback table is x64.
def _fake_get_arch():
    return "x64"


def _fake_is_x86_family(arch=None):
    return (arch or _fake_get_arch()) in ("x86", "x64")


def _fake_is_arm_family(arch=None):
    return (arch or _fake_get_arch()) in ("arm", "arm64")


def _fake_is_mips_family(arch=None):
    return (arch or _fake_get_arch()) in ("mips", "mips64")


# ---------------------------------------------------------------------------
# Fake ida_dbg module — the exact surface the spec's fake must carry
# ---------------------------------------------------------------------------
def _build_fake_dbg(**overrides):
    """Build a fresh fake ``ida_dbg`` module with mutable state + a call log."""
    dbg = types.ModuleType("ida_dbg")
    dbg.DSTATE_NOT_RUN = -1
    dbg.DSTATE_RUN = 0
    dbg.DSTATE_SUSP = 1
    dbg.DSTATE_IDLE = 2
    dbg.DSTATE_EXIT = 3

    # Mutable state (test switches flip these between calls).
    dbg._calls = []
    dbg._regs = {}
    dbg._state = dbg.DSTATE_SUSP
    dbg._load_results = {}
    dbg._read_bytes = b"\x90\x90\x00\x41"
    dbg._ip = 0x401000
    dbg._writes = []
    dbg._debugger_on = True

    def _record(name, *args):
        dbg._calls.append((name, args))

    def is_debugger_on():
        return dbg._debugger_on
    dbg.is_debugger_on = is_debugger_on

    def load_debugger(name, network=False):
        _record("load_debugger", name, network)
        return dbg._load_results.get(name, False)
    dbg.load_debugger = load_debugger

    def start_process(*args, **kwargs):
        _record("start_process", args, kwargs)
        return 1
    dbg.start_process = start_process

    def get_process_state():
        return dbg._state
    dbg.get_process_state = get_process_state

    def suspend_process(*args, **kwargs):
        _record("suspend_process")
        return 0
    dbg.suspend_process = suspend_process

    def continue_process(*args, **kwargs):
        _record("continue_process")
        return 0
    dbg.continue_process = continue_process

    def step_into(*args, **kwargs):
        _record("step_into")
        return True
    dbg.step_into = step_into

    def step_over(*args, **kwargs):
        _record("step_over")
        return True
    dbg.step_over = step_over

    def step_until_ret(*args, **kwargs):
        _record("step_until_ret")
        return True
    dbg.step_until_ret = step_until_ret

    def run_to(*args, **kwargs):
        _record("run_to", args)
        return True
    dbg.run_to = run_to

    def get_reg_val(name):
        _record("get_reg_val", name)
        return dbg._regs.get(name, 0)
    dbg.get_reg_val = get_reg_val

    def set_reg_val(name, value):
        dbg._regs[name] = value
        _record("set_reg_val", name, value)
        return True
    dbg.set_reg_val = set_reg_val

    def get_reg_vals():
        return dict(dbg._regs)
    dbg.get_reg_vals = get_reg_vals

    def read_dbg_memory(ea, buf, size):
        _record("read_dbg_memory", ea, size)
        data = dbg._read_bytes
        n = min(len(data), size)
        if n > 0:
            ctypes.memmove(buf, data, n)
        return n
    dbg.read_dbg_memory = read_dbg_memory

    def write_dbg_memory(ea, buf, size):
        raw = bytes(buf.raw[:size]) if hasattr(buf, "raw") else bytes(buf)[:size]
        dbg._writes.append((ea, raw))
        _record("write_dbg_memory", ea, size)
        return size
    dbg.write_dbg_memory = write_dbg_memory

    def get_ip_val():
        return dbg._ip
    dbg.get_ip_val = get_ip_val

    def get_current_thread():
        return 1
    dbg.get_current_thread = get_current_thread

    def exit_process():
        _record("exit_process")
        return 0
    dbg.exit_process = exit_process

    def stop_process():
        _record("stop_process")
        return 0
    dbg.stop_process = stop_process

    for key, value in overrides.items():
        setattr(dbg, key, value)
    return dbg


def _build_fake_governance():
    """Fake ``governance_engine`` whose evaluate_operation always approves."""
    gov = types.ModuleType("governance_engine")
    gov._calls = []

    def evaluate_operation(*args, **kwargs):
        gov._calls.append((args, kwargs))
        return {"approved": True, "verdict": "approved"}

    gov.evaluate_operation = evaluate_operation
    return gov


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestEmulateHost(unittest.TestCase):
    """Host-side unit tests for the emulate tool — no live IDA required."""

    def setUp(self):
        self.gov = _build_fake_governance()
        self._load(_build_fake_dbg())

    def _load(self, dbg):
        self.dbg = dbg
        sys.modules["ida_dbg"] = dbg
        # Cover both import styles the tool may use: `import governance_engine`
        # and `from . import governance_engine` (resolved via sys.modules).
        sys.modules["governance_engine"] = self.gov
        sys.modules["ida_pro_mcp.ida_mcp.tools.governance_engine"] = self.gov
        self.mod = load_tool_module(
            "emulate",
            common_overrides={
                "ida_dbg": dbg,
                "MCPError": _MCPError,
                "make_error": _make_error,
                "handle_error": _handle_error,
                "get_arch": _fake_get_arch,
                "is_x86_family": _fake_is_x86_family,
                "is_arm_family": _fake_is_arm_family,
                "is_mips_family": _fake_is_mips_family,
            },
        )
        # The tool caches these as module globals; reset per test.
        self.mod._BACKEND = None
        self.mod._BACKEND_REASON = ""
        self.mod._PROCESS_STARTED = False

    # -- helpers ----------------------------------------------------------
    def _prime_backend(self, name="linux"):
        self.mod._BACKEND = name
        self.mod._BACKEND_REASON = f"selected native '{name}'"

    def _prime_process(self, name="linux"):
        self._prime_backend(name)
        self.mod._PROCESS_STARTED = True

    def _load_debugger_calls(self):
        return [args for (fn, args) in self.dbg._calls if fn == "load_debugger"]

    def _called(self, name):
        return sum(1 for (fn, _args) in self.dbg._calls if fn == name)

    def _blocked_governance(self):
        """Context manager forcing the governance gate to deny.

        Patches whichever governance hook the tool bound (module or function)
        so the GOVERNANCE_BLOCKED path is exercised. ``unittest.mock.patch`` is
        used instead of pytest's ``monkeypatch`` fixture because pytest does not
        inject fixtures into ``unittest.TestCase`` test methods.
        """
        gov = getattr(self.mod, "governance_engine", None)
        if gov is not None and hasattr(gov, "evaluate_operation"):
            return mock.patch.object(
                gov, "evaluate_operation", return_value={"approved": False, "verdict": "blocked"}
            )
        return mock.patch.object(
            self.mod, "evaluate_operation", return_value={"approved": False, "verdict": "blocked"}
        )

    # -- backend selection -------------------------------------------------
    def test_backend_auto_select_falls_back_to_native(self):
        self.dbg._load_results = {"Emulator": False, "emulator": False, "linux": True}
        result = self.mod.emulate(action="backend")
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "linux")
        self.assertEqual(
            result["backend_candidates"],
            ["Emulator", "emulator", "linux", "bochs", "gdb"],
        )
        self.assertIn("backend_reason", result)
        self.assertIn("linux", result["backend_reason"])
        self.assertEqual(
            self._load_debugger_calls(),
            [("Emulator", False), ("emulator", False), ("linux", False)],
        )

    def test_backend_attempts_log_ok_and_failures(self):
        self.dbg._load_results = {"Emulator": False, "emulator": False, "linux": True}
        result = self.mod.emulate(action="backend")
        self.assertTrue(result["ok"])
        attempts = result["backend_attempts"]
        self.assertEqual(attempts["linux"], "ok")
        self.assertIn("error", attempts["Emulator"])
        self.assertIn("error", attempts["emulator"])

    def test_backend_reason_names_builtin_emulator_candidates(self):
        self.dbg._load_results = {"Emulator": False, "emulator": False, "linux": True}
        result = self.mod.emulate(action="backend")
        self.assertTrue(result["ok"])
        self.assertIn("built-in emulator candidates", result["backend_reason"])
        self.assertIn("'Emulator'", result["backend_reason"])
        self.assertIn("selected native backend 'linux'", result["backend_reason"])

    def test_backend_first_success_wins(self):
        self.dbg._load_results = {"Emulator": True}
        result = self.mod.emulate(action="backend")
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "Emulator")

    def test_backend_explicit_name_first(self):
        self.dbg._load_results = {"gdb": True, "Emulator": True, "linux": True}
        result = self.mod.emulate(action="backend", name="gdb")
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "gdb")
        calls = self._load_debugger_calls()
        self.assertTrue(calls, "load_debugger was never called")
        self.assertEqual(calls[0], ("gdb", False))

    def test_backend_no_backend_available_maps_to_emulation_error(self):
        self.dbg._load_results = {}
        result = self.mod.emulate(action="backend")
        self.assertTrue(result.get("error"))
        self.assertEqual(result.get("code"), "EMULATION_ERROR")

    # -- info --------------------------------------------------------------
    def test_info_does_not_auto_select_backend(self):
        self.dbg._load_results = {"linux": True, "gdb": True}
        result = self.mod.emulate(action="info")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["backend"], "none")
        self.assertEqual(self._load_debugger_calls(), [])

    def test_info_reports_backend_registers_and_why(self):
        self._prime_backend("linux")
        self.dbg._regs = {"rip": 0x401000, "rax": 0x10, "rbx": 0x20, "rcx": 0x30}
        result = self.mod.emulate(action="info")
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "linux")
        self.assertIn("rip", result["registers"])
        self.assertIs(result["registers_available"], True)
        self.assertEqual(result["why_chosen"], "selected native 'linux'")

    # -- process lifecycle --------------------------------------------------
    def test_start_calls_start_process(self):
        self.dbg._load_results = {"linux": True}
        result = self.mod.emulate(action="start")
        self.assertTrue(result["ok"], result)
        self.assertIs(result["started"], True)
        self.assertIs(result["process_running"], True)
        self.assertIn("backend", result)
        self.assertGreater(self._called("start_process"), 0)

    def test_start_governance_denied(self):
        with self._blocked_governance():
            result = self.mod.emulate(action="start")
        self.assertTrue(result.get("error"))
        self.assertEqual(result.get("code"), "GOVERNANCE_BLOCKED")

    def _governance_op_types(self):
        return [args[0] for (args, _kwargs) in self.gov._calls if args]

    def test_step_governance_uses_execution_operation(self):
        self._prime_process()
        result = self.mod.emulate(action="step", mode="into", count=1)
        self.assertTrue(result["ok"], result)
        self.assertIn("execution", self._governance_op_types())

    def test_set_reg_governance_uses_patch_operation(self):
        self._prime_process()
        result = self.mod.emulate(action="set_reg", name="rax", value="0x10")
        self.assertTrue(result["ok"], result)
        self.assertIn("patch", self._governance_op_types())

    def test_set_mem_governance_uses_patch_operation(self):
        self._prime_process()
        self.dbg._state = self.dbg.DSTATE_SUSP
        result = self.mod.emulate(action="set_mem", address="0x401000", data="9090")
        self.assertTrue(result["ok"], result)
        self.assertIn("patch", self._governance_op_types())

    # -- stepping ------------------------------------------------------------
    def test_step_modes(self):
        for mode, fn_name in (
            ("into", "step_into"),
            ("over", "step_over"),
            ("ret", "step_until_ret"),
        ):
            self._prime_process()
            self.dbg._calls.clear()
            result = self.mod.emulate(action="step", mode=mode, count=1)
            self.assertTrue(result["ok"], f"mode={mode}: {result}")
            self.assertEqual(result["steps_done"], 1, mode)
            self.assertEqual(self._called(fn_name), 1, mode)

    def test_step_multi_count_with_timeout(self):
        self._prime_process()
        self.dbg._state = self.dbg.DSTATE_SUSP
        result = self.mod.emulate(action="step", mode="into", count=5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["steps_done"], 5)
        self.assertEqual(self._called("step_into"), 5)

    def test_step_timeout_maps_to_emulation_timeout(self):
        self._prime_process()
        self.dbg._state = self.dbg.DSTATE_RUN
        result = self.mod.emulate(action="step", mode="into", count=1, timeout_ms=100)
        self.assertEqual(result.get("code"), "EMULATION_TIMEOUT")
        self.assertIs(result.get("recoverable"), True)

    # -- run_to ----------------------------------------------------------------
    def test_run_to_calls_run_to_and_suspends(self):
        self._prime_process()
        self.dbg._state = self.dbg.DSTATE_SUSP
        result = self.mod.emulate(action="run_to", address="0x401000")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["target"], "0x401000")
        self.assertGreater(self._called("run_to"), 0)

    def test_run_to_timeout(self):
        self._prime_process()
        self.dbg._state = self.dbg.DSTATE_RUN
        result = self.mod.emulate(action="run_to", address="0x401000", timeout_ms=100)
        self.assertEqual(result.get("code"), "EMULATION_TIMEOUT")

    # -- registers -------------------------------------------------------------
    def test_get_reg_single_and_bulk(self):
        self._prime_process()
        self.dbg._regs = {"rax": 0x1234, "rbx": 0x5678}
        result = self.mod.emulate(action="get_reg", name="rax")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["regs"], {"rax": "0x1234"})
        result = self.mod.emulate(action="get_reg", names=["rax", "rbx"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["regs"], {"rax": "0x1234", "rbx": "0x5678"})

    def test_set_reg_writes_and_roundtrips(self):
        self._prime_process()
        result = self.mod.emulate(action="set_reg", name="rax", value="0x10")
        self.assertTrue(result["ok"], result)
        self.assertIs(result["written"], True)
        set_calls = [args for (fn, args) in self.dbg._calls if fn == "set_reg_val"]
        self.assertEqual(set_calls, [("rax", 0x10)])
        result = self.mod.emulate(action="get_reg", name="rax")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["regs"], {"rax": "0x10"})

    # -- memory -----------------------------------------------------------------
    def test_read_mem_hex_and_ascii(self):
        self._prime_process()
        self.dbg._read_bytes = b"\x90\x90\x00\x41"
        result = self.mod.emulate(action="read_mem", address="0x401000", size=4)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["data"], "90900041")

    def test_set_mem_invalid_hex(self):
        self._prime_process()
        result = self.mod.emulate(action="set_mem", address="0x401000", data="ZZ")
        self.assertTrue(result.get("error"))
        self.assertEqual(result.get("code"), "INVALID_ARGS")
        self.assertEqual(self._called("write_dbg_memory"), 0)

    # -- stop ---------------------------------------------------------------------
    def test_stop_uses_exit_process_fallback(self):
        # No exit_process -> stop_process fallback.
        dbg_no_exit = _build_fake_dbg()
        del dbg_no_exit.exit_process
        self._load(dbg_no_exit)
        self._prime_process()
        result = self.mod.emulate(action="stop")
        self.assertTrue(result["ok"], result)
        self.assertIs(result["stopped"], True)
        self.assertIs(result["process_running"], False)
        self.assertGreater(self._called("stop_process"), 0)
        self.assertEqual(self._called("exit_process"), 0)

        # Only exit_process -> exit_process called.
        dbg_only_exit = _build_fake_dbg()
        del dbg_only_exit.stop_process
        self._load(dbg_only_exit)
        self._prime_process()
        result = self.mod.emulate(action="stop")
        self.assertTrue(result["ok"], result)
        self.assertIs(result["stopped"], True)
        self.assertIs(result["process_running"], False)
        self.assertGreater(self._called("exit_process"), 0)
        self.assertEqual(self._called("stop_process"), 0)

    # -- response envelope / error paths -----------------------------------------
    def test_every_success_response_carries_backend(self):
        self.dbg._load_results = {"linux": True}
        results = [
            self.mod.emulate(action="info"),
            self.mod.emulate(action="backend"),
            self.mod.emulate(action="start"),
            self.mod.emulate(action="state"),
            self.mod.emulate(action="step", count=1),
            self.mod.emulate(action="get_reg", name="rax"),
            self.mod.emulate(action="read_mem", address="0x401000", size=4),
        ]
        for result in results:
            self.assertTrue(result.get("ok"), result)
            self.assertIn("backend", result, result)

    def test_unknown_action(self):
        result = self.mod.emulate(action="bogus")
        self.assertTrue(result.get("error"))
        self.assertEqual(result.get("code"), "ACTION_NOT_FOUND")

    def test_error_envelopes_carry_backend_identity(self):
        self.dbg._load_results = {"linux": True}
        result = self.mod.emulate(action="start", governed=False)
        self.assertTrue(result["ok"], result)
        # Force an error path (unknown action) and confirm the backend keys
        # are present even though the handler returned an error envelope.
        err = self.mod.emulate(action="bogus")
        self.assertTrue(err.get("error"))
        self.assertIn("backend", err)
        self.assertIn("backend_reason", err)
        self.assertIn("backend_attempts", err)
        self.assertIn("backend_candidates", err)

    def test_backend_force_tears_down_live_process(self):
        self.dbg._load_results = {"linux": True}
        result = self.mod.emulate(action="start", governed=False)
        self.assertTrue(result["ok"], result)
        self.dbg._calls.clear()
        result = self.mod.emulate(action="backend", force=True)
        self.assertTrue(result["ok"], result)
        # exit_process was called before re-selecting the backend.
        self.assertGreater(self._called("exit_process"), 0)

    def test_governed_false_skips_governance(self):
        self.dbg._load_results = {"linux": True}
        result = self.mod.emulate(action="start", governed=False)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.gov._calls, [])
        self.assertGreater(self._called("start_process"), 0)

    # -- remaining helper and failure modes --------------------------------
    def test_register_and_ip_helpers_cover_architecture_fallbacks(self):
        self.dbg.get_reg_vals = None
        def get_reg_val(name):
            return {"eip": 0x10, "pc": 0x20}.get(name)

        self.dbg.get_reg_val = get_reg_val
        with mock.patch.object(self.mod, "get_arch", return_value="x86"), mock.patch.object(
            self.mod, "_inf_bitness", return_value=32, create=True
        ):
            self.assertEqual(self.mod._ip_reg_name(), "eip")
            self.assertIn("eip", self.mod._common_register_names())
            regs, available = self.mod._read_all_registers()
            self.assertTrue(available)
            self.assertEqual(regs["eip"], "0x10")

        with mock.patch.object(self.mod, "get_arch", return_value="arm64"), mock.patch.object(
            self.mod, "_inf_bitness", return_value=64, create=True
        ):
            self.assertEqual(self.mod._ip_reg_name(), "pc")
            self.assertIn("x30", self.mod._common_register_names())
        with mock.patch.object(self.mod, "get_arch", return_value="mips"), mock.patch.object(
            self.mod, "_inf_bitness", return_value=32, create=True
        ):
            self.assertIn("ra", self.mod._common_register_names())

        self.dbg.get_ip_val = None
        self.assertIsNone(self.mod._current_ip())
        self.dbg.get_ip_val = lambda: "not-an-integer"
        self.assertEqual(self.mod._current_ip(), "not-an-integer")
        self.mod._set_ip(0x1234)
        self.assertEqual(self.dbg._regs["rip"], 0x1234)

    def test_event_pump_and_suspend_helpers_cover_absent_error_and_timeout(self):
        self.dbg.WFNE_SUSP = 1
        self.dbg.wait_for_next_event = lambda *_args: 0
        self.assertFalse(self.mod._pump_suspended(10))
        self.dbg.wait_for_next_event = lambda *_args: 1
        self.assertTrue(self.mod._pump_suspended(10))
        self.dbg.wait_for_next_event = lambda *_args: (_ for _ in ()).throw(RuntimeError("event loop"))
        self.assertTrue(self.mod._pump_suspended(10))
        self.dbg.wait_for_next_event = None
        self.assertTrue(self.mod._pump_suspended(10))

        self.dbg._state = self.dbg.DSTATE_SUSP
        self.assertTrue(self.mod._suspend_if_needed(timeout_sec=0))
        self.dbg._state = self.dbg.DSTATE_RUN
        self.dbg.suspend_process = None
        self.assertFalse(self.mod._suspend_if_needed(timeout_sec=0))

        def suspend_then_pause():
            self.dbg._state = self.dbg.DSTATE_SUSP

        self.dbg.suspend_process = suspend_then_pause
        self.dbg._state = self.dbg.DSTATE_RUN
        self.assertTrue(self.mod._suspend_if_needed(timeout_sec=0.01))

    def test_backend_and_start_failure_modes_are_explicit(self):
        del self.dbg.load_debugger
        self.mod._BACKEND = None
        self.assertIsNone(self.mod._select_backend(force=True))
        self.assertIn("no backend loadable", self.mod._BACKEND_REASON)
        self.assertTrue(self.mod._no_backend_error()["error"])

        self._prime_backend()
        del self.dbg.start_process
        result = self.mod._action_start(False, None, None, None, None)
        self.assertEqual(result["code"], "EMULATION_ERROR")

        self.dbg.start_process = lambda *_args: -1
        result = self.mod._action_start(False, None, None, None, None)
        self.assertEqual(result["code"], "EMULATION_ERROR")
        self.dbg.start_process = lambda *_args: (_ for _ in ()).throw(RuntimeError("spawn"))
        result = self.mod._action_start(False, None, None, None, None)
        self.assertEqual(result["code"], "IDA_ERROR")

    def test_step_run_to_and_register_failures_keep_stable_errors(self):
        self._prime_process()
        self.assertEqual(self.mod._action_step(False, "bad", 1, 1)["code"], "INVALID_ARGS")
        self.assertEqual(self.mod._action_step(False, "into", "bad", 1)["code"], "INVALID_ARGS")
        self.assertEqual(self.mod._action_step(False, "into", -1, 1)["code"], "INVALID_ARGS")
        self.dbg.step_into = None
        self.assertEqual(self.mod._action_step(False, "into", 1, 1)["code"], "EMULATION_ERROR")
        self.dbg.step_into = lambda: False
        self.assertEqual(self.mod._action_step(False, "into", 1, 1)["steps_done"], 0)

        self.assertEqual(self.mod._action_run_to(False, None, 1)["code"], "INVALID_ARGS")
        with mock.patch.object(self.mod, "validate_addr", return_value=(None, {"code": "ADDRESS_INVALID"})):
            self.assertEqual(self.mod._action_run_to(False, "bad", 1)["code"], "ADDRESS_INVALID")
        self.dbg.run_to = None
        self.assertEqual(self.mod._action_run_to(False, "0x401000", 1)["code"], "EMULATION_ERROR")
        self.dbg.run_to = lambda _ea: False
        self.assertFalse(self.mod._action_run_to(False, "0x401000", 1)["reached"])

        self.assertEqual(self.mod._action_get_reg(False, None, None)["code"], "INVALID_ARGS")
        self.dbg.get_reg_val = lambda name: None if name == "missing" else (_ for _ in ()).throw(RuntimeError("context"))
        result = self.mod._action_get_reg(False, None, ["missing", "broken"])
        self.assertEqual(result["unavailable"], ["missing", "broken"])
        self.dbg.get_reg_val = None
        self.assertEqual(self.mod._action_get_reg(False, "rax", None)["code"], "EMULATION_ERROR")

    def test_memory_fallbacks_and_write_errors_are_safe(self):
        self._prime_process()
        self.dbg.read_dbg_memory = lambda *_args: (_ for _ in ()).throw(RuntimeError("buffer shape"))
        self.dbg.get_dbg_byte = lambda ea: [0x41, 0x00, -1][ea - 0x401000]
        self.assertEqual(self.mod._read_dbg_memory(0x401000, 4), b"A\x00")
        self.dbg.get_dbg_byte = lambda _ea: (_ for _ in ()).throw(RuntimeError("no bytes"))
        self.assertIsNone(self.mod._read_dbg_memory(0x401000, 4))

        self.assertEqual(self.mod._action_read_mem(False, None, 4)["code"], "INVALID_ARGS")
        self.dbg.read_dbg_memory = None
        self.dbg.get_dbg_byte = None
        self.assertEqual(self.mod._action_read_mem(False, "0x401000", 4)["code"], "EMULATION_ERROR")
        self.dbg.write_dbg_memory = None
        self.assertEqual(self.mod._action_set_mem(False, "0x401000", "90")["code"], "EMULATION_ERROR")
        self.dbg.write_dbg_memory = lambda *_args: (_ for _ in ()).throw(RuntimeError("write denied"))
        self.assertEqual(self.mod._action_set_mem(False, "0x401000", "90")["code"], "IDA_ERROR")

    def test_stop_suspend_continue_and_public_dispatch_missing_methods(self):
        self._prime_process()
        self.dbg.exit_process = None
        self.dbg.stop_process = None
        self.assertEqual(self.mod._action_stop(False, False)["code"], "EMULATION_ERROR")
        self.dbg.suspend_process = None
        self.assertEqual(self.mod._action_suspend(False)["code"], "EMULATION_ERROR")
        self.dbg.continue_process = None
        self.assertEqual(self.mod._action_continue(False)["code"], "EMULATION_ERROR")
        self.assertEqual(self.mod._action_set_reg(False, None, 1)["code"], "INVALID_ARGS")
        self.assertEqual(self.mod._action_set_reg(False, "rax", None)["code"], "INVALID_ARGS")
        self.assertEqual(self.mod._action_set_reg(False, "rax", "bad")["code"], "INVALID_ARGS")

        self.assertEqual(self.mod.emulate(action="run_to")["code"], "INVALID_ARGS")
        self.assertEqual(self.mod.emulate(action="step", mode="unknown")["code"], "INVALID_ARGS")
        self.assertEqual(self.mod.emulate(action="nope")["code"], "ACTION_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
