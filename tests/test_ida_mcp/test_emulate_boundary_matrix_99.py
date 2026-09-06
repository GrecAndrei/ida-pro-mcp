"""Cross-mode boundary coverage for the debugger/emulation surface."""

from __future__ import annotations

import importlib
import types

import pytest

emulate_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.emulate")


@pytest.fixture(autouse=True)
def _reset_emulator(monkeypatch):
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    monkeypatch.setattr(emulate_mod, "_BACKEND_REASON", "")
    monkeypatch.setattr(emulate_mod, "_BACKEND_ATTEMPTS", {})
    monkeypatch.setattr(emulate_mod, "_PROCESS_STARTED", False)
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "x86")
    monkeypatch.setattr(emulate_mod, "_inf_bitness_or_64", lambda: 64)
    monkeypatch.setattr(emulate_mod, "validate_addr", lambda value: (int(str(value), 0), None))


def _debugger(**attrs):
    def get_reg_val(name):
        return {"rax": 3}.get(name)

    value = types.SimpleNamespace(
        DSTATE_RUNNING=1,
        DSTATE_RUN=1,
        DSTATE_SUSP=2,
        DSTATE_IDLE=3,
        DSTATE_NOT_RUN=4,
        DSTATE_EXIT=5,
        WFNE_SUSP=10,
        get_process_state=lambda: 2,
        load_debugger=lambda _name, _quiet: True,
        get_ip_val=lambda: 0x401000,
        get_reg_val=get_reg_val,
        get_reg_vals=lambda: {"rax": 3},
        set_reg_val=lambda *_args: None,
        read_dbg_memory=lambda *_args: 0,
        write_dbg_memory=lambda *_args: 0,
        exit_process=lambda: None,
        suspend_process=lambda: True,
        continue_process=lambda: True,
        step_into=lambda: True,
        step_over=lambda: True,
        step_until_ret=lambda: True,
        run_to=lambda _ea: True,
    )
    for key, item in attrs.items():
        setattr(value, key, item)
    return value


def test_helper_fallbacks_cover_register_architecture_and_hex_modes(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    assert emulate_mod._hex_to_bytes("0x90 90,_aa") == b"\x90\x90\xaa"
    assert emulate_mod._hex_to_bytes("9") is None
    assert emulate_mod._hex_to_bytes("gg") is None
    assert emulate_mod._as_int_opt("") is None
    assert emulate_mod._as_int_opt("bad") is None
    assert emulate_mod._hex_reg("not numeric") == "not numeric"
    dbg.get_ip_val = lambda: (_ for _ in ()).throw(RuntimeError("no ip"))
    assert emulate_mod._current_ip() is None
    dbg.get_ip_val = lambda: "symbolic"
    assert emulate_mod._current_ip() == "symbolic"
    dbg.get_process_state = lambda: (_ for _ in ()).throw(RuntimeError("state"))
    assert emulate_mod._state_name() == "unknown"
    assert emulate_mod._process_running() is False

    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "x86")
    monkeypatch.setattr(emulate_mod, "_inf_bitness_or_64", lambda: 32)
    assert emulate_mod._ip_reg_name() == "eip"
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "arm64")
    assert emulate_mod._ip_reg_name() == "pc"
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: (_ for _ in ()).throw(RuntimeError("arch")))
    assert emulate_mod._arch_name() == "unknown"

    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "arm")
    monkeypatch.setattr(emulate_mod, "_inf_bitness_or_64", lambda: 32)
    assert "r12" in emulate_mod._common_register_names()
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "mips64")
    assert "ra" in emulate_mod._common_register_names()
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "mystery")
    assert emulate_mod._common_register_names() == ["pc"]


def test_backend_selection_and_event_pump_cover_no_backend_modes(monkeypatch):
    dbg = _debugger(load_debugger=None)
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    assert emulate_mod._try_load("none") is False
    assert "no load_debugger" in emulate_mod._BACKEND_ATTEMPTS["none"]
    monkeypatch.setattr(dbg, "load_debugger", lambda *_args: (_ for _ in ()).throw(RuntimeError("missing")))
    assert emulate_mod._try_load("broken") is False
    assert "missing" in emulate_mod._BACKEND_ATTEMPTS["broken"]
    assert "selected backend" in emulate_mod._build_backend_reason("linux", [])
    assert "native backend" in emulate_mod._build_backend_reason("linux", ["Emulator"])
    assert "candidates" in emulate_mod._build_backend_reason("gdb", ["linux", "bochs"])

    monkeypatch.setattr(dbg, "load_debugger", lambda *_args: False)
    assert emulate_mod._select_backend() is None
    assert emulate_mod._no_backend_error()["error"] is True
    assert emulate_mod._require_backend()["code"] == "EMULATION_ERROR"
    assert emulate_mod._pump_suspended(1) is True
    dbg.WFNE_SUSP = None
    assert emulate_mod._pump_suspended(1) is True
    dbg.WFNE_SUSP = 10
    dbg.wait_for_next_event = lambda *_args: 0
    assert emulate_mod._pump_suspended(1) is False
    dbg.wait_for_next_event = lambda *_args: (_ for _ in ()).throw(RuntimeError("event"))
    assert emulate_mod._pump_suspended(1) is True


def test_action_info_backend_and_start_failure_modes(monkeypatch, tmp_path):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    info = emulate_mod._action_info()
    assert info["backend"] == "none" and info["registers_available"] is False
    emulate_mod._BACKEND = "linux"
    emulate_mod._BACKEND_REASON = "selected"
    emulate_mod.get_arch = lambda: "x86"
    info = emulate_mod._action_info()
    assert info["registers"]["rax"] == "0x3"
    assert emulate_mod._action_backend() ["backend"] == "linux"
    dbg.get_reg_vals = lambda: (_ for _ in ()).throw(RuntimeError("bulk unavailable"))
    dbg.get_reg_val = {"rax": 1}.get
    assert emulate_mod._read_all_registers()[1] is True

    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    monkeypatch.setattr(dbg, "load_debugger", lambda *_args: True)
    dbg.start_process = None
    assert emulate_mod._action_start(False, None, None, None, None)["code"] == "EMULATION_ERROR"
    dbg.start_process = lambda *_args: -1
    assert emulate_mod._action_start(False, None, None, None, None)["code"] == "EMULATION_ERROR"
    dbg.start_process = lambda *_args: 1
    monkeypatch.setattr(emulate_mod, "_suspend_if_needed", lambda: True)
    monkeypatch.setattr(emulate_mod, "_set_ip", lambda _ea: None)
    monkeypatch.setattr(emulate_mod, "validate_addr", lambda _value: (0, {"error": True}))
    assert emulate_mod._action_start(False, "bad", None, None, None)["error"] is True
    assert emulate_mod._action_start(False, None, None, "--x", str(tmp_path))["ok"] is True
    monkeypatch.setattr(emulate_mod.os, "chdir", lambda _path: (_ for _ in ()).throw(OSError("directory")))
    assert emulate_mod._action_start(False, None, None, None, "/bad")["error"] is True
    dbg.start_process = lambda *_args: (_ for _ in ()).throw(RuntimeError("start"))
    assert emulate_mod._action_start(False, None, None, None, None)["error"] is True


def test_step_run_to_and_suspend_actions_cover_rejections_and_timeouts(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    emulate_mod._BACKEND = "linux"
    assert emulate_mod._action_step(False, "bad", 1, 1)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_step(False, "into", "bad", 1)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_step(False, "into", -1, 1)["code"] == "INVALID_ARGS"
    dbg.step_into = None
    assert emulate_mod._action_step(False, "into", 1, 1)["code"] == "EMULATION_ERROR"
    dbg.step_into = lambda: False
    assert emulate_mod._action_step(False, "into", 1, "bad")["steps_done"] == 0
    dbg.step_into = lambda: (_ for _ in ()).throw(RuntimeError("step"))
    assert emulate_mod._action_step(False, "into", 1, 1)["error"] is True

    dbg.run_to = None
    assert emulate_mod._action_run_to(False, "0x1000", 1)["code"] == "EMULATION_ERROR"
    dbg.run_to = lambda _ea: False
    assert emulate_mod._action_run_to(False, "0x1000", "bad")["reached"] is False
    dbg.run_to = lambda _ea: (_ for _ in ()).throw(RuntimeError("run"))
    assert emulate_mod._action_run_to(False, "0x1000", 1)["error"] is True
    assert emulate_mod._action_run_to(False, None, 1)["code"] == "INVALID_ARGS"

    dbg.suspend_process = None
    assert emulate_mod._action_suspend(False)["code"] == "EMULATION_ERROR"
    dbg.suspend_process = lambda: (_ for _ in ()).throw(RuntimeError("suspend"))
    assert emulate_mod._action_suspend(False)["error"] is True
    dbg.continue_process = None
    assert emulate_mod._action_continue(False)["code"] == "EMULATION_ERROR"
    dbg.continue_process = lambda: (_ for _ in ()).throw(RuntimeError("continue"))
    assert emulate_mod._action_continue(False)["error"] is True


def test_register_and_memory_fallbacks_cover_unavailable_backend_apis(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    emulate_mod._BACKEND = "linux"
    assert emulate_mod._action_get_reg(False, None, None)["code"] == "INVALID_ARGS"
    dbg.get_reg_val = None
    assert emulate_mod._action_get_reg(False, "rax", None)["code"] == "EMULATION_ERROR"
    dbg.get_reg_val = lambda _name: (_ for _ in ()).throw(RuntimeError("no context"))
    assert emulate_mod._action_get_reg(False, None, ["rax"])["unavailable"] == ["rax"]
    assert emulate_mod._action_set_reg(False, None, 1)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_set_reg(False, "rax", None)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_set_reg(False, "rax", "bad")["code"] == "INVALID_ARGS"
    dbg.set_reg_val = None
    assert emulate_mod._action_set_reg(False, "rax", 1)["code"] == "EMULATION_ERROR"

    dbg.read_dbg_memory = lambda *_args: (_ for _ in ()).throw(RuntimeError("buffer"))
    dbg.get_dbg_byte = lambda ea: 0x41 if ea < 0x1003 else -1
    assert emulate_mod._read_dbg_memory(0x1000, 8) == b"AAA"
    dbg.get_dbg_byte = None
    assert emulate_mod._read_dbg_memory(0x1000, 2) is None
    assert emulate_mod._action_read_mem(False, None, 1)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_read_mem(False, "0x1000", "bad")["code"] == "INVALID_ARGS"
    assert emulate_mod._action_read_mem(False, "0x1000", 1)["code"] == "EMULATION_ERROR"

    assert emulate_mod._action_set_mem(False, "0x1000", None)["code"] == "INVALID_ARGS"
    assert emulate_mod._action_set_mem(False, "0x1000", "odd")["code"] == "INVALID_ARGS"
    dbg.write_dbg_memory = None
    assert emulate_mod._action_set_mem(False, "0x1000", "90")["code"] == "EMULATION_ERROR"
    dbg.write_dbg_memory = lambda *_args: (_ for _ in ()).throw(RuntimeError("write"))
    assert emulate_mod._action_set_mem(False, "0x1000", "90")["error"] is True


def test_stop_fallbacks_and_public_error_annotation(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    emulate_mod._BACKEND = "linux"
    dbg.exit_process = None
    dbg.stop_process = lambda: None
    assert emulate_mod._action_stop(False, False)["stopped"] is True
    dbg.stop_process = lambda: (_ for _ in ()).throw(RuntimeError("stop"))
    assert emulate_mod._action_stop(False, False)["code"] == "EMULATION_ERROR"
    dbg.stop_process = None
    assert emulate_mod._action_stop(False, False)["code"] == "EMULATION_ERROR"
    result = emulate_mod.emulate(action="not-real")
    assert result["error"] is True and "backend" in result
    monkeypatch.setattr(emulate_mod, "ida_dbg", None)
    result = emulate_mod.emulate(action="info")
    assert result["code"] == "EMULATION_ERROR" and "backend_candidates" in result


def test_helper_and_register_exceptional_branches(monkeypatch):
    import time

    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)

    # Line 141: get_ip_val returns None
    dbg.get_ip_val = lambda: None
    assert emulate_mod._current_ip() is None

    # Lines 226-227: get_process_state raises in _wait_not_running
    dbg.get_process_state = lambda: (_ for _ in ()).throw(RuntimeError("fail state"))
    assert emulate_mod._wait_not_running(time.time() + 0.05) is True

    # Line 255: WFNE_SUSP is not an int
    dbg.wait_for_next_event = lambda *_args: 1
    dbg.WFNE_SUSP = "not an int"
    assert emulate_mod._pump_suspended(10) is True

    # Lines 267-268 & 273-274: get_arch and is_x86_family exceptions in _ip_reg_name
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: (_ for _ in ()).throw(RuntimeError("arch fail")))
    assert emulate_mod._ip_reg_name() in ("rip", "eip", "pc")
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "x86")
    monkeypatch.setattr(emulate_mod, "is_x86_family", lambda _a: (_ for _ in ()).throw(RuntimeError("x86 fail")))
    assert emulate_mod._ip_reg_name() == "pc"

    # Line 281, 284, 287-288: _set_ip branches
    monkeypatch.setattr(emulate_mod, "_ip_reg_name", lambda: "")
    emulate_mod._set_ip(0x401000)
    monkeypatch.setattr(emulate_mod, "_ip_reg_name", lambda: "pc")
    dbg.set_reg_val = None
    emulate_mod._set_ip(0x401000)
    dbg.set_reg_val = lambda *_args: (_ for _ in ()).throw(RuntimeError("setreg fail"))
    emulate_mod._set_ip(0x401000)

    # Lines 302-303, 310-311, 317-318, 322-323: _common_register_names exceptions
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: (_ for _ in ()).throw(RuntimeError("arch fail")))
    assert emulate_mod._common_register_names() == ["pc"]
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "x86")
    monkeypatch.setattr(emulate_mod, "is_x86_family", lambda _a: (_ for _ in ()).throw(RuntimeError("x86 fail")))
    assert "pc" in emulate_mod._common_register_names()
    monkeypatch.setattr(emulate_mod, "is_x86_family", lambda _a: False)
    monkeypatch.setattr(emulate_mod, "is_arm_family", lambda _a: (_ for _ in ()).throw(RuntimeError("arm fail")))
    assert "pc" in emulate_mod._common_register_names()
    monkeypatch.setattr(emulate_mod, "is_arm_family", lambda _a: False)
    monkeypatch.setattr(emulate_mod, "is_mips_family", lambda _a: (_ for _ in ()).throw(RuntimeError("mips fail")))
    assert emulate_mod._common_register_names() == ["pc"]

    # Lines 347-348: _read_all_registers per-register exception
    dbg.get_reg_vals = None
    dbg.get_reg_val = lambda _name: (_ for _ in ()).throw(RuntimeError("reg err"))
    regs, ok = emulate_mod._read_all_registers()
    assert ok is False

    # Lines 369-370: _governance_check evaluate_operation exception
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("gov fail")))
    assert emulate_mod._governance_check("start", True) is None

    # Line 424: _select_backend returns cached backend when not force
    emulate_mod._BACKEND = "bochs"
    assert emulate_mod._select_backend() == "bochs"

    # Line 462: _no_backend_error when _BACKEND_ATTEMPTS is empty
    emulate_mod._BACKEND_ATTEMPTS.clear()
    err = emulate_mod._no_backend_error()
    assert "None of the candidates (Emulator, emulator" in err["hint"]


def test_ensure_suspended_exceptional_and_polling_paths(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)

    # Lines 509-510: get_process_state raises initially
    dbg.get_process_state = lambda: (_ for _ in ()).throw(RuntimeError("init state fail"))
    assert emulate_mod._suspend_if_needed(timeout_sec=0.01) is True

    # Lines 518-519: suspend_process raises
    dbg.get_process_state = lambda: dbg.DSTATE_RUNNING
    dbg.suspend_process = lambda: (_ for _ in ()).throw(RuntimeError("suspend fail"))
    assert emulate_mod._suspend_if_needed(timeout_sec=0.01) is False

    # Lines 527-528 & 531-532: polling loop state transitions and exceptions
    state_seq = [dbg.DSTATE_RUNNING, dbg.DSTATE_RUNNING, dbg.DSTATE_SUSP]
    dbg.get_process_state = lambda: state_seq.pop(0) if state_seq else dbg.DSTATE_SUSP
    dbg.suspend_process = lambda: True
    assert emulate_mod._suspend_if_needed(timeout_sec=0.1) is True

    dbg.get_process_state = lambda: (_ for _ in ()).throw(RuntimeError("loop state fail"))
    assert emulate_mod._suspend_if_needed(timeout_sec=0.01) is True

    # Line 532: polling deadline expires while still running -> returns False
    dbg.get_process_state = lambda: dbg.DSTATE_RUNNING
    dbg.suspend_process = lambda: True
    assert emulate_mod._suspend_if_needed(timeout_sec=0.03) is False


def test_action_governance_and_missing_backend_boundaries(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)

    # Line 623: _action_start with missing backend
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    monkeypatch.setattr(dbg, "load_debugger", lambda *_args: False)
    assert emulate_mod._action_start(False, None, None, None, None)["code"] == "EMULATION_ERROR"

    # Line 692: _action_step blocked by governance
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": False})
    assert emulate_mod._action_step(True, "into", 1, 100)["code"] == "GOVERNANCE_BLOCKED"

    # Line 695: _action_step with missing backend
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    assert emulate_mod._action_step(False, "into", 1, 100)["code"] == "EMULATION_ERROR"

    # Line 757: _action_run_to blocked by governance
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": False})
    assert emulate_mod._action_run_to(True, "0x1000", 100)["code"] == "GOVERNANCE_BLOCKED"

    # Line 760: _action_run_to with missing backend
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    assert emulate_mod._action_run_to(False, "0x1000", 100)["code"] == "EMULATION_ERROR"

    # Line 769: _action_run_to with negative timeout
    emulate_mod._BACKEND = "linux"
    assert emulate_mod._action_run_to(False, "0x1000", -50)["ok"] is True

    # Line 812: _action_get_reg with missing backend
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    assert emulate_mod._action_get_reg(False, "rax", None)["code"] == "EMULATION_ERROR"

    # Line 855: _action_set_reg with missing backend
    assert emulate_mod._action_set_reg(False, "rax", 1)["code"] == "EMULATION_ERROR"

    # Lines 873-874: _action_set_reg fn raises exception
    emulate_mod._BACKEND = "linux"
    dbg.set_reg_val = lambda *_args: (_ for _ in ()).throw(RuntimeError("setreg fail"))
    assert emulate_mod._action_set_reg(False, "rax", 1)["error"] is True

    # Line 925: _action_read_mem with missing backend
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    assert emulate_mod._action_read_mem(False, "0x1000", 16)["code"] == "EMULATION_ERROR"

    # Line 933: _action_read_mem with invalid address
    emulate_mod._BACKEND = "linux"
    monkeypatch.setattr(emulate_mod, "validate_addr", lambda _val: (0, {"error": True, "code": "ADDRESS_INVALID"}))
    assert emulate_mod._action_read_mem(False, "bad_addr", 16)["code"] == "ADDRESS_INVALID"
    monkeypatch.setattr(emulate_mod, "validate_addr", lambda val: (int(str(val), 0), None))

    # Line 970: _action_set_mem blocked by governance
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": False})
    assert emulate_mod._action_set_mem(True, "0x1000", "9090")["code"] == "GOVERNANCE_BLOCKED"

    # Line 973: _action_set_mem with missing backend
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    assert emulate_mod._action_set_mem(False, "0x1000", "9090")["code"] == "EMULATION_ERROR"

    # Line 1004: _action_stop blocked by governance
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": False})
    assert emulate_mod._action_stop(True, False)["code"] == "GOVERNANCE_BLOCKED"

    # Line 1050: _action_suspend blocked by governance
    assert emulate_mod._action_suspend(True)["code"] == "GOVERNANCE_BLOCKED"

    # Line 1053: _action_suspend with missing backend
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    assert emulate_mod._action_suspend(False)["code"] == "EMULATION_ERROR"

    # Line 1080: _action_continue blocked by governance
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": False})
    assert emulate_mod._action_continue(True)["code"] == "GOVERNANCE_BLOCKED"

    # Line 1083: _action_continue with missing backend
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    assert emulate_mod._action_continue(False)["code"] == "EMULATION_ERROR"


def test_public_emulate_exceptional_action_and_dispatch_boundaries(monkeypatch):
    dbg = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)

    # Lines 1167-1168: action object raises on str()
    class _ThrowingAction:
        def __str__(self):
            raise RuntimeError("bad action str")

    res = emulate_mod.emulate(action=_ThrowingAction())
    assert res["code"] == "ACTION_NOT_FOUND"

    # Lines 1210-1212: unexpected dispatch exception handled by handle_error
    monkeypatch.setattr(emulate_mod, "_action_info", lambda: (_ for _ in ()).throw(RuntimeError("unexpected dispatch err")))
    res2 = emulate_mod.emulate(action="info")
    assert res2["error"] is True
    assert "unexpected dispatch err" in res2["message"]

    # Line 1210: action passes validation but misses all dispatch elif branches
    monkeypatch.setattr(emulate_mod, "_VALID_ACTIONS", ("synthetic_action",))
    res3 = emulate_mod.emulate(action="synthetic_action")
    assert res3["code"] == "ACTION_NOT_FOUND"
    assert "synthetic_action" in res3["message"]


def test_emulate_remaining_edges_and_fallbacks(monkeypatch):
    # line 309: _common_register_names 32-bit x86
    monkeypatch.setattr(emulate_mod, "get_arch", lambda: "x86")
    monkeypatch.setattr(emulate_mod, "_inf_bitness_or_64", lambda: 32)
    assert "eax" in emulate_mod._common_register_names()

    # line 378: _governance_check approved
    monkeypatch.setattr(emulate_mod, "evaluate_operation", lambda *_a, **_kw: {"approved": True})
    assert emulate_mod._governance_check("step", governed=True) is None

    # line 439: _select_backend returns name directly when load succeeds
    monkeypatch.setattr(emulate_mod, "_try_load", lambda name: True)
    assert emulate_mod._select_backend(name="win32") == "win32"

    # line 442: cand == name in candidate loop
    monkeypatch.setattr(emulate_mod, "_try_load", lambda name: False)
    assert emulate_mod._select_backend(name=emulate_mod._BACKEND_CANDIDATES[0], force=True) is None

    # line 1007: _action_stop with missing backend error
    monkeypatch.setattr(emulate_mod, "_BACKEND", None)
    monkeypatch.setattr(emulate_mod, "_select_backend", lambda **kw: None)
    res_stop_err = emulate_mod._action_stop(governed=False, unload=False)
    assert res_stop_err["error"] is True and "backend" in res_stop_err["message"].lower()

    # line 512: _suspend_if_needed already not running
    dbg = _debugger(get_process_state=lambda: 2)
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg)
    assert emulate_mod._suspend_if_needed() is True

    # line 515: _suspend_if_needed running but suspend_process not callable
    dbg2 = _debugger(get_process_state=lambda: 1, suspend_process=None)
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg2)
    assert emulate_mod._suspend_if_needed() is False

    # line 589: emulate action backend with force and process running
    stopped = []
    monkeypatch.setattr(emulate_mod, "_PROCESS_STARTED", True)
    monkeypatch.setattr(emulate_mod, "_best_effort_stop", lambda: stopped.append(True))
    monkeypatch.setattr(emulate_mod, "_select_backend", lambda **kw: "win32")
    res_b = emulate_mod.emulate(action="backend", name="win32", force=True)
    assert res_b["ok"] is True
    assert stopped == [True]

    # line 732: emulate step timeout
    dbg3 = _debugger()
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg3)
    monkeypatch.setattr(emulate_mod, "_BACKEND", "win32")
    monkeypatch.setattr(emulate_mod, "_wait_not_running", lambda deadline: False)
    step_err = emulate_mod.emulate(action="step", count=1)
    assert step_err["code"] == "EMULATION_TIMEOUT"

    # line 786: emulate run_to timeout
    run_err = emulate_mod.emulate(action="run_to", address="0x401000")
    assert run_err["code"] == "EMULATION_TIMEOUT"

    # lines 913-914: _read_dbg_mem get_byte exception fallback
    call_cnt = [0]

    def faulty_gb(ea):
        call_cnt[0] += 1
        if call_cnt[0] == 1:
            return 0x90
        raise RuntimeError("gb error")

    dbg4 = _debugger(read_dbg_memory=None, get_dbg_byte=faulty_gb)
    monkeypatch.setattr(emulate_mod, "ida_dbg", dbg4)
    read_bytes = emulate_mod._read_dbg_memory(0x1000, 4)
    assert read_bytes == b"\x90"

    # lines 67-68, 72-73: flat import fallbacks
    import importlib.util
    import sys
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "ida_pro_mcp.ida_mcp.tools.emulate_flat_test", Path(emulate_mod.__file__)
    )
    new_mod = importlib.util.module_from_spec(spec)
    new_mod.__package__ = "ida_pro_mcp.ida_mcp.tools"
    gov_dummy = types.SimpleNamespace(evaluate_operation=lambda *_a, **_kw: None)
    monkeypatch.setitem(sys.modules, "governance_engine", gov_dummy)
    orig_dbg = sys.modules.get("ida_dbg")
    orig_gov = sys.modules.get("ida_pro_mcp.ida_mcp.tools.governance_engine")
    try:
        sys.modules["ida_dbg"] = None
        sys.modules["ida_pro_mcp.ida_mcp.tools.governance_engine"] = None
        spec.loader.exec_module(new_mod)
        assert new_mod.ida_dbg is None
    finally:
        if orig_dbg is not None:
            sys.modules["ida_dbg"] = orig_dbg
        if orig_gov is not None:
            sys.modules["ida_pro_mcp.ida_mcp.tools.governance_engine"] = orig_gov
