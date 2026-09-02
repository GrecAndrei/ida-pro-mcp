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
