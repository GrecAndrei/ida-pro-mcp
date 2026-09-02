"""Exercise debugger backend fallbacks and volatile action boundaries."""

from __future__ import annotations

import types

import pytest

emulate_module = __import__(
    "ida_pro_mcp.ida_mcp.tools.emulate", fromlist=["emulate"]
)


class Debugger:
    DSTATE_RUNNING = 1
    DSTATE_SUSP = 2
    DSTATE_IDLE = 3
    DSTATE_NOT_RUN = 4
    DSTATE_EXIT = 5
    WFNE_SUSP = 0x10

    def __init__(self):
        self.state = self.DSTATE_SUSP
        self.regs = {"rax": 1, "rip": 0x1000}
        self.calls = []

    def load_debugger(self, name, _quiet):
        self.calls.append(("load", name))
        return name == "gdb"

    def get_process_state(self):
        return self.state

    def get_ip_val(self):
        return self.regs.get("rip")

    def get_reg_vals(self):
        return dict(self.regs)

    def get_reg_val(self, name):
        return self.regs.get(name)

    def set_reg_val(self, name, value):
        self.regs[name] = value

    def step_into(self):
        self.calls.append(("step", "into"))
        return True

    def step_over(self):
        self.calls.append(("step", "over"))
        return False

    def step_until_ret(self):
        self.calls.append(("step", "ret"))
        raise RuntimeError("no frame")

    def run_to(self, address):
        self.regs["rip"] = address
        return False

    def start_process(self, *_args):
        self.calls.append(("start",))
        return 0

    def suspend_process(self):
        self.calls.append(("suspend",))

    def continue_process(self):
        self.calls.append(("continue",))

    def exit_process(self):
        self.calls.append(("exit",))
        raise RuntimeError("already exited")

    def stop_process(self):
        self.calls.append(("stop",))
        self.state = self.DSTATE_EXIT


@pytest.fixture
def debugger(monkeypatch):
    dbg = Debugger()
    monkeypatch.setattr(emulate_module, "ida_dbg", dbg)
    monkeypatch.setattr(emulate_module, "_BACKEND", None)
    monkeypatch.setattr(emulate_module, "_BACKEND_REASON", "")
    monkeypatch.setattr(emulate_module, "_BACKEND_ATTEMPTS", {})
    monkeypatch.setattr(emulate_module, "_PROCESS_STARTED", False)
    monkeypatch.setattr(emulate_module, "get_arch", lambda: "metapc")
    monkeypatch.setattr(emulate_module, "_inf_bitness_or_64", lambda: 64)
    return dbg


def test_helper_fallbacks_cover_architectures_states_and_event_pumping(monkeypatch):
    mod = emulate_module
    monkeypatch.setattr(mod, "_inf_bitness", lambda: 32, raising=False)
    assert mod._inf_bitness_or_64() == 32
    monkeypatch.setattr(mod, "_inf_bitness", lambda: (_ for _ in ()).throw(RuntimeError()), raising=False)
    assert mod._inf_bitness_or_64() == 64
    monkeypatch.delattr(mod, "_inf_bitness", raising=False)

    assert mod._hex_reg("not-a-number") == "not-a-number"
    assert mod._as_int_opt(None) is None
    assert mod._as_int_opt("") is None
    assert mod._as_int_opt("bad") is None
    assert mod._hex_to_bytes("0x90, 90_90") == b"\x90\x90\x90"
    assert mod._hex_to_bytes("") is None
    assert mod._hex_to_bytes("0") is None
    assert mod._hex_to_bytes("gg") is None

    dbg = types.SimpleNamespace(
        DSTATE_RUNNING=1,
        DSTATE_RUN=2,
        DSTATE_SUSP=3,
        DSTATE_DEBUGGING=4,
        DSTATE_QUITTING=5,
        DSTATE_IDLE=6,
        DSTATE_NOT_RUN=7,
        DSTATE_EXIT=8,
        WFNE_SUSP=0x10,
        get_process_state=lambda: 6,
    )
    monkeypatch.setattr(mod, "ida_dbg", dbg)
    assert mod._running_states() == {1, 2}
    assert mod._active_states() == {1, 2, 3, 4, 5}
    assert mod._state_name() == "idle"
    monkeypatch.setattr(dbg, "get_process_state", lambda: 99)
    assert mod._state_name() == "unknown"
    monkeypatch.setattr(dbg, "get_process_state", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert mod._state_name() == "unknown"
    assert mod._process_running() is False
    monkeypatch.setattr(mod, "_PROCESS_STARTED", True)
    assert mod._process_running() is True

    dbg.get_process_state = lambda: dbg.DSTATE_RUNNING
    dbg.wait_for_next_event = lambda *_args: 0
    assert mod._pump_suspended(10) is False
    dbg.wait_for_next_event = lambda *_args: -1
    assert mod._pump_suspended(10) is True
    dbg.wait_for_next_event = lambda *_args: (_ for _ in ()).throw(RuntimeError())
    assert mod._pump_suspended(10) is True
    monkeypatch.delattr(dbg, "wait_for_next_event")
    assert mod._pump_suspended(10) is True

    ticks = iter((0.0, 0.0, 1.0))
    monkeypatch.setattr(mod.time, "time", lambda: next(ticks))
    monkeypatch.setattr(mod.time, "sleep", lambda _seconds: None)
    assert mod._wait_not_running(0.5) is False
    dbg.get_process_state = lambda: None
    monkeypatch.setattr(mod.time, "time", lambda: 0.0)
    assert mod._wait_not_running(2.0) is True

    monkeypatch.setattr(mod, "get_arch", lambda: "metapc")
    monkeypatch.setattr(mod, "is_x86_family", lambda arch: arch == "metapc")
    monkeypatch.setattr(mod, "_inf_bitness_or_64", lambda: 32)
    assert mod._ip_reg_name() == "eip"
    monkeypatch.setattr(mod, "get_arch", lambda: "arm")
    monkeypatch.setattr(mod, "is_arm_family", lambda arch: arch == "arm")
    monkeypatch.setattr(mod, "_inf_bitness_or_64", lambda: 64)
    assert mod._common_register_names()[0] == "x0"
    monkeypatch.setattr(mod, "_inf_bitness_or_64", lambda: 32)
    assert mod._common_register_names()[0] == "r0"
    monkeypatch.setattr(mod, "get_arch", lambda: "mips")
    monkeypatch.setattr(mod, "is_mips_family", lambda arch: arch == "mips")
    assert "ra" in mod._common_register_names()
    monkeypatch.setattr(mod, "get_arch", lambda: "unknown")
    assert mod._common_register_names() == ["pc"]

    dbg.get_reg_vals = lambda: {"rax": 7}
    assert mod._read_all_registers() == ({"rax": "0x7"}, True)
    dbg.get_reg_vals = dict
    dbg.get_reg_val = lambda name: 4 if name == "pc" else (_ for _ in ()).throw(RuntimeError())
    assert mod._read_all_registers()[1] is True


def test_backend_selection_reports_failures_and_no_backend(monkeypatch):
    mod = emulate_module
    dbg = types.SimpleNamespace(load_debugger=lambda *_args: False)
    monkeypatch.setattr(mod, "ida_dbg", dbg)
    monkeypatch.setattr(mod, "_BACKEND", None)
    monkeypatch.setattr(mod, "_BACKEND_REASON", "")
    attempts = {}
    monkeypatch.setattr(mod, "_BACKEND_ATTEMPTS", attempts)
    assert mod._select_backend(force=True) is None
    assert len(attempts) == len(mod._BACKEND_CANDIDATES)
    assert "no backend loadable" in mod._BACKEND_REASON
    assert mod._no_backend_error()["error"] is True
    assert mod._require_backend()["error"] is True

    monkeypatch.delattr(dbg, "load_debugger")
    attempts.clear()
    assert mod._select_backend(name="custom", force=True) is None
    assert attempts["custom"].startswith("error:")
    assert mod._build_backend_reason("gdb", []) == "selected backend 'gdb'"
    assert "native backend" in mod._build_backend_reason("gdb", ["Emulator"])
    assert "candidates" in mod._build_backend_reason("gdb", ["linux"])


def test_action_failure_modes_and_fallback_memory_paths(monkeypatch, debugger):
    mod = emulate_module
    mod._BACKEND = "gdb"
    monkeypatch.setattr(mod, "_governance_check", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(mod, "_require_backend", lambda: None)
    assert mod._action_start(False, None, None, None, "/missing")["error"] is True
    debugger.start_process = None
    assert mod._action_start(False, None, None, None, None)["error"] is True

    debugger.step_into = None
    assert mod._action_step(False, "into", 1, 1)["error"] is True
    debugger.step_into = lambda: False
    assert mod._action_step(False, "into", "2", -1)["steps_done"] == 0
    assert mod._action_step(False, "bad", 1, 1)["error"] is True
    debugger.step_until_ret = lambda: (_ for _ in ()).throw(RuntimeError("bad step"))
    assert mod._action_step(False, "ret", 1, 1)["error"] is True

    assert mod._action_run_to(False, None, 1)["error"] is True
    assert mod._action_run_to(False, "bad", 1)["error"] is True
    debugger.run_to = None
    assert mod._action_run_to(False, "0x1000", 1)["error"] is True

    debugger.get_reg_val = None
    assert mod._action_get_reg(False, "rax", None)["error"] is True
    debugger.set_reg_val = None
    assert mod._action_set_reg(False, "rax", 1)["error"] is True
    assert mod._action_set_reg(False, None, 1)["error"] is True
    assert mod._action_set_reg(False, "rax", None)["error"] is True

    def bulk_fail(*_args):
        raise TypeError("buffer shape")

    debugger.read_dbg_memory = bulk_fail
    debugger.get_dbg_byte = lambda address: (address - 0x1000) if address < 0x1002 else -1
    assert mod._read_dbg_memory(0x1000, 4) == b"\x00\x01"
    debugger.get_dbg_byte = lambda _address: -1
    assert mod._read_dbg_memory(0x1000, 4) is None
    assert mod._action_read_mem(False, None, 4)["error"] is True
    assert mod._action_read_mem(False, "0x1000", "bad")["error"] is True

    debugger.write_dbg_memory = None
    assert mod._action_set_mem(False, None, "90")["error"] is True
    assert mod._action_set_mem(False, "0x1000", "90")["error"] is True

    debugger.exit_process = None
    debugger.stop_process = None
    assert mod._action_stop(False, False)["error"] is True
    debugger.suspend_process = None
    assert mod._action_suspend(False)["error"] is True
    debugger.continue_process = None
    assert mod._action_continue(False)["error"] is True


def test_public_dispatcher_handles_missing_debugger_and_backend_metadata(monkeypatch):
    mod = emulate_module
    monkeypatch.setattr(mod, "ida_dbg", None)
    result = mod.emulate(action="info")
    assert result["error"] is True
    assert result["backend"] in {"gdb", "none"}
    assert mod._augment_backend({"ok": True})["backend_candidates"]
