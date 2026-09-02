"""Cross-mode coverage for the debugger/emulation surface.

The fake debugger below models the state transitions a real backend exposes:
load, start, suspend, step, run-to, register/memory access, and teardown.
The test deliberately drives the public dispatcher for every action so the
governance, backend metadata, and volatile read/write behavior are covered
together rather than only testing helper functions in isolation.
"""

from __future__ import annotations

import ctypes

import pytest

from ida_pro_mcp.ida_mcp.tools.emulate import emulate

emulate_module = __import__(
    "ida_pro_mcp.ida_mcp.tools.emulate", fromlist=["emulate"]
)


class _Debugger:
    DSTATE_RUNNING = 1
    DSTATE_SUSP = 2
    DSTATE_IDLE = 3
    DSTATE_NOT_RUN = 4
    DSTATE_EXIT = 5
    WFNE_SUSP = 0x10

    def __init__(self):
        self.state = self.DSTATE_NOT_RUN
        self.registers = {"rip": 0x401000, "rax": 7}
        self.memory = bytearray(b"hello\x00")
        self.loaded = []
        self.writes = []

    def load_debugger(self, name, _quiet):
        self.loaded.append(name)
        return name == "linux"

    def get_process_state(self):
        return self.state

    def get_ip_val(self):
        return self.registers.get("rip")

    def get_reg_vals(self):
        return dict(self.registers)

    def get_reg_val(self, name):
        return self.registers.get(name)

    def set_reg_val(self, name, value):
        self.registers[name] = value

    def start_process(self, path=None, args=None):
        self.started = (path, args)
        self.state = self.DSTATE_RUNNING
        return 1

    def suspend_process(self):
        self.state = self.DSTATE_SUSP
        return True

    def continue_process(self):
        self.state = self.DSTATE_RUNNING
        return True

    def step_into(self):
        self.registers["rip"] += 1
        self.state = self.DSTATE_SUSP
        return True

    def step_over(self):
        self.registers["rip"] += 2
        self.state = self.DSTATE_SUSP
        return True

    def step_until_ret(self):
        self.registers["rip"] += 3
        self.state = self.DSTATE_SUSP
        return True

    def run_to(self, address):
        self.registers["rip"] = address
        self.state = self.DSTATE_SUSP
        return True

    def read_dbg_memory(self, address, buf, size):
        del address
        raw = bytes(self.memory[:size])
        ctypes.memmove(buf, raw, len(raw))
        return len(raw)

    def write_dbg_memory(self, address, buf, size):
        raw = ctypes.string_at(buf, size)
        self.writes.append((address, raw))
        self.memory[:size] = raw
        return size

    def exit_process(self):
        self.state = self.DSTATE_EXIT


@pytest.fixture
def fake_debugger(monkeypatch):
    dbg = _Debugger()
    monkeypatch.setattr(emulate_module, "ida_dbg", dbg)
    monkeypatch.setattr(emulate_module, "_BACKEND", None)
    monkeypatch.setattr(emulate_module, "_BACKEND_REASON", "")
    monkeypatch.setattr(emulate_module, "_BACKEND_ATTEMPTS", {})
    monkeypatch.setattr(emulate_module, "_PROCESS_STARTED", False)
    monkeypatch.setattr(emulate_module, "get_arch", lambda: "metapc")
    monkeypatch.setattr(emulate_module, "_inf_bitness_or_64", lambda: 64)
    return dbg


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_every_emulation_action_round_trips_through_public_dispatcher(fake_debugger, tmp_path):
    info = _ok(emulate(action="info"))
    assert info["backend"] == "none"

    backend = _ok(emulate(action="backend", name="missing"))
    assert backend["backend"] == "linux"
    assert fake_debugger.loaded[:2] == ["missing", "Emulator"]
    assert "linux" in backend["backend_attempts"]

    started = _ok(
        emulate(
            action="start",
            start_addr="0x140001000",
            input_file="sample.bin",
            args="--safe",
            dir=str(tmp_path),
            governed=False,
        )
    )
    assert started["started"] is True
    assert fake_debugger.started == ("sample.bin", "--safe")
    assert fake_debugger.state == fake_debugger.DSTATE_SUSP

    assert _ok(emulate(action="state"))["process_state"] == "suspended"
    for mode in ("into", "over", "ret"):
        assert _ok(emulate(action="step", mode=mode, count=2, governed=False))["steps_done"] == 2
    assert _ok(emulate(action="run_to", address="0x140001234", governed=False))["reached"] is True
    assert _ok(emulate(action="get_reg", names=["rip", "missing"]))["unavailable"] == ["missing"]
    assert _ok(emulate(action="set_reg", name="rax", value="0x44", governed=False))["value"] == "0x44"
    assert _ok(emulate(action="read_mem", address="0x140001000", size=5))["ascii"] == "hello"
    written = _ok(emulate(action="set_mem", address="0x140001000", data="41 42", governed=False))
    assert written["size"] == 2
    assert fake_debugger.writes[-1] == (0x140001000, b"AB")
    assert _ok(emulate(action="continue", governed=False))["continued"] is True
    assert _ok(emulate(action="suspend", governed=False))["suspended"] is True
    assert _ok(emulate(action="stop", unload=True, governed=False))["stopped"] is True
    assert emulate_module._BACKEND is None


def test_emulation_errors_are_backend_annotated_and_governed(fake_debugger, monkeypatch):
    assert emulate(action="unknown")["error"] is True
    assert emulate(action="get_reg")["error"] is True
    assert emulate(action="step", mode="bad", governed=False)["error"] is True
    assert emulate(action="run_to", address="bad", governed=False)["error"] is True
    assert emulate(action="set_reg", name="rax", value="wat", governed=False)["error"] is True
    assert emulate(action="read_mem", address="0x10", size="bad")["error"] is True
    assert emulate(action="set_mem", address="0x10", data="odd", governed=False)["error"] is True
    monkeypatch.setattr(emulate_module, "evaluate_operation", lambda *args, **kwargs: {"approved": False})
    blocked = emulate(action="set_reg", name="rax", value=1)
    assert blocked["error"] is True
    assert blocked["code"] == "GOVERNANCE_BLOCKED"
