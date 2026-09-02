"""h02 runtime-spawn / resume regression tests.

Pins the s06-h02 work-order behavior in server_runtime.py / server_session.py:

- close-in-progress flag (``_session_teardown``) cleared unconditionally
- ``_retire_dead_runtime`` closes log fds + drops stale port/token WITHOUT
  releasing ownership or tombstoning
- ``_terminate_ida_processes_for_path`` EXACT argv match (positional or ``-o``
  forms) + live-runtime-pid exclusion — exercised against an opaque RISC-V
  raw-blob session IDB
- periodic analysis checkpointing (skip rules, save RPC, progress marker) and
  resume-staleness warning
- analysis-completion watcher clean stop (no leaked ``ida-an-*`` threads)
- architecture auto-apply for opaque blobs: Cortex-M and non-ambiguous RISC-V
  applied, ambiguous rv32c near-tie never forced
- ENOSPC detection in ``_extract_library_init_failure``
- honest ``indexing_state: "disabled"`` in the spawn return envelope

Standalone: no live IDA, ``_FakeIdaProcess``-style fakes only.
"""

from __future__ import annotations

import datetime
import io
import os
import struct
import sys
import threading
from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin
from ida_pro_mcp.host.server.server_session import ServerSessionMixin

SID = "AB12CDEF"
FAKE_PID = 2147483647  # above pid_max: os.kill/killpg are harmless no-ops


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, pid: int = FAKE_PID, alive: bool = True):
        self.pid = pid
        self._alive = alive

    def poll(self):
        return None if self._alive else 1

    def wait(self, timeout=None):
        return 1


class _Host(ServerRuntimeMixin):
    """Minimal runtime-mixin host (mirrors test_swarm_f04_runtime._Host)."""

    def __init__(self, tmp_path):
        self._runtime_lease_dir = str(tmp_path / "leases")
        os.makedirs(self._runtime_lease_dir, exist_ok=True)
        self._runtime_owner_id = "owner-x"
        self._runtime_lock = threading.RLock()
        self.session_runtimes = {}
        self._session_startup_locks = {}
        self._session_last_activity = {}
        self._session_inflight_calls = {}
        self._session_teardown = set()
        self.cache_dir = str(tmp_path / "cache")
        self.ida_dir = None
        self.idat_exe = "/fake/ida/idat64"
        self.session_mgr = SimpleNamespace(
            sessions={},
            _save_metadata=lambda s: None,
            get_session_artifact_dir=lambda sid, create=True: str(tmp_path / f"artifacts-{sid}"),
            get_session_log_dir=lambda sid, create=True: str(tmp_path / f"logs-{sid}"),
        )

    def _stop_analysis_watchdog(self, sid, join_timeout=0.5):
        pass

    @staticmethod
    def _runtime_alive(runtime):
        if not isinstance(runtime, dict):
            return False
        proc = runtime.get("process")
        if not proc:
            return False
        try:
            return proc.poll() is None
        except Exception:
            return False

    def _make_session(self, tmp_path, binary_name="sample.bin"):
        binary = tmp_path / f"{SID}_{binary_name}"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
        return SimpleNamespace(
            session_id=SID,
            binary_path=str(binary),
            idb_path=str(tmp_path / f"SID_{SID}_{binary_name}.i64"),
            analysis_options={},
            analysis_applied=False,
            packed_idb=False,
        )


def _make_log_handles(tmp_path):
    fh1 = open(str(tmp_path / "out.log"), "a", encoding="utf-8")
    fh2 = open(str(tmp_path / "err.log"), "a", encoding="utf-8")
    return fh1, fh2


def _session_host():
    """Bare ServerSessionMixin instance for self-independent methods."""
    return ServerSessionMixin.__new__(ServerSessionMixin)


# ---------------------------------------------------------------------------
# Opaque RISC-V / Cortex-M raw-blob builders (deterministic)
# ---------------------------------------------------------------------------


def _w32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _h16(v: int) -> bytes:
    return struct.pack("<H", v)


def _rv64c() -> bytes:
    """RV64C blob with ld (funct3=011) — clear 64-bit evidence, conf ~1.0,
    NOT ambiguous."""
    out = bytearray()
    out += _w32(0x00001097)  # auipc gp, 0x10000
    out += _w32(0x00018193)  # addi gp, gp, 0
    for _ in range(120):
        out += _h16(0x0004) + _h16(0x4084) + _h16(0x00E1) + _h16(0x40C1)
        out += _w32(0x0002B303)  # ld t1, 0(t0)
        out += _w32(0x0002B383)  # ld t2, 0(t0)
        out += _h16(0x9082) + _h16(0x8082)
    return bytes(out)


def _rv32c() -> bytes:
    """RV32C compressed-only blob: riscv known but bitness near-tie ->
    ambiguous=True, must NOT be auto-applied."""
    out = bytearray()
    out += _w32(0x00001097)
    out += _w32(0x00018193)
    for _ in range(120):
        out += _h16(0x0004) + _h16(0x4084) + _h16(0x00E1) + _h16(0x40C1)
        out += _h16(0x9082) + _h16(0x8082)
    return bytes(out)


def _cortex_m_blob() -> bytes:
    """Little-endian Cortex-M vector table: SP in RAM, Thumb reset vector,
    plausible Thumb pointer entries -> conf 0.92 with load_base."""
    head = struct.pack("<II", 0x20010000, 0x08000101)
    vec = b"".join(struct.pack("<I", 0x08000000 | (i * 4 + 1)) for i in range(1, 24))
    return head + vec


def _write_blob(tmp_path, blob, name="blob.bin"):
    p = tmp_path / name
    p.write_bytes(blob)
    return str(p)


# ---------------------------------------------------------------------------
# close-in-progress flag: cleared unconditionally
# ---------------------------------------------------------------------------


def test_teardown_session_context_clears_flag_on_success(tmp_path):
    host = _Host(tmp_path)
    with host._teardown_session(SID):
        assert host._session_teardown_active(SID)
    assert not host._session_teardown_active(SID)
    assert SID not in host._session_teardown


def test_teardown_session_context_clears_flag_on_error(tmp_path):
    host = _Host(tmp_path)
    with pytest.raises(RuntimeError), host._teardown_session(SID):
        assert host._session_teardown_active(SID)
        raise RuntimeError("delete failed")
    # The flag is cleared even when teardown itself raises, so a later re-open
    # of the same path is never refused by a stale marker.
    assert not host._session_teardown_active(SID)


def test_end_teardown_is_idempotent(tmp_path):
    host = _Host(tmp_path)
    host._end_session_teardown(SID)  # never set — no error
    host._begin_session_teardown(SID)
    host._end_session_teardown(SID)
    host._end_session_teardown(SID)  # double clear — no error
    assert not host._session_teardown_active(SID)


# ---------------------------------------------------------------------------
# _retire_dead_runtime: close fds / drop stale port/token, keep ownership
# ---------------------------------------------------------------------------


def test_retire_dead_runtime_closes_fds_and_drops_port_keeps_ownership(tmp_path):
    host = _Host(tmp_path)
    fh1, fh2 = _make_log_handles(tmp_path)
    host.session_runtimes[SID] = {
        "process": _FakeProc(alive=False),
        "port": 9876,
        "auth_token": "tok",
        "log_handles": [fh1, fh2],
        "idb_path": str(tmp_path / "a.i64"),
    }
    host._retire_dead_runtime(SID)
    assert fh1.closed and fh2.closed
    rt = host.session_runtimes[SID]
    assert rt["log_handles"] == []
    assert "port" not in rt
    assert "auth_token" not in rt
    # Ownership lease is NOT released and the session is NOT tombstoned: a
    # concurrent spawner must still see the dead runtime to reclaim, and the
    # close-in-progress flag stays clear so a fresh spawn is allowed.
    assert SID in host.session_runtimes
    assert not host._session_teardown_active(SID)


def test_retire_dead_runtime_noop_when_no_runtime(tmp_path):
    host = _Host(tmp_path)
    host._retire_dead_runtime(SID)  # no entry, no error
    assert SID not in host.session_runtimes


def test_start_server_retires_dead_runtime_before_fresh_spawn(tmp_path, monkeypatch):
    """A previously-crashed runtime's stale port/token/log fds must be dropped
    before the fresh spawn publishes a new runtime, but ownership stays held
    the whole time (h02 1b)."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    fh1, fh2 = _make_log_handles(tmp_path)
    host.session_runtimes[SID] = {
        "process": _FakeProc(alive=False),
        "port": 9876,
        "auth_token": "tok",
        "log_handles": [fh1, fh2],
    }
    observed = {}

    def _inner(s):
        rt = host.session_runtimes[SID]
        observed["port"] = rt.get("port")
        observed["token"] = rt.get("auth_token")
        observed["fds"] = list(rt["log_handles"])
        return {"ok": True, "idb_path": s.idb_path}

    monkeypatch.setattr(host, "_start_server_inner", _inner)
    res = host._start_server(session)

    assert "error" not in res
    assert observed["port"] is None
    assert observed["token"] is None
    assert observed["fds"] == []
    assert fh1.closed and fh2.closed
    # Ownership still held after the fresh spawn completes.
    assert os.path.exists(host._runtime_owner_path(SID))


# ---------------------------------------------------------------------------
# _terminate_ida_processes_for_path: EXACT argv match + live-pid exclusion
# ---------------------------------------------------------------------------


class _FakePsProcess:
    def __init__(self, info):
        self.info = info


class _FakePsutil:
    def __init__(self, procs):
        self._procs = procs

    def process_iter(self, attrs):
        return list(self._procs)


def test_argv_targets_path_exact_and_switch_forms(tmp_path):
    target = str(tmp_path / "SID_AB12CDEF_fw.bin.i64").lower()
    assert ServerRuntimeMixin._argv_targets_path(["idat64", target], target) is True
    assert ServerRuntimeMixin._argv_targets_path(["idat64", "-o" + target], target) is True
    assert ServerRuntimeMixin._argv_targets_path(["idat64", "-o", target], target) is True
    assert ServerRuntimeMixin._argv_targets_path(["idat64", "-o=" + target], target) is True
    # Substring/prefix containment is NOT an exact match.
    assert ServerRuntimeMixin._argv_targets_path(["idat64", target + ".bak"], target) is False
    assert ServerRuntimeMixin._argv_targets_path(["idat64", target + "x"], target) is False
    assert ServerRuntimeMixin._argv_targets_path(["idat64", "not-" + target], target) is False
    # -o with no following token does not match.
    assert ServerRuntimeMixin._argv_targets_path(["idat64", "-o"], target) is False
    # Empty argv / None never matches.
    assert ServerRuntimeMixin._argv_targets_path(None, target) is False


def test_terminate_ida_processes_for_path_exact_match_skips_live_and_substr(
    tmp_path, monkeypatch
):
    """Opaque RISC-V raw-blob session: the stale killer matches the session IDB
    path EXACTLY (positional or -o forms) and never signals the host's own live
    runtime or an unrelated process whose cmdline merely contains the path."""
    blob = _write_blob(tmp_path, _rv64c(), name="soc_fw.bin")
    idb_path = str(tmp_path / f"SID_{SID}_soc_fw.bin.i64")
    # The blob file is a stand-in for the analyzed IDB; the killer only matches
    # command lines, so the file itself does not need to exist.
    assert os.path.exists(blob)

    # One live runtime owned by this host (its cmdline legitimately carries the
    # session IDB path) must be excluded.
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {
        "process": _FakeProc(pid=6666, alive=True),
        "port": 7777,
        "idb_path": idb_path,
    }

    procs = [
        _FakePsProcess({"pid": 1111, "name": "idat64", "cmdline": ["/ida/idat64", idb_path]}),
        # substring only — must NOT be killed
        _FakePsProcess({"pid": 2222, "name": "idat64", "cmdline": ["/ida/idat64", idb_path + ".bak"]}),
        _FakePsProcess({"pid": 3333, "name": "idat64", "cmdline": ["/ida/idat64", "-o" + idb_path]}),
        _FakePsProcess({"pid": 4444, "name": "idat64", "cmdline": ["/ida/idat64", "-o", idb_path]}),
        _FakePsProcess({"pid": 5555, "name": "idat64", "cmdline": ["/ida/idat64", "-o=" + idb_path]}),
        # live owned runtime — must NOT be killed
        _FakePsProcess({"pid": 6666, "name": "idat64", "cmdline": ["/ida/idat64", idb_path]}),
        # non-IDA name — skipped entirely
        _FakePsProcess({"pid": 7777, "name": "gdb", "cmdline": ["gdb", idb_path]}),
    ]
    monkeypatch.setitem(sys.modules, "psutil", _FakePsutil(procs))
    killed_pids = []
    monkeypatch.setattr(server_runtime_mod.os, "getpgid", lambda pid: 9999)  # never leader
    monkeypatch.setattr(server_runtime_mod.os, "kill", lambda pid, sig: killed_pids.append(pid))
    monkeypatch.setattr(
        server_runtime_mod.os, "killpg", lambda pgid, sig: killed_pids.append(("pg", pgid))
    )

    killed = host._terminate_ida_processes_for_path(idb_path)

    assert sorted(killed) == [1111, 3333, 4444, 5555]
    assert killed_pids == [1111, 3333, 4444, 5555]  # pid-only signals, no killpg
    assert 6666 not in killed and 2222 not in killed and 7777 not in killed


def test_terminate_uses_killpg_only_for_group_leader(tmp_path, monkeypatch):
    """Preserved f04/orphan behavior: a stale process that LEADS its own
    process group is killpg'd; one sharing another group is signalled pid-only
    so the shared group (possibly the MCP server / shell) is never taken out."""
    host = _Host(tmp_path)
    idb_path = str(tmp_path / "SID_AB12CDEF_x.bin.i64")
    procs = [
        _FakePsProcess({"pid": 1111, "name": "idat64", "cmdline": ["idat64", idb_path]}),
        _FakePsProcess({"pid": 2222, "name": "idat64", "cmdline": ["idat64", idb_path]}),
    ]
    monkeypatch.setitem(sys.modules, "psutil", _FakePsutil(procs))
    # 1111 leads its own group (killpg), 2222 shares another group (kill).
    monkeypatch.setattr(server_runtime_mod.os, "getpgid", lambda pid: 1111 if pid == 1111 else 9999)
    killed = []
    killedpg = []
    monkeypatch.setattr(server_runtime_mod.os, "kill", lambda pid, sig: killed.append(pid))
    monkeypatch.setattr(server_runtime_mod.os, "killpg", lambda pgid, sig: killedpg.append(pgid))

    host._terminate_ida_processes_for_path(idb_path)

    assert killedpg == [1111]
    assert killed == [2222]


# ---------------------------------------------------------------------------
# Periodic analysis checkpointing + resume-staleness
# ---------------------------------------------------------------------------


def test_checkpoint_save_interval_respects_knob_and_floors(tmp_path):
    host = _Host(tmp_path)
    assert host._checkpoint_save_interval() == 5.0  # default
    host.checkpoint_save_seconds = 1.0
    assert host._checkpoint_save_interval() == 1.0
    host.checkpoint_save_seconds = 0.3  # floored to 1.0 — no hot-loop saving
    assert host._checkpoint_save_interval() == 1.0
    host.checkpoint_save_seconds = 7.5
    assert host._checkpoint_save_interval() == 7.5


def test_run_analysis_checkpoint_skips_until_analysis_complete(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    calls = []
    monkeypatch.setattr(
        host, "_send_rpc_raw", lambda *a, **k: calls.append(k) or {"ok": True}
    )
    monkeypatch.setattr(
        host, "_record_analysis_checkpoint", lambda sid: calls.append(("record", sid))
    )
    gate = {"done": False}
    # _analysis_is_complete lives on the session mixin, not the bare runtime
    # host; a plain instance override shadows cleanly here.
    host._analysis_is_complete = lambda sid: gate["done"]

    # Gate still pending (safe mode) -> skip even though the runtime is alive.
    host.session_runtimes[SID] = {"process": _FakeProc(pid=111, alive=True), "port": 7001}
    host._run_analysis_checkpoint(SID)
    assert calls == []

    # Gate complete but no published port -> skip.
    gate["done"] = True
    host.session_runtimes[SID] = {"process": _FakeProc(pid=111, alive=True)}
    host._run_analysis_checkpoint(SID)
    assert calls == []

    # Runtime gone -> skip.
    host.session_runtimes[SID] = {"process": _FakeProc(pid=111, alive=False), "port": 7001}
    host._run_analysis_checkpoint(SID)
    assert calls == []

    # No runtime at all -> skip.
    host.session_runtimes.pop(SID, None)
    host._run_analysis_checkpoint(SID)
    assert calls == []


def test_run_analysis_checkpoint_saves_and_records_marker(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {
        "process": _FakeProc(pid=111, alive=True),
        "port": 7001,
        "auth_token": "tok",
    }
    host._analysis_is_complete = lambda sid: True
    sent = []
    monkeypatch.setattr(
        host, "_send_rpc_raw", lambda *a, **k: sent.append((a, k)) or {"ok": True}
    )
    recorded = []
    monkeypatch.setattr(host, "_record_analysis_checkpoint", recorded.append)

    host._run_analysis_checkpoint(SID)

    assert recorded == [SID]
    (req, port), kw = sent[0]
    assert req == {"tool": "analysis", "args": {"action": "save_idb"}}
    assert port == 7001
    assert kw.get("auth_token") == "tok"
    assert kw.get("queue_timeout") == 0

    # A failed save (error envelope) records no marker.
    sent.clear()
    recorded.clear()
    monkeypatch.setattr(
        host,
        "_send_rpc_raw",
        lambda *a, **k: sent.append((a, k)) or {"error": True, "code": 999},
    )
    host._run_analysis_checkpoint(SID)
    assert sent and recorded == []


def test_record_analysis_checkpoint_persists_progress_marker(tmp_path, monkeypatch):
    host = _Host(tmp_path)
    host.session_runtimes[SID] = {"process": _FakeProc(pid=111, alive=True), "port": 7001}
    monkeypatch.setattr(
        host,
        "_query_ida_state",
        lambda sid, timeout=2.0: {"ok": True, "inventory": {"functions_qty": 42}},
    )
    written = {}
    monkeypatch.setattr(
        host, "_update_session_indexing_metadata", lambda sid, **kw: written.update(kw)
    )
    host._record_analysis_checkpoint(SID)
    assert written.get("analysis_progress") == 42
    assert str(written.get("analysis_checkpointed_at") or "").endswith("Z")


def test_checkpoint_staleness_warning_only_when_marker_stale():
    def _marker(seconds_ago: float) -> str:
        now_utc = datetime.datetime.now(datetime.UTC)
        stamp = now_utc.replace(tzinfo=None) - datetime.timedelta(seconds=seconds_ago)
        return stamp.isoformat() + "Z"

    # Fresh session (no marker) -> no warning.
    assert ServerSessionMixin._checkpoint_staleness_warning(SimpleNamespace(metadata={})) is None
    assert ServerSessionMixin._checkpoint_staleness_warning(SimpleNamespace(metadata=None)) is None
    # Recently checkpointed -> no warning.
    now = _marker(0)
    assert (
        ServerSessionMixin._checkpoint_staleness_warning(
            SimpleNamespace(metadata={"analysis_checkpointed_at": now})
        )
        is None
    )
    # Stale marker (older than _CHECKPOINT_STALENESS_SECONDS) -> warning.
    old = _marker(10000)
    warn = ServerSessionMixin._checkpoint_staleness_warning(
        SimpleNamespace(metadata={"analysis_checkpointed_at": old})
    )
    assert warn is not None and "stale" in warn


# ---------------------------------------------------------------------------
# Analysis-completion watcher: clean stop, no leaked ida-an-* thread
# ---------------------------------------------------------------------------


def test_analysis_watcher_stops_cleanly_no_leaked_thread():
    host = _session_host()
    # Keep the watcher alive: session pending (safe mode on) + a session record
    # so the poll loop does not return early, and no runtime so it never
    # observes completion.
    host._pending_analysis = {SID}
    host.session_runtimes = {}
    host.session_mgr = SimpleNamespace(get_session=lambda sid: SimpleNamespace(session_id=sid))
    host.safe_mode_poll_seconds = 0.05
    host._spawn_analysis_watcher(SID)
    assert SID in host._analysis_watcher_stop_events
    watcher = host._analysis_watcher_threads[SID]
    assert watcher.name == f"ida-an-{SID}"

    # _forget_analysis_state clears the pending gate FIRST, then stops the
    # watcher — otherwise the watcher's exit path would re-arm itself.
    host._pending_analysis.discard(SID)
    host._stop_analysis_watcher(SID, join_timeout=1.0)

    assert SID not in host._analysis_watcher_stop_events
    assert SID not in host._analysis_watcher_threads
    assert not any(t.name == f"ida-an-{SID}" for t in threading.enumerate())
    # _forget_analysis_state calls the same stopper; calling it again on a
    # stopped session is a no-op (the watcher set no longer holds the sid).
    host._stop_analysis_watcher(SID, join_timeout=1.0)


# ---------------------------------------------------------------------------
# Architecture auto-apply for opaque blobs (h02 q02)
# ---------------------------------------------------------------------------


def test_auto_apply_cortex_m_high_confidence(tmp_path):
    from ida_pro_mcp.host.analysis.arch_profile import infer_binary_arch_profile

    path = _write_blob(tmp_path, _cortex_m_blob(), name="mcu.bin")
    inf = infer_binary_arch_profile(path)
    assert inf["processor"] == "arm" and inf["bitness"] == 32
    assert inf["confidence"] >= 0.9 and not inf.get("ambiguous")

    opts = {}
    warn = _session_host()._auto_apply_inferred_profile(opts, inf)
    assert warn is not None and "arm 32-bit" in warn
    assert opts["processor"] == "arm"
    assert opts["bitness"] == 32
    assert opts["endian"] == "little"
    assert opts.get("baseaddr") == 0x08000100  # reset-vector-derived load base


def test_auto_apply_riscv_non_ambiguous_but_not_near_tie(tmp_path):
    from ida_pro_mcp.host.analysis.arch_profile import infer_binary_arch_profile

    host = _session_host()
    # rv64c: riscv/64 at conf ~1.0, NOT ambiguous -> applied.
    path64 = _write_blob(tmp_path, _rv64c(), name="rv64c.bin")
    inf64 = infer_binary_arch_profile(path64)
    assert inf64["confidence"] >= 0.9 and not inf64.get("ambiguous")
    opts = {}
    warn = host._auto_apply_inferred_profile(opts, inf64)
    assert warn is not None and "riscv 64-bit" in warn
    assert opts["processor"] == "riscv" and opts["bitness"] == 64

    # rv32c: riscv known but bitness near-tie -> ambiguous, NEVER forced.
    path32 = _write_blob(tmp_path, _rv32c(), name="rv32c.bin")
    inf32 = infer_binary_arch_profile(path32)
    assert inf32.get("ambiguous") is True
    opts = {}
    assert host._auto_apply_inferred_profile(opts, inf32) is None
    assert opts == {}


def test_prepare_open_args_applies_inference_and_surfaces_warning(tmp_path):
    """The open path (shared by blocking create + background) applies the
    inferred arch into the spawn options and surfaces the warning on the open
    envelope, while explicit user options always win."""
    host = _session_host()
    path = _write_blob(tmp_path, _cortex_m_blob(), name="mcu2.bin")
    binary_path, analysis_options, arch_meta, force_new, ida_args, err = (
        host._prepare_open_args({"binary_path": path})
    )
    assert err is None
    assert binary_path == path
    assert analysis_options["processor"] == "arm"
    assert analysis_options["bitness"] == 32
    assert analysis_options.get("baseaddr") == 0x08000100
    assert arch_meta["inference_applied"] is True
    assert "inference_warning" in arch_meta

    # Explicit user options take precedence and disable auto-apply for those keys.
    _, opts2, meta2, _, _, err2 = host._prepare_open_args(
        {"binary_path": path, "analysis_options": {"processor": "mips"}}
    )
    assert err2 is None
    assert opts2["processor"] == "mips"  # user choice untouched
    assert opts2["bitness"] == 32  # only the unset key is filled
    assert "inference_warning" in meta2


# ---------------------------------------------------------------------------
# ENOSPC detection in library-init failures
# ---------------------------------------------------------------------------


def test_extract_library_init_failure_enospc_cause_and_hint():
    host = ServerRuntimeMixin.__new__(ServerRuntimeMixin)
    info = host._extract_library_init_failure(
        "Error 2: library init failed: mmap failed: No space left on device"
    )
    assert info is not None
    assert info["error_code"] == 2
    assert any("ENOSPC" in c or "disk space" in c for c in info["causes"])
    assert any("df -h" in r or "disk" in r for r in info["recommendations"])

    # "not enough space" phrase and bare ENOSPC also map to the disk cause.
    info2 = host._extract_library_init_failure(
        "library initialization failed: not enough space on /tmp"
    )
    assert info2 is not None and any("disk space" in c for c in info2["causes"])
    info3 = host._extract_library_init_failure(
        "library init failed: ENOSPC writing unpacked sidecar"
    )
    assert info3 is not None and any("ENOSPC" in c or "disk space" in c for c in info3["causes"])

    # A missing-library failure has no disk-space cause; bare ENOSPC (no phrase)
    # is not even classified as a library-init failure.
    no_space = host._extract_library_init_failure(
        "library init failed: cannot open shared object file 'libfoo.so'"
    )
    assert no_space is not None
    assert not any("disk space" in c for c in no_space["causes"])
    assert host._extract_library_init_failure("ENOSPC") is None


# ---------------------------------------------------------------------------
# Honest indexing_state in the spawn envelope
# ---------------------------------------------------------------------------


def test_start_server_reports_indexing_state_disabled(tmp_path, monkeypatch):
    """Directive 6: the spawn success envelope reports indexing_state="disabled"
    (the semantic index is only ever built on demand or reused), not a promise
    of an idle-index worker."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    monkeypatch.setattr(host, "_is_executable_file", lambda p: True)
    monkeypatch.setattr(host, "_build_ida_command", lambda *a, **k: ["fake"])
    monkeypatch.setattr(host, "_nuclear_reset", lambda idb_path, aggressive=False: None)
    monkeypatch.setattr(host, "_cleanup_stale_idb_family", lambda idb_path: None)
    monkeypatch.setattr(host, "_terminate_ida_processes_for_path", lambda target: [])
    monkeypatch.setattr(server_runtime_mod.time, "sleep", lambda *a: None)
    server_process = _FakeProc(pid=222, alive=True)
    monkeypatch.setattr(
        server_runtime_mod.subprocess, "Popen", lambda *a, **k: server_process
    )
    monkeypatch.setattr(
        host, "_send_rpc_raw", lambda *a, **k: {"pong": True, "port": 7777}
    )
    monkeypatch.setattr(
        host,
        "_apply_session_options",
        lambda session, runtime: {"ok": True, "current_options": {}, "apply_steps": [], "steps_done": 0},
    )
    started = []
    monkeypatch.setattr(
        host, "_start_session_background_services", lambda session, port: started.append(port)
    )

    real_isfile = os.path.isfile

    def _fake_isfile(p):
        return True if str(p).endswith(".port") else real_isfile(p)

    monkeypatch.setattr(server_runtime_mod.os.path, "isfile", _fake_isfile)
    real_open = open

    def _fake_open(path, *a, **k):
        if str(path).endswith(".port"):
            return io.StringIO("7777")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _fake_open)
    session_dir = str(tmp_path / "artifacts")
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(str(tmp_path / "logs"), exist_ok=True)
    monkeypatch.setattr(
        host.session_mgr, "get_session_artifact_dir", lambda sid, create=True: session_dir
    )
    monkeypatch.setattr(
        host.session_mgr, "get_session_log_dir", lambda sid, create=True: str(tmp_path / "logs")
    )

    res = host._start_server(session)

    assert "error" not in res, res
    assert res["indexing_state"] == "disabled"
    assert started == [7777]
    assert SID in host.session_runtimes


def test_start_session_background_services_persists_indexing_state_disabled(
    tmp_path, monkeypatch
):
    """The background-services bootstrap records indexing_state="disabled" into
    the session metadata (consumed by status/health reporting)."""
    host = _Host(tmp_path)
    session = host._make_session(tmp_path)
    meta = {}
    host.session_mgr.sessions[SID] = SimpleNamespace(metadata=meta)

    def _update(sid, **kw):
        meta.update(kw)

    monkeypatch.setattr(host, "_update_session_indexing_metadata", _update)
    monkeypatch.setattr(host, "_start_analysis_watchdog", lambda sid, port: None)
    monkeypatch.setattr(host, "_start_analysis_checkpoint_timer", lambda sid, port: None)
    # The reuse scan runs on an async daemon thread; make it fail fast so it
    # never flips indexing_state to "idle"/"reused" before we assert on the
    # synchronous "disabled" write. _seed_index_from_matching_binary lives on
    # the batch mixin, not the bare runtime host, hence a plain instance attr.
    def _boom(session):
        raise RuntimeError("reuse disabled for test")

    host._seed_index_from_matching_binary = _boom

    host._start_session_background_services(session, 7777)

    assert meta.get("indexing_state") == "disabled"
    assert meta.get("indexing_mode") == "none"
    assert meta.get("indexing_complete") is True
    assert meta.get("hot_indexed_count") == 0
