"""Behavioural cover for host-side safety invariants.

Each test here fails if the corresponding guarantee regresses:
  - a session cannot relax the operator's policy mode
  - session health survives concurrent runtime teardown
  - a kill that did not kill is not reported as success
  - confidence decay does not masquerade as a recent edit
  - a runtime lease is never observable in a partial state
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ida_pro_mcp.host.policy import PolicyMode, strictest
from ida_pro_mcp.host.server import server_runtime as server_runtime_mod
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
from ida_pro_mcp.host.server.server_runtime import ServerRuntimeMixin
from ida_pro_mcp.host.server.server_session import ServerSessionMixin
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

# --------------------------------------------------------------------------
# Policy mode: a session may tighten the operator baseline, never relax it
# --------------------------------------------------------------------------


class _PolicyHost(ServerDispatchMixin):
    def __init__(self, session_mode=None):
        if session_mode is not None:
            self.current_session = type(
                "S", (), {"session_id": "A1B2C3D4", "policy_mode": session_mode}
            )()


def test_strictest_picks_the_strongest_mode():
    assert strictest("off", "enforce") == PolicyMode.ENFORCE
    assert strictest("permissive", "assist") == PolicyMode.ASSIST
    assert strictest("off", "permissive") == PolicyMode.PERMISSIVE
    assert strictest() == PolicyMode.ASSIST


def test_session_cannot_relax_the_operator_baseline(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "enforce")

    assert _PolicyHost(session_mode="off")._resolve_policy_mode() == "enforce"
    assert _PolicyHost(session_mode="permissive")._resolve_policy_mode() == "enforce"


def test_session_may_tighten_the_operator_baseline(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "permissive")

    assert _PolicyHost(session_mode="enforce")._resolve_policy_mode() == "enforce"


def test_baseline_applies_when_the_session_sets_nothing(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")

    assert _PolicyHost()._resolve_policy_mode() == "assist"
    assert _PolicyHost(session_mode=None)._resolve_policy_mode() == "assist"


def test_unparseable_baseline_falls_back_to_assist(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "not-a-mode")

    assert _PolicyHost()._resolve_policy_mode() == "assist"


def test_session_create_does_not_carry_a_caller_supplied_policy_mode(tmp_path):
    """The tool argument must not reach the session object."""
    from ida_pro_mcp.host.server.session import SessionManager

    mgr = SessionManager(str(tmp_path))
    session = mgr.create_session(str(tmp_path / "sample.bin"))

    assert getattr(session, "policy_mode", None) is None


# --------------------------------------------------------------------------
# session(action='health') must not crash on concurrent runtime teardown
# --------------------------------------------------------------------------


class _HealthHost(ServerDispatchMixin):
    def __init__(self):
        self.session_runtimes = {}
        self._runtime_lock = threading.RLock()
        self.cache_dir = ""
        self.ida_dir = ""
        self.idat_exe = ""
        self.session_mgr = type("M", (), {"discover_sessions": staticmethod(list)})()

    def _resolve_wiki_root(self):
        return ""

    @staticmethod
    def _runtime_alive(_runtime):
        # Yield inside the loop so a concurrent writer reliably lands between
        # iterations. Without this the real liveness check is fast enough that
        # an unlocked iteration only rarely observes the mutation, and the test
        # would pass against the unlocked implementation it exists to reject.
        time.sleep(0.0002)
        return False


def test_session_health_survives_concurrent_runtime_mutation():
    host = _HealthHost()
    for i in range(24):
        host.session_runtimes[f"SID{i:04d}"] = {"process": None, "port": 9000 + i}

    stop = threading.Event()
    errors: list[BaseException] = []

    def churn():
        i = 0
        while not stop.is_set():
            key = f"CHURN{i % 32:04d}"
            with host._runtime_lock:
                host.session_runtimes[key] = {"process": None, "port": 1234}
                host.session_runtimes.pop(f"CHURN{(i - 1) % 32:04d}", None)
            i += 1

    churner = threading.Thread(target=churn, daemon=True)
    churner.start()
    try:
        for _ in range(8):
            try:
                payload = host._handle_session_health({"verbose": True})
            except BaseException as e:  # noqa: BLE001 - the point of the test
                errors.append(e)
                break
            tracked = payload["sessions"]["runtime_processes"]["tracked"]
            # The snapshot must be self-consistent: one listing per tracked runtime.
            assert len(payload["sessions"]["runtimes"]) == tracked
    finally:
        stop.set()
        churner.join(timeout=5)

    assert not errors, f"health check raised under concurrent mutation: {errors[0]!r}"


# --------------------------------------------------------------------------
# A kill that did not terminate the process must not report success
# --------------------------------------------------------------------------


class _UnkillableProc:
    """A process that ignores SIGTERM and SIGKILL and never exits."""

    pid = 4242
    returncode = None

    def poll(self):
        return None

    def terminate(self):
        return None

    def kill(self):
        return None

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired(cmd="idat", timeout=timeout)


class _ExitsOnKillProc(_UnkillableProc):
    def __init__(self):
        self._killed = False
        self.returncode = None

    def kill(self):
        self._killed = True

    def wait(self, timeout=None):
        if not self._killed:
            raise subprocess.TimeoutExpired(cmd="idat", timeout=timeout)
        self.returncode = -9
        return -9


class _KillHost(ServerSessionMixin, ServerRuntimeMixin):
    def __init__(self, proc):
        self.session_runtimes = {"A1B2C3D4": {"process": proc, "port": 9999}}
        self._client_request_state().owned_session_ids.add("A1B2C3D4")

    def _resolve_session_id(self, args):
        return "A1B2C3D4", None

    def _require_owned_session_id(self, sid):
        return None

    def _collect_ida_state_snapshot(self, **kwargs):
        return {}

    def _cleanup_runtime(self, sid):
        self.session_runtimes.pop(sid, None)


def test_failed_kill_is_reported_as_an_error_not_ok():
    result = _KillHost(_UnkillableProc())._session_action_kill({"grace_sec": 0.5})

    assert result.get("error") is True, f"failed kill reported: {result}"
    assert result.get("ok") is not True
    assert result["details"]["terminated"] is False
    assert result["details"]["pid"] == 4242


def test_successful_kill_still_reports_ok():
    result = _KillHost(_ExitsOnKillProc())._session_action_kill({"grace_sec": 0.5})

    assert result["ok"] is True
    assert result["terminated"] is True
    assert result["signaled"] == "SIGKILL"


# --------------------------------------------------------------------------
# Confidence decay must not look like a recent edit
# --------------------------------------------------------------------------


def _age_entry(store: BlackboardStore, entry_id: str, days: float) -> None:
    import sqlite3

    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE blackboard SET updated_at=? WHERE id=?",
            (time.time() - days * 86400, entry_id),
        )
        conn.commit()


def test_decay_does_not_bump_updated_at(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    entry_id = store.upsert_finding("Stale claim", category="note", confidence=0.9)["entry_id"]
    _age_entry(store, entry_id, days=30)
    before = store.read(entry_id)["updated_at"]

    assert store.decay_stale_confidence(half_life_days=14.0) == 1

    after = store.read(entry_id)
    assert after["confidence"] < 0.9
    assert after["updated_at"] == pytest.approx(before), (
        "decay rewrote updated_at, so a stale entry now sorts as freshly edited"
    )


def test_decay_keeps_working_on_repeated_runs(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    entry_id = store.upsert_finding("Stale claim", category="note", confidence=0.9)["entry_id"]
    _age_entry(store, entry_id, days=30)

    assert store.decay_stale_confidence(half_life_days=14.0) == 1
    first = store.read(entry_id)["confidence"]

    # Age it again relative to the decay we just recorded.
    import sqlite3

    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE blackboard SET decayed_at=? WHERE id=?",
            (time.time() - 30 * 86400, entry_id),
        )
        conn.commit()

    assert store.decay_stale_confidence(half_life_days=14.0) == 1, (
        "second decay run did nothing; decay reset its own clock"
    )
    assert store.read(entry_id)["confidence"] < first


def test_decay_skips_recently_touched_entries(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    store.upsert_finding("Fresh claim", category="note", confidence=0.9)

    assert store.decay_stale_confidence(half_life_days=14.0) == 0


# --------------------------------------------------------------------------
# Runtime ownership leases are published atomically
# --------------------------------------------------------------------------


class _LeaseHost(ServerRuntimeMixin):
    def __init__(self, lease_dir, owner_id):
        self._runtime_lease_dir = str(lease_dir)
        self._runtime_owner_id = owner_id


def test_only_one_host_claims_a_lease(tmp_path):
    hosts = [_LeaseHost(tmp_path, f"owner-{i}") for i in range(16)]

    with ThreadPoolExecutor(max_workers=16) as pool:
        claims = list(pool.map(lambda h: h._claim_runtime_ownership("A1B2C3D4"), hosts))

    granted = [c for c in claims if c]
    assert len(granted) == 1, f"{len(granted)} hosts believe they own the same IDB"

    owner = json.loads(open(granted[0], encoding="utf-8").read())
    assert owner["session_id"] == "A1B2C3D4"
    assert owner["owner_id"].startswith("owner-")


def test_lease_file_is_never_observable_empty(tmp_path):
    """A reader that catches the lease mid-publication must not see no owner."""
    host = _LeaseHost(tmp_path, "owner-a")
    path = host._runtime_owner_path("A1B2C3D4")

    empty_reads = []
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            try:
                with open(path, encoding="utf-8") as fh:
                    if not json.load(fh).get("owner_id"):
                        empty_reads.append(True)
            except FileNotFoundError:
                continue
            except Exception:
                empty_reads.append(True)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        for _ in range(200):
            assert host._claim_runtime_ownership("A1B2C3D4")
            os.remove(path)
    finally:
        stop.set()
        watcher.join(timeout=5)

    assert not empty_reads, "lease was readable while incomplete"


def test_claim_is_refused_while_a_live_owner_holds_it(tmp_path):
    holder = _LeaseHost(tmp_path, "owner-a")
    assert holder._claim_runtime_ownership("A1B2C3D4")

    other = _LeaseHost(tmp_path, "owner-b")
    assert other._claim_runtime_ownership("A1B2C3D4") is None


def test_claim_reclaims_malformed_owner_record(tmp_path):
    """A damaged owner file cannot crash or permanently block a session."""
    host = _LeaseHost(tmp_path, "owner-a")
    path = host._runtime_owner_path("A1B2C3D4")
    with open(path, "w", encoding="utf-8") as owner_fh:
        json.dump(["not-an-owner"], owner_fh)

    assert host._claim_runtime_ownership("A1B2C3D4") == path
    owner = json.loads(open(path, encoding="utf-8").read())
    assert owner["owner_id"] == "owner-a"


def test_claim_reclaims_owner_pid_after_process_reuse(tmp_path, monkeypatch):
    """A live PID with a changed start token is not the old host anymore."""
    holder = _LeaseHost(tmp_path, "owner-old")
    path = holder._runtime_owner_path("A1B2C3D4")
    with open(path, "w", encoding="utf-8") as owner_fh:
        json.dump(
            {
                "session_id": "A1B2C3D4",
                "owner_pid": 424242,
                "owner_id": "owner-old",
                "owner_start_token": "old",
            },
            owner_fh,
        )

    replacement = _LeaseHost(tmp_path, "owner-new")
    monkeypatch.setattr(server_runtime_mod.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(server_runtime_mod, "_process_start_token", lambda pid: "new")

    assert replacement._claim_runtime_ownership("A1B2C3D4") == path
    owner = json.loads(open(path, encoding="utf-8").read())
    assert owner["owner_id"] == "owner-new"


def test_reclaiming_own_lease_is_idempotent(tmp_path):
    host = _LeaseHost(tmp_path, "owner-a")
    first = host._claim_runtime_ownership("A1B2C3D4")

    assert first is not None
    assert host._claim_runtime_ownership("A1B2C3D4") == first
