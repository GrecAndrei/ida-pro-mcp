"""Per-connection MCP client state.

The stdio transport has one client per process, while the optional daemon
serves several connections concurrently.  Keeping this state in a
``ContextVar`` lets both transports use the same request handlers without
allowing one daemon client to switch another client's active IDA session.

This lives in its own mixin so that every mixin performing a session
ownership check inherits the real implementation.  Looking the check up with
``getattr`` instead would let it silently fail open on any object that forgot
to inherit it.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ..errors import MCPError, make_error

# Guards lazy initialisation of the per-server SSO realm store (the daemon
# serves several connection threads, and ``sso_activate`` is one-shot).
_SSO_REALM_INIT_LOCK = threading.Lock()
# ContextVar identity must be shared by every request on a server. Without a
# guard, concurrent first requests could each publish a different ContextVar
# and split connection ownership state across threads.
_CLIENT_STATE_VAR_INIT_LOCK = threading.Lock()
# The daemon updates the live-connection and sticky-owner registries from
# several transport threads.  Keep lazy creation and compound updates
# serialized; a plain set/dict is not enough when two sockets open or close
# at the same time.
_CLIENT_REGISTRY_INIT_LOCK = threading.Lock()
# The runtime table is normally created during server initialisation, before
# any request thread exists.  Keep a lazy-init guard as well because a number
# of focused mixin tests construct the object without running the full server
# constructor.
_RUNTIME_LOCK_INIT_LOCK = threading.Lock()


def mint_agent_ticket(
    secret: str,
    name: str,
    exp: float | int | None = None,
    scopes: list[str] | None = None,
    nonce: str | None = None,
) -> str:
    """Mint an agent SSO ticket (orchestrator side).

    Format: ``<name>.<base64url(json payload)>.<hex(HMAC-SHA256(secret, payload))>``
    where the payload is the canonical JSON string (sorted keys, no spaces).
    The server verifies by re-deriving the HMAC over the decoded payload string.
    """
    payload = {
        "name": name,
        "exp": int(exp or 0),
        "scopes": scopes or ["all"],
        "nonce": nonce or secrets.token_hex(8),
    }
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(
        str(secret).encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    body = base64.urlsafe_b64encode(payload_str.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{name}.{body}.{sig}"


@dataclass
class _ClientRequestState:
    """Mutable state that belongs to one MCP client connection."""

    current_session: Any = None
    pending_post_process: dict[str, Any] = field(default_factory=dict)
    # Normalized, PP-stripped tool args snapshot for the current dispatch; lets
    # _execute_tool cache a continuation token with the exact args a replay
    # will use (never the raw caller args that still carry head/grep/limit).
    pending_tool_args: dict[str, Any] = field(default_factory=dict)
    pending_truncation: dict[str, Any] = field(default_factory=dict)
    last_spawn_error: Any = None
    vertex_compat: bool = False
    owned_session_ids: set[str] = field(default_factory=set)
    connection_id: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    # --- Agent SSO (per-call identity over a shared connection) ---
    # active_agent is set only for the duration of a single tool call that
    # carried an ``agent`` tag; everything below is keyed by agent name so a
    # logged-in subagent's sessions, ownership and teardown stay isolated
    # from every other agent sharing the same MCP connection.
    active_agent: str | None = None
    agents_logged_in: set[str] = field(default_factory=set)
    current_session_by_agent: dict[str, Any] = field(default_factory=dict)
    owned_sessions_by_agent: dict[str, set[str]] = field(default_factory=dict)


class ServerClientStateMixin:
    """Connection-scoped session state and the ownership guard built on it."""

    def _runtime_state_lock(self) -> threading.RLock:
        """Return the lock protecting the in-process runtime table."""
        lock = getattr(self, "_runtime_lock", None)
        if lock is None:
            with _RUNTIME_LOCK_INIT_LOCK:
                lock = getattr(self, "_runtime_lock", None)
                if lock is None:
                    lock = threading.RLock()
                    self._runtime_lock = lock
        return lock

    def _runtime_record(self, session_id: Any) -> dict[str, Any] | None:
        """Read one runtime record without racing table mutation."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            if not isinstance(runtimes, dict):
                return None
            record = runtimes.get(str(session_id))
            return record if isinstance(record, dict) else None

    def _runtime_items_snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        """Return a stable runtime-table snapshot for work outside the lock."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            if not isinstance(runtimes, dict):
                return []
            return [
                (str(session_id), record)
                for session_id, record in runtimes.items()
                if isinstance(record, dict)
            ]

    def _runtime_update(self, session_id: Any, **updates: Any) -> bool:
        """Atomically update fields on an existing runtime record."""
        with self._runtime_state_lock():
            runtimes = getattr(self, "session_runtimes", None)
            record = runtimes.get(str(session_id)) if isinstance(runtimes, dict) else None
            if not isinstance(record, dict):
                return False
            record.update(updates)
            return True

    def _client_registry_lock(self) -> threading.RLock:
        """Return the per-server lock for live connections and owners."""
        lock = getattr(self, "_client_registry_lock_instance", None)
        if lock is None:
            with _CLIENT_REGISTRY_INIT_LOCK:
                lock = getattr(self, "_client_registry_lock_instance", None)
                if lock is None:
                    lock = threading.RLock()
                    self._client_registry_lock_instance = lock
        return lock

    def _state_var(self) -> contextvars.ContextVar:
        var = getattr(self, "_client_request_state_var", None)
        if var is None:
            with _CLIENT_STATE_VAR_INIT_LOCK:
                var = getattr(self, "_client_request_state_var", None)
                if var is None:
                    var = contextvars.ContextVar(
                        "ida_mcp_client_request_state", default=None
                    )
                    self._client_request_state_var = var
        return var

    def _client_request_state(self) -> _ClientRequestState:
        """Return state local to the current MCP connection/request thread."""
        var = self._state_var()
        state = var.get()
        if state is None:
            state = _ClientRequestState()
            var.set(state)
        return state

    def _begin_client_connection(self) -> contextvars.Token:
        """Start an isolated state scope for one daemon connection."""
        state = _ClientRequestState(
            vertex_compat=bool(getattr(self, "default_vertex_compat", False))
        )
        # Track the connection as live so the sticky-ownership guard
        # (``_ensure_client_owns_session``) can tell a still-connected owner
        # from a disconnected one when deciding whether a session is adoptable.
        with self._client_registry_lock():
            live = getattr(self, "_live_connections", None)
            if not isinstance(live, set):
                live = set()
                self._live_connections = live
            live.add(state.connection_id)
        return self._state_var().set(state)

    def _end_client_connection(self, token: contextvars.Token) -> None:
        """Discard a daemon connection's state when its socket closes."""
        var = self._state_var()
        state = var.get()
        if state is not None:
            # Tear down IDA runtimes owned by this connection so disconnect
            # does not leave orphaned idat processes holding IDB locks. Agent
            # SSO runtimes are released per-agent first so a logout-less
            # disconnect still frees every subagent's sessions.
            cleanup = getattr(self, "_cleanup_runtime", None)
            if callable(cleanup):
                for agent in list(getattr(state, "agents_logged_in", set()) or set()):
                    for sid in list(
                        (getattr(state, "owned_sessions_by_agent", {}) or {}).get(
                            agent, set()
                        )
                        or set()
                    ):
                        if not self._connection_should_teardown(state, str(sid)):
                            # A sibling connection adopted this session after
                            # this connection's runtime died, or a sibling's
                            # spawn is still in flight; its runtime must not be
                            # torn down here.
                            continue
                        with contextlib.suppress(Exception):
                            cleanup(str(sid))
                for sid in list(getattr(state, "owned_session_ids", set()) or set()):
                    if not self._connection_should_teardown(state, str(sid)):
                        continue
                    with contextlib.suppress(Exception):
                        cleanup(str(sid))
            # This connection's socket is closing: drop it from the live
            # connection registry so sessions it recorded as owned become
            # adoptable by a restarted client (sticky ownership only holds
            # while the owner is actually connected).
            with self._client_registry_lock():
                live = getattr(self, "_live_connections", None)
                if isinstance(live, set):
                    live.discard(state.connection_id)
            # Drop this connection's agents from the shared realm registry.
            realm = getattr(self, "_sso_realm_store", None)
            if isinstance(realm, dict) and isinstance(state.agents_logged_in, set):
                logged_in = realm.get("logged_in") or {}
                names = list(state.agents_logged_in)
                lock = realm.get("lock")
                if lock is None:
                    for name in names:
                        logged_in.pop(name, None)
                else:
                    # Login/logout mutate realm['logged_in'] under this lock
                    # (see _bind_agent_call), so an unlocked teardown could
                    # race a concurrent _bind_agent_call observing an entry
                    # mid-removal on a multi-connection daemon.
                    with lock:
                        for name in names:
                            logged_in.pop(name, None)
        var.reset(token)

    @property
    def current_session(self):
        """The connection's active session — or, when an agent is bound for
        the current call, that agent's own active session. Returning the
        agent's session here is what keeps two subagents sharing one MCP
        connection from clobbering each other's target."""
        state = self._client_request_state()
        if state.active_agent:
            return state.current_session_by_agent.get(state.active_agent)
        return state.current_session

    @current_session.setter
    def current_session(self, value) -> None:
        state = self._client_request_state()
        sid = getattr(value, "session_id", None) if value is not None else None
        if state.active_agent:
            agent = state.active_agent
            if sid:
                state.current_session_by_agent[agent] = value
                state.owned_sessions_by_agent.setdefault(agent, set()).add(str(sid))
                self._record_session_current_owner(str(sid))
            else:
                state.current_session_by_agent.pop(agent, None)
            return
        state.current_session = value
        if sid:
            state.owned_session_ids.add(str(sid))
            self._record_session_current_owner(str(sid))

    def _client_owns_session(self, session_id: str) -> bool:
        """Whether this MCP connection has explicitly selected the session.

        When an agent is bound for the current call, ownership is scoped to
        that agent's sessions only — an agent can never read another agent's
        session, even though they share the connection.
        """
        state = self._client_request_state()
        if state.active_agent:
            owned = state.owned_sessions_by_agent.get(state.active_agent, set()) or set()
            return str(session_id) in owned
        return str(session_id) in state.owned_session_ids

    def _record_session_current_owner(self, sid: str) -> None:
        """Record this connection as the session's latest owner/user.

        ``_end_client_connection`` consults this registry so a connection whose
        ownership record went stale (its runtime died and a sibling adopted the
        session) does not SIGKILL the sibling's live runtime on disconnect.
        """
        state = self._client_request_state()
        with self._client_registry_lock():
            owner = getattr(self, "_session_current_owner", None)
            if not isinstance(owner, dict):
                owner = {}
                self._session_current_owner = owner
            owner[str(sid)] = str(state.connection_id)

    def _connection_is_current_owner(self, state: Any, sid: str) -> bool:
        """Whether this connection may tear down ``sid``'s runtime.

        True when nobody is recorded as the session's current owner (fall back
        to historical behavior) or when this connection is the recorded owner.
        False only when a *different* connection adopted the session — tearing
        that down would kill the sibling's live runtime and lose its IDB state.
        """
        with self._client_registry_lock():
            owner = getattr(self, "_session_current_owner", None)
            if not isinstance(owner, dict):
                return True
            recorded = owner.get(str(sid))
            if recorded is None:
                return True
            return recorded == str(getattr(state, "connection_id", ""))

    def _connection_is_explicit_owner(self, state: Any, sid: str) -> bool:
        """Whether *this* connection is the explicitly recorded owner of *sid*.

        Unlike ``_connection_is_current_owner`` this has no "nobody recorded"
        fallback — used to decide who may abort a mid-spawn runtime, where an
        unattributed session must not be torn down by a bystander.
        """
        with self._client_registry_lock():
            owner = getattr(self, "_session_current_owner", None)
            if not isinstance(owner, dict):
                return False
            recorded = owner.get(str(sid))
            return recorded is not None and recorded == str(
                getattr(state, "connection_id", "")
            )

    def _connection_is_live(self, connection_id: Any) -> bool:
        """Whether a connection with the given id is still connected."""
        with self._client_registry_lock():
            live = getattr(self, "_live_connections", None)
            if not isinstance(live, set):
                return False
            return str(connection_id) in live

    def _runtime_spawn_in_flight(self, sid: str) -> bool:
        """Whether *sid*'s runtime is mid-spawn (ownership claimed, no live runtime).

        ``_start_server`` claims the owner.json (``_claim_runtime_ownership``)
        before the runtime lands in ``session_runtimes``. In that window a
        ``_cleanup_runtime`` call from a bystander connection would release the
        freshly-claimed owner file and tombstone the session, aborting the
        sibling's launch.
        """
        rec = self._runtime_record(sid)
        alive = getattr(self, "_runtime_alive", None)
        if rec is not None and callable(alive):
            try:
                if alive(rec):
                    return False
            except Exception:
                pass
        owner_path = getattr(self, "_runtime_owner_path", None)
        if not callable(owner_path):
            return False
        try:
            return bool(owner_path(str(sid))) and os.path.exists(
                str(owner_path(str(sid)))
            )
        except Exception:
            return False

    def _connection_should_teardown(self, state: Any, sid: str) -> bool:
        """Whether this connection may tear down *sid*'s runtime on disconnect.

        Two guards compose: the connection must be the recorded owner (or no
        owner is recorded), AND — when the runtime is still mid-spawn — only
        the explicitly recorded owner may abort it. A sibling connection's
        in-flight launch must never be killed by an unrelated disconnect.
        """
        if not self._connection_is_current_owner(state, str(sid)):
            return False
        return not (
            self._runtime_spawn_in_flight(str(sid))
            and not self._connection_is_explicit_owner(state, str(sid))
        )

    def _session_has_live_owner_connection(self, state: Any, sid: str) -> bool:
        """Whether a *different*, still-connected connection owns *sid*.

        This is the sticky-ownership consent rule: a session whose recorded
        owner connection is still open must not be silently adopted by a
        sibling, even when its runtime has died — ownership survives a runtime
        death until the owning connection actually disconnects.
        """
        with self._client_registry_lock():
            owner = getattr(self, "_session_current_owner", None)
            if not isinstance(owner, dict):
                return False
            recorded = owner.get(str(sid))
            if recorded is None or recorded == str(getattr(state, "connection_id", "")):
                return False
            live = getattr(self, "_live_connections", None)
            return isinstance(live, set) and str(recorded) in live

    def _session_is_busy(self, session_id: str) -> bool:
        """Whether another live owner is actively running the session's IDA.

        A session is busy when this host tracks a live runtime for it (daemon
        mode: any connection may have spawned it) or when a lease in the
        shared cache is held by a live foreign host (stdio mode: another
        MCP process). Sessions that are merely *recorded* — persisted across
        restarts with no running idat — are never busy.
        """
        return bool(self._session_ownership_report(str(session_id)).get("locked"))

    def _session_ownership_report(self, session_id: str) -> dict[str, Any]:
        """Forensics on who currently holds a session.

        Returns a structured report describing whether the session is locked
        and, when it is, the identity and liveness of its holder.  This turns
        the opaque FILE_LOCKED error into an actionable one and lets
        session-list/state payloads mark busy sessions.

        ``holder`` is ``"this-host-runtime"`` (a live runtime in *this* server,
        possibly spawned by another daemon connection) or ``"foreign-lease"``
        (a lease owned by a different MCP host process).  A stale lease whose
        owner is dead is reported but never marked ``locked`` — it is reclaimable.
        """
        report: dict[str, Any] = {
            "session_id": str(session_id),
            "locked": False,
            "holder": None,
            "owner_id": None,
            "owner_pid": None,
            "owner_alive": None,
            "idat_pid": None,
            "lease_age_seconds": None,
            "lease_updated_at": None,
        }
        rec = self._runtime_record(session_id)
        alive = getattr(self, "_runtime_alive", None)
        if rec is not None and callable(alive) and alive(rec):
            report["locked"] = True
            report["holder"] = "this-host-runtime"
            proc = rec.get("process")
            report["idat_pid"] = getattr(proc, "pid", None) if proc is not None else None
            report["owner_id"] = str(
                getattr(self, "_runtime_owner_id", None) or "this-host"
            )
            report["owner_pid"] = os.getpid()
            report["owner_alive"] = True
            return report
        lease_path: str | None = None
        get_lease = getattr(self, "_runtime_lease_path", None)
        if callable(get_lease):
            with contextlib.suppress(Exception):
                lease_path = str(get_lease(str(session_id)))
        lease = None
        if lease_path and os.path.exists(lease_path):
            try:
                with open(lease_path, encoding="utf-8") as f:
                    lease = json.load(f)
            except Exception:
                lease = None
        if lease is None:
            return report
        try:
            report["owner_id"] = lease.get("owner_id")
            report["owner_pid"] = int(lease.get("owner_pid") or 0) or None
            report["idat_pid"] = int(lease.get("pid") or 0) or None
            report["lease_updated_at"] = lease.get("updated_at")
            if report["lease_updated_at"]:
                report["lease_age_seconds"] = round(
                    max(0.0, time.time() - float(report["lease_updated_at"])), 1
                )
        except Exception:
            pass
        has_live = getattr(self, "_lease_has_live_foreign_owner", None)
        if callable(has_live) and has_live(lease):
            report["locked"] = True
            report["holder"] = "foreign-lease"
            report["owner_alive"] = True
        else:
            # Lease present but not held by a live foreign owner: reclaimable.
            # Determine the owner's actual liveness (a stale lease whose owner
            # is our own process is still "alive" — the runtime just died).
            owner_alive: bool | None = None
            if report["owner_pid"]:
                try:
                    os.kill(int(report["owner_pid"]), 0)
                    owner_alive = True
                except ProcessLookupError:
                    owner_alive = False
                except Exception:
                    owner_alive = None
            report["owner_alive"] = owner_alive
        return report

    def _truncation_owner_id(self) -> str:
        """Stable per-connection id used to scope truncated response tokens.

        Includes the bound agent so two subagents never collide on the same
        ``next_token`` bucket while sharing one connection."""
        state = self._client_request_state()
        base = str(state.connection_id or "")
        if state.active_agent:
            return f"{base}:{state.active_agent}"
        return base

    def _ensure_client_owns_session(self, session: Any) -> dict[str, Any] | None:
        """Reject cross-client use of a session that this connection never selected.

        A session is adoptable — and the guard passes — when nobody is
        actively running it (no live runtime, no live foreign lease). This is
        what lets a restarted MCP client reload its old sessions and reuse the
        recorded IDB instead of silently creating a fresh session each time.
        Adopting a session records ownership so later calls keep working.
        """
        sid = getattr(session, "session_id", None)
        if not sid:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                "Session reference is incomplete.",
            )
        if self._client_owns_session(str(sid)):
            return None
        report = self._session_ownership_report(str(sid))
        if report.get("locked"):
            holder = report.get("holder")
            owner_pid = report.get("owner_pid")
            owner_id = report.get("owner_id")
            idat_pid = report.get("idat_pid")
            age = report.get("lease_age_seconds")
            if holder == "foreign-lease":
                who = "another MCP host process"
                if owner_pid:
                    who += f" (pid {owner_pid})"
                if owner_id:
                    who += f" [owner {owner_id}]"
                if idat_pid:
                    who += f" running idat pid {idat_pid}"
            else:
                who = "another connection on this server"
                if idat_pid:
                    who += f" (idat pid {idat_pid})"
            age_txt = f"; lease {age:g}s old" if age is not None else ""
            return make_error(
                MCPError.FILE_LOCKED,
                "This session is not available to the current MCP client.",
                hint=(
                    f"The session's IDA runtime is held by {who}{age_txt}. "
                    "Close it there, or open the binary with force_new=true "
                    "to create an independent session."
                ),
                details={
                    "session_id": str(sid),
                    **{k: report[k] for k in (
                        "locked", "holder", "owner_id", "owner_pid",
                        "owner_alive", "idat_pid", "lease_age_seconds",
                        "lease_updated_at",
                    )},
                },
            )
        # Sticky ownership (D3-F10): even with no live runtime or lease, a
        # session whose recorded owner connection is STILL CONNECTED is not
        # adoptable by a sibling. Ownership survives a runtime death; it only
        # releases when the owning connection's socket closes (or the owner
        # explicitly hands the session over). This keeps a still-active client's
        # session out of a peer's hands during transient runtime restarts while
        # still allowing a genuinely restarted client to reclaim a disconnected
        # owner's session below.
        state = self._client_request_state()
        if self._session_has_live_owner_connection(state, str(sid)):
            owner_id = getattr(self, "_session_current_owner", {}).get(str(sid))
            sticky = {
                "session_id": str(sid),
                "locked": True,
                "holder": "this-host-owner",
                "owner_id": str(owner_id) if owner_id else None,
                "owner_pid": os.getpid(),
                "owner_alive": True,
                "idat_pid": None,
                "lease_age_seconds": None,
                "lease_updated_at": None,
            }
            return make_error(
                MCPError.FILE_LOCKED,
                "This session is not available to the current MCP client.",
                hint=(
                    "The session is owned by another connection on this "
                    "server that is still connected, even though its IDA "
                    "runtime is not currently running. Close the session "
                    "there, wait for that client to disconnect, or open the "
                    "binary with force_new=true to create an independent "
                    "session."
                ),
                details=sticky,
            )
        # Nobody is running it (and no live owner connection holds it): take
        # it over so the rest of this request (and later ones) can use the
        # recorded IDB. When an agent is bound, ownership is recorded under
        # the agent so a sibling subagent cannot adopt it and the agent's own
        # logout tears it down.
        if state.active_agent:
            state.owned_sessions_by_agent.setdefault(state.active_agent, set()).add(
                str(sid)
            )
        else:
            state.owned_session_ids.add(str(sid))
        self._record_session_current_owner(str(sid))
        return None

    @property
    def _pending_pp(self) -> dict[str, Any]:
        return self._client_request_state().pending_post_process

    @_pending_pp.setter
    def _pending_pp(self, value: Any) -> None:
        self._client_request_state().pending_post_process = (
            value if isinstance(value, dict) else {}
        )

    @property
    def _pending_tool_args(self) -> dict[str, Any]:
        return self._client_request_state().pending_tool_args

    @_pending_tool_args.setter
    def _pending_tool_args(self, value: Any) -> None:
        self._client_request_state().pending_tool_args = (
            value if isinstance(value, dict) else {}
        )

    @property
    def _pending_truncation(self) -> dict[str, Any]:
        return self._client_request_state().pending_truncation

    @_pending_truncation.setter
    def _pending_truncation(self, value: Any) -> None:
        self._client_request_state().pending_truncation = (
            value if isinstance(value, dict) else {}
        )

    # ------------------------------------------------------------------
    # Agent SSO realm
    #
    # The orchestrator activates a one-shot realm (``sso_activate``), which
    # pre-registers the allowed agent names. Each subagent logs on with a
    # signed ticket (``agent_login``). Every subsequent session-scoped tool
    # call then carries an ``agent=<name>`` tag that ``_bind_agent_call``
    # validates against the realm *for this connection* and binds for the
    # duration of the call. ``agent_logout`` / connection close release only
    # that agent's runtimes and leases.
    # ------------------------------------------------------------------
    def _sso_realm(self) -> dict[str, Any]:
        """Server-process-wide SSO realm state (lazily initialised)."""
        realm = getattr(self, "_sso_realm_store", None)
        if realm is None:
            with _SSO_REALM_INIT_LOCK:
                realm = getattr(self, "_sso_realm_store", None)
                if realm is None:
                    realm = {
                        "active": False,
                        "secret": "",
                        "agents": set(),
                        "activated_at": None,
                        "logged_in": {},  # name -> {exp, scopes, conn_id, login_at}
                        "lock": threading.Lock(),
                    }
                    self._sso_realm_store = realm
        return realm

    def _sso_activate_realm(
        self, agents: list[Any], secret: str | None = None
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Enable the realm and pre-register the allowed agent names."""
        clean: list[str] = []
        for raw in agents or []:
            name = str(raw or "").strip()
            if not name or any(ch in name for ch in "\n\r:"):
                return None, make_error(
                    MCPError.INVALID_ARGS, f"Invalid agent name: {raw!r}"
                )
            if name not in clean:
                clean.append(name)
        if not clean:
            return None, make_error(
                MCPError.INVALID_ARGS,
                "sso_activate requires at least one agent name.",
            )
        secret_provided = bool((secret or "").strip())
        env_secret = bool((os.environ.get("IDA_MCP_SSO_SECRET") or "").strip())
        if secret_provided:
            secret = str(secret).strip()
        elif env_secret:
            secret = os.environ.get("IDA_MCP_SSO_SECRET")
        else:
            secret = secrets.token_urlsafe(32)
        realm = self._sso_realm()
        with realm["lock"]:
            if realm.get("active"):
                return None, make_error(
                    MCPError.INVALID_ARGS,
                    "SSO realm is already activated on this host.",
                )
            now = time.time()
            realm.update(
                active=True,
                secret=secret,
                agents=set(clean),
                activated_at=now,
                logged_in={},
            )
        sso_payload: dict[str, Any] = {
            "active": True,
            "agents": clean,
            "activated_at": now,
            "secret_generated": not secret_provided and not env_secret,
            "secret_from_env": env_secret and not secret_provided,
        }
        if not secret_provided and not env_secret:
            # The auto-generated secret is otherwise undisclosed anywhere, so
            # the realm it created could never be authenticated to — every
            # mint_agent_ticket/agent_login round would fail HMAC verification.
            # Return it to the orchestrator that activated the realm.
            sso_payload["secret"] = secret
        return (
            {
                "ok": True,
                "sso": sso_payload,
            },
            None,
        )

    def _sso_agent_login(
        self, name: Any, ticket: Any
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Validate a signed ticket and log the agent in on this connection."""
        state = self._client_request_state()
        realm = self._sso_realm()
        if not realm.get("active"):
            return None, make_error(
                MCPError.POLICY_DENIED,
                "SSO realm is not activated. The orchestrator must call "
                "session action=sso_activate first.",
            )
        name = str(name or "").strip()
        ticket_str = str(ticket or "").strip()
        if not name or not ticket_str:
            return None, make_error(
                MCPError.INVALID_ARGS, "agent_login requires both 'name' and 'ticket'."
            )
        parts = ticket_str.split(".")
        if len(parts) != 3:
            return None, make_error(
                MCPError.POLICY_DENIED,
                "Malformed ticket. Expected <name>.<payload>.<signature>.",
            )
        tname, body, sig = parts
        if tname != name:
            return None, make_error(
                MCPError.POLICY_DENIED,
                "Ticket name does not match the login name.",
            )
        if name not in realm.get("agents", set()):
            return None, make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{name}' is not in the allowed agents list.",
            )
        try:
            padded = body + "=" * (-len(body) % 4)
            payload_str = base64.urlsafe_b64decode(padded).decode("utf-8")
            expected = hmac.new(
                str(realm["secret"]).encode("utf-8"),
                payload_str.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, sig):
                return None, make_error(
                    MCPError.POLICY_DENIED, "Invalid ticket signature."
                )
            meta = json.loads(payload_str)
        except Exception:
            return None, make_error(MCPError.POLICY_DENIED, "Invalid ticket payload.")
        if str(meta.get("name") or "") != name:
            return None, make_error(
                MCPError.POLICY_DENIED, "Ticket payload name mismatch."
            )
        try:
            exp = float(meta.get("exp") or 0)
        except (TypeError, ValueError, OverflowError):
            return None, make_error(
                MCPError.POLICY_DENIED, "Ticket expiry must be a finite number."
            )
        if not math.isfinite(exp):
            return None, make_error(
                MCPError.POLICY_DENIED, "Ticket expiry must be a finite number."
            )
        if exp and exp < time.time():
            return None, make_error(MCPError.POLICY_DENIED, "Ticket has expired.")
        raw_scopes = meta.get("scopes")
        if raw_scopes is None:
            scopes = ["all"]
        elif isinstance(raw_scopes, list) and all(
            isinstance(s, str) and s.strip() for s in raw_scopes
        ):
            scopes = [s.strip() for s in raw_scopes]
        else:
            # Scopes are stored and echoed back to the caller; malformed values
            # would imply a scope model the host does not actually enforce.
            return None, make_error(
                MCPError.POLICY_DENIED,
                "Ticket scopes must be a list of non-empty strings.",
            )
        with realm["lock"]:
            existing = realm["logged_in"].get(name)
            if existing and existing.get("conn_id") != state.connection_id:
                return None, make_error(
                    MCPError.POLICY_DENIED,
                    f"Agent '{name}' is already logged in on another connection.",
                )
            realm["logged_in"][name] = {
                "exp": exp,
                "scopes": scopes,
                "conn_id": state.connection_id,
                "login_at": time.time(),
            }
        state.agents_logged_in.add(name)
        return (
            {"ok": True, "agent": name, "expires": exp, "scopes": scopes},
            None,
        )

    def _sso_agent_logout(
        self, name: Any = None
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Log out an agent and tear down only its runtimes/leases."""
        state = self._client_request_state()
        agent = str(name or "").strip() if name is not None else state.active_agent
        if not agent:
            return None, make_error(
                MCPError.INVALID_ARGS,
                "agent_logout requires 'name' (or be logged in as the agent).",
            )
        if agent not in state.agents_logged_in:
            return None, make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' is not logged in on this connection.",
            )
        self._agent_logout_cleanup(agent)
        return (
            {
                "ok": True,
                "agent": agent,
                "released_sessions": True,
            },
            None,
        )

    def _agent_logout_cleanup(self, agent: str) -> None:
        """Release the given agent's runtimes/leases and drop its identity.

        Only touches sessions owned by *this* agent — a sibling subagent's
        runtimes are left running, which is the whole point of per-agent
        teardown."""
        state = self._client_request_state()
        cleanup = getattr(self, "_cleanup_runtime", None)
        if callable(cleanup):
            for sid in list(
                state.owned_sessions_by_agent.get(agent, set()) or set()
            ):
                with contextlib.suppress(Exception):
                    cleanup(str(sid))
        state.owned_sessions_by_agent.pop(agent, None)
        state.current_session_by_agent.pop(agent, None)
        state.agents_logged_in.discard(agent)
        realm = getattr(self, "_sso_realm_store", None)
        if isinstance(realm, dict):
            with realm["lock"]:
                (realm.get("logged_in") or {}).pop(agent, None)

    def _bind_agent_call(self, agent_name: Any) -> dict[str, Any] | None:
        """Validate a per-call ``agent`` tag and bind it for this call.

        Returns an error dict (already serialisable) on rejection, or ``None``
        on success. The caller must pair this with ``_unbind_agent_call`` (see
        ``_call_as_agent``) so the identity never leaks past the request.
        """
        if not agent_name:
            return None
        agent = str(agent_name).strip()
        if not agent:
            return None
        state = self._client_request_state()
        realm = self._sso_realm()
        if not realm.get("active"):
            return make_error(
                MCPError.POLICY_DENIED,
                "SSO realm is not activated. The orchestrator must call "
                "session action=sso_activate first.",
            )
        # Read the login record under the realm lock: login/logout mutate
        # realm['logged_in'] under that lock, so an unlocked read could observe
        # a half-removed entry (agent briefly treated as logged in) or a login
        # before conn_id is set — inconsistent identity enforcement on a
        # multi-connection daemon.
        with realm["lock"]:
            entry = (realm.get("logged_in") or {}).get(agent)
        if not entry:
            return make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' is not logged in on this connection. "
                "Call session action=agent_login first.",
            )
        if entry.get("conn_id") != state.connection_id:
            return make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' is logged in on a different connection.",
            )
        try:
            exp = float(entry.get("exp") or 0)
        except (TypeError, ValueError, OverflowError):
            return make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' ticket has an invalid expiry; call agent_login again.",
            )
        if not math.isfinite(exp):
            return make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' ticket has an invalid expiry; call agent_login again.",
            )
        if exp and exp < time.time():
            return make_error(
                MCPError.POLICY_DENIED,
                f"Agent '{agent}' ticket has expired; call agent_login again.",
            )
        state.active_agent = agent
        return None

    def _unbind_agent_call(self) -> None:
        """Clear the per-call agent identity (pairs with ``_bind_agent_call``)."""
        self._client_request_state().active_agent = None

    def _call_as_agent(self, agent_name: Any, fn) -> Any:
        """Run ``fn`` with the given agent identity bound; restore after.

        Used by the ``tools/call`` dispatcher so a per-call ``agent`` tag is
        validated once and scoped strictly to the executing tool call.
        """
        if not agent_name:
            return fn()
        err = self._bind_agent_call(agent_name)
        if err is not None:
            return err
        try:
            return fn()
        finally:
            self._unbind_agent_call()
