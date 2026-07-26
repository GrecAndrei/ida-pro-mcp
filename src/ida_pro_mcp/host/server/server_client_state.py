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

import contextlib
import contextvars
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..errors import MCPError, make_error


@dataclass
class _ClientRequestState:
    """Mutable state that belongs to one MCP client connection."""

    current_session: Any = None
    pending_post_process: dict[str, Any] = field(default_factory=dict)
    pending_truncation: dict[str, Any] = field(default_factory=dict)
    last_spawn_error: Any = None
    vertex_compat: bool = False
    owned_session_ids: set[str] = field(default_factory=set)
    connection_id: str = field(default_factory=lambda: secrets.token_urlsafe(16))


class ServerClientStateMixin:
    """Connection-scoped session state and the ownership guard built on it."""

    def _state_var(self) -> contextvars.ContextVar:
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
        return self._state_var().set(
            _ClientRequestState(
                vertex_compat=bool(getattr(self, "default_vertex_compat", False))
            )
        )

    def _end_client_connection(self, token: contextvars.Token) -> None:
        """Discard a daemon connection's state when its socket closes."""
        var = self._state_var()
        state = var.get()
        if state is not None:
            # Tear down IDA runtimes owned by this connection so disconnect
            # does not leave orphaned idat processes holding IDB locks.
            cleanup = getattr(self, "_cleanup_runtime", None)
            if callable(cleanup):
                for sid in list(getattr(state, "owned_session_ids", set()) or set()):
                    with contextlib.suppress(Exception):
                        cleanup(str(sid))
        var.reset(token)

    @property
    def current_session(self):
        return self._client_request_state().current_session

    @current_session.setter
    def current_session(self, value) -> None:
        state = self._client_request_state()
        state.current_session = value
        sid = getattr(value, "session_id", None) if value is not None else None
        if sid:
            state.owned_session_ids.add(str(sid))

    def _client_owns_session(self, session_id: str) -> bool:
        """Whether this MCP connection has explicitly selected the session."""
        return str(session_id) in self._client_request_state().owned_session_ids

    def _truncation_owner_id(self) -> str:
        """Stable per-connection id used to scope truncated response tokens."""
        return str(self._client_request_state().connection_id or "")

    def _ensure_client_owns_session(self, session: Any) -> dict[str, Any] | None:
        """Reject cross-client use of a session that this connection never selected."""
        sid = getattr(session, "session_id", None)
        if not sid:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                "Session reference is incomplete.",
            )
        if self._client_owns_session(str(sid)):
            return None
        return make_error(
            MCPError.FILE_LOCKED,
            "This session is not available to the current MCP client.",
            hint=(
                "Open the binary in this client to create an independent session, "
                "or switch only to a session this connection already owns."
            ),
            details={"session_id": str(sid)},
        )

    @property
    def _pending_pp(self) -> dict[str, Any]:
        return self._client_request_state().pending_post_process

    @_pending_pp.setter
    def _pending_pp(self, value: Any) -> None:
        self._client_request_state().pending_post_process = (
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
