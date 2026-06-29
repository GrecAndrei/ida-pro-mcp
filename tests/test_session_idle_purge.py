"""AST + dispatch tests for the new ``session(action='idle_purge')`` action.

This walks the registry / action handler pair to pin:

- ``idle_purge`` is registered in _SESSION_ACTIONS and resolves to
  ``_session_action_idle_purge``.
- The handler requires an integer ``idle_seconds`` arg and rejects
  missing / non-int / non-positive values with MCPError.INVALID_ARGS
  envelopes (mirrors the existing cleanup_stale contract).
- The handler only acts on sessions that have a live runtime
  (skips db-only stale rows that cleanup_stale owns).
- The response shape matches cleanup_stale: closed_sids /
  orphan_sids / count.

These are AST-tests because the host boot path requires a real DB
and IDA runtime; off-the-shelf mocks would exercise almost none of
the production code we want to pin here.
"""

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "ida_pro_mcp" / "host" / "server" / "server_session.py"


def _read() -> str:
    return SRC.read_text()


def _module() -> ast.Module:
    return ast.parse(_read())


# ---------------------------------------------------------------------------
# Registration / dispatch
# ---------------------------------------------------------------------------


def _find_dict_literal(name: str) -> ast.Dict:
    tree = _module()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                return node.value  # type: ignore[return-value]
    raise AssertionError(f"{name} not found in server_session.py")


def test_idle_purge_action_registered():
    src = _read()
    assert '"idle_purge": "_session_action_idle_purge"' in src, (
        "idle_purge must be registered in _SESSION_ACTIONS"
    )


def test_idle_purge_routes_to_handler():
    """Hash-key dispatch: action=='idle_purge' must reach the handler
    defined in this module.
    """
    src = _read()
    assert "def _session_action_idle_purge(" in src, (
        "_session_action_idle_purge must be defined in server_session.py"
    )


# ---------------------------------------------------------------------------
# Handler contract
# ---------------------------------------------------------------------------


def test_handler_requires_idle_seconds():
    """When the client forgets to pass idle_seconds, return an envelope."""
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "idle_seconds is required" in body
    assert "MCPError.INVALID_ARGS" in body


def test_handler_rejects_non_int_idle_seconds():
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "idle_seconds must be an integer" in body


def test_handler_rejects_non_positive_idle_seconds():
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "idle_seconds must be a positive integer" in body


def test_handler_only_targets_live_runtimes():
    """db-only stale sessions stay out of scope — cleanup_stale owns them."""
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "session_runtimes" in body
    assert "has_runtime" in body
    assert "skipped_sids" in body


def test_handler_parses_iso_timestamp():
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    # Must use the existing datetime import; ``fromisoformat`` + replace
    # the trailing 'Z' is the established pattern in this codebase.
    assert "datetime.fromisoformat" in body
    assert "Z" in body


def test_handler_response_shape_matches_cleanup_stale():
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert '"closed_sids":' in body
    assert '"orphan_sids":' in body
    assert '"count":' in body
    assert '"closed_count":' in body
    assert '"orphan_count":' in body
    assert '"skipped_count":' in body
    assert '"idle_seconds":' in body


def test_handler_uses_cleanup_runtime():
    """Live sessions must have their runtime torn down before the row
    is dropped — otherwise processes leak.
    """
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "self._cleanup_runtime(sid)" in body


def test_handler_clears_current_session_if_purged():
    """Purging the active session must clear current_session; otherwise
    the next tool call dispatches to a now-dead process.
    """
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "self.current_session = None" in body


def test_handler_respects_prune_orphans_default():
    src = _read()
    fn_idx = src.index("def _session_action_idle_purge(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert 'args.get("prune_orphans", True)' in body
    assert "bin_missing" in body
    assert "idb_missing" in body
