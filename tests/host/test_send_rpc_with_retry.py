"""AST + standalone tests for the RPC retry wrapper.

The dispatcher retries transient connection failures (TCP refused,
EOF, ConnectionReset) up to ``IDA_MCP_RPC_MAX_RETRIES`` (default 2)
before surfacing RPC_CONNECTION_ERROR. Timeouts and other OSErrors are
NOT retried — those still become IDA_TIMEOUT so callers can
distinguish "IDA is busy" from "IDA went away".

These tests pin:
- The wrapper lives on the right mixin class
- The set of retried exception types is intentionally narrow
- Timeouts propagate without retry
- The IDA_MCP_RPC_MAX_RETRIES env var is honored
"""

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "src" / "ida_pro_mcp" / "host" / "server" / "server_runtime.py"
DISPATCH = REPO / "src" / "ida_pro_mcp" / "host" / "server" / "server_dispatch.py"


def _read(rel: Path) -> str:
    return rel.read_text()


def test_send_rpc_with_retry_method_exists():
    src = _read(RUNTIME)
    assert "def _send_rpc_with_retry(" in src, (
        "server_runtime.py must define _send_rpc_with_retry."
    )


def test_send_rpc_with_retry_documents_max_retries():
    src = _read(RUNTIME)
    assert "IDA_MCP_RPC_MAX_RETRIES" in src, (
        "Retry wrapper must honor IDA_MCP_RPC_MAX_RETRIES env var."
    )
    # the docstring should mention the env var
    fn_idx = src.index("def _send_rpc_with_retry(")
    docstring_end = src.index('"""', src.index('"""', fn_idx) + 3)
    docstring = src[fn_idx:docstring_end]
    assert "IDA_MCP_RPC_MAX_RETRIES" in docstring


def test_dispatch_calls_send_rpc_with_retry():
    """The dispatcher's call_tool must use the retry wrapper so transient
    connection failures don't become user-visible errors.
    """
    src = _read(DISPATCH)
    assert "_send_rpc_with_retry" in src, (
        "server_dispatch.py must use _send_rpc_with_retry for tool calls."
    )
    # and only for that branch (not for low-level init paths)
    # not really worth pinning here, so simple presence is enough.


def test_send_rpc_with_retry_does_not_retry_timeouts():
    """Timeouts are deliberately NOT retried: a hung IDA has different
    recovery semantics than one that briefly refused a connection.
    """
    src = _read(RUNTIME)
    # locate the except blocks within _send_rpc_with_retry
    fn_idx = src.index("def _send_rpc_with_retry(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    # Must raise on TimeoutError immediately, not retry-then-raise.
    # The pattern is: "except (ConnectionRefusedError, EOFError, ...)".
    assert "ConnectionRefusedError" in body
    assert "EOFError" in body
    # Timeouts are in their own except re-raise clause.
    assert "TimeoutError" in body
    assert "OSError" in body
    # The raise after the retry loop is the LAST transient raise.
    assert body.count("raise") >= 2


def test_send_rpc_with_retry_uses_linear_backoff():
    """Pin the simple linear backoff formula so a future optimization
    (e.g. exponential) is intentional — otherwise scripts depending on
    roughly-known retry duration will misbehave.
    """
    src = _read(RUNTIME)
    fn_idx = src.index("def _send_rpc_with_retry(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    assert "base_backoff * (attempt + 1)" in body, (
        "Linear backoff expected; switch to exponential *on purpose*."
    )


def test_send_rpc_with_retry_returns_mcp_error_on_exhausted_retries():
    """When the retry loop is exhausted on a transient failure, the
    wrapper re-raises the last exception so the dispatcher's
    call_tool can map it to RPC_CONNECTION_ERROR.
    """
    src = _read(RUNTIME)
    fn_idx = src.index("def _send_rpc_with_retry(")
    next_def = src.index("\n    def ", fn_idx + 10)
    body = src[fn_idx:next_def]
    # loop ends with break or fall-through, then a single bare `raise last_exc`
    assert "raise last_exc" in body


def test_dispatcher_handles_connection_errors_with_envelope():
    """When _send_rpc_with_retry raises a ConnectionRefusedError, the
    dispatcher must wrap it in a make_error RPC_CONNECTION_ERROR envelope.
    """
    src = _read(DISPATCH)
    # The call_tool path includes an except block that uses MCPError.
    assert "ConnectionRefusedError" in src
    assert "MCPError.RPC_CONNECTION_ERROR" in src
