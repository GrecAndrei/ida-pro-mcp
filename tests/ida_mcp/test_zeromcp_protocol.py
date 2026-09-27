"""Regression tests for the vendored zeromcp MCP transport server.

The zeromcp package cannot be imported through ``ida_mcp`` in this venv
because ``ida_mcp/__init__.py`` pulls in ``sync.py`` -> ``ida_kernwin``
(only present inside IDA). These tests load ``jsonrpc.py`` and ``mcp.py``
standalone under a fake package name (mirroring the approach in
tests/host/test_tool_cache.py).

Coverage:
- JSON-RPC param validation: ``**kwargs``/``*args`` are never required and
  extra kwargs are accepted, so tools/call works for every tool whose
  signature ends in ``**kwargs``.
- JSON-RPC 2.0 notification semantics: a structurally-invalid request with
  no ``id`` must not receive a reply.
- MCP tool error envelopes: tool-level ``{error: True, ...}`` results (the
  make_error contract) are surfaced with ``isError: True``.
- The envelope layer copies tool results before injecting ``_elapsed_ms`` so
  the dict aliased by the idaread cache is never mutated.
- SSE POST validates the session BEFORE dispatch so a bogus session can
  never execute a (mutating) tool.
- HTTP robustness: malformed Content-Length -> clean 400; over-limit body ->
  413 with Connection: close; notifications get an empty 202 body.
- resource URI templates: literal parts are regex-escaped so special chars
  cannot widen the match.
"""

import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ZMCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "zeromcp"
_PKG = "zeromcp_isolated"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(f"{_PKG}.{name}", str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"{_PKG}.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_pkg():
    """Load jsonrpc.py + mcp.py under a fake package so mcp.py's
    ``from .jsonrpc import ...`` resolves."""
    pkg = types.ModuleType(_PKG)
    pkg.__path__ = [str(ZMCP)]
    sys.modules[_PKG] = pkg
    jr = _load_module("jsonrpc", ZMCP / "jsonrpc.py")
    mcp = _load_module("mcp", ZMCP / "mcp.py")
    return jr, mcp


class _FakeWfile:
    """Records bytes written so tests can assert on response bodies."""

    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)
        return len(data)

    def flush(self):
        pass


class _FakeHandler:
    """Minimal stand-in for McpHttpRequestHandler used by the HTTP tests.

    Records the messages a real handler would emit; individual tests swap in
    the real ``send_error`` (bound to the fake) when they need to assert on
    connection-close behavior.
    """

    def __init__(self, server, path="/mcp", headers=None):
        self.mcp_server = server
        self.path = path
        self.headers = headers if headers is not None else {}
        self.close_connection = False
        self.sent = []  # ("response"|"error"|"header"|"end", ...)
        self.wfile = _FakeWfile()

    def send_cors_headers(self, *, preflight=False):
        self.sent.append(("cors", preflight))

    def send_response(self, code, message=None):
        self.sent.append(("response", code))

    def send_error(self, code, message=None, explain=None):
        self.sent.append(("error", code, message))

    def send_header(self, key, value):
        self.sent.append(("header", key, value))

    def end_headers(self):
        self.sent.append(("end",))


# ---------------------------------------------------------------------------
# jsonrpc.py: *args / **kwargs must not be treated as required parameters
# ---------------------------------------------------------------------------

def test_var_keyword_not_required():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()

    def calc(action, expr=None, **kwargs):
        return {"action": action, "expr": expr, "kwargs": kwargs}

    reg.method(calc)

    resp = reg.dispatch(
        {"jsonrpc": "2.0", "method": "calc", "params": {"action": "eval"}, "id": 1}
    )
    assert resp is not None and "error" not in resp
    assert resp["result"] == {"action": "eval", "expr": None, "kwargs": {}}


def test_var_keyword_accepts_extra_kwargs():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()
    received = {}

    def calc(action, expr=None, **kwargs):
        received.update(kwargs)
        return {"ok": True}

    reg.method(calc)

    resp = reg.dispatch(
        {
            "jsonrpc": "2.0",
            "method": "calc",
            "params": {"action": "eval", "verbose": True},
            "id": 1,
        }
    )
    assert "error" not in resp
    assert received == {"verbose": True}


def test_var_positional_not_required():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()

    def f(a, *args):
        return {"a": a}

    reg.method(f)

    resp = reg.dispatch({"jsonrpc": "2.0", "method": "f", "params": {"a": 1}, "id": 1})
    assert resp is not None and "error" not in resp


def test_real_required_param_still_enforced():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()

    def calc(action, expr=None, **kwargs):
        return {}

    reg.method(calc)

    resp = reg.dispatch({"jsonrpc": "2.0", "method": "calc", "params": {}, "id": 1})
    assert "error" in resp
    assert resp["error"]["code"] == -32602
    assert "action" in resp["error"]["message"]


# ---------------------------------------------------------------------------
# jsonrpc.py: never reply to a notification, even a structurally-invalid one
# ---------------------------------------------------------------------------

def _register_ping(reg):
    def ping():
        return {}

    reg.method(ping)
    return ping


def test_invalid_notification_gets_no_reply():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()
    _register_ping(reg)

    # Structural errors on a notification (no id member) must not be replied to.
    assert reg.dispatch({"jsonrpc": "3.0", "method": "ping"}) is None
    assert reg.dispatch({"jsonrpc": "2.0"}) is None
    assert reg.dispatch({"jsonrpc": "2.0", "method": 42}) is None
    # A valid notification is also suppressed (existing behavior preserved).
    assert reg.dispatch({"jsonrpc": "2.0", "method": "ping"}) is None


def test_invalid_request_with_id_still_reported():
    jr, _ = _load_pkg()
    reg = jr.JsonRpcRegistry()
    _register_ping(reg)

    resp = reg.dispatch({"jsonrpc": "3.0", "method": "ping", "id": 5})
    assert resp is not None and resp["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# mcp.py: tool-level make_error results must surface as isError: True
# ---------------------------------------------------------------------------

def test_tool_error_result_is_iserror_true():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    def failing(**kwargs):
        return {
            "error": True,
            "code": "ADDRESS_NOT_MAPPED",
            "message": "nope",
            "hint": "use ida_overview",
        }

    server.tool(failing)

    out = server._mcp_tools_call("failing", {})
    assert out["isError"] is True
    assert out["structuredContent"]["error"]["code"] == "ADDRESS_NOT_MAPPED"
    assert "ADDRESS_NOT_MAPPED" in out["content"][0]["text"]
    assert "use ida_overview" in out["content"][0]["text"]


def test_ok_false_result_is_error():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    def bad():
        return {"ok": False, "message": "failed"}

    server.tool(bad)

    out = server._mcp_tools_call("bad", {})
    assert out["isError"] is True
    assert "failed" in out["content"][0]["text"]


def test_ok_result_is_not_error_and_cache_object_not_mutated():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    captured = {}

    def good(x):
        d = {"ok": True, "x": x}
        captured["ref"] = d
        return d

    server.tool(good)

    out = server._mcp_tools_call("good", {"x": 1})
    assert out["isError"] is False
    assert out["structuredContent"]["ok"] is True
    assert out["structuredContent"]["_elapsed_ms"] >= 0
    # The envelope must not mutate the dict the tool returned: that exact
    # object is aliased by the idaread cache, so _elapsed_ms must only land
    # on the copy handed to the client.
    assert "_elapsed_ms" not in captured["ref"]


def test_unknown_tool_is_iserror_true():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    out = server._mcp_tools_call("does_not_exist", {})
    assert out["isError"] is True
    assert out["structuredContent"]["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# mcp.py: a non-serializable tool result is a crisp isError envelope, never a crash
# ---------------------------------------------------------------------------

def test_tool_non_serializable_result_is_iserror_not_crash():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    def returns_set(**kwargs):
        return {1, 2, 3}  # set() is not JSON-serializable

    server.tool(returns_set)

    out = server._mcp_tools_call("returns_set", {})
    assert out["isError"] is True
    assert out["structuredContent"]["error"]["code"] == "INTERNAL"
    # The error text must be serializable to JSON so the transport never dies.
    json.dumps(out)
    assert "non-serializable" in out["content"][0]["text"]


def test_tool_nested_non_serializable_dict_is_iserror_not_crash():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    def returns_nested(**kwargs):
        return {"ok": True, "payload": {frozenset([1])}}  # frozenset nested value

    server.tool(returns_nested)

    out = server._mcp_tools_call("returns_nested", {})
    assert out["isError"] is True
    assert out["structuredContent"]["error"]["code"] == "INTERNAL"
    json.dumps(out)


def test_mcp_post_non_serializable_response_returns_32603():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    # Force the registry to hand back a non-serializable response (a dict with
    # a set value keeps the JSON-RPC id so the error reply can match it).
    server.registry.dispatch = lambda body: {"id": 9, "result": {1, 2, 3}}

    fake = _FakeHandler(server, path="/mcp")
    body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 9}).encode()
    mcp.McpHttpRequestHandler._handle_mcp_post(fake, body)

    assert ("response", 200) in fake.sent
    assert fake.wfile.writes
    payload = json.loads(fake.wfile.writes[0])
    assert payload["error"]["code"] == -32603
    assert payload["id"] == 9


# ---------------------------------------------------------------------------
# mcp.py: SSE POST must validate the session BEFORE dispatching
# ---------------------------------------------------------------------------

def test_sse_post_does_not_execute_with_unknown_session():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    calls = []

    def record(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    server.tool(record)

    # A well-formed MCP tools/call targeting a mutating tool. With a bogus
    # session the handler must reject it BEFORE dispatch so the tool never
    # executes.
    fake = _FakeHandler(server, path="/sse?session=bogus")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "record", "arguments": {}},
            "id": 1,
        }
    ).encode()
    mcp.McpHttpRequestHandler._handle_sse_post(fake, body)

    # The mutating tool must never run for an unknown/stale session.
    assert calls == []
    assert any(s[0] == "error" and s[1] == 400 for s in fake.sent)


def test_sse_post_with_valid_session_dispatches_and_sends_event():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    calls = []

    def record(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    server.tool(record)

    conn_wfile = _FakeWfile()
    conn = mcp._McpSseConnection(conn_wfile)
    conn.alive = True
    server._sse_connections[conn.session_id] = conn

    fake = _FakeHandler(server, path=f"/sse?session={conn.session_id}")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "record", "arguments": {}},
            "id": 1,
        }
    ).encode()
    mcp.McpHttpRequestHandler._handle_sse_post(fake, body)

    assert calls == [{}]
    assert ("response", 202) in fake.sent
    assert ("header", "Content-Length", "0") in fake.sent
    # SSE event carries the dispatch result; the raw request body is not echoed.
    assert fake.wfile.writes == []
    assert len(conn_wfile.writes) == 1
    assert b'"ok"' in conn_wfile.writes[0]


def test_sse_registry_can_churn_while_broadcasting_and_closing():
    """Connection lifecycle and broadcasts share one synchronization boundary."""
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    errors = []
    stop = threading.Event()

    def churn():
        try:
            while not stop.is_set():
                conn = mcp._McpSseConnection(_FakeWfile())
                server._register_sse_connection(conn)
                server.broadcast_sse_event("analysis", {"ok": True})
                server._unregister_sse_connection(conn)
                conn.close()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=churn) for _ in range(4)]
    for thread in threads:
        thread.start()
    for _ in range(20):
        server.broadcast_sse_event("analysis", {"ok": True})
        server._close_sse_connections()
    stop.set()
    for thread in threads:
        thread.join()

    assert errors == []
    assert server._snapshot_sse_connections() == ()


# ---------------------------------------------------------------------------
# mcp.py: HTTP robustness (Content-Length parsing, 413 close, empty 202)
# ---------------------------------------------------------------------------

def test_post_malformed_content_length_returns_400():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    fake = _FakeHandler(server, path="/mcp", headers={"Content-Length": "abc"})
    mcp.McpHttpRequestHandler.do_POST(fake)  # must not raise
    assert any(s[0] == "error" and s[1] == 400 for s in fake.sent)


def test_post_over_limit_413_closes_connection():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    server.post_body_limit = 100
    fake = _FakeHandler(server, path="/mcp", headers={"Content-Length": "5000"})
    fake.send_error = mcp.McpHttpRequestHandler.send_error.__get__(
        fake, mcp.McpHttpRequestHandler
    )
    mcp.McpHttpRequestHandler.do_POST(fake)

    # The real send_error emits a response with code 413.
    assert ("response", 413) in fake.sent
    # Closing the connection discards the unread over-limit body instead of
    # desyncing a kept-alive connection.
    assert fake.close_connection is True
    assert ("header", "Connection", "close") in fake.sent


def test_mcp_post_notification_gets_empty_202():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    fake = _FakeHandler(server, path="/mcp")
    body = json.dumps({"jsonrpc": "2.0", "method": "ping"}).encode()  # no id
    mcp.McpHttpRequestHandler._handle_mcp_post(fake, body)

    assert ("response", 202) in fake.sent
    assert ("header", "Content-Length", "0") in fake.sent
    assert fake.wfile.writes == []  # empty body, not an "Accepted" payload


def test_mcp_post_request_gets_200_json():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")
    fake = _FakeHandler(server, path="/mcp")
    body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 7}).encode()
    mcp.McpHttpRequestHandler._handle_mcp_post(fake, body)

    assert ("response", 200) in fake.sent
    assert fake.wfile.writes
    payload = json.loads(fake.wfile.writes[0])
    assert payload["id"] == 7
    assert "result" in payload


# ---------------------------------------------------------------------------
# mcp.py: resource URI templates escape regex-special literal characters
# ---------------------------------------------------------------------------

def test_resources_read_escapes_literal_regex_chars():
    jr, mcp = _load_pkg()
    server = mcp.McpServer("test")

    @server.resource("file://a.b/{name}")
    def read_res(name):
        return {"ok": True, "name": name}

    # The literal '.' must not act as a wildcard: 'aXb' must not match.
    with pytest.raises(jr.JsonRpcException):
        server._mcp_resources_read("file://aXb/foo")

    out = server._mcp_resources_read("file://a.b/foo")
    assert out["contents"][0]["uri"] == "file://a.b/foo"
    assert "foo" in out["contents"][0]["text"]
