"""Protocol-level coverage for the vendored zero-dependency MCP transport."""

from __future__ import annotations

import io
import json
import threading
import types
from typing import Annotated, Literal, NotRequired, TypedDict

import pytest

from tests.ida_mcp import test_p16_zeromcp as support


class _Payload(TypedDict):
    required: int
    optional: NotRequired[list[str]]


def test_sse_connection_serialization_close_and_broken_pipe():
    _jr, mcp = support._load_pkg()
    output = support._FakeWfile()
    conn = mcp._McpSseConnection(output)
    assert conn.send_event("message", "hello") is True
    assert conn.send_event("data", {"ok": True}) is True
    assert b"event: message" in output.writes[0]
    assert b'"ok": true' in output.writes[1]

    assert conn.send_event("bad", {"value": {1, 2}}) is True
    assert b"serialization failed" in output.writes[-1]
    conn.close()
    assert conn.send_event("after-close", {}) is False

    class _Broken(support._FakeWfile):
        def write(self, _data):
            raise BrokenPipeError

    broken = mcp._McpSseConnection(_Broken())
    assert broken.send_event("message", {}) is False
    assert broken.alive is False


def test_cors_variants_and_http_dispatch_branches():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    assert server.cors_localhost("http://localhost:9999") is True
    assert server.cors_localhost("https://127.0.0.1:1") is True
    assert server.cors_localhost("https://remote.invalid") is False

    fake = support._FakeHandler(server, headers={"Origin": "https://client.invalid"})
    server.cors_allowed_origins = ["https://client.invalid"]
    mcp.McpHttpRequestHandler.send_cors_headers(fake, preflight=True)
    assert ("header", "Access-Control-Allow-Origin", "https://client.invalid") in fake.sent
    assert any(row[1] == "Access-Control-Allow-Methods" for row in fake.sent if row[0] == "header")

    fake.headers["Access-Control-Request-Private-Network"] = "true"
    mcp.McpHttpRequestHandler.send_cors_headers(fake, preflight=True)
    assert ("header", "Access-Control-Allow-Private-Network", "true") in fake.sent
    server.cors_allowed_origins = lambda origin: origin.endswith(".invalid")
    fake.sent.clear()
    mcp.McpHttpRequestHandler.send_cors_headers(fake)
    assert ("header", "Access-Control-Allow-Origin", "https://client.invalid") in fake.sent
    server.cors_allowed_origins = None
    fake.sent.clear()
    mcp.McpHttpRequestHandler.send_cors_headers(fake)
    assert not any(row[0] == "header" for row in fake.sent)

    fake = support._FakeHandler(server, path="/mcp", headers={"Content-Length": "-1"})
    fake.send_error = mcp.McpHttpRequestHandler.send_error.__get__(fake, mcp.McpHttpRequestHandler)
    mcp.McpHttpRequestHandler.do_POST(fake)
    assert ("response", 400) in fake.sent

    fake = support._FakeHandler(server, path="/unknown", headers={"Content-Length": "0"})
    fake.rfile = types.SimpleNamespace(read=lambda _n: b"")
    mcp.McpHttpRequestHandler.do_POST(fake)
    assert any(row[0] == "error" and row[1] == 404 for row in fake.sent)

    for path, code in (("/mcp", 405), ("/missing", 404)):
        fake = support._FakeHandler(server, path=path)
        mcp.McpHttpRequestHandler.do_GET(fake)
        assert any(row[0] == "error" and row[1] == code for row in fake.sent)
    sse_fake = support._FakeHandler(server, path="/sse")
    mcp.McpHttpRequestHandler._handle_sse_get(sse_fake)
    assert b"event: endpoint" in sse_fake.wfile.writes[0]
    assert server._snapshot_sse_connections() == ()
    fake = support._FakeHandler(server)
    mcp.McpHttpRequestHandler.do_OPTIONS(fake)
    assert ("response", 200) in fake.sent

    routed = support._FakeHandler(server, path="/sse?session=unused", headers={"Content-Length": "3"})
    routed.rfile = types.SimpleNamespace(read=lambda _n: b"abc")
    called = []

    def record_sse_post(body):
        called.append(body)

    routed._handle_sse_post = record_sse_post
    mcp.McpHttpRequestHandler.do_POST(routed)
    assert called == [b"abc"]


def test_stdio_and_mcp_protocol_methods_cover_notifications_and_failures():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    @server.tool
    def text_tool() -> str:
        return "hello"

    @server.tool
    def none_tool():
        return None

    @server.tool
    def annotated(value: Annotated[int, "number"]) -> list[int]:
        return [value]

    assert server._mcp_ping() == {}
    initialized = server._mcp_initialize("old", {}, {})
    assert initialized["serverInfo"] == {"name": "demo", "version": "2.0"}
    assert {row["name"] for row in server._mcp_tools_list()["tools"]} == {"text_tool", "none_tool", "annotated"}
    assert server._mcp_tools_call("text_tool", {})["structuredContent"] == {"result": "hello"}
    assert server._mcp_tools_call("none_tool", {})["structuredContent"] == {"result": None}
    assert server._mcp_tools_call("annotated", {"value": 4})["isError"] is False

    server.tools.dispatch = lambda _request: {"error": {"code": 7, "message": "bad", "data": {1}}}
    error = server._mcp_tools_call("anything", {})
    assert error["isError"] is True and "bad" in error["content"][0]["text"]
    server.tools.dispatch = lambda _request: {"result": {"error": True, "message": "tool bad", "details": {1}}}
    error = server._mcp_tools_call("anything", {})
    assert error["isError"] is True and "{1}" in error["content"][0]["text"]

    stdin = io.BytesIO(
        b"\n"
        + json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode()
        + b"\n"
        + json.dumps({"jsonrpc": "2.0", "method": "ping"}).encode()
        + b"\n"
    )
    stdout = io.BytesIO()
    server.registry.dispatch = lambda request: {"jsonrpc": "2.0", "id": 1, "result": {1}}
    server.stdio(stdin, stdout)
    payload = json.loads(stdout.getvalue().splitlines()[0])
    assert payload["error"]["code"] == -32603


def test_resources_prompts_and_type_schemas_across_shapes():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo")

    @server.resource("demo://static")
    def static_resource():
        "Static resource"
        return {"ok": True}

    @server.resource("demo://item/{name}")
    def item_resource(name: str):
        return {"name": name}

    assert server._mcp_resources_list()["resources"][0]["uri"] == "demo://static"
    assert server._mcp_resource_templates_list()["resourceTemplates"][0]["uriTemplate"] == "demo://item/{name}"
    assert json.loads(server._mcp_resources_read("demo://item/value")["contents"][0]["text"])["name"] == "value"
    with pytest.raises(mcp.JsonRpcException) as missing:
        server._mcp_resources_read("demo://unknown")
    assert missing.value.code == -32002

    server.resources.dispatch = lambda _request: {"error": {"code": 8, "message": "resource failed"}}
    with pytest.raises(mcp.JsonRpcException) as resource_error:
        server._mcp_resources_read("demo://item/value")
    assert resource_error.value.code == 8
    server.resources.dispatch = lambda _request: {"result": {1}}
    with pytest.raises(mcp.JsonRpcException) as resource_serialization:
        server._mcp_resources_read("demo://item/value")
    assert resource_serialization.value.code == -32603

    @server.prompt
    def list_prompt(value: int):
        return [{"role": "user", "content": {"type": "text", "text": str(value)}}]

    @server.prompt
    def json_prompt() -> dict:
        return {"prompt": "hello"}

    @server.prompt
    def documented_prompt(value: Annotated[int, "required number"], optional: str = "x"):
        """A documented prompt."""
        return str(value) + optional

    assert server._mcp_prompts_list()["prompts"]
    documented = next(row for row in server._mcp_prompts_list()["prompts"] if row["name"] == "documented_prompt")
    assert documented["arguments"][0]["description"] == "required number"
    assert documented["arguments"][0]["required"] is True
    assert "required" not in documented["arguments"][1]
    assert server._mcp_prompts_get("list_prompt", {"value": 2})["messages"][0]["role"] == "user"
    assert "hello" in server._mcp_prompts_get("json_prompt")["messages"][0]["content"]["text"]
    server.prompts.dispatch = lambda _request: {"error": {"code": 9, "message": "prompt failed"}}
    with pytest.raises(mcp.JsonRpcException):
        server._mcp_prompts_get("json_prompt")
    server.prompts.dispatch = lambda _request: {"result": {1}}
    with pytest.raises(mcp.JsonRpcException) as prompt_serialization:
        server._mcp_prompts_get("json_prompt")
    assert prompt_serialization.value.code == -32603

    assert server._type_to_json_schema(Annotated[int, "count"])["description"] == "count"
    assert server._type_to_json_schema(NotRequired[str]) == {"type": "string"}
    assert server._type_to_json_schema(int | str)["anyOf"]
    assert server._type_to_json_schema(list[int])["items"] == {"type": "integer"}
    assert server._type_to_json_schema(dict[str, float])["additionalProperties"] == {"type": "number"}
    assert set(server._type_to_json_schema(_Payload)["required"]) == {"required", "optional"}
    assert server._type_to_json_schema(Literal["a", "b"])["enum"] == ["a", "b"]
    assert server._type_to_json_schema(type(None)) == {"type": "null"}
    tool_schema = server._generate_tool_schema("annotated", lambda value: value)
    assert tool_schema["inputSchema"]["required"] == []
    def list_result() -> list[int]:
        return [1]

    assert server._generate_tool_schema("list_result", list_result)["outputSchema"]["required"] == ["result"]
    assert server._generate_prompt_schema("plain", lambda: "x")["description"] == "Prompt plain"


def test_server_lifecycle_decorators_and_sse_registry(monkeypatch):
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo")
    assert isinstance(server.tools.methods, dict)

    @server.resource("x://{value}")
    def resource(value):
        return value

    assert resource.__resource_uri__ == "x://{value}"

    conn = mcp._McpSseConnection(support._FakeWfile())
    server._register_sse_connection(conn)
    assert server._get_sse_connection(conn.session_id) is conn
    assert server._snapshot_sse_connections() == (conn,)
    server.broadcast_sse_event("ping", {"ok": True})
    server._unregister_sse_connection(conn)
    assert server._snapshot_sse_connections() == ()
    server._register_sse_connection(conn)
    server._close_sse_connections()
    assert conn.alive is False

    closed = threading.Event()

    class _Http:
        allow_reuse_address = True

        def __init__(self, _addr, _handler, bind_and_activate=False):
            self.mcp_server = None

        def server_bind(self):
            return None

        def server_activate(self):
            return None

        def serve_forever(self):
            closed.wait(2)

        def shutdown(self):
            closed.set()

        def server_close(self):
            return None

    monkeypatch.setattr(mcp, "ThreadingHTTPServer", _Http)
    server.serve("127.0.0.1", 0)
    assert server._running is True
    server.stop()
    assert server._running is False
    server.stop()

    class _BrokenHttp(_Http):
        def server_bind(self):
            raise OSError("busy")

    monkeypatch.setattr(mcp, "HTTPServer", _BrokenHttp)
    failed = mcp.McpServer("broken")
    with pytest.raises(OSError):
        failed.serve("127.0.0.1", 0, background=False)
    assert failed._http_server is None
    failed._running = True
    failed.serve("127.0.0.1", 0)


# ── handler construction / dispatch gap closure ───────────────────────────


def _make_handler(mcp, server):
    """Build a real McpHttpRequestHandler over in-memory streams (no socket)."""

    class _MemHandler(mcp.McpHttpRequestHandler):
        def setup(self):
            self.rfile = io.BytesIO(b"")
            self.wfile = io.BytesIO()

        def finish(self):
            pass

    return _MemHandler(
        object(), ("127.0.0.1", 0), types.SimpleNamespace(mcp_server=server)
    )


def test_handler_init_and_log_message():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    handler = _make_handler(mcp, server)
    assert handler.mcp_server is server
    assert handler.log_message("ignored %s", "x") is None


def test_cors_missing_origin_and_string_allowlist():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    fake = support._FakeHandler(server, headers={})
    mcp.McpHttpRequestHandler.send_cors_headers(fake)
    assert not any(row[0] == "header" for row in fake.sent)

    fake = support._FakeHandler(server, headers={"Origin": "https://client.invalid"})
    server.cors_allowed_origins = "https://client.invalid"
    mcp.McpHttpRequestHandler.send_cors_headers(fake)
    assert ("header", "Access-Control-Allow-Origin", "https://client.invalid") in fake.sent


def test_handle_swallows_connection_errors():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    handler = _make_handler(mcp, server)

    def _boom():
        raise ConnectionResetError("peer gone")

    handler.handle_one_request = _boom
    assert handler.handle() is None


def test_do_get_routes_sse():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    fake = support._FakeHandler(server, path="/sse")
    fake._handle_sse_get = mcp.McpHttpRequestHandler._handle_sse_get.__get__(fake)
    mcp.McpHttpRequestHandler.do_GET(fake)
    assert b"event: endpoint" in fake.wfile.writes[0]
    assert server._snapshot_sse_connections() == ()


def test_do_post_routes_mcp_and_rejects_garbage():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    body = b"not json"
    fake = support._FakeHandler(
        server, path="/mcp", headers={"Content-Length": str(len(body))}
    )
    fake.rfile = types.SimpleNamespace(read=lambda _n: body)
    fake._handle_mcp_post = mcp.McpHttpRequestHandler._handle_mcp_post.__get__(fake)
    fake._handle_sse_post = mcp.McpHttpRequestHandler._handle_sse_post.__get__(fake)
    mcp.McpHttpRequestHandler.do_POST(fake)
    assert ("response", 200) in fake.sent
    assert b"jsonrpc" in fake.wfile.writes[0]


def test_sse_get_ping_loop(monkeypatch):
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    server._running = True
    fake = support._FakeHandler(server, path="/sse")
    ticks = iter([100.0, 131.0])
    monkeypatch.setattr(mcp.time, "time", lambda: next(ticks, 200.0))
    monkeypatch.setattr(
        mcp.time, "sleep", lambda _s: setattr(server, "_running", False)
    )
    try:
        mcp.McpHttpRequestHandler._handle_sse_get(fake)
    finally:
        server._running = False
    assert b"event: ping" in fake.wfile.writes[-1]
    assert server._snapshot_sse_connections() == ()


def test_sse_get_skips_ping_when_fresh(monkeypatch):
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    server._running = True
    fake = support._FakeHandler(server, path="/sse")
    ticks = iter([100.0, 110.0])
    monkeypatch.setattr(mcp.time, "time", lambda: next(ticks, 200.0))
    monkeypatch.setattr(
        mcp.time, "sleep", lambda _s: setattr(server, "_running", False)
    )
    try:
        mcp.McpHttpRequestHandler._handle_sse_get(fake)
    finally:
        server._running = False
    assert not any(b"event: ping" in write for write in fake.wfile.writes)
    assert server._snapshot_sse_connections() == ()


def test_sse_get_breaks_on_dead_ping(monkeypatch):
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    server._running = True

    class _Dying(support._FakeWfile):
        def __init__(self):
            super().__init__()
            self.writes_count = 0

        def write(self, data):
            self.writes_count += 1
            if self.writes_count > 1:
                raise BrokenPipeError("gone")
            return super().write(data)

    fake = support._FakeHandler(server, path="/sse")
    fake.wfile = _Dying()
    ticks = iter([100.0, 131.0])
    monkeypatch.setattr(mcp.time, "time", lambda: next(ticks, 200.0))
    monkeypatch.setattr(mcp.time, "sleep", lambda _s: None)
    try:
        mcp.McpHttpRequestHandler._handle_sse_get(fake)
    finally:
        server._running = False
    assert server._snapshot_sse_connections() == ()


def test_sse_post_missing_session():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    fake = support._FakeHandler(
        server, path="/sse", headers={"Content-Length": "0"}
    )
    fake.rfile = types.SimpleNamespace(read=lambda _n: b"")
    fake._handle_sse_post = mcp.McpHttpRequestHandler._handle_sse_post.__get__(fake)
    fake._handle_mcp_post = mcp.McpHttpRequestHandler._handle_mcp_post.__get__(fake)
    mcp.McpHttpRequestHandler.do_POST(fake)
    assert any(row[0] == "error" and row[1] == 400 for row in fake.sent)


def test_sse_post_dispatches_to_live_session():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    conn = mcp._McpSseConnection(support._FakeWfile())
    server._register_sse_connection(conn)
    body = b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}'
    fake = support._FakeHandler(
        server,
        path=f"/sse?session={conn.session_id}",
        headers={"Content-Length": str(len(body))},
    )
    fake.rfile = types.SimpleNamespace(read=lambda _n: body)
    fake._handle_sse_post = mcp.McpHttpRequestHandler._handle_sse_post.__get__(fake)
    fake._handle_mcp_post = mcp.McpHttpRequestHandler._handle_mcp_post.__get__(fake)
    try:
        mcp.McpHttpRequestHandler.do_POST(fake)
    finally:
        server._unregister_sse_connection(conn)
    assert ("response", 202) in fake.sent
    assert any(b"event: message" in write for write in conn.wfile.writes)


def test_sse_post_notification_skips_event_stream():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    conn = mcp._McpSseConnection(support._FakeWfile())
    server._register_sse_connection(conn)
    body = b'{"jsonrpc": "2.0", "method": "ping"}'
    fake = support._FakeHandler(
        server,
        path=f"/sse?session={conn.session_id}",
        headers={"Content-Length": str(len(body))},
    )
    fake.rfile = types.SimpleNamespace(read=lambda _n: body)
    fake._handle_sse_post = mcp.McpHttpRequestHandler._handle_sse_post.__get__(fake)
    fake._handle_mcp_post = mcp.McpHttpRequestHandler._handle_mcp_post.__get__(fake)
    try:
        mcp.McpHttpRequestHandler.do_POST(fake)
    finally:
        server._unregister_sse_connection(conn)
    assert ("response", 202) in fake.sent
    assert all(b"event: message" not in write for write in conn.wfile.writes)


# ── server lifecycle / stdio gap closure ──────────────────────────────────


def test_unregister_foreign_connection_is_noop():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    stranger = mcp._McpSseConnection(support._FakeWfile())
    server._unregister_sse_connection(stranger)
    assert server._snapshot_sse_connections() == ()


def test_broadcast_isolates_raising_connection():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    class _Raising:
        session_id = "raising"

        def send_event(self, _kind, _event):
            raise RuntimeError("dead")

    live = mcp._McpSseConnection(support._FakeWfile())
    server._register_sse_connection(_Raising())
    server._register_sse_connection(live)
    try:
        server.broadcast_sse_event("message", {"ok": True})
    finally:
        server._unregister_sse_connection(live)
        with server._sse_lock:
            server._sse_connections.pop("raising", None)
    assert any(b"event: message" in write for write in live.wfile.writes)


def test_serve_thread_error_disarms_server(monkeypatch):
    _jr, mcp = support._load_pkg()

    class _Exploding:
        def __init__(self, _addr, _handler, bind_and_activate=False):
            pass

        def server_bind(self):
            return None

        def server_activate(self):
            return None

        def serve_forever(self):
            raise RuntimeError("boom")

        def shutdown(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setattr(mcp, "ThreadingHTTPServer", _Exploding)
    server = mcp.McpServer("demo", "2.0")
    server.serve("127.0.0.1", 0)
    deadline = mcp.time.time() + 5.0
    while server._running and mcp.time.time() < deadline:
        mcp.time.sleep(0.01)
    assert server._running is False
    server._server_thread.join(5)
    server._http_server.server_close()
    server._http_server = None
    server._server_thread = None


def test_serve_foreground_runs_inline(monkeypatch):
    _jr, mcp = support._load_pkg()

    class _Inline:
        def __init__(self, _addr, _handler, bind_and_activate=False):
            self.served = False

        def server_bind(self):
            return None

        def server_activate(self):
            return None

        def serve_forever(self):
            self.served = True

        def shutdown(self):
            return None

        def server_close(self):
            return None

    monkeypatch.setattr(mcp, "HTTPServer", _Inline)
    server = mcp.McpServer("demo", "2.0")
    server.serve("127.0.0.1", 0, background=False)
    # The foreground path runs the serve loop inline; the shared closure
    # disarms _running in its finally block once the loop returns.
    assert server._running is False
    assert server._http_server.served is True
    server._http_server.server_close()
    server._http_server = None


def test_stop_without_server_handles_missing_pieces():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    server._running = True
    server.stop()
    assert server._running is False


def test_stdio_skips_notifications():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    stdin = io.BytesIO(b'{"jsonrpc": "2.0", "method": "ping"}\n')
    stdout = io.BytesIO()
    server.stdio(stdin=stdin, stdout=stdout)
    assert stdout.getvalue() == b""


def test_stdio_broken_pipe_breaks_loop():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    stdin = io.BytesIO(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')

    class _BrokenOut(io.BytesIO):
        def write(self, _data):
            raise BrokenPipeError("gone")

    server.stdio(stdin=stdin, stdout=_BrokenOut())


def test_prompt_string_result_passes_through():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    @server.prompt
    def str_prompt() -> str:
        return "hello"

    messages = server._mcp_prompts_get("str_prompt")["messages"]
    assert messages[0]["content"]["text"] == "hello"


def test_tools_call_codeless_error():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")
    server.tools.dispatch = lambda _request: {"error": {"message": "boom"}}
    result = server._mcp_tools_call("anything")
    assert result["content"][0]["text"] == "boom"


def test_tool_error_maps_to_mcp_code():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    @server.tool
    def failing() -> int:
        raise mcp.McpToolError("nope")

    response = server.tools.dispatch(
        {"jsonrpc": "2.0", "method": "failing", "id": 1}
    )
    assert response["error"]["code"] == -32000

    @server.tool
    def broken() -> int:
        raise ValueError("unexpected")

    response = server.tools.dispatch(
        {"jsonrpc": "2.0", "method": "broken", "id": 2}
    )
    assert response["error"]["code"] == -32603


# ── schema generation gap closure ─────────────────────────────────────────


def test_notrequired_import_fallback_chain(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _blocker(name, *args, **kwargs):
        fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist", ())
        if (
            name in ("typing", "typing_extensions")
            and fromlist
            and "NotRequired" in fromlist
        ):
            raise ImportError("blocked for fallback test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocker)
    _jr, mcp = support._load_pkg()
    assert mcp.NotRequired is mcp.Optional


class _SchemaResult(TypedDict):
    value: int


def test_tool_schema_defaulted_params_not_required():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    def with_defaults(count: int = 3, name: str = "x") -> int:
        return count

    schema = server._generate_tool_schema("with_defaults", with_defaults)
    assert schema["inputSchema"]["required"] == []


def test_tool_schema_object_return_unwrapped():
    _jr, mcp = support._load_pkg()
    server = mcp.McpServer("demo", "2.0")

    def structured() -> _SchemaResult:
        return {"value": 1}

    schema = server._generate_tool_schema("structured", structured)
    assert schema["outputSchema"]["type"] == "object"
    assert "result" not in schema["outputSchema"].get("properties", {})
