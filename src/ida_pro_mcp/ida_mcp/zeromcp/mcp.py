import re
import sys
import time
import uuid
import json
import inspect
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, HTTPServer
from typing import Any, Callable, Union, Annotated, BinaryIO, get_origin, get_args, get_type_hints, is_typeddict, Literal, Optional

# Compatibility for Python < 3.11
try:
    from typing import NotRequired
except ImportError:
    try:
        from typing_extensions import NotRequired
    except ImportError:
        NotRequired = Optional
from types import UnionType
from urllib.parse import urlparse, parse_qs
from io import BufferedIOBase

from .jsonrpc import JsonRpcRegistry, JsonRpcError, JsonRpcException

class McpToolError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

class McpRpcRegistry(JsonRpcRegistry):
    """JSON-RPC registry with custom error handling for MCP tools"""
    def map_exception(self, e: Exception) -> JsonRpcError:
        if isinstance(e, McpToolError):
            return {
                "code": -32000,
                "message": e.args[0] or "MCP Tool Error",
            }
        return super().map_exception(e)

class _McpSseConnection:
    """Manages a single SSE client connection"""
    def __init__(self, wfile):
        self.wfile: BufferedIOBase = wfile
        self.session_id = str(uuid.uuid4())
        self.alive = True

    def send_event(self, event_type: str, data):
        """Send an SSE event to the client

        Args:
            event_type: Type of event (e.g., "endpoint", "message", "ping")
            data: Event data - can be string (sent as-is) or dict (JSON-encoded)
        """
        if not self.alive:
            return False

        try:
            # SSE format: "event: type\ndata: content\n\n"
            if isinstance(data, str):
                data_str = f"data: {data}\n\n"
            else:
                try:
                    data_str = f"data: {json.dumps(data)}\n\n"
                except (TypeError, ValueError, OverflowError):
                    # A non-serializable event payload must not crash the
                    # connection (or, for a notification stream, take the whole
                    # server down); emit a crisp error event instead.
                    data_str = f"data: {json.dumps({'error': True, 'code': 'INTERNAL', 'message': 'event serialization failed'})}\n\n"
            message = f"event: {event_type}\n{data_str}".encode("utf-8")
            self.wfile.write(message)
            self.wfile.flush()  # Ensure data is sent immediately
            return True
        except (BrokenPipeError, OSError):
            self.alive = False
            return False

class McpHttpRequestHandler(BaseHTTPRequestHandler):
    server_version = "zeromcp/1.4.0"
    error_message_format = "%(code)d - %(message)s"
    error_content_type = "text/plain"
    # Bound each blocking socket operation (StreamRequestHandler.setup()
    # calls connection.settimeout() with this value) so a stalled or
    # slowloris client cannot pin a handler thread forever waiting on a
    # request line, headers, or body that never fully arrives.
    timeout = 60

    def __init__(self, request, client_address, server):
        self.mcp_server: "McpServer" = getattr(server, "mcp_server")
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        """Override to suppress default logging or customize"""
        pass

    def send_cors_headers(self, *, preflight = False):
        origin = self.headers.get("Origin", "")
        if not origin:
            return
        def is_allowed():
            allowed = self.mcp_server.cors_allowed_origins
            if allowed is None:
                return False
            if callable(allowed):
                return allowed(origin)
            if isinstance(allowed, str):
                allowed = [allowed]
            return "*" in allowed or origin in allowed
        if not is_allowed():
            return
        self.send_header("Access-Control-Allow-Origin", origin)
        if preflight:
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version")
            if self.headers.get("Access-Control-Request-Private-Network") == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")

    def send_error(self, code, message=None, explain=None):
        # Always close the connection on an error response. BaseHTTPRequestHandler's
        # default send_error() does this too; without it a 413 (or any error) on a
        # kept-alive HTTP/1.1 connection leaves an unread request body behind, which
        # the server would then misparse as the client's next request line.
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(f"{message}\n".encode("utf-8"))

    def handle(self):
        """Override to add error handling for connection errors"""
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, TimeoutError):
            # Client disconnected or stalled (socket timeout) - normal, suppress traceback
            pass

    def do_GET(self):
        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_get()
            case "/mcp":
                self.send_error(405, "Method Not Allowed")
            case _:
                self.send_error(404, "Not Found")

    def do_POST(self):
        # Read request body. A non-numeric or negative Content-Length is a
        # protocol error, not an exception: reject it with a clean 400 instead
        # of letting int() crash the handler thread.
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else 0
        except (TypeError, ValueError):
            self.send_error(400, "Invalid Content-Length")
            return
        if content_length < 0:
            self.send_error(400, "Invalid Content-Length")
            return

        if content_length > self.mcp_server.post_body_limit:
            # send_error() closes the connection, so the unread over-limit body
            # is discarded with the socket rather than desyncing a kept-alive
            # connection.
            self.send_error(413, f"Payload Too Large: exceeds {self.mcp_server.post_body_limit} bytes")
            return

        body = self.rfile.read(content_length) if content_length > 0 else b""

        match urlparse(self.path).path:
            case "/sse":
                self._handle_sse_post(body)
            case "/mcp":
                self._handle_mcp_post(body)
            case _:
                self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_cors_headers(preflight=True)
        self.end_headers()

    def _handle_sse_get(self):
        # Create SSE connection wrapper
        conn = _McpSseConnection(self.wfile)
        self.mcp_server._sse_connections[conn.session_id] = conn

        try:
            # Send SSE headers
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors_headers()
            self.end_headers()

            # Send endpoint event with session ID for routing
            conn.send_event("endpoint", f"/sse?session={conn.session_id}")

            # Keep connection alive with periodic pings
            last_ping = time.time()
            while conn.alive and self.mcp_server._running:
                now = time.time()
                if now - last_ping > 30:  # Ping every 30 seconds
                    if not conn.send_event("ping", {}):
                        break
                    last_ping = now
                time.sleep(1)

        finally:
            conn.alive = False
            if conn.session_id in self.mcp_server._sse_connections:
                del self.mcp_server._sse_connections[conn.session_id]

    def _handle_sse_post(self, body: bytes):
        query_params = parse_qs(urlparse(self.path).query)
        session_id = query_params.get("session", [None])[0]
        if session_id is None:
            self.send_error(400, "Missing ?session for SSE POST")
            return

        # Resolve and validate the SSE session BEFORE dispatching. A request
        # carrying an unknown or stale session id must never execute a tool
        # (which may mutate the IDB); previously the tool ran and the bogus
        # session was only noticed afterwards, discarding the result.
        sse_conn = self.mcp_server._sse_connections.get(session_id)
        if sse_conn is None or not sse_conn.alive:
            self.send_error(400, f"No active SSE connection found for session {session_id}")
            return

        # Dispatch to MCP registry
        setattr(self.mcp_server._protocol_version, "data", "2024-11-05")
        response = self.mcp_server.registry.dispatch(body)

        # Send response via SSE event stream if there is one
        if response is not None:
            sse_conn.send_event("message", response)

        # Return 202 Accepted to acknowledge POST. The body is intentionally
        # empty: echoing the raw request body (which may not even be JSON)
        # back with Content-Type: application/json is not valid.
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.send_cors_headers()
        self.end_headers()

    def _handle_mcp_post(self, body: bytes):
        # Dispatch to MCP registry
        setattr(self.mcp_server._protocol_version, "data", "2025-06-18")
        response = self.mcp_server.registry.dispatch(body)

        def send_response(status: int, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)

        # Check if notification (returns None)
        if response is None:
            # MCP Streamable HTTP requires an empty 202 body for a
            # notification ("Accepted" is not valid JSON despite the
            # application/json content type).
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.send_cors_headers()
            self.end_headers()
        else:
            try:
                payload = json.dumps(response).encode("utf-8")
            except (TypeError, ValueError, OverflowError):
                # A non-serializable tool result must not crash the handler
                # thread; return an isError-style JSON-RPC error so the client
                # sees a crisp failure instead of a dropped connection.
                err_payload = {
                    "jsonrpc": "2.0",
                    "id": response.get("id") if isinstance(response, dict) else None,
                    "error": {"code": -32603, "message": "Internal error: response serialization failed"},
                }
                payload = json.dumps(err_payload).encode("utf-8")
            send_response(200, payload)

class McpServer:
    def __init__(self, name: str, version = "1.0.0"):
        self.name = name
        self.version = version
        self.post_body_limit = 10 * 1024 * 1024
        self.cors_allowed_origins: Callable[[str], bool] | list[str] | str | None = self.cors_localhost
        self.tools = McpRpcRegistry()
        self.resources = McpRpcRegistry()
        self.prompts = McpRpcRegistry()

        self._http_server: HTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._running = False
        self._sse_connections: dict[str, _McpSseConnection] = {}
        self._protocol_version = threading.local()

        # Register MCP protocol methods with correct names
        self.registry = JsonRpcRegistry()
        self.registry.methods["ping"] = self._mcp_ping
        self.registry.methods["initialize"] = self._mcp_initialize
        self.registry.methods["tools/list"] = self._mcp_tools_list
        self.registry.methods["tools/call"] = self._mcp_tools_call
        self.registry.methods["resources/list"] = self._mcp_resources_list
        self.registry.methods["resources/templates/list"] = self._mcp_resource_templates_list
        self.registry.methods["resources/read"] = self._mcp_resources_read
        self.registry.methods["prompts/list"] = self._mcp_prompts_list
        self.registry.methods["prompts/get"] = self._mcp_prompts_get

    def tool(self, func: Callable) -> Callable:
        return self.tools.method(func)

    def prompt(self, func: Callable) -> Callable:
        return self.prompts.method(func)

    def resource(self, uri: str) -> Callable[[Callable], Callable]:
        def decorator(func: Callable) -> Callable:
            setattr(func, "__resource_uri__", uri)
            return self.resources.method(func)
        return decorator

    def serve(self, host: str, port: int, *, background = True, request_handler = McpHttpRequestHandler):
        if self._running:
            print("[MCP] Server is already running")
            return

        # Create server with deferred binding
        assert issubclass(request_handler, McpHttpRequestHandler)
        self._http_server = (ThreadingHTTPServer if background else HTTPServer)(
            (host, port), request_handler, bind_and_activate=False
        )
        self._http_server.allow_reuse_address = False

        # Set the MCPServer instance on the handler class
        setattr(self._http_server, "mcp_server", self)

        try:
            # Bind and activate in main thread - errors propagate synchronously
            self._http_server.server_bind()
            self._http_server.server_activate()
        except OSError:
            # Cleanup on binding failure
            self._http_server.server_close()
            self._http_server = None
            raise

        # Only start thread after successful bind
        self._running = True

        print("[MCP] Server started:")
        print(f"  Streamable HTTP: http://{host}:{port}/mcp")
        print(f"  SSE: http://{host}:{port}/sse")

        def serve_forever():
            try:
                self._http_server.serve_forever()  # type: ignore
            except Exception as e:
                print(f"[MCP] Server error: {e}")
                traceback.print_exc()
            finally:
                self._running = False

        if background:
            self._server_thread = threading.Thread(target=serve_forever, daemon=True)
            self._server_thread.start()
        else:
            serve_forever()

    def stop(self):
        if not self._running:
            return

        self._running = False

        # Close all SSE connections
        for conn in self._sse_connections.values():
            conn.alive = False
        self._sse_connections.clear()

        # Shutdown the HTTP server
        if self._http_server:
            # shutdown() must be called from a different thread
            # than the one running serve_forever()
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None

        if self._server_thread:
            self._server_thread.join()
            self._server_thread = None

        print("[MCP] Server stopped")

    def stdio(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None):
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        while True:
            try:
                request = stdin.readline()
                if not request:  # EOF
                    break

                # Strip whitespace (trailing newline) before parsing
                request = request.strip()
                if not request:
                    continue

                response = self.registry.dispatch(request)
                if response is not None:
                    try:
                        payload = json.dumps(response).encode("utf-8")
                    except (TypeError, ValueError, OverflowError):
                        # A non-serializable response in stdio mode must not
                        # kill the server loop; emit a crisp JSON-RPC error.
                        err_id = response.get("id") if isinstance(response, dict) else None
                        payload = json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": err_id,
                                "error": {"code": -32603, "message": "Internal error: response serialization failed"},
                            }
                        ).encode("utf-8")
                    stdout.write(payload + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt):  # Client disconnected
                break

    def cors_localhost(self, origin: str) -> bool:
        """Allow CORS requests from localhost on ANY port."""
        return urlparse(origin).hostname in ("localhost", "127.0.0.1", "::1")

    def _mcp_ping(self, _meta: dict | None = None) -> dict:
        """MCP ping method"""
        return {}

    def _mcp_initialize(self, protocolVersion: str, capabilities: dict, clientInfo: dict, _meta: dict | None = None) -> dict:
        """MCP initialize method"""
        return {
            "protocolVersion": getattr(self._protocol_version, "data", protocolVersion),
            "capabilities": {
                "tools": {},
                "resources": {
                    "subscribe": False,
                    "listChanged": False,
                },
                "prompts": {},
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            },
        }

    def _mcp_tools_list(self, _meta: dict | None = None) -> dict:
        """MCP tools/list method"""
        return {
            "tools": [
                self._generate_tool_schema(func_name, func)
                for func_name, func in self.tools.methods.items()
            ],
        }

    def _mcp_tools_call(self, name: str, arguments: dict | None = None, _meta: dict | None = None) -> dict:
        """MCP tools/call method"""
        t0 = time.time()

        # Wrap tool call in JSON-RPC request
        tool_response = self.tools.dispatch({
            "jsonrpc": "2.0",
            "method": name,
            "params": arguments,
            "id": None,
        })
        assert tool_response is not None, "Only notification requests return None"

        elapsed_ms = round((time.time() - t0) * 1000)

        # Check for error response
        if "error" in tool_response:
            error = tool_response["error"]
            message = error.get("message") or "Unknown error"
            code = error.get("code")
            data = error.get("data")

            # Build a richer, LLM-friendly error payload with code + details
            text_parts = []
            if code is not None:
                text_parts.append(f"[code {code}] {message}")
            else:
                text_parts.append(message)
            if data:
                try:
                    text_parts.append(json.dumps(data, indent=2))
                except TypeError:  # json.dumps raises TypeError on non-serializable objects
                    text_parts.append(str(data))

            return {
                "content": [{"type": "text", "text": "\n".join(text_parts)}],
                "structuredContent": {"error": error},
                "isError": True,
            }

        result = tool_response.get("result")

        # ida_mcp tools report failures as a *result* dict built by
        # error_handling.make_error ({error: True, code, message, hint, ...}),
        # matching host.errors.is_error_result (which also treats {"ok": False}
        # as an error). Detect those so clients branching on isError can see
        # the failure instead of treating a failed IDA call as a success.
        if isinstance(result, dict) and (result.get("error") or result.get("ok") is False):
            error = result
            message = error.get("message") or "Unknown error"
            code = error.get("code")
            hint = error.get("hint")
            data = error.get("details") or error.get("data")

            text_parts = []
            if code is not None:
                text_parts.append(f"[code {code}] {message}")
            else:
                text_parts.append(message)
            if hint:
                text_parts.append(f"Hint: {hint}")
            if data:
                try:
                    text_parts.append(json.dumps(data, indent=2))
                except TypeError:  # json.dumps raises TypeError on non-serializable objects
                    text_parts.append(str(data))

            return {
                "content": [{"type": "text", "text": "\n".join(text_parts)}],
                "structuredContent": {"error": error},
                "isError": True,
            }

        # Copy the tool result before decorating it. @idaread/@idawrite
        # (sync.py) store the exact dict a tool returns in TOOL_CACHE and
        # return that same object on hits, so injecting _elapsed_ms in place
        # would leak the timing key into cached results (and any caller-side
        # mutation of the returned dict would poison later cache hits). The
        # copy keeps the cache object pristine and gives the client its own.
        if isinstance(result, dict):
            result = dict(result)
            result["_elapsed_ms"] = elapsed_ms

        if isinstance(result, str):
            content = result
            structured = {"result": result}
        else:
            try:
                content = json.dumps(result, indent=2)
                structured = result if isinstance(result, dict) else {"result": result}
            except (TypeError, ValueError, OverflowError):
                # A tool that returns a non-serializable object (set, bytes,
                # lambdas, an object with a broken __dict__) must surface as an
                # isError tool result, never crash the whole MCP server.
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "[code INTERNAL] Tool returned a non-serializable result; see the error envelope for details.",
                        }
                    ],
                    "structuredContent": {
                        "error": {
                            "error": True,
                            "code": "INTERNAL",
                            "category": "internal",
                            "message": "Tool result could not be JSON-serialized.",
                            "recoverable": False,
                            "hint": "The tool returned an object that cannot be encoded as JSON.",
                        }
                    },
                    "isError": True,
                }
        return {
            "content": [{"type": "text", "text": content}],
            "structuredContent": structured,
            "isError": False,
        }

    def _enumerate_resources(self):
        for name, func in self.resources.methods.items():
            uri: str = getattr(func, "__resource_uri__")
            description = (func.__doc__ or f"Read {uri}").strip()
            yield uri, name, description

    def _mcp_resources_list(self, _meta: dict | None = None) -> dict:
        """MCP resources/list method - returns static resources only (no URI parameters)"""
        return {
            "resources": [
                {
                    "uri": uri,
                    "name": name,
                    "description": description,
                    "mimeType": "application/json",
                }
                for uri, name, description in self._enumerate_resources()
                if "{" not in uri
            ]
        }

    def _mcp_resource_templates_list(self, _meta: dict | None = None) -> dict:
        """MCP resources/templates/list method - returns parameterized resource templates"""
        return {
            "resourceTemplates": [
                {
                    "uriTemplate": uri,
                    "name": name,
                    "description": description,
                    "mimeType": "application/json",
                }
                for uri, name, description in self._enumerate_resources()
                if "{" in uri
            ]
        }

    def _mcp_resources_read(self, uri: str, _meta: dict | None = None) -> dict:
        """MCP resources/read method"""

        # Try to match URI against all registered resource patterns
        for pattern, name, _ in self._enumerate_resources():
            # Convert the URI template to a regex, replacing {param} with
            # named capture groups. The literal parts must be re.escape()d so
            # regex-special characters ('.', '+', '(', ...) in a registered
            # URI cannot act as wildcards and match unintended URIs.
            regex_parts = []
            offset = 0
            for m in re.finditer(r"\{(\w+)\}", pattern):
                regex_parts.append(re.escape(pattern[offset:m.start()]))
                regex_parts.append(f"(?P<{m.group(1)}>[^/]+)")
                offset = m.end()
            regex_parts.append(re.escape(pattern[offset:]))
            regex_pattern = f"^{''.join(regex_parts)}$"

            match = re.match(regex_pattern, uri)
            if match:
                # Found matching resource - call it via JSON-RPC
                params = list(match.groupdict().values())

                resource_response = self.resources.dispatch({
                    "jsonrpc": "2.0",
                    "method": name,
                    "params": params,
                    "id": None,
                })
                assert resource_response is not None, "Only notification requests return None"

                if "error" in resource_response:
                    error = resource_response["error"]
                    raise JsonRpcException(error["code"], error["message"], error.get("data"))

                try:
                    text = json.dumps(resource_response.get("result"), indent=2)
                except (TypeError, ValueError, OverflowError):
                    # A resource returning a non-serializable payload must be a
                    # crisp JSON-RPC error, not an uncaught exception that
                    # takes down the whole server.
                    raise JsonRpcException(
                        -32603, "Resource result could not be JSON-serialized", {"uri": uri}
                    )

                return {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text,
                    }]
                }

        raise JsonRpcException(-32002, "Resource not found", {"uri": uri})

    def _mcp_prompts_list(self, _meta: dict | None = None) -> dict:
        """MCP prompts/list method"""
        return {
            "prompts": [
                self._generate_prompt_schema(func_name, func)
                for func_name, func in self.prompts.methods.items()
            ],
        }

    def _mcp_prompts_get(
        self, name: str, arguments: dict | None = None, _meta: dict | None = None
    ) -> dict:
        """MCP prompts/get method"""
        # Dispatch to prompts registry
        prompt_response = self.prompts.dispatch(
            {
                "jsonrpc": "2.0",
                "method": name,
                "params": arguments,
                "id": None,
            }
        )
        assert prompt_response is not None, "Only notification requests return None"

        # Check for error response
        if "error" in prompt_response:
            error = prompt_response["error"]
            raise JsonRpcException(error["code"], error["message"], error.get("data"))

        result = prompt_response.get("result")

        # Pass through list of messages directly
        if isinstance(result, list):
            return {"messages": result}

        # Convert non-string results to JSON
        if not isinstance(result, str):
            try:
                result = json.dumps(result, indent=2)
            except (TypeError, ValueError, OverflowError):
                raise JsonRpcException(
                    -32603, "Prompt result could not be JSON-serialized", {"name": name}
                )
        return {
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": result},
                },
            ],
        }

    def _generate_prompt_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP prompt schema from a function"""
        hints = get_type_hints(func, include_extras=True)
        hints.pop("return", None)
        sig = inspect.signature(func)

        # Build arguments list (PromptArgument format)
        arguments = []
        for param_name, param_type in hints.items():
            arg: dict[str, Any] = {"name": param_name}

            # Extract description from Annotated
            origin = get_origin(param_type)
            if origin is Annotated:
                args = get_args(param_type)
                arg["description"] = str(args[-1])

            # Check if required (no default value)
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                arg["required"] = True

            arguments.append(arg)

        schema: dict[str, Any] = {
            "name": func_name,
            "description": (func.__doc__ or f"Prompt {func_name}").strip(),
        }

        if arguments:
            schema["arguments"] = arguments

        return schema

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON schema object"""
        origin = get_origin(py_type)
        # Annotated[T, "description"]
        if origin is Annotated:
            args = get_args(py_type)
            return {
                **self._type_to_json_schema(args[0]),
                "description": str(args[-1]),
            }

        # NotRequired[T]
        if origin is NotRequired:
            return self._type_to_json_schema(get_args(py_type)[0])

        # Union[Ts..], Optional[T] and T1 | T2
        if origin in (Union, UnionType):
            return {"anyOf": [self._type_to_json_schema(t) for t in get_args(py_type)]}

        # list[T]
        if origin is list:
            return {
                "type": "array",
                "items": self._type_to_json_schema(get_args(py_type)[0]),
            }

        # dict[str, T]
        if origin is dict:
            return {
                "type": "object",
                "additionalProperties": self._type_to_json_schema(get_args(py_type)[1]),
            }

        # TypedDict
        if is_typeddict(py_type):
            return self._typed_dict_to_schema(py_type)

        # Literal (enum)
        if origin is Literal:
            return {"type": "string", "enum": list(get_args(py_type))}

        # Primitives
        return {
            "type": {
                int: "integer",
                float: "number",
                str: "string",
                bool: "boolean",
                list: "array",
                dict: "object",
                type(None): "null",
            }.get(py_type, "object"),
        }

    def _typed_dict_to_schema(self, typed_dict_class) -> dict:
        """Convert TypedDict to JSON schema"""
        hints = get_type_hints(typed_dict_class, include_extras=True)
        required_keys = getattr(typed_dict_class, "__required_keys__", set(hints.keys()))

        return {
            "type": "object",
            "properties": {
                field_name: self._type_to_json_schema(field_type)
                for field_name, field_type in hints.items()
            },
            "required": [key for key in hints.keys() if key in required_keys],
            "additionalProperties": False,
        }

    def _generate_tool_schema(self, func_name: str, func: Callable) -> dict:
        """Generate MCP tool schema from a function"""
        hints = get_type_hints(func, include_extras=True)
        return_type = hints.pop("return", None)
        sig = inspect.signature(func)

        # Build parameter schema
        properties = {}
        required = []

        for param_name, param_type in hints.items():
            properties[param_name] = self._type_to_json_schema(param_type)

            # Add to required if no default value
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                required.append(param_name)

        schema: dict[str, Any] = {
            "name": func_name,
            "description": (func.__doc__ or f"Call {func_name}").strip(),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

        # Add outputSchema if return type exists and is not None
        if return_type and return_type is not type(None):
            return_schema = self._type_to_json_schema(return_type)

            # Wrap non-object returns in a "result" property
            if return_schema.get("type") != "object":
                return_schema = {
                    "type": "object",
                    "properties": {"result": return_schema},
                    "required": ["result"],
                }

            schema["outputSchema"] = return_schema

        return schema
