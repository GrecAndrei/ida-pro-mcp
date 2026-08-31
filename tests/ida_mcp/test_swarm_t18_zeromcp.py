"""Regression tests for t18_zeromcp: mcp_http config endpoints.

Coverage:
- enabled_tools filter is honored once tools are registered (previously it ran
  at module import against an empty lazy registry, so the persisted config was
  a no-op and every disabled tool reappeared after a restart).
- The config page keeps showing (and re-enabling) tools the filter has dropped
  from the live registry via the ``_KNOWN_TOOLS`` reference.
- A disabled tool imported after a save is filtered out again; a brand-new tool
  defaults to enabled and is persisted.
- /config POST robustness: an empty body, an over-limit Content-Length, and a
  truncated body are all rejected without touching the stored config, instead
  of silently disabling every tool.
- The origin check already rejects a cross-port localhost origin, so a page on
  another localhost port cannot flip the CORS policy to 'unrestricted'.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IDA_MCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp"


def _load_standalone(relpath: str, name: str):
    """Load an ida_mcp source module standalone (no package init)."""
    path = IDA_MCP / f"{relpath}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "ida_pro_mcp.ida_mcp"
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _register_ida_mcp_pkg():
    pkg = sys.modules.get("ida_pro_mcp") or types.ModuleType("ida_pro_mcp")
    pkg.__path__ = [str(REPO / "src" / "ida_pro_mcp")]
    sys.modules["ida_pro_mcp"] = pkg
    sub = sys.modules.get("ida_pro_mcp.ida_mcp") or types.ModuleType("ida_pro_mcp.ida_mcp")
    sub.__path__ = [str(IDA_MCP)]
    sys.modules["ida_pro_mcp.ida_mcp"] = sub
    return sub


def _load_mcp_http():
    """Load mcp_http standalone with ida_netnode/rpc/sync stubbed.

    Returns the module plus a ``blobs`` dict backing the fake netnode so tests
    can seed and inspect persisted config. mcp_http no longer filters tools at
    import (the registry is empty then), so the stub needs only a live ``tools``
    registry, not a pre-seeded one.
    """
    _register_ida_mcp_pkg()

    ida_netnode = types.ModuleType("ida_netnode")
    blobs: dict = {}

    def netnode(name, *a, **k):
        return types.SimpleNamespace(
            getblob=lambda tag, typ: blobs.get(name),
            setblob=lambda blob, tag, typ: blobs.__setitem__(name, blob),
        )

    ida_netnode.netnode = netnode
    sys.modules["ida_netnode"] = ida_netnode

    def _passthrough(f):
        return f

    sync_stub = types.ModuleType("ida_pro_mcp.ida_mcp.sync")
    sync_stub.idaread = _passthrough
    sync_stub.idawrite = _passthrough
    sys.modules["ida_pro_mcp.ida_mcp.sync"] = sync_stub

    registry = types.SimpleNamespace(methods={})
    rpc_stub = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc_stub.MCP_SERVER = types.SimpleNamespace(
        tools=registry,
        cors_localhost=lambda origin: True,
        cors_allowed_origins=None,
    )
    rpc_stub.MCP_UNSAFE = frozenset()
    class _ParentMcpHttpRequestHandler:
        def do_POST(self):
            self.parent_post_called = True

    rpc_stub.McpHttpRequestHandler = _ParentMcpHttpRequestHandler
    rpc_stub.McpRpcRegistry = type("McpRpcRegistry", (), {})
    rpc_stub.McpToolError = type("McpToolError", (Exception,), {})
    sys.modules["ida_pro_mcp.ida_mcp.rpc"] = rpc_stub

    m = _load_standalone("mcp_http", "t18_mcp_http_ut")
    return m, blobs


def _tool(name=None):
    """A stand-in tool callable (handle_enabled_tools keys on registry names)."""
    return lambda: {"ok": True}


def _make_config_handler(mod, body=b"", content_type="application/x-www-form-urlencoded",
                         content_length=None, port=13337):
    """Fake self for the real IdaMcpHttpRequestHandler methods."""
    h = type("FakeCfgHandler", (), {})()
    h.headers = {}
    if content_type is not None:
        h.headers["content-type"] = content_type
    if content_length is None:
        content_length = len(body)
    h.headers["content-length"] = str(content_length)
    h.server_port = port
    h.body = body
    h.rfile = types.SimpleNamespace(read=lambda n: h.body[:n])
    h.sent = []
    h.send_error = lambda code, msg, explain=None: h.sent.append(("error", code, msg))
    h.send_response = lambda code, msg=None: h.sent.append(("response", code))
    h.send_header = lambda k, v: h.sent.append(("header", k, v))
    h.end_headers = lambda: h.sent.append(("end",))
    h.mcp_server = mod.MCP_SERVER
    h.update_cors_policy = mod.IdaMcpHttpRequestHandler.update_cors_policy.__get__(h)
    h._check_origin = mod.IdaMcpHttpRequestHandler._check_origin.__get__(h)
    return h


# ---------------------------------------------------------------------------
# Finding 1: the enabled_tools filter must honor persisted config once tools
# are actually registered (the eager import-time call ran on an empty registry)
# ---------------------------------------------------------------------------

def test_filter_honors_persisted_config_on_populated_registry():
    mod, _ = _load_mcp_http()
    # Tools register lazily, AFTER module import — simulate that.
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool(), "ida_patch": _tool(), "ida_rename": _tool()}
    # The user previously disabled two tools via the config page.
    mod.config_json_set("enabled_tools", {
        "ida_overview": True, "ida_patch": False, "ida_rename": False,
    })

    h = _make_config_handler(mod)
    mod.IdaMcpHttpRequestHandler._sync_enabled_tools(h)

    assert set(reg.methods) == {"ida_overview"}
    # The disabled tools remain *known* so the page can re-enable them.
    assert set(mod._all_known_tools()) == {"ida_overview", "ida_patch", "ida_rename"}


def test_disabled_tool_imported_after_save_is_filtered_again():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool()}
    mod.config_json_set("enabled_tools", {"ida_overview": True, "ida_rename": False})

    h = _make_config_handler(mod)
    cls = mod.IdaMcpHttpRequestHandler
    cls._sync_enabled_tools(h)
    # The disabled tool is imported later (lazy registration)...
    reg.methods["ida_rename"] = _tool()
    # ...and the next request filters it out again instead of force-enabling it.
    cls._sync_enabled_tools(h)
    assert set(reg.methods) == {"ida_overview"}


def test_newly_registered_tool_defaults_enabled_and_is_persisted():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool(), "ida_rename": _tool()}
    mod.config_json_set("enabled_tools", {"ida_overview": True, "ida_rename": False})

    h = _make_config_handler(mod)
    cls = mod.IdaMcpHttpRequestHandler
    cls._sync_enabled_tools(h)
    # A brand-new tool is enabled by default and persisted so the next save
    # does not wipe it.
    reg.methods["ida_analysis"] = _tool()
    cls._sync_enabled_tools(h)
    assert set(reg.methods) == {"ida_overview", "ida_analysis"}
    assert mod.config_json_get("enabled_tools", {})["ida_analysis"] is True


def test_all_known_tools_includes_post_import_tools():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool()}
    # The old ORIGINAL_TOOLS was frozen at import (empty); _KNOWN_TOOLS must
    # track tools registered later so the page/config POST see the full set.
    h = _make_config_handler(mod)
    mod.IdaMcpHttpRequestHandler._sync_enabled_tools(h)
    reg.methods["ida_graph"] = _tool()
    assert set(mod._all_known_tools()) == {"ida_overview", "ida_graph"}


# ---------------------------------------------------------------------------
# Finding 3: /config POST must not let an empty / truncated / over-limit body
# silently disable every tool
# ---------------------------------------------------------------------------

def test_config_post_empty_body_rejected_without_wiping_tools():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool(), "ida_rename": _tool()}
    mod._KNOWN_TOOLS.update(reg.methods)
    mod.config_json_set("enabled_tools", {"ida_overview": True, "ida_rename": True})

    h = _make_config_handler(mod, body=b"")  # Content-Length: 0, like bare curl
    mod.IdaMcpHttpRequestHandler._handle_config_post(h)

    assert ("error", 400, "Empty form body") in h.sent
    assert set(reg.methods) == {"ida_overview", "ida_rename"}
    assert mod.config_json_get("enabled_tools", {}) == {
        "ida_overview": True, "ida_rename": True,
    }


def test_config_post_over_limit_body_rejected_413():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool()}
    mod._KNOWN_TOOLS.update(reg.methods)

    h = _make_config_handler(mod, body=b"x" * 100, content_length=2_000_000)
    mod.IdaMcpHttpRequestHandler._handle_config_post(h)

    assert any(s[0] == "error" and s[1] == 413 for s in h.sent)
    assert set(reg.methods) == {"ida_overview"}
    assert mod.config_json_get("enabled_tools", {}) == {}


def test_config_post_truncated_body_rejected():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool()}
    mod._KNOWN_TOOLS.update(reg.methods)

    # Client advertises 100 bytes but sends 19.
    h = _make_config_handler(mod, body=b"cors_policy=direct", content_length=100)
    mod.IdaMcpHttpRequestHandler._handle_config_post(h)

    assert ("error", 400, "Truncated request body") in h.sent
    assert set(reg.methods) == {"ida_overview"}
    assert mod.config_json_get("enabled_tools", {}) == {}


def test_config_post_valid_form_applies_selection():
    mod, _ = _load_mcp_http()
    reg = mod.MCP_SERVER.tools
    reg.methods = {"ida_overview": _tool(), "ida_rename": _tool()}
    mod._KNOWN_TOOLS.update(reg.methods)

    body = b"cors_policy=direct&ida_overview=ida_overview"
    h = _make_config_handler(mod, body=body)
    mod.IdaMcpHttpRequestHandler._handle_config_post(h)

    assert ("response", 302) in h.sent
    assert set(reg.methods) == {"ida_overview"}
    persisted = mod.config_json_get("enabled_tools", {})
    assert persisted["ida_overview"] is True
    assert persisted["ida_rename"] is False


# ---------------------------------------------------------------------------
# Finding 2 (rejected): a cross-origin / cross-port page cannot flip CORS to
# unrestricted — _check_origin already requires the server's own port
# ---------------------------------------------------------------------------

def test_origin_check_rejects_cross_port_localhost_origin():
    mod, _ = _load_mcp_http()
    cls = mod.IdaMcpHttpRequestHandler
    h = type("FakeOrigin", (), {})()
    h.server_port = 13337
    h.headers = {"Origin": "http://localhost:8888"}
    h.sent = {}
    h.send_error = lambda code, msg, explain=None: h.sent.update(code=code, msg=msg)

    def _local_endpoints(self):
        return (
            f"127.0.0.1:{self.server_port}",
            f"localhost:{self.server_port}",
            f"[::1]:{self.server_port}",
        )

    h._local_endpoints = types.MethodType(_local_endpoints, h)

    # A page served from another localhost port must be rejected — the origin
    # check requires the origin's port to equal the MCP server's own port.
    assert cls._check_origin(h) is False
    assert h.sent["code"] == 403


def test_mcp_post_rejects_cross_origin_before_dispatch():
    mod, _ = _load_mcp_http()
    cls = mod.IdaMcpHttpRequestHandler
    h = object.__new__(cls)
    h.headers = {"Origin": "http://evil.example"}
    h.mcp_server = mod.MCP_SERVER
    h.path = "/mcp"
    h.sent = []
    h.send_error = lambda code, msg, explain=None: h.sent.append(("error", code, msg))
    h._local_endpoints = lambda: ("127.0.0.1:13337", "localhost:13337", "[::1]:13337")

    cls.do_POST(h)

    assert any(item[0] == "error" and item[1] == 403 for item in h.sent)
    assert not getattr(h, "parent_post_called", False)


def test_mcp_post_without_origin_remains_available_to_direct_clients():
    mod, _ = _load_mcp_http()
    cls = mod.IdaMcpHttpRequestHandler
    h = object.__new__(cls)
    h.headers = {}
    h.mcp_server = mod.MCP_SERVER
    h.path = "/mcp"
    h.parent_post_called = False

    cls.do_POST(h)

    assert h.parent_post_called is True


def test_unrestricted_policy_explicitly_allows_cross_origin_mcp_post():
    mod, _ = _load_mcp_http()
    cls = mod.IdaMcpHttpRequestHandler
    mod.MCP_SERVER.cors_allowed_origins = "*"
    h = object.__new__(cls)
    h.headers = {"Origin": "http://remote.example"}
    h.mcp_server = mod.MCP_SERVER
    h.path = "/mcp"
    h.parent_post_called = False

    cls.do_POST(h)

    assert h.parent_post_called is True
