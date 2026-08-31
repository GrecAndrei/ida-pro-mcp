import html
import json
from http.server import HTTPServer
from typing import TypeVar, cast
from urllib.parse import parse_qs, urlparse

import ida_netnode

from .rpc import MCP_SERVER, MCP_UNSAFE, McpHttpRequestHandler, McpRpcRegistry
from .sync import idaread, idawrite

T = TypeVar("T")


@idaread
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idawrite
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


# D8: cache of the last-seen enabled-tools config, keyed by config_key →
# (len(registry.methods) at compute time, enabled_tools dict). Tools register
# lazily, so ``len(registry.methods)`` is the natural signature: while no new
# tool registers, the persisted config is read once and the conditional write
# (which used to fire on EVERY request until a new tool was persisted — each
# write being an @idawrite that invalidates the shared tool cache) is skipped.
# Cleared on /config POST. Values are snapshots (dict copies) so callers can
# safely mutate their local copy.
_ENABLED_TOOLS_CACHE: dict[str, tuple[int, dict]] = {}


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Filter the registry down to the tools enabled in the persisted config.

    Returns the full pre-filter tool set. Tools the config has never seen
    (registered after the last save) default to enabled and are persisted, so
    the next /config POST does not wipe them. Every tool ever seen is also
    recorded in ``_KNOWN_TOOLS`` so the config page can keep listing (and
    re-enabling) tools that are currently filtered out.
    """
    original_tools = registry.methods.copy()
    _KNOWN_TOOLS.update(original_tools)
    registry_size = len(original_tools)

    cached = _ENABLED_TOOLS_CACHE.get(config_key)
    if cached is not None and cached[0] == registry_size:
        enabled_tools = dict(cached[1])
    else:
        enabled_tools = config_json_get(
            config_key, dict.fromkeys(original_tools, True)
        )
        removed_tools = [name for name in enabled_tools if name not in original_tools]
        if removed_tools:
            for name in removed_tools:
                enabled_tools.pop(name)
        _ENABLED_TOOLS_CACHE[config_key] = (registry_size, dict(enabled_tools))

    new_tools = [name for name in original_tools if name not in enabled_tools]
    if new_tools:
        enabled_tools.update(dict.fromkeys(new_tools, True))
        config_json_set(config_key, enabled_tools)
        _ENABLED_TOOLS_CACHE[config_key] = (registry_size, dict(enabled_tools))

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_CORS_POLICY = "local"

MAX_CONFIG_BODY = 1_048_576

# Every tool this process has ever seen, by name. The live registry
# (MCP_SERVER.tools.methods) holds only *enabled* tools once handle_enabled_tools
# has filtered it, so the config page needs this separate reference to keep
# listing (and re-enabling) tools that are currently disabled. It cannot be an
# import-time snapshot: tool modules register lazily (ida_mcp/tools/__init__.py
# imports on demand), so the registry is still empty when this module loads and
# a filter applied then would be a no-op — see _sync_enabled_tools.
_KNOWN_TOOLS: dict = {}


def _all_known_tools() -> dict:
    """Union of every tool ever registered and the current live registry.

    The config page and /config POST must never operate on the filtered live
    registry alone, or disabled tools would disappear from the page and become
    impossible to re-enable.
    """
    merged = dict(_KNOWN_TOOLS)
    merged.update(MCP_SERVER.tools.methods)
    return merged


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.update_cors_policy()
        self._sync_enabled_tools()
        # Bound how long a single client connection can sit idle, so a hung
        # or slow client cannot block a request thread (and the config body
        # read below) indefinitely.
        try:
            self.connection.settimeout(30)
        except (AttributeError, OSError):
            pass

    def update_cors_policy(self):
        match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
            case "unrestricted":
                self.mcp_server.cors_allowed_origins = "*"
            case "local":
                self.mcp_server.cors_allowed_origins = self.mcp_server.cors_localhost
            case "direct":
                self.mcp_server.cors_allowed_origins = None

    def _sync_enabled_tools(self):
        """Honor the persisted enabled_tools config on the live tool registry.

        Runs on every request (idempotently) instead of at module import: tool
        modules register lazily, so the registry is empty when this module loads
        and an eager filter would be a no-op — every disabled tool would
        reappear after a restart. Re-filtering here keeps the registry
        consistent with the stored config as soon as tools are registered,
        including a previously-disabled tool imported after a save.
        """
        handle_enabled_tools(self.mcp_server.tools, "enabled_tools")

    def do_POST(self):
        """Handles POST requests."""
        path = urlparse(self.path).path
        if path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        elif not self._check_origin():
            # The MCP endpoint can mutate the IDB and the SSE POST endpoint
            # can route tool calls to a live stream. Apply the same CSRF gate
            # to both; otherwise a local browser visit could trigger tools
            # even though the config endpoint is protected.
            return
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        path = urlparse(self.path).path
        if path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
        elif path == "/sse" and not self._check_origin():
            # SSE subscriptions expose a live session endpoint and consume a
            # handler thread. Keep cross-origin pages from opening one unless
            # unrestricted access was explicitly selected.
            return
        else:
            super().do_GET()

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _local_endpoints(self) -> tuple[str, ...]:
        """The only hosts/origins this server accepts: loopback v4, hostname,
        and loopback v6 (``[::1]``), always with the actual server port."""
        port = self.server_port
        return (
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
        )

    def _check_origin(self) -> bool:
        """
        Prevents CSRF and DNS rebinding attacks by ensuring POST requests
        originate from pages served by this server, not external websites.

        A missing Origin header is allowed: browsers always send Origin on
        cross-origin POSTs, so only non-browser clients (curl, MCP, scripts)
        omit it — and they have no CSRF context. IPv6 loopback is accepted so
        localhost resolving to ``[::1]`` keeps working.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        # The configuration page makes unrestricted cross-origin access an
        # explicit opt-in. Keep that choice meaningful while protecting the
        # default local/direct policies from browser CSRF.
        if getattr(getattr(self, "mcp_server", None), "cors_allowed_origins", None) == "*":
            return True
        try:
            parts = urlparse(origin)
        except ValueError:
            parts = None
        if parts is None or parts.scheme != "http" or parts.netloc not in self._local_endpoints():
            self.send_error(403, "Invalid Origin")
            return False
        return True

    def _check_host(self) -> bool:
        """
        Prevents DNS rebinding attacks where an attacker's domain (e.g., evil.com)
        resolves to 127.0.0.1, allowing their page to read localhost resources.
        """
        host = self.headers.get("Host")
        if host not in self._local_endpoints():
            self.send_error(403, "Invalid Host")
            return False
        return True

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)

        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

h2 {
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"],
input[type="radio"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="submit"] {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover {
  opacity: 0.9;
}

.tooltip {
  border-bottom: 1px dotted var(--text);
}
  </style>
  <script defer>
  function setTools(mode) {
    document.querySelectorAll('input[data-tool]').forEach(cb => {
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    });
  }
  </script>
</head>
<body>
<h1>IDA Pro MCP Config</h1>

<form method="post" action="/config">

<h2>API Access</h2>
"""
        cors_options = [
            (
                "unrestricted",
                "⛔ Unrestricted",
                "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
            ),
            (
                "local",
                "🏠 Local apps only",
                "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
            ),
            (
                "direct",
                "🔒 Direct connections only",
                "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
            ),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'
        body += "<br><input type='submit' value='Save'>"

        quick_select = """<p style="font-size: 0.9rem; margin: 0.5rem 0;">
  Select:
  <a href="#" onclick="setTools('all'); return false;">All</a> ·
  <a href="#" onclick="setTools('none'); return false;">None</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">Disable unsafe</a>
</p>"""

        body += "<h2>Enabled Tools</h2>"
        body += quick_select
        for name, func in _all_known_tools().items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += quick_select
        body += "<br><input type='submit' value='Save'>"
        body += "</form></body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        # Parse the form data. Mirror zeromcp do_POST: reject a non-integer
        # Content-Length outright, reject negative values (rfile.read(-1) would
        # read the whole stream), and reject over-limit bodies outright — a
        # truncated body would be parsed as a valid submission and silently
        # disable every unchecked tool.
        try:
            length = int(self.headers.get("content-length", "0"))
        except (TypeError, ValueError):
            self.send_error(400, "Invalid Content-Length")
            return
        if length < 0:
            self.send_error(400, "Invalid Content-Length")
            return
        if length > MAX_CONFIG_BODY:
            self.send_error(413, f"Payload Too Large: exceeds {MAX_CONFIG_BODY} bytes")
            return
        body = self.rfile.read(length)
        if len(body) != length:
            # The client advertised more bytes than it sent; the form is
            # truncated and must not be applied as a partial config.
            self.send_error(400, "Truncated request body")
            return
        postvars = parse_qs(body.decode("utf-8"))

        # A genuinely empty body (bare curl POST, health-check probe, etc.) is
        # never a real form submission — the config page always includes the
        # cors_policy radio group. Treat it as a client error instead of
        # interpreting it as "disable every tool".
        if not postvars:
            self.send_error(400, "Empty form body")
            return

        # Update CORS policy
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        config_json_set("cors_policy", cors_policy)
        self.update_cors_policy()

        # Update the server's tools, over the full known tool set (including
        # any tools registered after this module was imported).
        all_tools = _all_known_tools()
        enabled_tools = {name: name in postvars for name in all_tools}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in all_tools.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)
        # The config just changed under the enabled-tools cache: drop it so the
        # next request re-reads (and re-applies) the new tool set.
        _ENABLED_TOOLS_CACHE.clear()

        # Redirect back to the config page
        self.send_response(302)
        self.send_header("Location", "/config.html")
        self.end_headers()
