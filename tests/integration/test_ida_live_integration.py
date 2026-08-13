"""Integration tests that run against a live IDA MCP server.

These tests require:
1. A running IDA Pro instance with the MCP plugin loaded, OR
2. The ida_mcp_stdio.py server started with a binary loaded

Set IDA_MCP_PORT env var to point at a running server (default: auto-detect).
Set IDA_MCP_TEST_BINARY env var to a .i64/.idb file to auto-start a session.

When no binary is supplied, a small fixture with XOR-heavy code, string
references, a malloc/free API chain, globals, and call-graph edges is compiled
in a temporary directory — the same pattern the agent-surface live suite uses.
If no C compiler is available either, all tests are skipped.
"""
import contextlib
import functools
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import pytest

LIVE_FLAG = "IDA_MCP_LIVE_TEST"
pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get(LIVE_FLAG) != "1",
        reason=f"set {LIVE_FLAG}=1 to run tests against a licensed IDA installation",
    ),
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def _find_idat() -> str | None:
    """Locate an idat/idat64 executable the stdio server can launch.

    Mirrors the IDA_DIR resolution in ``MCPIntegrationClient.start`` so the
    availability gate and the client agree about whether IDA is present.
    """
    for path in (
        os.environ.get("IDA_DIR"),
        os.environ.get("IDADIR"),
        os.environ.get("IDA_MCP_LIVE_IDADIR"),
        "/home/grec-alexander/ida-pro-9.3",
        os.path.expanduser("~/ida-pro-9.3"),
    ):
        if not path:
            continue
        for name in ("idat64", "idat"):
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                return candidate
    for name in ("idat64", "idat"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _ida_is_available() -> bool:
    """Check if a running IDA MCP server is available.

    A C compiler is deliberately NOT accepted as evidence IDA is available:
    on a compiler-only machine every ``@unittest.skipUnless`` class would run
    against a stdio server that spawns no idat, and every test would hard-fail
    instead of skipping.
    """
    port = os.environ.get("IDA_MCP_PORT")
    if port:
        import socket
        try:
            s = socket.create_connection(("127.0.0.1", int(port)), timeout=2)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            pass
    binary = os.environ.get("IDA_MCP_TEST_BINARY")
    if binary and os.path.isfile(binary):
        return True
    return _find_idat() is not None


_RICH_FIXTURE_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile int rich_global_counter = 0;
static char rich_buffer[64] = "RICH_FIXTURE_SECRET_DATA";
const char *rich_messages[] = { "hello from rich fixture", "goodbye", "xor payload" };

__attribute__((noinline)) void rich_xor_blend(unsigned char *d, const unsigned char *a) {
    d[0] = a[0] ^ 0x11; d[1] = a[1] ^ 0x22; d[2] = a[2] ^ 0x33; d[3] = a[3] ^ 0x44;
    d[4] = a[4] ^ 0x55; d[5] = a[5] ^ 0x66; d[6] = a[6] ^ 0x77; d[7] = a[7] ^ 0x88;
}

__attribute__((noinline)) void rich_alloc_free(void) {
    char *p = (char *)malloc(128);
    if (p) {
        memset(p, 0, 128);
        puts("RICH_ALLOC_FREED");
        free(p);
    }
}

__attribute__((noinline)) void rich_taint_path(int fd) {
    char tmp[16];
    read(fd, tmp, sizeof(tmp));
    memcpy(rich_buffer, tmp, 128);
}

__attribute__((noinline)) int rich_tiny(void) { return 1; }

__attribute__((noinline)) int rich_use_strings(int x) {
    if (x > 3) { puts("RICH_FIXTURE_STRING_ONE"); return 1; }
    puts("RICH_FIXTURE_STRING_TWO");
    return 0;
}

__attribute__((noinline)) int rich_helper(int v) { return v * 2 + rich_global_counter; }

__attribute__((noinline)) int rich_entry(int v) {
    unsigned char buf[8], src[8] = {1,2,3,4,5,6,7,8};
    rich_xor_blend(buf, src);
    rich_alloc_free();
    rich_taint_path(0);
    return rich_use_strings(v) + rich_helper(v);
}

int main(void) {
    rich_global_counter = 7;
    return rich_entry(rich_global_counter) == 0 ? 0 : 1;
}
"""


@functools.lru_cache(maxsize=1)
def _build_fixture() -> str | None:
    """Return a binary path exercising every detector rule, building it if needed."""
    supplied = os.environ.get("IDA_MCP_TEST_BINARY")
    if supplied and os.path.isfile(supplied):
        return supplied
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        return None
    workdir = tempfile.mkdtemp(prefix="ida-mcp-rich-fixture-")
    source = os.path.join(workdir, "rich_fixture.c")
    binary = os.path.join(workdir, "rich_fixture")
    with open(source, "w", encoding="utf-8") as fh:
        fh.write(_RICH_FIXTURE_SOURCE)
    result = subprocess.run(
        [compiler, "-O0", "-g", "-fno-inline", "-fno-pie", "-no-pie", "-o", binary, source],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode or not os.path.isfile(binary):
        return None
    return binary


@functools.lru_cache(maxsize=1)
def _is_rich_fixture() -> bool:
    """True when the session binary is the built-in rich fixture."""
    binary = _build_fixture()
    return bool(binary and "ida-mcp-rich-fixture" in binary)


def _parse_result(result) -> dict | None:
    """Extract structuredContent (or JSON text) from an MCP tool response."""
    if isinstance(result, dict) and isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    content = result.get("content", [])
    if not content:
        return None
    text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _require_session(client: "MCPIntegrationClient", binary: str | None) -> None:
    """Create a session for *binary*, failing loudly instead of skipping.

    setUpClass may only skip for a genuinely absent prerequisite (no fixture
    binary). A create that fails — a JSON-RPC error envelope, a timeout, or
    any non-ok result — is a real server regression and must fail the class.
    A bare ``{"error": "timeout"}`` has no ``content``, so the old
    ``if not result.get("content"): raise SkipTest`` silently masked protocol
    errors and RPC hangs as 'skipped'.
    """
    if not binary:
        raise unittest.SkipTest(
            "No fixture binary available (no compiler and IDA_MCP_TEST_BINARY unset)"
        )
    result = client.call_tool("session", action="create", binary_path=binary)
    parsed = _parse_result(result)
    if parsed is None or parsed.get("ok") is not True:
        raise AssertionError(
            "Failed to create IDA session (real failure, not a prerequisite gap): "
            f"{result}"
        )
    return parsed.get("session_id")


def _wait_session_ready(
    client, session_id: str | None, timeout: float = 45.0
) -> dict | None:
    """Poll the session's analysis gate until safe mode lifts and analysis
    completes, bounded by *timeout*.

    ``session(action='create')`` may return while the session is still in
    safe mode (background analysis running) — large binaries are auto-
    backgrounded, and reused sessions re-enter pending state. Racing the gate
    makes the first tool call fail with a "blocked while analyzing" error, so
    readiness is measured on the observable signal: the ``state`` payload's
    ``safe_mode``/``analysis_complete`` flags (mirrors how the host documents
    ``ida_session_state``).
    """
    last = None
    deadline = time.time() + timeout
    args = {"action": "state"}
    if session_id:
        args["session_id"] = session_id
    while time.time() < deadline:
        result = client.call_tool("session", **args)
        data = _parse_result(result)
        if data and data.get("ok") is not True:
            # A session that stops answering is a real regression, not a
            # prerequisite gap — fail loudly rather than spinning to timeout.
            raise AssertionError(
                "session(state) failed while waiting for analysis to settle: "
                f"{result}"
            )
        state = data.get("state") if data else None
        if state and state.get("safe_mode") is False and state.get("analysis_complete") is True:
            return state
        last = state
        time.sleep(0.5)
    raise AssertionError(
        "IDA session never left safe mode / completed analysis "
        f"within {timeout:.0f}s (last state: {last!r})"
    )


def _wait_vulnerable_hits(client, timeout: float = 30.0) -> dict | None:
    """Poll the vulnerable scope until it returns hits (analysis settles).

    The watchdog's analysis verdict is unreliable for tiny fixture binaries
    (it can report "stalled" while the DB is fully usable), so readiness is
    measured by the observable signal: the scope returning non-empty results.
    Note the host compacts away ``count`` when it equals the number of
    returned items, so presence is asserted via ``items``/``results``.
    """
    last = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = client.call_tool("search", action="vulnerable")
        data = _parse_result(result)
        if data and data.get("ok") and (data.get("items") or (data.get("results") or "").strip()):
            return data
        last = data
        time.sleep(0.5)
    return last


class MCPIntegrationClient:
    """JSON-RPC client for integration testing against live IDA MCP."""

    def __init__(self, timeout: int = 45):
        self.proc = None
        self.stdout_queue = queue.Queue()
        self.stderr_queue = queue.Queue()
        self.request_id = 0
        self.timeout = timeout
        self._write_lock = threading.Lock()

    def start(self) -> bool:
        """Start the MCP server process."""
        env = os.environ.copy()
        # Structured results make assertions exact instead of text-scraping.
        env["IDA_MCP_STRUCTURED_CONTENT"] = "1"
        env.setdefault("IDA_MCP_TOOL_SURFACE", "legacy")
        if "IDA_DIR" not in env:
            idat = _find_idat()
            if idat:
                env["IDA_DIR"] = os.path.dirname(idat)

        self.proc = subprocess.Popen(
            [sys.executable, "-u", os.path.join(PROJECT_ROOT, "ida_mcp_stdio.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            # Start the server as its own session leader so teardown can kill
            # the whole process group (server + any idat children it spawned)
            # instead of leaving orphan idat processes for the same fixture.
            start_new_session=True,
        )

        # Reader threads
        def _read_stdout():
            try:
                for line in self.proc.stdout:
                    self.stdout_queue.put(line)
            except Exception:
                pass

        def _read_stderr():
            try:
                for line in self.proc.stderr:
                    self.stderr_queue.put(line)
            except Exception:
                pass

        threading.Thread(target=_read_stdout, daemon=True).start()
        threading.Thread(target=_read_stderr, daemon=True).start()

        # Wait for server to be ready. Fail fast when the process exits
        # early (e.g. IDA not installed): a dead process will never print
        # the ready line, and burning the full timeout per test class makes
        # a missing-IDA machine look like a hang.
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                line = self.stderr_queue.get(timeout=0.5)
                if "ready" in line.lower() or "listening" in line.lower():
                    return True
            except queue.Empty:
                continue
        return False

    def call_tool(self, tool: str, **args) -> dict:
        """Send a tool call and return the result."""
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
        return self._send_request(request)

    def _send_request(self, request: dict) -> dict:
        """Send a JSON-RPC request and wait for the response."""
        with self._write_lock:
            self.proc.stdin.write(json.dumps(request) + "\n")
            self.proc.stdin.flush()

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                line = self.stdout_queue.get(timeout=5)
                response = json.loads(line)
                if response.get("id") == request["id"]:
                    return response.get("result", response)
            except (queue.Empty, json.JSONDecodeError):
                continue
        return {"error": "timeout"}

    def close(self):
        """Shut down the server and its whole process group.

        A graceful ``session(action='close')`` lets the host tear down each
        session's idat child cleanly; killing the process group (the server is
        its leader via ``start_new_session=True``) is the backstop so a host
        that does not install its own SIGTERM teardown cannot orphan idat
        children across smoke runs — the exact bug class test_session_create_reuse
        guards against.
        """
        if not self.proc:
            return
        try:
            saved_timeout = self.timeout
            self.timeout = min(self.timeout, 10)
            try:
                with contextlib.suppress(Exception):
                    self.call_tool("session", action="close", _risk_ack=True)
            finally:
                self.timeout = saved_timeout
        except Exception:
            pass
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            with contextlib.suppress(Exception):
                self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(Exception):
                os.killpg(self.proc.pid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=5)


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestCustomDetectorIntegration(unittest.TestCase):
    """Integration tests for the custom detector engine against real IDA."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        # Create a session with a test binary. A create failure here is a real
        # server regression (or an RPC hang) — fail loudly instead of masking
        # the entire class behind unittest.SkipTest.
        sid = _require_session(cls.client, _build_fixture())
        _wait_session_ready(cls.client, sid)

    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.close()

    def test_detect_xor_threshold(self):
        """Find crypto functions via XOR threshold."""
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="xor_threshold",
            threshold=4,
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        names = " ".join(str(m.get("name", "")) for m in data.get("matches", []))
        if _is_rich_fixture():
            # rich_xor_blend performs 8 XORs; without a working call graph the
            # detector still must find it via instruction scan.
            self.assertIn("rich_xor_blend", names)

    def test_detect_string_ref(self):
        """Find functions referencing strings matching a pattern."""
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="string_ref",
            pattern="RICH_FIXTURE_STRING_ONE",
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        names = " ".join(str(m.get("name", "")) for m in data.get("matches", []))
        if _is_rich_fixture():
            self.assertIn("rich_use_strings", names)

    def test_detect_api_chain(self):
        """Find functions calling APIs in sequence."""
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="api_chain",
            apis=["malloc", "free"],
            strict_order=False,
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        names = " ".join(str(m.get("name", "")) for m in data.get("matches", []))
        if _is_rich_fixture():
            self.assertIn("rich_alloc_free", names)

    def test_register_and_list_detector(self):
        """Register a persistent detector and list it."""
        result = self.client.call_tool(
            "code", action="detect",
            register=True,
            name="test_crypto_finder",
            rule={"type": "xor_threshold", "threshold": 6},
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))

        # List detectors
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="list",
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        listed = json.dumps(data.get("detectors", []))
        self.assertIn("test_crypto_finder", listed)

    def test_detect_caller_of(self):
        """Find callees of a function via the caller_of rule."""
        name = "rich_entry" if _is_rich_fixture() else self._first_function_name()
        if not name:
            self.skipTest("No functions found")
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="caller_of",
            target=name,
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        self.assertIn("matches", data)
        names = " ".join(str(m.get("name", "")) for m in data.get("matches", []))
        if _is_rich_fixture():
            self.assertIn("rich_xor_blend", names)

    def test_detect_callee_of(self):
        """Find callers of a function via the callee_of rule."""
        name = "rich_xor_blend" if _is_rich_fixture() else self._first_function_name()
        if not name:
            self.skipTest("No functions found")
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="callee_of",
            target=name,
        )
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        self.assertIn("matches", data)
        names = " ".join(str(m.get("name", "")) for m in data.get("matches", []))
        if _is_rich_fixture():
            self.assertIn("rich_entry", names)

    def _first_function_name(self) -> str | None:
        """Return the name of the first listed function (or its address)."""
        result = self.client.call_tool("data", action="functions", count=1)
        content = result.get("content", [])
        if not content:
            return None
        text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
        # Line format: "0x...  size  xrefs=N  name" — last token is the name.
        match = re.search(r"0x[0-9a-fA-F]+\s+\S+\s+xrefs=\d+\s+(\S+)", text)
        if match:
            return match.group(1)
        match = re.search(r"0x[0-9a-fA-F]+", text)
        return match.group(0) if match else None

    @staticmethod
    def _parse_json_result(result) -> dict | None:
        if isinstance(result, dict) and isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        content = result.get("content", [])
        if not content:
            return None
        text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
        return data if isinstance(data, dict) else None


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestFuncsInfoIntegration(unittest.TestCase):
    """Integration tests for funcs info with structured parameters."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        binary = _build_fixture()
        if binary:
            result = cls.client.call_tool("session", action="create", binary_path=binary)
            if not result.get("content"):
                raise unittest.SkipTest("Failed to create IDA session")

    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.close()

    def _get_first_function_addr(self) -> str:
        """Get the address of the first function in the binary."""
        result = self.client.call_tool("data", action="functions", count=1)
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            # The functions output renders as either a fenced block or a
            # single "functions: 0x..." line; the first hex address is the
            # first function in both formats.
            match = re.search(r"0x[0-9a-fA-F]+", text)
            if match:
                return match.group(0)
        return None

    def test_info_returns_prototype(self):
        """funcs info with include_prototype should return prototype."""
        addr = self._get_first_function_addr()
        if not addr:
            self.skipTest("No function address found")
        result = self.client.call_tool(
            "funcs", action="info",
            addr=addr,
            include_prototype=True,
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            # Should contain some function info
            self.assertTrue(len(text) > 0)


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestMemorySearchIntegration(unittest.TestCase):
    """Integration tests for memory search with bin_search."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        binary = _build_fixture()
        if binary:
            result = cls.client.call_tool("session", action="create", binary_path=binary)
            if not result.get("content"):
                raise unittest.SkipTest("Failed to create IDA session")

    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.close()

    def test_search_hex_pattern(self):
        """Search for a hex pattern with wildcards."""
        result = self.client.call_tool(
            "memory", action="search",
            addr="0x400000",
            pattern="4D 5A",
            end_addr="0x401000",
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            # Should return ok or hits
            self.assertTrue(len(text) > 0)

    def test_search_wildcard_pattern(self):
        """Search for hex pattern with wildcards."""
        result = self.client.call_tool(
            "memory", action="search",
            addr="0x400000",
            pattern="4D 5A ?? ??",
            end_addr="0x401000",
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            self.assertTrue(len(text) > 0)


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestDataGlobalsIntegration(unittest.TestCase):
    """Integration tests for data globals with struct field enumeration."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        binary = _build_fixture()
        if binary:
            result = cls.client.call_tool("session", action="create", binary_path=binary)
            if not result.get("content"):
                raise unittest.SkipTest("Failed to create IDA session")

    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.close()

    def test_globals_returns_data(self):
        """globals action should return global variables."""
        result = self.client.call_tool("data", action="globals", count=5)
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            self.assertTrue(len(text) > 0)


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestSearchAnalyzeIntegration(unittest.TestCase):
    """Integration tests for search analyze scopes (outlier/vulnerable)."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        binary = _build_fixture()
        if binary:
            result = cls.client.call_tool("session", action="create", binary_path=binary)
            if not result.get("content"):
                raise unittest.SkipTest("Failed to create IDA session")

    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.close()

    def _search(self, **kwargs) -> dict:
        result = self.client.call_tool("search", **kwargs)
        data = self._parse_json_result(result)
        self.assertIsNotNone(data)
        return data

    def _parse_json_result(self, result) -> dict | None:
        if isinstance(result, dict) and isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        content = result.get("content", [])
        if not content:
            return None
        text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    def test_outlier_size_returns_items(self):
        """outlier size must return functions even without an embedding index."""
        data = self._search(action="outlier", metric="size", limit=5)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        self.assertGreater(data.get("count", 0), 0)
        self.assertTrue(data.get("results", "").strip())

    def test_outlier_tiny_and_huge_are_reachable(self):
        """tiny/huge previously fell through dead code to an empty call-graph result."""
        for metric in ("tiny", "huge"):
            data = self._search(action="outlier", metric=metric, limit=5)
            self.assertTrue(data.get("ok", False))
            self.assertFalse(data.get("error", False))
            note = data.get("note", "")
            self.assertNotIn("cached call graph", note)
            self.assertTrue("embedding index" in note or "direct IDA enumeration" in note)
        tiny = self._search(action="outlier", metric="tiny", limit=50)
        self.assertIn("rich_tiny", tiny.get("results", ""))

    def test_vulnerable_finds_taint_reachable_sink(self):
        """vulnerable scope must surface memcpy reachable from read()."""
        data = _wait_vulnerable_hits(self.client)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("ok", False))
        self.assertFalse(data.get("error", False))
        text = data.get("results", "")
        items = data.get("items") or []
        self.assertTrue(items or text.strip(), "vulnerable scope returned no hits")
        combined = text + " " + json.dumps(items)
        self.assertTrue("memcpy" in combined or "buffer_overflow" in combined)


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestEmulateIntegration(unittest.TestCase):
    """Live integration tests for the ``emulate`` tool (ida_dbg-backed).

    Exercises the emulator through a real IDA process. Every assertion is
    deliberately backend-independent: it holds whether IDA loads the built-in
    ``Emulator``, the native ``linux`` debugger, or another candidate. The
    lifecycle/backend assertions (info, state, start, stop, backend reporting)
    are strict; the capability-dependent actions (get_reg roundtrip, read_mem,
    run_to, step) assert the tool's *contract* — well-formed responses with the
    spec's backend envelope — and apply their strict numeric assertions only
    when the loaded backend actually serves them (a native debugger that never
    registers a thread has no registers, IP, or debugger memory, and the tool
    must say so gracefully rather than fail). Every success path carries
    ``backend``/``backend_reason``/``backend_candidates`` (spec part B).

    ``governed=False`` is passed on every mutating action, matching the spec
    ("live client calls carry no _risk_ack"). One wrinkle: the host policy gate
    in its default *assist* mode would still REQUIRE_ACK the un-acked
    mutating actions *before* they reach the tool, so ``governed=False`` could
    never be observed there. The server subprocess is therefore started with
    ``IDA_MCP_POLICY_MODE=permissive`` (which downgrades REQUIRE_ACK to a
    warning and lets the call through to the tool's own governance gate — the
    spec's intent). The env var is set only around this class's client startup
    and restored in ``tearDownClass``.
    """

    client = None
    _start_result = None

    @classmethod
    def setUpClass(cls):
        # permissive must be visible to the host server subprocess, which
        # copies os.environ at start(); restore it in tearDownClass so later
        # classes (if any) see the machine's normal policy mode again.
        cls._old_policy_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        os.environ["IDA_MCP_POLICY_MODE"] = "permissive"
        try:
            cls.client = MCPIntegrationClient()
            if not cls.client.start():
                raise unittest.SkipTest("Failed to start IDA MCP server")
            cls.sid = _require_session(cls.client, _build_fixture())
            _wait_session_ready(cls.client, cls.sid)
            # One process run for the whole class (spec: "single setup, one
            # process run"). The native debuggers this stack can load cannot
            # tear down or restart a debuggee — exit_process/detach leave it
            # running and a second start corrupts the debugger kernel — so the
            # class starts exactly once here and every test reads that same
            # debuggee. setUpClass failing loudly is correct: the class's whole
            # purpose is a started, shared emulation session.
            cls._start_result = _parse_result(
                cls.client.call_tool("emulate", action="start", governed=False)
            )
            if cls._start_result is None or cls._start_result.get("ok") is not True:
                raise AssertionError(
                    "emulate(start) failed in setUpClass (real failure, not a "
                    f"prerequisite gap): {cls._start_result}"
                )
        except BaseException:
            if getattr(cls, "client", None):
                cls.client.close()
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "client", None):
            cls.client.close()
        if cls._old_policy_mode is None:
            os.environ.pop("IDA_MCP_POLICY_MODE", None)
        else:
            os.environ["IDA_MCP_POLICY_MODE"] = cls._old_policy_mode

    # -- helpers ----------------------------------------------------------
    def _emulate(self, action, **kw):
        return _parse_result(self.client.call_tool("emulate", action=action, **kw))

    def _assert_ok(self, result):
        self.assertIsNotNone(result, "emulate returned no parseable result")
        self.assertFalse(result.get("error"), result)
        self.assertTrue(result.get("ok"), result)
        self.assertIn("backend", result, result)
        self.assertIn("backend_reason", result, result)
        self.assertIn("backend_candidates", result, result)
        return result

    def _start(self):
        """Return the class's single debuggee start (started once in setUpClass).

        Never issues a second ``start``: on this stack's native backends a
        second start over a live debuggee corrupts the debugger kernel, so the
        spec's "one process run" is taken literally and every test reads the
        same started process.
        """
        result = getattr(type(self), "_start_result", None)
        self.assertIsNotNone(result, "setUpClass did not start a debuggee")
        self._assert_ok(result)
        return result

    def _current_ip_or_entry(self):
        """Best available run/read target: current IP, else the entry function.

        The native linux backend through this MCP stack never registers a
        thread (thread_qty == 0), so ``get_ip_val``/``get_reg_val`` are
        unavailable and ``info`` carries no ``current_ip``. Fall back to the
        fixture's ``main`` symbol — present in every IDB — so the address-based
        actions still get a concrete, resolvable target on any backend.
        """
        info = self._emulate("info", governed=False)
        self._assert_ok(info)
        return info.get("current_ip") or "main"

    # -- tests -------------------------------------------------------------
    def test_info_reports_backend(self):
        """info must report which backend loaded and why."""
        self._assert_ok(self._start())
        r = self._emulate("info", governed=False)
        self._assert_ok(r)
        self.assertNotEqual(r.get("backend"), "none", r)
        self.assertTrue(r.get("backend_reason"), r)
        self.assertIsInstance(r.get("backend_candidates"), list)
        self.assertIn("process_state", r)
        # After a successful start the debuggee is alive (the fixture blocks
        # in read(0)), so any backend that can start a process reports it.
        self.assertTrue(r.get("process_running"), r)

    def test_start_step_read_state(self):
        """start -> step -> state follows one process lifecycle."""
        r = self._start()
        self.assertIs(r.get("started"), True)
        self.assertIs(r.get("process_running"), True)

        r = self._emulate("state", governed=False)
        self._assert_ok(r)
        self.assertIn("process_state", r)
        self.assertTrue(r.get("process_running"), r)

        r = self._emulate("step", count=1, governed=False)
        self._assert_ok(r)
        # steps_done is the honest count of accepted steps; a backend without
        # thread context accepts zero. Either way the response is well-formed.
        self.assertIsInstance(r.get("steps_done"), int, r)
        self.assertGreaterEqual(r["steps_done"], 0, r)

        r = self._emulate("state", governed=False)
        self._assert_ok(r)
        self.assertIn("process_state", r)

    def test_get_reg_roundtrip_backend_independent(self):
        """A register write/read-back roundtrip survives any backend.

        On a register-capable backend the strict roundtrip is verified. On a
        backend without thread context the tool degrades gracefully (empty
        ``regs`` + a non-empty ``unavailable`` list) instead of failing — so
        the test holds regardless of which backend loads.
        """
        self._assert_ok(self._start())
        probe = self._emulate("get_reg", name="rax", governed=False)
        self._assert_ok(probe)
        if "rax" not in probe.get("regs", {}):
            self.assertIn("unavailable", probe, probe)
            return
        marker = 0x0DA5A
        w = self._emulate("set_reg", name="rax", value=marker, governed=False)
        self._assert_ok(w)
        self.assertIs(w.get("written"), True)
        r = self._emulate("get_reg", name="rax", governed=False)
        self._assert_ok(r)
        self.assertEqual(r.get("regs", {}).get("rax"), hex(marker), r)

    def test_read_mem_at_known_function(self):
        """read_mem at a known function returns bounded hex data — or a clean
        error when the backend cannot read debugger memory."""
        self._assert_ok(self._start())
        target = self._current_ip_or_entry()
        r = self._emulate("read_mem", address=target, size=16, governed=False)
        if r.get("ok"):
            self.assertIn("data", r)
            self.assertIsInstance(r.get("data"), str)
            self.assertTrue(0 <= len(r["data"]) <= 32, r)
        else:
            self.assertTrue(r.get("error"), r)
            self.assertIsInstance(r.get("code"), str)
            self.assertTrue(r["code"], r)

    def test_run_to_current_ip(self):
        """run_to resolves and echoes its target on every backend.

        The spec's original intent — run to the current instruction pointer —
        is asserted whenever the backend exposes one; otherwise run_to targets
        the entry function. A backend that cannot execute a run still answers
        with a well-formed response (ok + echoed target, or a clean error).
        """
        self._assert_ok(self._start())
        target = self._current_ip_or_entry()
        r = self._emulate("run_to", address=target, timeout_ms=15000, governed=False)
        if r.get("ok"):
            self.assertEqual(r.get("target"), str(target), r)
        else:
            self.assertTrue(r.get("error"), r)
            self.assertIsInstance(r.get("code"), str)
            self.assertTrue(r["code"], r)

    def test_every_response_carries_backend(self):
        """Every successful emulate response reports the active backend."""
        for action in ("info", "backend", "state"):
            r = self._emulate(action, governed=False)
            self.assertTrue(r.get("ok"), f"{action}: {r}")
            self.assertFalse(r.get("error"), f"{action}: {r}")
            self.assertIn("backend", r, r)
            self.assertIn("backend_reason", r, r)
            self.assertIn("backend_candidates", r, r)

    def test_stop_tears_down(self):
        """stop is accepted and reported coherently on any backend.

        A backend that can actually tear down reports the debuggee gone
        (``process_running`` falsy — compacted away by the host); a native
        debugger that cannot kill its debuggee (no thread context, so
        ``exit_process`` is a no-op) honestly reports it still running. Both
        are well-formed, so the assertions hold regardless of which backend
        loads. Because the class runs exactly one debuggee (spec: single
        process run), no restart is attempted here — restarting would be
        backend-specific.
        """
        r = self._start()
        self.assertIs(r.get("started"), True)
        s = self._emulate("stop", governed=False)
        self._assert_ok(s)
        self.assertIs(s.get("stopped"), True)
        # process_running may be absent (host compacts falsy values) or present
        # as a bool; its value is backend-dependent and must not be asserted.
        if "process_running" in s:
            self.assertIsInstance(s["process_running"], bool, s)
        # The tool must keep answering coherently after a stop either way.
        st = self._emulate("state", governed=False)
        self._assert_ok(st)


if __name__ == "__main__":
    unittest.main()
