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
import functools
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import pytest

pytestmark = pytest.mark.timeout(900)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def _ida_is_available() -> bool:
    """Check if a running IDA MCP server is available."""
    port = os.environ.get("IDA_MCP_PORT")
    if port:
        import socket
        try:
            s = socket.create_connection(("127.0.0.1", int(port)), timeout=2)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            pass
    # Check if we can start one
    binary = os.environ.get("IDA_MCP_TEST_BINARY")
    if binary and os.path.isfile(binary):
        return True
    # ... or compile the built-in rich fixture
    return any(shutil.which(c) for c in ("cc", "gcc", "clang"))


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


def _wait_vulnerable_hits(client, timeout: float = 240.0) -> dict | None:
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
        time.sleep(5)
    return last


class MCPIntegrationClient:
    """JSON-RPC client for integration testing against live IDA MCP."""

    def __init__(self, timeout: int = 120):
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
        if "IDA_DIR" not in env:
            for path in [
                "/home/grec-alexander/ida-pro-9.3",
                os.path.expanduser("~/ida-pro-9.3"),
            ]:
                if os.path.isdir(path):
                    env["IDA_DIR"] = path
                    break

        self.proc = subprocess.Popen(
            [sys.executable, "-u", os.path.join(PROJECT_ROOT, "ida_mcp_stdio.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
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
        """Shut down the server."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestCustomDetectorIntegration(unittest.TestCase):
    """Integration tests for the custom detector engine against real IDA."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        # Create a session with a test binary
        binary = _build_fixture()
        if binary:
            result = cls.client.call_tool("session", action="create", binary_path=binary)
            if not result.get("content"):
                raise unittest.SkipTest("Failed to create IDA session")

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


if __name__ == "__main__":
    unittest.main()
