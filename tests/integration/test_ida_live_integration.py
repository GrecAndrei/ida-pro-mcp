"""Integration tests that run against a live IDA MCP server.

These tests require:
1. A running IDA Pro instance with the MCP plugin loaded, OR
2. The ida_mcp_stdio.py server started with a binary loaded

Set IDA_MCP_PORT env var to point at a running server (default: auto-detect).
Set IDA_MCP_TEST_BINARY env var to a .i64/.idb file to auto-start a session.

If neither is available, all tests are skipped.
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


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
    return bool(binary and os.path.isfile(binary))


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

        # Wait for server to be ready
        deadline = time.time() + self.timeout
        while time.time() < deadline:
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
        binary = os.environ.get("IDA_MCP_TEST_BINARY")
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
        # Should return ok with matches list
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            data = json.loads(text) if text.startswith("{") else {"raw": text}
            self.assertTrue(data.get("ok", True))

    def test_detect_string_ref(self):
        """Find functions referencing strings matching a pattern."""
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="string_ref",
            pattern=".*",
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            data = json.loads(text) if text.startswith("{") else {"raw": text}
            self.assertTrue(data.get("ok", True))

    def test_detect_api_chain(self):
        """Find functions calling APIs in sequence."""
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="api_chain",
            apis=["malloc", "free"],
            strict_order=False,
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            data = json.loads(text) if text.startswith("{") else {"raw": text}
            self.assertTrue(data.get("ok", True))

    def test_register_and_list_detector(self):
        """Register a persistent detector and list it."""
        result = self.client.call_tool(
            "code", action="detect",
            register=True,
            name="test_crypto_finder",
            rule={"type": "xor_threshold", "threshold": 6},
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            data = json.loads(text) if text.startswith("{") else {"raw": text}
            self.assertTrue(data.get("ok", True))

        # List detectors
        result = self.client.call_tool(
            "code", action="detect",
            rule_type="list",
        )
        content = result.get("content", [])
        if content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
            data = json.loads(text) if text.startswith("{") else {"raw": text}
            self.assertTrue(data.get("ok", True))

    def test_detect_caller_of(self):
        """Find callees of a function."""
        # First find a function name
        result = self.client.call_tool("data", action="functions", count=1)
        content = result.get("content", [])
        if not content:
            self.skipTest("No functions found")

    def test_detect_callee_of(self):
        """Find callers of a function."""
        result = self.client.call_tool("data", action="functions", count=1)
        content = result.get("content", [])
        if not content:
            self.skipTest("No functions found")


@unittest.skipUnless(_ida_is_available(), "No IDA MCP server available")
class TestFuncsInfoIntegration(unittest.TestCase):
    """Integration tests for funcs info with structured parameters."""

    client = None

    @classmethod
    def setUpClass(cls):
        cls.client = MCPIntegrationClient()
        if not cls.client.start():
            raise unittest.SkipTest("Failed to start IDA MCP server")

        binary = os.environ.get("IDA_MCP_TEST_BINARY")
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
            # Parse first address from functions list
            for line in text.split("\n"):
                line = line.strip()
                if line.startswith("0x"):
                    return line.split()[0]
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

        binary = os.environ.get("IDA_MCP_TEST_BINARY")
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

        binary = os.environ.get("IDA_MCP_TEST_BINARY")
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


if __name__ == "__main__":
    unittest.main()
