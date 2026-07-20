"""End-to-end coverage for the public ``ida_*`` MCP surface.

This suite deliberately talks JSON-RPC over the real stdio server and lets the
host launch a real ``idat`` process.  It is opt-in because it needs a licensed
IDA installation and can take a few minutes:

    IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
      pytest -q --timeout=600 tests/integration/test_agent_surface_live.py

When no binary is supplied, a small ELF fixture with known symbols, callers,
imports, strings, and mutation targets is compiled in pytest's temporary
directory.  Nothing is written to the checkout or a user IDB.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_FLAG = "IDA_MCP_LIVE_TEST"
pytestmark = [
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get(LIVE_FLAG) != "1",
        reason=f"set {LIVE_FLAG}=1 to run tests against a licensed IDA installation",
    ),
    pytest.mark.timeout(600),
]


def _fixture_source() -> str:
    strings = ",\n    ".join(f'"AGENT_SURFACE_STRING_{index:03d}"' for index in range(96))
    return f"""
#include <stdio.h>

volatile int fixture_side_effect = 0;
static const char *fixture_strings[] = {{
    {strings}
}};

__attribute__((noinline)) int fixture_leaf(int value) {{
    fixture_side_effect += value;
    return value + 7;
}}

__attribute__((noinline)) int fixture_helper(int value) {{
    return fixture_leaf(value) * 3;
}}

__attribute__((noinline)) int fixture_mutation_target(int value) {{
    return fixture_helper(value) + fixture_strings[value % 96][0];
}}

__attribute__((noinline)) int fixture_entry(int value) {{
    puts("IDA_MCP_AGENT_SURFACE_MARKER");
    return fixture_mutation_target(value);
}}

int main(void) {{
    return fixture_entry(5) == 0;
}}
"""


def _build_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    supplied = os.environ.get("IDA_MCP_LIVE_BINARY")
    if supplied:
        fixture = Path(supplied).expanduser().resolve()
        if not fixture.is_file():
            pytest.fail(f"IDA_MCP_LIVE_BINARY does not exist: {fixture}")
        return fixture

    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        pytest.fail("No C compiler found. Set IDA_MCP_LIVE_BINARY to an existing test binary.")
    fixture_dir = tmp_path_factory.mktemp("ida-agent-fixture")
    source = fixture_dir / "agent_surface_fixture.c"
    binary = fixture_dir / "agent_surface_fixture"
    source.write_text(_fixture_source(), encoding="utf-8")
    result = subprocess.run(
        [compiler, "-O0", "-g", "-fno-inline", "-fno-pie", "-no-pie", "-o", str(binary), str(source)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        pytest.fail(f"Could not build live IDA fixture:\n{result.stderr or result.stdout}")
    return binary


def _ida_dir() -> Path:
    idat_override = os.environ.get("IDA_MCP_LIVE_IDAT")
    if idat_override:
        idat = Path(idat_override).expanduser().resolve()
        if idat.is_file() and os.access(idat, os.X_OK):
            return idat.parent
        pytest.fail(f"IDA_MCP_LIVE_IDAT is not executable: {idat}")
    for variable in ("IDA_MCP_LIVE_IDADIR", "IDADIR", "IDA_DIR"):
        value = os.environ.get(variable)
        if not value:
            continue
        candidate = Path(value).expanduser().resolve()
        if candidate.is_file():
            candidate = candidate.parent
        if (candidate / "idat").is_file() or (candidate / "idat64").is_file():
            return candidate
        pytest.fail(f"{variable} does not contain idat/idat64: {candidate}")
    for name in ("idat", "idat64"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve().parent
    pytest.fail("IDA was requested but not found. Set IDA_MCP_LIVE_IDADIR or IDA_MCP_LIVE_IDAT.")


class LiveMCPClient:
    """Small stdio client used only at the process boundary in live tests."""

    def __init__(
        self,
        *,
        ida_dir: Path,
        runtime_dir: Path,
        response_mode: str,
        timeout: int,
        embeddings_enabled: bool = True,
    ) -> None:
        self.ida_dir = ida_dir
        self.runtime_dir = runtime_dir
        self.response_mode = response_mode
        self.timeout = timeout
        self.embeddings_enabled = embeddings_enabled
        self.process: subprocess.Popen[str] | None = None
        self._responses: queue.Queue[str] = queue.Queue()
        self._stderr: queue.Queue[str] = queue.Queue()
        self._next_id = 0

    def start(self) -> None:
        env = os.environ.copy()
        env.update(
            {
                "IDADIR": str(self.ida_dir),
                "IDA_MCP_TOOL_SURFACE": "agent",
                "IDA_MCP_RESPONSE_MODE": self.response_mode,
                "IDA_MCP_COMPACT_CHAR_BUDGET": "500",
                "IDA_MCP_CACHE_DIR": str(self.runtime_dir),
                "IDA_MCP_RUNTIME_DIR": str(self.runtime_dir),
                "IDA_MCP_DISABLE_RATE_LIMIT": "1",
                "IDA_MCP_DISABLE_STUCK_DETECTION": "1",
                "IDA_MCP_POLICY_MODE": "permissive",
                "IDA_MCP_EMBED_DISABLED": "0" if self.embeddings_enabled else "1",
                "IDA_MCP_STRUCTURED_CONTENT": "1",
                "IDA_MCP_STARTUP_TIMEOUT": str(self.timeout),
            }
        )
        source_root = str(REPO_ROOT / "src")
        env["PYTHONPATH"] = source_root + os.pathsep + env.get("PYTHONPATH", "")
        self.process = subprocess.Popen(
            [sys.executable, "-u", "-m", "ida_pro_mcp.host.server"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        assert self.process.stdout is not None and self.process.stderr is not None
        threading.Thread(target=self._drain, args=(self.process.stdout, self._responses), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.process.stderr, self._stderr), daemon=True).start()
        self.request("initialize", {"capabilities": {}, "clientInfo": {"name": "live-agent-surface", "version": "1"}})

    @staticmethod
    def _drain(stream, destination: queue.Queue[str]) -> None:
        try:
            for line in stream:
                destination.put(line)
        finally:
            with contextlib.suppress(Exception):
                stream.close()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.process or self.process.poll() is not None or not self.process.stdin:
            raise AssertionError(self._failure_message("MCP host is not running"))
        self._next_id += 1
        request_id = self._next_id
        request: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                response = json.loads(self._responses.get(timeout=min(1, max(0.01, deadline - time.monotonic()))))
            except queue.Empty:
                continue
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("id") == request_id:
                if "error" in response:
                    raise AssertionError(self._failure_message(f"MCP protocol error: {response['error']}"))
                return response
        raise AssertionError(self._failure_message(f"Timed out waiting for {method}"))

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.request("tools/call", {"name": name, "arguments": arguments})
        result = response.get("result")
        if not isinstance(result, dict):
            raise AssertionError(f"{name} returned no MCP result: {response}")
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if not isinstance(content, list) or not content or not isinstance(content[0], dict):
            raise AssertionError(f"{name} returned no text content: {result}")
        try:
            return json.loads(str(content[0].get("text") or ""))
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{name} returned non-JSON content: {content[0]!r}") from exc

    def stop(self) -> None:
        if not self.process:
            return
        with contextlib.suppress(Exception):
            if self.process.stdin:
                self.process.stdin.close()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

    def _failure_message(self, prefix: str) -> str:
        lines: list[str] = []
        while not self._stderr.empty() and len(lines) < 50:
            lines.append(self._stderr.get_nowait().rstrip())
        suffix = "\n".join(lines[-20:])
        return f"{prefix}\nHost stderr:\n{suffix}" if suffix else prefix


def _assert_ok(payload: dict[str, Any], operation: str) -> dict[str, Any]:
    if payload.get("error") is True or payload.get("ok") is False:
        pytest.fail(f"{operation} failed:\n{json.dumps(payload, indent=2, default=str)}")
    return payload


@dataclass
class LiveContext:
    client: LiveMCPClient
    binary: Path


@pytest.fixture(scope="module")
def live_context(tmp_path_factory: pytest.TempPathFactory) -> LiveContext:
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-agent-runtime")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="full",
        timeout=int(os.environ.get("IDA_MCP_LIVE_CALL_TIMEOUT", "180")),
    )
    client.start()
    try:
        _assert_ok(client.call("ida_open_binary", {"binary_path": str(binary)}), "ida_open_binary")
        yield LiveContext(client=client, binary=binary)
    finally:
        with contextlib.suppress(Exception):
            _assert_ok(client.call("ida_close_session", {}), "ida_close_session")
        client.stop()


def test_public_catalog_and_help_are_live_contracts(live_context: LiveContext):
    response = live_context.client.request("tools/list")
    tools = response["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert response["result"]["surface"] == "agent"
    assert len(names) == 23
    assert all(name.startswith("ida_") for name in names)
    assert "search" not in names
    help_payload = _assert_ok(live_context.client.call("ida_help", {"topic": "ida_decompile"}), "ida_help")
    assert help_payload["operation"]["inputSchema"]["required"] == ["address"]


def test_live_session_discovery_and_index_surface(live_context: LiveContext):
    client = live_context.client
    for name, arguments in (
        ("ida_session_state", {}),
        ("ida_session_status", {}),
        ("ida_overview", {}),
        ("ida_list_functions", {"query": "fixture_", "limit": 50}),
        ("ida_list_strings", {"query": "IDA_MCP_AGENT_SURFACE_MARKER", "limit": 50}),
        ("ida_list_imports", {"limit": 100}),
        ("ida_find", {"query": "fixture_entry", "limit": 20}),
    ):
        payload = _assert_ok(client.call(name, arguments), name)
        if name == "ida_find":
            assert "fixture_entry" in json.dumps(payload).lower()

    index_payload = _assert_ok(client.call("ida_index_functions", {}), "ida_index_functions")
    assert index_payload.get("indexed", 0) > 0, f"ida_index_functions did not build an index: {index_payload}"
    semantic_payload = client.call(
        "ida_semantic_search", {"query": "function that prints the marker string", "mode": "quick", "limit": 10}
    )
    assert semantic_payload.get("error") is not True, (
        f"ida_semantic_search did not observe the index built by ida_index_functions. "
        f"index={index_payload}; search={semantic_payload}"
    )


def test_live_full_decomp_index_is_resumable_and_retrieves_behavior(live_context: LiveContext):
    if os.environ.get("IDA_MCP_LIVE_BINARY"):
        pytest.skip("deterministic semantic assertion requires the generated fixture")

    client = live_context.client
    cursor = None
    passes: list[dict[str, Any]] = []
    for _ in range(64):
        arguments: dict[str, Any] = {"quality": "full", "limit": 8}
        if cursor:
            arguments["cursor"] = cursor
        payload = _assert_ok(client.call("ida_index_functions", arguments), "ida_index_functions full")
        passes.append(payload)
        if payload.get("complete"):
            break
        cursor = payload.get("next_cursor")
        assert cursor, f"incomplete full index did not return a cursor: {payload}"
    else:
        pytest.fail(f"full index did not complete after {len(passes)} passes")

    assert sum(int(row.get("input", {}).get("pseudocode_chars", 0)) for row in passes) > 0
    final_counts = passes[-1].get("index", {}).get("quality_counts", {})
    assert int(final_counts.get("full", 0)) > 0, passes[-1]
    assert passes[-1].get("fully_indexed") is True, passes[-1]

    behavior_queries = {
        "function that prints the fixed agent surface marker": "fixture_entry",
        "function that updates a global side effect and adds seven": "fixture_leaf",
        "function that multiplies a child function result by three": "fixture_helper",
        "function that indexes a 96-entry string table using modulo": "fixture_mutation_target",
    }
    for query, expected_name in behavior_queries.items():
        search = _assert_ok(
            client.call(
                "ida_semantic_search",
                {"query": query, "mode": "quick", "limit": 5},
            ),
            "ida_semantic_search after full index",
        )
        assert expected_name in json.dumps(search).lower(), {"query": query, "search": search}


def test_live_code_navigation_uses_fixture_symbols(live_context: LiveContext):
    client = live_context.client
    calls = (
        ("ida_xrefs_to", {"address": "fixture_leaf"}),
        ("ida_callers", {"address": "fixture_leaf"}),
        ("ida_callees", {"address": "fixture_entry"}),
    )
    decompile = _assert_ok(client.call("ida_decompile", {"address": "fixture_entry"}), "ida_decompile")
    disassembly = _assert_ok(
        client.call("ida_disassemble", {"address": "fixture_entry", "style": "classic", "limit": 80}),
        "ida_disassemble",
    )
    for payload in (decompile, disassembly):
        serialized = json.dumps(payload)
        assert '"structure"' in serialized, payload
        assert '"cfg"' in serialized, payload
    for name, arguments in calls:
        payload = _assert_ok(client.call(name, arguments), name)
        assert payload


def test_live_mutations_and_findings_are_observable(live_context: LiveContext):
    client = live_context.client
    renamed = "fixture_mutation_target_renamed"
    _assert_ok(
        client.call("ida_rename", {"address": "fixture_mutation_target", "name": renamed, "risk_ack": True}),
        "ida_rename",
    )
    _assert_ok(
        client.call("ida_comment", {"address": renamed, "comment": "live agent-surface test", "risk_ack": True}),
        "ida_comment",
    )
    find_payload = _assert_ok(client.call("ida_find", {"query": renamed, "limit": 10}), "ida_find after rename")
    assert renamed in json.dumps(find_payload)

    title = "live agent-surface finding"
    _assert_ok(
        client.call(
            "ida_write_finding",
            {
                "title": title,
                "content": "The live fixture exposes a caller/callee chain for public MCP validation.",
                "address": "fixture_entry",
                "category": "test",
                "confidence": 1.0,
                "tags": ["live", "agent-surface"],
            },
        ),
        "ida_write_finding",
    )
    findings = _assert_ok(client.call("ida_list_findings", {"limit": 50}), "ida_list_findings")
    assert title in json.dumps(findings)
    _assert_ok(client.call("ida_next_target", {"limit": 10}), "ida_next_target")


def test_live_protocol_rejects_public_contract_edge_cases(live_context: LiveContext):
    client = live_context.client
    cases = (
        ("ida_open_binary", {}),
        ("ida_find", {"pattern": "fixture_entry"}),
        ("ida_decompile", {"address": 123}),
        ("ida_semantic_search", {"query": "fixture", "mode": "invalid"}),
    )
    for name, arguments in cases:
        payload = client.call(name, arguments)
        assert payload.get("error") is True, f"{name} accepted invalid arguments: {payload}"
        assert payload.get("code") == "INVALID_ARGS"


def test_live_index_fails_honestly_when_embeddings_are_disabled(
    tmp_path_factory: pytest.TempPathFactory,
    live_context: LiveContext,
):
    runtime_dir = tmp_path_factory.mktemp("ida-agent-no-embeddings")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="full",
        timeout=int(os.environ.get("IDA_MCP_LIVE_CALL_TIMEOUT", "180")),
        embeddings_enabled=False,
    )
    client.start()
    try:
        _assert_ok(client.call("ida_open_binary", {"binary_path": str(live_context.binary)}), "ida_open_binary (no embeddings)")
        payload = client.call("ida_index_functions", {})
        assert payload.get("error") is True, f"disabled embeddings produced a fake index: {payload}"
        assert payload.get("code") == "IDA_ERROR"
        assert "No embeddings were created" in str(payload.get("message"))
    finally:
        with contextlib.suppress(Exception):
            _assert_ok(client.call("ida_close_session", {}), "ida_close_session (no embeddings)")
        client.stop()


def test_live_continuation_reads_a_real_truncated_response(tmp_path_factory: pytest.TempPathFactory, live_context: LiveContext):
    runtime_dir = tmp_path_factory.mktemp("ida-agent-truncation")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="compact",
        timeout=int(os.environ.get("IDA_MCP_LIVE_CALL_TIMEOUT", "180")),
    )
    client.start()
    try:
        _assert_ok(client.call("ida_open_binary", {"binary_path": str(live_context.binary)}), "ida_open_binary (truncation)")
        payload = _assert_ok(client.call("ida_list_strings", {"query": "AGENT_SURFACE_STRING_", "limit": 200}), "ida_list_strings (truncation)")
        continuation = payload.get("_continue")
        assert isinstance(continuation, dict) and continuation.get("token"), f"expected a continuation token, got {payload}"
        resumed = _assert_ok(client.call("ida_continue", {"token": continuation["token"]}), "ida_continue")
        assert resumed.get("count", 0) > 0
    finally:
        with contextlib.suppress(Exception):
            _assert_ok(client.call("ida_close_session", {}), "ida_close_session (truncation)")
        client.stop()
