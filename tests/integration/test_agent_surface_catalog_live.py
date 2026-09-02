"""Catalog smoke: every public ``ida_*`` operation must answer correctly live.

One test per operation in ``AGENT_OPERATIONS``, driven against a real stdio
server + real IDA session. The catalog example arguments are used as-is
(validated against the op schema), with the fixture-relative substitutions
below (the catalog examples use synthetic addresses like 0x401000 that do
not exist in the test fixture).

Expectations are per-op:

- ``ok`` — the operation must succeed (``error`` falsy, ``ok`` true).
- ``graceful`` — the operation may fail with a *coded* error (never a
  protocol error, never an exception); the failure class is pinned where the
  environment makes it deterministic (e.g. GOVERNANCE_BLOCKED for the
  hard-blocked patch_bytes, TRUNCATION_TOKEN_INVALID for a bogus token).

Stateful operations that need embeddings or a background job
(ida_index_functions, ida_semantic_search, ida_function_families,
ida_index_status, ida_cancel_index) run with their graceful contract here;
the deep behavior suite (test_agent_surface_behavior_live.py) and the
indexing suite (test_agent_surface_live.py) cover the happy paths.

Opt-in, like the other live suites:

    IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
      pytest -q tests/integration/test_agent_surface_catalog_live.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))
from ida_pro_mcp.host.agent_operations import AGENT_OPERATIONS  # noqa: E402
from ida_pro_mcp.host.server.server_client_state import mint_agent_ticket  # noqa: E402
from tests.integration.test_agent_surface_live import (  # noqa: E402
    DEFAULT_LIVE_PYTEST_TIMEOUT,
    LiveMCPClient,
    _fixture_source,
    _ida_dir,
    live_call_timeout,
    seed_function_addrs,
)

LIVE_FLAG = "IDA_MCP_LIVE_TEST"
pytestmark = [
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get(LIVE_FLAG) != "1",
        reason=f"set {LIVE_FLAG}=1 to run tests against a licensed IDA installation",
    ),
    pytest.mark.timeout(DEFAULT_LIVE_PYTEST_TIMEOUT),
]

# Operations whose catalog example is stateful/environmental and may answer
# with a coded error (never a protocol error). Each entry pins the expected
# code where the environment makes it deterministic (code=None = any code).
GRACEFUL: dict[str, str | None] = {
    "ida_open_background": "FEATURE_DISABLED",   # opt-in flag unset by default
    "ida_semantic_search": "NOT_FOUND",          # no embedding index yet
    "ida_function_families": "NO_RESULTS",       # no embedding index yet
    "ida_index_status": None,                    # no background job
    "ida_cancel_index": "NOT_FOUND",             # unknown task id
    "ida_continue": "TRUNCATION_TOKEN_INVALID",  # bogus token
    "ida_patch_bytes": "GOVERNANCE_BLOCKED",     # destructive hard block
    "ida_update_finding": "NOT_FOUND",           # unknown entry id
    "ida_get_type": "TYPE_ERROR",                # SOME_STRUCT absent
    "ida_rename_local": None,                    # v3 likely absent
    "ida_til_delete": "TYPE_ERROR",              # OBSOLETE_STRUCT absent
    "ida_til_import": "FILE_NOT_FOUND",          # /tmp/session_types.h absent
    "ida_change_function": None,                 # mapped end may be invalid
    "ida_create_strlit": None,                   # depends on prior undefine
    "ida_enum_member_add": "TYPE_ERROR",         # status_t not declared here
    "ida_enum_member_rename": "TYPE_ERROR",
    "ida_enum_member_revalue": "TYPE_ERROR",
    "ida_apply_sig": "NOT_FOUND",                 # catalog remaps to a missing stem
    "ida_r2_status": None,                       # r2 sidecar may be absent
    "ida_r2_bininfo": None,
    "ida_r2_load_hints": None,
    "ida_r2_disassemble_hypothesis": None,
    "ida_r2_vxrefs": None,
}

# Operations NOT exercised by the catalog smoke: they are lifecycle entry
# points handled by the module fixture (ida_open_binary), teardown
# (ida_close_session), or heavy/background work covered by the other live
# suites (ida_index_functions is exercised end-to-end in
# test_agent_surface_live.py).
EXCLUDED = {
    "ida_open_binary",   # module fixture opens the binary
    "ida_close_session", # module teardown closes it
    "ida_index_functions",
}

# Catalog example values replaced with fixture-derived addresses.
_ADDR_TOKENS = ("0x401000", "0x401234", "0x401a20", "0x1234", "0x1000",
                "0x601020", "0x40000000")
_CATALOG_SSO_SECRET = "catalog-live-sso-secret"
_CATALOG_SSO_EXPIRY = 4_102_444_800.0  # 2100-01-01; independent of wall clock


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
    fixture_dir = tmp_path_factory.mktemp("ida-catalog-fixture")
    source = fixture_dir / "catalog_fixture.c"
    binary = fixture_dir / "catalog_fixture"
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


class CatalogContext:
    """Per-run fixture state: client, session id, and resolved addresses."""

    def __init__(self, client: LiveMCPClient, session_id: str | None):
        self.client = client
        self.session_id = session_id or ""
        self.main_addr: str = "main"
        self.sub_addr: str | None = None
        self.functions: dict[str, str] = {}

    def call(self, name: str, arguments: dict):
        return self.client.call(name, arguments)


@pytest.fixture(scope="module")
def catalog_ctx(tmp_path_factory: pytest.TempPathFactory):
    """Open one live session over the deterministic fixture for the catalog run."""
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-catalog-runtime")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="full",
        timeout=live_call_timeout(),
    )
    client.start()
    try:
        opened = client.call("ida_open_binary", {"binary_path": str(binary)})
        if not isinstance(opened, dict) or opened.get("error") is True:
            raise AssertionError(f"ida_open_binary failed: {opened}")
        ctx = CatalogContext(client, opened.get("session_id"))
        ctx.functions = seed_function_addrs(client)
        if "main" in ctx.functions:
            ctx.main_addr = ctx.functions["main"]
        for name, addr in ctx.functions.items():
            if name not in ("main", ".init_proc", "_start", ".puts") and ctx.sub_addr is None:
                ctx.sub_addr = addr
                break
        yield ctx
    finally:
        with __import__("contextlib").suppress(Exception):
            client.call("ida_close_session", {"risk_ack": True})
        client.stop()


def _map_arguments(op_name: str, args: dict, ctx: CatalogContext) -> dict:
    """Substitute synthetic catalog addresses with fixture addresses."""
    out = dict(args)
    addr = ctx.main_addr
    for key, value in list(out.items()):
        if not isinstance(value, str):
            continue
        if value in _ADDR_TOKENS:
            out[key] = addr
        elif value in ("main", "recv"):
            out[key] = "main"
    # Fixture-sensitive parameters
    if op_name == "ida_add_segment":
        # The catalog example's 0x40000000 range collides with the loaded
        # image; use a free address window (as the segments docs advise).
        out["start"] = "0x60000000"
        out["end"] = "0x60001000"
    if op_name == "ida_set_segment_attrs":
        out["address"] = "0x60000000"  # the segment added by ida_add_segment
    if op_name in ("ida_fw_detect_vector_table", "ida_fw_detect_mmio",
                   "ida_fw_rtos_scan", "ida_fw_detect_load_base"):
        out["start"] = "0x0"
        out["end"] = "0x400"
    if op_name == "ida_fw_carve":
        out["start"] = "0x100"
        out["end"] = "0x200"
    if op_name == "ida_r2_disassemble_hypothesis":
        out["address"] = "0x0"  # file offset, not a virtual address
    if op_name == "ida_r2_vxrefs":
        out["value"] = ctx.main_addr
    if op_name == "ida_calc_deref":
        out["address"] = ctx.main_addr
    if op_name == "ida_calc_chain":
        out["address"] = ctx.main_addr
    if op_name == "ida_calc_resolve":
        out["address"] = ctx.main_addr
    if op_name == "ida_search_data_value":
        out["start"] = "0x400000"
        out["end"] = "0x405000"
    if op_name == "ida_auto_wait":
        out["timeout_ms"] = 1000
    if op_name == "ida_apply_sig":
        out["name"] = "__ida_mcp_missing_sig__"
    if op_name in ("ida_session_state", "ida_session_status"):
        out["idb"] = ctx.session_id
    if op_name == "ida_session_get":
        out["session_id"] = ctx.session_id
    if op_name == "ida_session_switch":
        out["session_id"] = ctx.session_id
        out["reopen"] = False
    if op_name == "ida_sso_activate":
        # The catalog example intentionally omits the optional secret.  A
        # real login immediately afterward needs a deterministic secret that
        # the test can use to mint a valid HMAC ticket.
        out["secret"] = _CATALOG_SSO_SECRET
    if op_name == "ida_agent_login":
        out["ticket"] = mint_agent_ticket(
            _CATALOG_SSO_SECRET,
            str(out.get("name") or "rev_a"),
            exp=_CATALOG_SSO_EXPIRY,
        )
    if op_name == "ida_export_findings":
        out.pop("path", None)  # inline export; /tmp escapes the allowed root
    # The catalog's struct-member examples are independent snippets; string
    # them into one lifecycle so every op asserts a real mutation:
    # add crc → rename crc→checksum → retype checksum → delete checksum.
    if op_name in ("ida_struct_member_set_type", "ida_struct_member_del"):
        out["member_name"] = "checksum"
    # Destructive cluster targets a disposable function, never main: the
    # smoke's later reads (apply_type, mark_dangerous, callgraph...) need
    # main intact. undefine → create_strlit → create_data → make_code run in
    # this order on the same disposable function.
    if op_name in ("ida_undefine", "ida_create_strlit", "ida_create_data", "ida_make_code"):
        out["address"] = ctx.sub_addr or ctx.main_addr
        if op_name == "ida_create_strlit":
            out["size"] = 16
        elif op_name == "ida_create_data":
            out["type"] = "dword"
            out["count"] = 4
        elif op_name == "ida_undefine":
            out["size"] = 8
    if op_name == "ida_change_function":
        out["address"] = ctx.main_addr
        try:
            out["end"] = hex(int(ctx.main_addr, 16) + 0x80)
        except ValueError:
            out["end"] = ctx.main_addr
    if op_name == "ida_rename_local":
        out["address"] = ctx.main_addr
    if op_name == "ida_mark_dangerous":
        out["address"] = ctx.main_addr
    if op_name == "ida_apply_type":
        out["address"] = ctx.main_addr
    return out


def _catalog_order() -> list[str]:
    """Catalog order with two clusters moved for session coherence:

    - the destructive data-layout cluster (undefine/create_strlit/create_data/
      make_code) moves to the end so main stays intact for every earlier op;
    - the struct-member cluster is re-ordered into its lifecycle sequence
      (add → rename → set_type → del) so each op mutates what the previous
      one produced instead of tripping on the other's example.
    """
    names = [op.name for op in AGENT_OPERATIONS if op.name not in EXCLUDED]
    layout = ("ida_undefine", "ida_create_strlit", "ida_create_data", "ida_make_code")
    moved_layout = [n for n in layout if n in names]
    members = ("ida_struct_member_add", "ida_struct_member_rename",
               "ida_struct_member_set_type", "ida_struct_member_del")
    moved_members = [n for n in members if n in names]
    rest = [n for n in names if n not in set(moved_layout) | set(moved_members)]
    return rest + moved_members + moved_layout


@pytest.mark.parametrize("op_name", _catalog_order())
def test_catalog_operation_live(catalog_ctx: CatalogContext, op_name: str):
    """Every public operation answers correctly with its catalog example."""
    for op in AGENT_OPERATIONS:
        if op.name == op_name:
            break
    else:  # pragma: no cover - parametrize source is the catalog itself
        pytest.fail(f"{op_name} missing from AGENT_OPERATIONS")
    args = _map_arguments(op_name, dict(op.example or {}), catalog_ctx)
    payload = catalog_ctx.call(op_name, args)

    assert isinstance(payload, dict), (
        f"{op_name} returned a non-object response: {payload!r}"
    )
    assert payload.get("error") is not True or isinstance(payload.get("code"), str), (
        f"{op_name} failed without an error code: {payload}"
    )
    expected = GRACEFUL.get(op_name, "ok")
    if expected == "ok":
        assert payload.get("error") is not True, f"{op_name}: {payload}"
        assert payload.get("ok") is True, f"{op_name}: {payload}"
    else:
        # graceful: a coded error is acceptable, and a success is always fine
        assert payload.get("error") is not True or payload.get("ok") is not True, (
            f"{op_name}: {payload}"
        )
        if expected and payload.get("error") is True:
            assert payload.get("code") == expected, f"{op_name}: {payload}"
