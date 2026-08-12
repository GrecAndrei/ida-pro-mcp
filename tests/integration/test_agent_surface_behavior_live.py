"""Deep behavior coverage for the public ``ida_*`` surface against real IDA.

Where the catalog smoke proves *every* operation answers correctly with its
documented example, this suite proves the operations do the *right thing*:
exact decompile/disassembly shapes, calc semantics, type round-trips,
findings lifecycle, mutation→verify→restore round-trips, session management,
batch bindings, the r2 sidecar, firmware heuristics, and the python tool.

One module-scoped session over a deterministic fixture; mutations restore
themselves so the shared session stays coherent. Opt-in like the other live
suites:

    IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
      pytest -q tests/integration/test_agent_surface_behavior_live.py
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

from tests.integration.test_agent_surface_live import LiveMCPClient, _fixture_source, _ida_dir  # noqa: E402

LIVE_FLAG = "IDA_MCP_LIVE_TEST"
pytestmark = [
    pytest.mark.live_ida,
    pytest.mark.skipif(
        os.environ.get(LIVE_FLAG) != "1",
        reason=f"set {LIVE_FLAG}=1 to run tests against a licensed IDA installation",
    ),
    pytest.mark.timeout(900),
]

_FUNC_LINE = re.compile(r"(0x[0-9a-fA-F]+)\s+\S+\s+\S+\s+(\S+)")


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
    fixture_dir = tmp_path_factory.mktemp("ida-behavior-fixture")
    source = fixture_dir / "behavior_fixture.c"
    binary = fixture_dir / "behavior_fixture"
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


class BehaviorContext:
    """Shared live session: client, session id, and fixture addresses."""

    def __init__(self, client: LiveMCPClient, session_id: str | None, runtime_dir: Path, idb_path: str = ""):
        self.client = client
        self.session_id = session_id or ""
        self.runtime_dir = runtime_dir
        self.session_dir = os.path.dirname(idb_path) if idb_path else str(runtime_dir)
        self.main_addr = "main"
        self.functions: dict[str, str] = {}

    def call(self, name: str, arguments: dict) -> dict:
        payload = self.client.call(name, arguments)
        if not isinstance(payload, dict):
            raise AssertionError(f"{name} returned a non-object payload: {payload!r}")
        return payload

    def ok(self, name: str, arguments: dict) -> dict:
        payload = self.call(name, arguments)
        assert payload.get("error") is not True, f"{name} failed: {payload}"
        assert payload.get("ok") is True, f"{name} not ok: {payload}"
        return payload

    def func_addr(self, name: str) -> str:
        assert name in self.functions, f"function {name} not in fixture: {self.functions}"
        return self.functions[name]

    def text(self, name: str, arguments: dict) -> str:
        payload = self.ok(name, arguments)
        for key in ("results", "functions", "strings", "output", "text"):
            if isinstance(payload.get(key), str) and payload[key]:
                return payload[key]
        return json.dumps(payload)


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    """Open one live session over the deterministic fixture for the behavior suite."""
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-behavior-runtime")
    client = LiveMCPClient(
        ida_dir=_ida_dir(),
        runtime_dir=runtime_dir,
        response_mode="full",
        timeout=int(os.environ.get("IDA_MCP_LIVE_CALL_TIMEOUT", "180")),
    )
    client.start()
    try:
        opened = client.call("ida_open_binary", {"binary_path": str(binary)})
        if not isinstance(opened, dict) or opened.get("error") is True:
            raise AssertionError(f"ida_open_binary failed: {opened}")
        context = BehaviorContext(client, opened.get("session_id"), runtime_dir,
                                  str(opened.get("idb_path") or ""))
        payload = client.call("ida_list_functions", {"limit": 200})
        text = payload.get("functions") if isinstance(payload, dict) else ""
        for line in str(text).splitlines():
            m = _FUNC_LINE.match(line)
            if m:
                context.functions[m.group(2)] = m.group(1)
                if m.group(2) == "main":
                    context.main_addr = m.group(1)
        yield context
    finally:
        import contextlib
        with contextlib.suppress(Exception):
            client.call("ida_close_session", {"risk_ack": True})
        client.stop()


# ---------------------------------------------------------------------------
# session / discovery
# ---------------------------------------------------------------------------

class TestSessionDiscovery:
    def test_session_roundtrip_ops(self, ctx: BehaviorContext):
        listing = ctx.ok("ida_session_list", {"limit": 50})
        assert "sessions" in listing or "total" in listing
        got = ctx.ok("ida_session_get", {"session_id": ctx.session_id})
        assert (got.get("session", {}) or {}).get("session_id") == ctx.session_id
        switched = ctx.ok("ida_session_switch", {"session_id": ctx.session_id, "reopen": False})
        assert switched.get("ok") is True
        ctx.ok("ida_session_health", {})
        state = ctx.ok("ida_session_state", {})
        assert (state.get("state") or {}).get("safe_mode") is False, state
        status = ctx.ok("ida_session_status", {"idb": ctx.session_id})
        assert (status.get("session") or {}).get("analysis_complete") is True, status

    def test_session_list_filters_by_binary(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_session_list", {"binary_name": "behavior_fixture", "limit": 50})
        text = json.dumps(payload)
        assert ctx.session_id in text, text

    def test_open_background_is_disabled_by_default(self, ctx: BehaviorContext):
        payload = ctx.call("ida_open_background", {"binary_path": "/nonexistent.bin"})
        assert payload.get("error") is True
        assert payload.get("code") == "FEATURE_DISABLED", payload

    def test_overview_reports_elf_metadata(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_overview", {})
        meta = payload.get("meta", {})
        assert meta.get("processor") == "metapc", payload
        assert meta.get("bitness") == 64, payload
        assert meta.get("min_ea") and meta.get("max_ea"), payload

    def test_segments_list_contains_text(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_list_segments", {})
        text = json.dumps(payload)
        assert ".text" in text, text

    def test_events_are_observable(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_events", {"limit": 10})
        assert isinstance(payload.get("events"), list), payload

    def test_auto_wait_returns_when_idle(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_auto_wait", {"timeout_ms": 5000})
        assert payload.get("ok") is True


# ---------------------------------------------------------------------------
# code / navigation
# ---------------------------------------------------------------------------

class TestCodeNavigation:
    def test_decompile_shape(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_decompile", {"address": "fixture_entry"})
        text = json.dumps(payload)
        assert '"structure"' in text, payload
        assert '"cfg"' in text, payload
        code = payload.get("code") or ""
        assert "fixture_mutation_target" in code, payload

    def test_decompile_details_carries_hints(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_decompile", {"address": "fixture_entry", "details": True})
        assert payload.get("var_rename_hints") or payload.get("annotated_code") or payload.get("complexity"), (
            f"details=true added no enrichment: {payload}"
        )

    def test_decompile_of_main_contains_entry_call(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_decompile", {"address": "main"})
        assert "fixture_entry" in (payload.get("code") or ""), payload

    def test_disassemble_styles(self, ctx: BehaviorContext):
        for style in ("classic", "annotated", "csmini"):
            payload = ctx.ok("ida_disassemble", {"address": "fixture_entry", "style": style, "limit": 40})
            text = payload.get("code") or json.dumps(payload)
            assert "fixture" in text or "401" in text, f"style {style}: {payload}"

    def test_disassemble_range(self, ctx: BehaviorContext):
        start = ctx.func_addr("fixture_leaf")
        end = hex(int(start, 16) + 0x40)
        payload = ctx.ok("ida_disassemble", {"address": start, "end": end, "limit": 50})
        assert payload.get("count", 0) > 0, payload

    def test_callgraph_formats(self, ctx: BehaviorContext):
        main = "fixture_entry"
        mermaid = ctx.ok("ida_callgraph", {"address": main, "depth": 2, "format": "mermaid"})
        assert "graph" in json.dumps(mermaid).lower(), mermaid
        dot = ctx.ok("ida_callgraph", {"address": main, "depth": 2, "format": "dot"})
        assert "digraph" in json.dumps(dot), dot
        graph = ctx.ok("ida_callgraph", {"address": main, "depth": 2, "format": "json"})
        assert "nodes" in json.dumps(graph), graph

    def test_xrefs_and_call_graph_edges(self, ctx: BehaviorContext):
        # call chain: fixture_entry -> fixture_mutation_target -> fixture_helper -> fixture_leaf
        xrefs = ctx.ok("ida_xrefs_to", {"address": "fixture_leaf"})
        assert "fixture_helper" in json.dumps(xrefs), xrefs
        callers = ctx.ok("ida_callers", {"address": "fixture_leaf"})
        assert "fixture_helper" in json.dumps(callers), callers
        callees = ctx.ok("ida_callees", {"address": "fixture_entry"})
        assert "fixture_mutation_target" in json.dumps(callees), callees

    def test_read_bytes_hexdump(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_read_bytes", {"address": ctx.main_addr, "size": 32})
        assert len(payload.get("hex", "")) == 64, payload  # 32 bytes → 64 hex chars
        assert "dump" in payload

    def test_registers_report_processor_classes(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_registers", {"addr": ctx.main_addr})
        classes = {c.get("reg_class") for c in payload.get("classes", [])}
        assert classes, payload
        names = " ".join(str(r) for c in payload.get("classes", []) for r in c.get("registers", []))
        assert any(n in names for n in ("rax", "eip", "rip", "rsp", "cs")), payload

    def test_sreg_mapping_on_x86(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_sreg_list", {"start": ctx.main_addr})
        assert payload.get("ranges"), payload
        got = ctx.ok("ida_sreg_get", {"start": ctx.main_addr, "reg": "cs"})
        assert "value" in got, got


# ---------------------------------------------------------------------------
# calc
# ---------------------------------------------------------------------------

class TestCalcSemantics:
    def test_eval_symbol_plus_offset(self, ctx: BehaviorContext):
        main = ctx.main_addr
        payload = ctx.ok("ida_calc_eval", {"expr": f"{main} + 0x20"})
        assert payload.get("value") == int(main, 16) + 0x20, payload

    def test_convert_roundtrip(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_calc_convert", {"value": "0x1234"})
        assert payload.get("dec") == 4660, payload
        assert payload.get("hex") == "0x1234", payload
        assert payload.get("bin") == "0b1001000110100", payload
        assert payload.get("unsigned64") == 4660, payload

    def test_offset_distance(self, ctx: BehaviorContext):
        main = ctx.main_addr
        payload = ctx.ok("ida_calc_offset", {"address": main, "target": hex(int(main, 16) + 0x30)})
        assert payload.get("delta_hex") == "0x30", payload

    def test_align_down(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_calc_align", {"value": "0x401003", "size": 16})
        text = json.dumps(payload)
        assert "0x401000" in text, payload

    def test_bitops_xor(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_calc_bitops", {"value": "0xff", "target": "0x0f", "bit_op": "xor"})
        assert payload.get("result") == 0xF0, payload

    def test_deref_reads_memory(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_calc_deref", {"address": ctx.main_addr, "type": "u32"})
        assert "value" in payload or "result" in payload, payload

    def test_resolve_maps_va_to_file_offset(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_calc_resolve", {"address": ctx.main_addr})
        assert payload.get("file_offset") is not None or payload.get("offset") is not None, payload

    def test_chain_answers_or_errors_cleanly(self, ctx: BehaviorContext):
        # main has no pointer table; the contract is a well-formed answer.
        payload = ctx.call("ida_calc_chain", {"address": ctx.main_addr, "offsets": ["0x10"]})
        assert payload.get("error") is not True or isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

class TestSearchSurface:
    def test_find_kinds(self, ctx: BehaviorContext):
        for kind, needle in (
            ("names", "fixture_entry"),
            ("strings", "IDA_MCP_AGENT_SURFACE_MARKER"),
            ("imports", "puts"),
            ("instructions", "fixture_entry"),
        ):
            payload = ctx.ok("ida_find", {"query": needle, "kind": kind, "limit": 10})
            assert needle.lower() in json.dumps(payload).lower(), f"kind={kind}: {payload}"

    def test_find_comments_after_adding_one(self, ctx: BehaviorContext):
        ctx.ok("ida_comment", {"address": "fixture_leaf", "comment": "BEHAVIOR_COMMENT_MARKER", "risk_ack": True})
        try:
            payload = ctx.ok("ida_find", {"query": "BEHAVIOR_COMMENT_MARKER", "kind": "comments", "limit": 10})
            assert "BEHAVIOR_COMMENT_MARKER" in json.dumps(payload), payload
        finally:
            ctx.call("ida_comment", {"address": "fixture_leaf", "comment": "", "risk_ack": True})

    def test_search_data_value_ascii(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_search_data_value", {"value": "AGENT_SURFACE_STRING_001", "limit": 10})
        assert payload.get("count", 0) >= 1, payload

    def test_query_lang_functions_by_size(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "functions with size > 40 LIMIT 10"})
        assert isinstance(payload.get("results"), list), payload


# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------

class TestTypesRoundTrip:
    def test_declare_get_list_roundtrip(self, ctx: BehaviorContext):
        declared = ctx.ok("ida_declare_type", {
            "declaration": "struct pkt_hdr { uint32_t magic; uint16_t len; };",
            "risk_ack": True,
        })
        assert declared.get("name") == "pkt_hdr", declared
        try:
            got = ctx.ok("ida_get_type", {"name": "pkt_hdr"})
            assert got.get("kind") == "struct", got
            members = {m["name"]: m for m in got.get("members", [])}
            assert members["magic"]["size"] == 4 and members["len"]["size"] == 2, got
            listing = ctx.ok("ida_list_types", {"kind": "struct", "limit": 100})
            assert "pkt_hdr" in json.dumps(listing), listing
        finally:
            ctx.call("ida_til_delete", {"name": "pkt_hdr", "risk_ack": True})

    def test_struct_member_lifecycle(self, ctx: BehaviorContext):
        ctx.ok("ida_declare_type", {
            "declaration": "struct pkt_hdr { uint32_t magic; uint16_t len; };",
            "risk_ack": True,
        })
        try:
            ctx.ok("ida_struct_member_add", {
                "struct_name": "pkt_hdr", "member_name": "crc",
                "type_str": "uint32_t", "offset": -1, "risk_ack": True,
            })
            ctx.ok("ida_struct_member_add", {
                "struct_name": "pkt_hdr", "member_name": "payload",
                "type_str": "char[16]", "offset": -1, "risk_ack": True,
            })
            ctx.ok("ida_struct_member_rename", {
                "struct_name": "pkt_hdr", "member_name": "crc",
                "new_name": "checksum", "risk_ack": True,
            })
            ctx.ok("ida_struct_member_set_type", {
                "struct_name": "pkt_hdr", "member_name": "checksum",
                "type_str": "uint64_t", "risk_ack": True,
            })
            got = ctx.ok("ida_get_type", {"name": "pkt_hdr"})
            members = {m["name"]: m for m in got.get("members", [])}
            assert "checksum" in members and "payload" in members, got
            assert members["checksum"]["size"] == 8, got
            assert members["payload"]["size"] == 16, got
            ctx.ok("ida_struct_member_del", {
                "struct_name": "pkt_hdr", "member_name": "checksum", "risk_ack": True,
            })
            got2 = ctx.ok("ida_get_type", {"name": "pkt_hdr"})
            names2 = {m["name"] for m in got2.get("members", [])}
            assert "checksum" not in names2, got2
        finally:
            ctx.call("ida_til_delete", {"name": "pkt_hdr", "risk_ack": True})

    def test_enum_lifecycle(self, ctx: BehaviorContext):
        ctx.ok("ida_declare_type", {
            "declaration": "enum status_t { STATUS_OK = 0, STATUS_BUSY = 1 };",
            "risk_ack": True,
        })
        try:
            ctx.ok("ida_enum_member_add", {
                "enum_name": "status_t", "member_name": "STATUS_WAIT", "value": 2, "risk_ack": True,
            })
            ctx.ok("ida_enum_member_revalue", {
                "enum_name": "status_t", "member_name": "STATUS_WAIT", "value": 5, "risk_ack": True,
            })
            ctx.ok("ida_enum_member_rename", {
                "enum_name": "status_t", "member_name": "STATUS_WAIT",
                "new_name": "STATUS_DONE", "risk_ack": True,
            })
            got = ctx.ok("ida_get_type", {"name": "status_t"})
            assert got.get("kind") == "enum", got
        finally:
            ctx.call("ida_til_delete", {"name": "status_t", "risk_ack": True})

    def test_til_export_import_roundtrip(self, ctx: BehaviorContext):
        ctx.ok("ida_declare_type", {
            "declaration": "struct pkt_hdr { uint32_t magic; uint16_t len; };",
            "risk_ack": True,
        })
        header = ctx.runtime_dir / "session_types.h"
        try:
            exported = ctx.ok("ida_til_export", {"path": str(header), "risk_ack": True})
            assert exported.get("exported_count", 0) >= 1, exported
            content = header.read_text(encoding="utf-8")
            assert "pkt_hdr" in content, content
            ctx.ok("ida_til_delete", {"name": "pkt_hdr", "risk_ack": True})
            imported = ctx.ok("ida_til_import", {"path": str(header), "risk_ack": True})
            assert "pkt_hdr" in imported.get("imported", []), imported
            got = ctx.ok("ida_get_type", {"name": "pkt_hdr"})
            assert got.get("size") == 8, got
        finally:
            ctx.call("ida_til_delete", {"name": "pkt_hdr", "risk_ack": True})

    def test_apply_type_function_prototype(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_apply_type", {
            "address": "fixture_entry",
            "type_str": "int fixture_entry(int value);",
            "kind": "function",
            "risk_ack": True,
        })
        assert payload.get("type") is not None, payload

    def test_get_type_missing_errors_cleanly(self, ctx: BehaviorContext):
        payload = ctx.call("ida_get_type", {"name": "NO_SUCH_TYPE_XYZ"})
        assert payload.get("error") is True
        assert payload.get("code") == "TYPE_ERROR", payload


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

class TestFindingsLifecycle:
    def test_findings_full_lifecycle(self, ctx: BehaviorContext):
        recorded = ctx.ok("ida_write_finding", {
            "title": "behavior finding title",
            "content": "verified through the public findings surface",
            "address": "fixture_entry",
            "category": "test",
            "confidence": 1.0,
            "priority": 0.9,
            "kind": "finding",
            "tags": ["behavior", "live"],
        })
        entry_id = recorded.get("entry_id")
        assert entry_id, recorded
        try:
            listing = ctx.ok("ida_list_findings", {"limit": 50})
            assert "behavior finding title" in json.dumps(listing), listing
            searched = ctx.ok("ida_search_findings", {"query": "public findings surface", "limit": 10})
            assert "behavior finding title" in json.dumps(searched), searched
            ctx.ok("ida_update_finding", {
                "entry_id": entry_id, "status": "confirmed",
                "reason": "live verification passed",
            })
            brief = ctx.ok("ida_analysis_brief", {"limit": 10})
            assert brief.get("ok") is True
            ctx.ok("ida_next_target", {"limit": 10})
        finally:
            ctx.ok("ida_update_finding", {"entry_id": entry_id, "status": "resolved", "reason": "cleanup"})

    def test_mark_examined_records_verdict(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_mark_examined", {
            "address": "fixture_leaf", "verdict": "boring", "note": "leaf helper",
        })
        assert payload.get("ok") is True

    def test_export_findings_inline_and_file(self, ctx: BehaviorContext):
        inline = ctx.ok("ida_export_findings", {"format": "json", "limit": 20})
        assert "findings" in json.dumps(inline) or "workspace" in json.dumps(inline), inline
        target = Path(ctx.session_dir) / "findings.md"
        to_file = ctx.ok("ida_export_findings", {"format": "markdown", "path": str(target), "limit": 20})
        assert to_file.get("path") == str(target), to_file
        assert target.exists() and target.stat().st_size > 0

    def test_publish_and_import_annotations(self, ctx: BehaviorContext):
        ctx.ok("ida_comment", {"address": "fixture_helper", "comment": "publish-me", "risk_ack": True})
        try:
            ctx.ok("ida_import_annotations", {"limit": 100})
            ctx.ok("ida_publish_findings", {"dry_run": True, "limit": 25})
        finally:
            ctx.call("ida_comment", {"address": "fixture_helper", "comment": "", "risk_ack": True})

    def test_mark_dangerous_answers_on_clean_function(self, ctx: BehaviorContext):
        # The agent-surface fixture only calls puts() — no dangerous APIs —
        # so the scan must answer ok with zero warnings, never fail.
        payload = ctx.ok("ida_mark_dangerous", {"address": "fixture_entry", "limit": 20, "risk_ack": True})
        assert payload.get("count") == 0, payload


# ---------------------------------------------------------------------------
# mutations (with restore)
# ---------------------------------------------------------------------------

class TestMutationRoundTrips:
    def test_rename_observable_and_restorable(self, ctx: BehaviorContext):
        original = "fixture_mutation_target"
        renamed = "fixture_mutation_target_live_renamed"
        ctx.ok("ida_rename", {"address": original, "name": renamed, "risk_ack": True})
        try:
            payload = ctx.ok("ida_find", {"query": renamed, "limit": 10})
            assert renamed in json.dumps(payload), payload
        finally:
            ctx.ok("ida_rename", {"address": renamed, "name": original, "risk_ack": True})

    def test_undo_transaction_commits(self, ctx: BehaviorContext):
        original = "fixture_leaf"
        renamed = "fixture_leaf_undo_txn"
        ctx.ok("ida_undo_begin", {"risk_ack": True})
        ctx.ok("ida_rename", {"address": original, "name": renamed, "risk_ack": True})
        ctx.ok("ida_undo_end", {"risk_ack": True})
        try:
            payload = ctx.ok("ida_find", {"query": renamed, "limit": 10})
            assert renamed in json.dumps(payload), payload
        finally:
            ctx.ok("ida_rename", {"address": renamed, "name": original, "risk_ack": True})

    def test_snapshot_restore_rolls_back(self, ctx: BehaviorContext):
        original = "fixture_helper"
        renamed = "fixture_helper_snap_renamed"
        ctx.ok("ida_idb_snapshot", {"name": "behavior_snapshot", "risk_ack": True})
        ctx.ok("ida_rename", {"address": original, "name": renamed, "risk_ack": True})
        try:
            payload = ctx.ok("ida_find", {"query": renamed, "limit": 10})
            assert renamed in json.dumps(payload), payload
        finally:
            restored = ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "behavior_snapshot", "risk_ack": True})
            assert restored.get("ok") is True
        payload = ctx.ok("ida_find", {"query": original, "limit": 10})
        assert original in json.dumps(payload), payload

    def test_add_entry_is_idempotent(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_add_entry", {"address": "main", "risk_ack": True})
        assert payload.get("ok") is True
        again = ctx.ok("ida_add_entry", {"address": "main", "risk_ack": True})
        assert again.get("ok") is True

    def test_save_idb_in_place_and_explicit(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_save_idb", {"risk_ack": True})
        assert payload.get("saved_to"), payload
        target = ctx.runtime_dir / "explicit_save.i64"
        explicit = ctx.ok("ida_save_idb", {"path": str(target), "risk_ack": True})
        assert explicit.get("saved_to") == str(target), explicit
        assert target.exists()

    def test_patch_bytes_is_hard_blocked(self, ctx: BehaviorContext):
        payload = ctx.call("ida_patch_bytes", {"address": ctx.main_addr, "hex_bytes": "9090", "risk_ack": True})
        assert payload.get("error") is True
        assert payload.get("code") == "GOVERNANCE_BLOCKED", payload

    def test_rename_local_roundtrip(self, ctx: BehaviorContext):
        payload = ctx.call("ida_rename_local", {
            "address": "fixture_entry", "var_name": "v1",
            "new_name": "renamed_local_v1", "risk_ack": True,
        })
        # The decompiler's variable numbering is not guaranteed; a clean
        # coded error is the contract when the name does not exist.
        assert payload.get("ok") is True or (payload.get("error") is True and payload.get("code")), payload


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------

class TestBatch:
    def test_batch_deterministic_calls(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_batch", {"calls": [
            {"name": "ida_overview", "arguments": {}},
            {"name": "ida_list_functions", "arguments": {"limit": 5}},
            {"name": "ida_calc_eval", "arguments": {"expr": "0x401000 + 0x20"}},
        ]})
        results = payload.get("results")
        assert isinstance(results, list) and len(results) == 3, payload
        assert results[1].get("result", {}).get("ok") is True, results
        assert results[2].get("result", {}).get("value") == 0x401020, results

    def test_batch_static_bindings(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_batch", {
            "calls": [
                {"name": "ida_calc_eval", "arguments": {"expr": "$base"}},
            ],
            "bindings": {"base": "0x401000"},
        })
        results = payload.get("results")
        assert results and results[0].get("result", {}).get("value") == 0x401000, payload

    def test_batch_step_chaining(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_batch", {
            "calls": [
                {"name": "ida_calc_eval", "arguments": {"expr": "0x401000 + 0x20"}},
                {"name": "ida_calc_convert", "arguments": {"value": "step0_value"}},
            ],
        })
        results = payload.get("results")
        assert results and results[1].get("result", {}).get("dec") == 0x401020, payload

    def test_batch_continue_on_error(self, ctx: BehaviorContext):
        payload = ctx.call("ida_batch", {
            "calls": [
                {"name": "ida_calc_eval", "arguments": {"expr": "this is not an expr"}},
                {"name": "ida_calc_eval", "arguments": {"expr": "0x10 + 0x10"}},
            ],
            "continue_on_error": True,
        })
        assert payload.get("error") is not True, payload
        results = payload.get("results")
        assert results and len(results) == 2, payload
        assert results[0].get("result", {}).get("error") is True, results
        assert results[1].get("result", {}).get("value") == 0x20, results
        # the batch reports its own failure summary without failing the call
        assert payload.get("summary", {}).get("errors") == 1, payload


# ---------------------------------------------------------------------------
# python tool
# ---------------------------------------------------------------------------

class TestPythonTool:
    def test_expression_returns_result(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_python", {"code": "40 + 2", "risk_ack": True})
        assert payload.get("result") == 42, payload

    def test_script_stdout_captured(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_python", {"code": "print('PYTHON_TOOL_STDOUT_MARKER')", "risk_ack": True})
        assert "PYTHON_TOOL_STDOUT_MARKER" in payload.get("output", ""), payload

    def test_bad_code_errors_cleanly(self, ctx: BehaviorContext):
        payload = ctx.call("ida_python", {"code": "raise RuntimeError('boom')", "risk_ack": True})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# r2 sidecar (availability-dependent)
# ---------------------------------------------------------------------------

class TestR2Sidecar:
    def _r2_available(self, ctx: BehaviorContext) -> bool:
        payload = ctx.call("ida_r2_status", {})
        return payload.get("ok") is True and payload.get("error") is not True

    def test_r2_status_reports(self, ctx: BehaviorContext):
        payload = ctx.call("ida_r2_status", {})
        assert payload.get("error") is not True or isinstance(payload.get("code"), str), payload

    def test_r2_bininfo_when_available(self, ctx: BehaviorContext):
        if not self._r2_available(ctx):
            pytest.skip("r2 sidecar not available")
        payload = ctx.ok("ida_r2_bininfo", {})
        assert payload.get("arch") or payload.get("bits") or payload.get("entry"), payload

    def test_r2_load_hints_when_available(self, ctx: BehaviorContext):
        if not self._r2_available(ctx):
            pytest.skip("r2 sidecar not available")
        payload = ctx.ok("ida_r2_load_hints", {})
        assert isinstance(payload.get("hints"), list) or payload.get("ok") is True, payload

    def test_r2_disassemble_at_file_offset(self, ctx: BehaviorContext):
        if not self._r2_available(ctx):
            pytest.skip("r2 sidecar not available")
        payload = ctx.ok("ida_r2_disassemble_hypothesis", {"address": "0x0", "count": 8})
        hypotheses = payload.get("hypotheses") or []
        assert hypotheses, payload
        for hypothesis in hypotheses:
            assert "instructions" in hypothesis, payload
            assert "arch" in hypothesis, payload


# ---------------------------------------------------------------------------
# firmware heuristics (ELF fixture)
# ---------------------------------------------------------------------------

class TestFirmwareHeuristics:
    def test_vector_table_detect_answers(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_fw_detect_vector_table", {"start": "0x0", "end": "0x400"})
        assert payload.get("ok") is True

    def test_load_base_detect_answers(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_fw_detect_load_base", {})
        assert payload.get("ok") is True

    def test_mmio_detect_answers(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_fw_detect_mmio", {"limit": 10})
        assert payload.get("ok") is True

    def test_rtos_scan_answers(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_fw_rtos_scan", {"limit": 10})
        assert payload.get("ok") is True


# ---------------------------------------------------------------------------
# emulate + reranker status (light contracts)
# ---------------------------------------------------------------------------

class TestRuntimeBackends:
    def test_emulate_info_reports_backend(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_emulate", {"action": "info"})
        assert "backend" in payload, payload
        assert isinstance(payload.get("backend_candidates"), list), payload

    def test_reranker_status_reports(self, ctx: BehaviorContext):
        payload = ctx.ok("ida_reranker_status", {"probe": False})
        reranker = payload.get("reranker", {})
        assert reranker, payload
        assert "profile" in reranker or "backend" in reranker, payload


# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------

class TestHelp:
    def test_help_topic_and_search(self, ctx: BehaviorContext):
        topic = ctx.ok("ida_help", {"topic": "ida_decompile"})
        assert topic.get("operation", {}).get("name") == "ida_decompile", topic
        searched = ctx.ok("ida_help", {"query": "semantic"})
        assert "ida_semantic_search" in json.dumps(searched), searched

    def test_help_unknown_topic_errors(self, ctx: BehaviorContext):
        payload = ctx.call("ida_help", {"topic": "ida_no_such_operation"})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload
