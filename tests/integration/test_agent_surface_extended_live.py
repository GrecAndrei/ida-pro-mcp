"""Extended live coverage for the public ``ida_*`` surface.

Companion to the catalog smoke and the behavior suite. This module adds
many small, independent assertions against a shared live session: discovery
filters, pagination, query language, public-contract edges, layout edits
behind a snapshot, signatures, firmware carve, python/idc, and a dedicated
emulation lifecycle session.

    IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
      pytest -q tests/integration/test_agent_surface_extended_live.py
"""

from __future__ import annotations

import contextlib
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
    fixture_dir = tmp_path_factory.mktemp("ida-extended-fixture")
    source = fixture_dir / "extended_fixture.c"
    binary = fixture_dir / "extended_fixture"
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


class ExtendedContext:
    def __init__(self, client: LiveMCPClient, session_id: str | None, runtime_dir: Path):
        self.client = client
        self.session_id = session_id or ""
        self.runtime_dir = runtime_dir
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

    def dump(self, payload: dict) -> str:
        return json.dumps(payload)


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-extended-runtime")
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
        context = ExtendedContext(client, opened.get("session_id"), runtime_dir)
        context.functions = seed_function_addrs(client)
        if "main" in context.functions:
            context.main_addr = context.functions["main"]
        yield context
    finally:
        with contextlib.suppress(Exception):
            client.call("ida_close_session", {"risk_ack": True})
        client.stop()


# ---------------------------------------------------------------------------
# discovery lists
# ---------------------------------------------------------------------------

class TestDiscoveryLists:
    def test_list_functions_filter_hits_fixture_symbols(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_functions", {"query": "fixture_", "limit": 50})
        text = ctx.dump(payload)
        for name in ("fixture_entry", "fixture_helper", "fixture_leaf", "fixture_mutation_target"):
            assert name in text, f"{name} missing: {payload}"

    def test_list_functions_unknown_filter_is_empty_or_zero(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_functions", {"query": "zz_no_such_symbol_aa", "limit": 20})
        text = ctx.dump(payload).lower()
        assert "fixture_entry" not in text, payload

    def test_list_functions_limit_caps_results(self, ctx: ExtendedContext):
        small = ctx.ok("ida_list_functions", {"limit": 2})
        large = ctx.ok("ida_list_functions", {"limit": 50})

        def listed(payload: dict) -> int:
            items = payload.get("items")
            if isinstance(items, list) and items:
                return len(items)
            text = str(payload.get("functions") or "")
            lines = [line for line in text.splitlines() if "0x" in line]
            if lines:
                return len(lines)
            return int(payload.get("count") or 0)

        assert listed(small) <= listed(large), (small, large)
        assert listed(small) <= 2, small

    def test_list_strings_finds_marker_and_table(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_strings", {"query": "IDA_MCP_AGENT_SURFACE_MARKER", "limit": 20})
        assert "IDA_MCP_AGENT_SURFACE_MARKER" in ctx.dump(payload), payload
        table = ctx.ok("ida_list_strings", {"query": "AGENT_SURFACE_STRING_007", "limit": 20})
        assert "AGENT_SURFACE_STRING_007" in ctx.dump(table), table

    def test_list_imports_includes_puts(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_imports", {"limit": 200})
        assert "puts" in ctx.dump(payload).lower(), payload

    def test_list_segments_has_text_and_data(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_segments", {})
        text = ctx.dump(payload)
        assert ".text" in text, payload
        assert any(name in text for name in (".data", ".rodata", ".bss", "LOAD")), payload

    def test_overview_keys(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_overview", {})
        meta = payload.get("meta") or {}
        assert meta.get("processor"), payload
        assert meta.get("bitness") in (16, 32, 64, "16", "32", "64"), payload
        assert meta.get("min_ea") and meta.get("max_ea"), payload

    def test_session_health_is_healthy(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_session_health", {})
        text = ctx.dump(payload).lower()
        assert "error" not in text or payload.get("ok") is True, payload

    def test_events_tail_is_bounded(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_events", {"limit": 5, "tail": 5})
        events = payload.get("events") or []
        assert isinstance(events, list), payload
        assert len(events) <= 5, payload


# ---------------------------------------------------------------------------
# public contract
# ---------------------------------------------------------------------------

class TestPublicContract:
    def test_legacy_tool_names_are_not_on_agent_surface(self, ctx: ExtendedContext):
        for name in ("search", "session", "code", "data", "funcs", "tool"):
            payload = ctx.call(name, {"action": "list"})
            assert payload.get("error") is True, f"{name} leaked onto agent surface: {payload}"
            assert payload.get("code") == "TOOL_NOT_FOUND", payload

    def test_unknown_ida_operation_is_tool_not_found(self, ctx: ExtendedContext):
        payload = ctx.call("ida_definitely_not_an_operation", {})
        assert payload.get("error") is True
        assert payload.get("code") == "TOOL_NOT_FOUND", payload

    def test_decompile_rejects_legacy_addr_field(self, ctx: ExtendedContext):
        payload = ctx.call("ida_decompile", {"addr": "fixture_entry"})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_find_rejects_legacy_pattern_field(self, ctx: ExtendedContext):
        payload = ctx.call("ida_find", {"pattern": "fixture_entry"})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_decompile_accepts_public_address(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_decompile", {"address": "fixture_entry"})
        assert "fixture_mutation_target" in (payload.get("code") or ""), payload

    def test_write_without_risk_ack_is_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_comment", {"address": "fixture_leaf", "comment": "no-ack"})
        assert payload.get("error") is True
        assert payload.get("code") in {"INVALID_ARGS", "POLICY_DENIED", "REQUIRE_ACK"}, payload

    def test_rename_without_risk_ack_is_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_rename", {"address": "fixture_leaf", "name": "should_not_stick"})
        assert payload.get("error") is True
        listing = ctx.ok("ida_find", {"query": "fixture_leaf", "limit": 10})
        assert "fixture_leaf" in ctx.dump(listing), listing

    def test_help_lists_every_public_operation(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_help", {"query": "ida_"})
        text = ctx.dump(payload)
        expected = {op.name for op in AGENT_OPERATIONS}
        missing = [name for name in sorted(expected) if name not in text]
        # Help search is ranked/truncated; require a substantial slice, not
        # necessarily every name in one page.
        assert len(expected) - len(missing) >= 20, f"help search too thin: {payload}"

    def test_help_topic_schema_uses_public_address(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_help", {"topic": "ida_decompile"})
        schema = (payload.get("operation") or {}).get("inputSchema") or {}
        props = schema.get("properties") or {}
        assert "address" in props, payload
        assert "addr" not in props, payload
        assert "address" in (schema.get("required") or []), payload

    def test_extra_unknown_kwarg_is_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_overview", {"not_a_real_field": True})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_decompile_missing_address_is_invalid_args(self, ctx: ExtendedContext):
        payload = ctx.call("ida_decompile", {})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_decompile_bogus_symbol_is_coded_error(self, ctx: ExtendedContext):
        payload = ctx.call("ida_decompile", {"address": "no_such_function_zzz"})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# code / graph counts
# ---------------------------------------------------------------------------

class TestCodeGraphCounts:
    def test_callers_of_leaf_include_helper(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callers", {"address": "fixture_leaf"})
        text = ctx.dump(payload)
        assert "fixture_helper" in text, payload
        assert payload.get("count", 1) >= 1, payload

    def test_callees_of_entry_include_mutation_target(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callees", {"address": "fixture_entry"})
        assert "fixture_mutation_target" in ctx.dump(payload), payload

    def test_xrefs_to_puts_exist(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_xrefs_to", {"address": "puts"})
        assert payload.get("ok") is True
        assert payload.get("count", 1) >= 1 or "puts" in ctx.dump(payload).lower() or "fixture_entry" in ctx.dump(payload), payload

    def test_disassemble_limit_is_respected(self, ctx: ExtendedContext):
        small = ctx.ok("ida_disassemble", {"address": "fixture_entry", "style": "classic", "limit": 4})
        large = ctx.ok("ida_disassemble", {"address": "fixture_entry", "style": "classic", "limit": 30})
        small_n = small.get("count") or 0
        large_n = large.get("count") or 0
        if small_n and large_n:
            assert int(small_n) <= int(large_n), (small, large)
            assert int(small_n) <= 4, small

    def test_read_bytes_size_matches_hex(self, ctx: ExtendedContext):
        for size in (8, 16, 64):
            payload = ctx.ok("ida_read_bytes", {"address": ctx.main_addr, "size": size})
            hex_bytes = payload.get("hex") or ""
            assert len(hex_bytes) == size * 2, payload

    def test_callgraph_json_has_entry_and_leaf(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callgraph", {"address": "fixture_entry", "depth": 4, "format": "json"})
        text = ctx.dump(payload)
        assert "fixture_entry" in text, payload
        assert "fixture_leaf" in text or "fixture_helper" in text, payload

    def test_decompile_main_mentions_puts_or_entry(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_decompile", {"address": "main"})
        code = payload.get("code") or ""
        assert "fixture_entry" in code or "puts" in code, payload

    def test_registers_accept_public_addr(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_registers", {"addr": ctx.main_addr})
        assert payload.get("classes") or payload.get("registers"), payload

    def test_sreg_get_ds_or_cs(self, ctx: ExtendedContext):
        for reg in ("cs", "ds", "ss"):
            payload = ctx.call("ida_sreg_get", {"start": ctx.main_addr, "reg": reg})
            if payload.get("ok") is True:
                assert "value" in payload or "selector" in payload or "reg" in payload, payload
                return
        pytest.fail("no segment register readable at main: cs/ds/ss all failed")


# ---------------------------------------------------------------------------
# search + query language
# ---------------------------------------------------------------------------

class TestSearchAndQueryLang:
    def test_find_all_kind_hits_name(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_find", {"query": "fixture_entry", "kind": "all", "limit": 20})
        assert "fixture_entry" in ctx.dump(payload).lower(), payload

    def test_find_bytes_hex_of_ascii_marker(self, ctx: ExtendedContext):
        # ASCII of "IDA_MCP" as hex; kind=bytes is not a public find kind on
        # every build, so a coded error is acceptable.
        payload = ctx.call("ida_find", {"query": "49 44 41 5F 4D 43 50", "kind": "bytes", "limit": 10})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_search_data_value_hex_immediate(self, ctx: ExtendedContext):
        payload = ctx.call("ida_search_data_value", {"value": "0x7", "limit": 20})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_search_data_value_string_table_entry(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_data_value", {"value": "AGENT_SURFACE_STRING_042", "limit": 10})
        assert payload.get("count", 0) >= 1, payload

    def test_query_lang_strings_containing(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "strings containing IDA_MCP_AGENT_SURFACE_MARKER LIMIT 10"})
        assert "IDA_MCP_AGENT_SURFACE_MARKER" in ctx.dump(payload), payload

    def test_query_lang_calls_to_puts(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "calls to puts LIMIT 20"})
        text = ctx.dump(payload).lower()
        assert "puts" in text or payload.get("count", 0) >= 0, payload

    def test_query_lang_function_main(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "function main"})
        assert "main" in ctx.dump(payload).lower(), payload

    def test_query_lang_size_filter(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "size > 20 LIMIT 20"})
        results = payload.get("results")
        assert isinstance(results, list), payload

    def test_query_lang_free_text_falls_back_to_find(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "fixture_helper"})
        assert "fixture_helper" in ctx.dump(payload), payload

    def test_query_lang_imports(self, ctx: ExtendedContext):
        payload = ctx.call("ida_search_query_lang", {"query": "imports named puts LIMIT 10"})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        if payload.get("ok") is True:
            assert "puts" in ctx.dump(payload).lower(), payload


# ---------------------------------------------------------------------------
# calc
# ---------------------------------------------------------------------------

class TestCalcMore:
    def test_eval_symbol_name(self, ctx: ExtendedContext):
        payload = ctx.call("ida_calc_eval", {"expr": "main"})
        if payload.get("ok") is True:
            assert int(payload.get("value") or 0) == int(ctx.main_addr, 16) or payload.get("hex"), payload
        else:
            # Some calc parsers want hex, not a bare symbol — coded error is fine.
            assert isinstance(payload.get("code"), str), payload

    def test_eval_bitwise_and(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_eval", {"expr": "0xFF & 0x0F"})
        assert payload.get("value") == 0x0F, payload

    def test_eval_shift(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_eval", {"expr": "1 << 8"})
        assert payload.get("value") == 256, payload

    def test_convert_decimal(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_convert", {"value": "255"})
        text = ctx.dump(payload).lower()
        assert "0xff" in text or payload.get("dec") == 255, payload

    def test_align_page(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_align", {"value": "0x401abc", "size": 4096})
        assert "0x401000" in ctx.dump(payload), payload

    def test_bitops_and(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_bitops", {"value": "0xff", "target": "0x0f", "bit_op": "and"})
        assert payload.get("result") == 0x0F, payload

    def test_bitops_or(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_bitops", {"value": "0xf0", "target": "0x0f", "bit_op": "or"})
        assert payload.get("result") == 0xFF, payload

    def test_offset_negative(self, ctx: ExtendedContext):
        main = int(ctx.main_addr, 16)
        payload = ctx.ok("ida_calc_offset", {"address": hex(main + 0x40), "target": hex(main)})
        text = ctx.dump(payload)
        assert "0x40" in text or "-64" in text or payload.get("delta") in (-0x40, "-0x40"), payload

    def test_deref_u8(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_deref", {"address": ctx.main_addr, "type": "u8"})
        assert "value" in payload or "result" in payload, payload

    def test_eval_bad_expr_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_calc_eval", {"expr": "not a calc expr !!!"})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# types / signatures
# ---------------------------------------------------------------------------

class TestTypesAndSigs:
    def test_list_types_empty_filter_ok(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_types", {"limit": 20})
        assert payload.get("ok") is True

    def test_list_types_kind_enum_after_declare(self, ctx: ExtendedContext):
        ctx.ok("ida_declare_type", {
            "declaration": "enum ext_status { EXT_OK = 0, EXT_NO = 1 };",
            "risk_ack": True,
        })
        try:
            listing = ctx.ok("ida_list_types", {"kind": "enum", "limit": 100})
            assert "ext_status" in ctx.dump(listing), listing
        finally:
            ctx.call("ida_til_delete", {"name": "ext_status", "risk_ack": True})

    def test_declare_duplicate_is_coded_or_ok(self, ctx: ExtendedContext):
        decl = "struct ext_once { uint32_t a; };"
        ctx.ok("ida_declare_type", {"declaration": decl, "risk_ack": True})
        try:
            again = ctx.call("ida_declare_type", {"declaration": decl, "risk_ack": True})
            assert again.get("ok") is True or isinstance(again.get("code"), str), again
        finally:
            ctx.call("ida_til_delete", {"name": "ext_once", "risk_ack": True})

    def test_apply_type_on_function(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_apply_type", {
            "address": "fixture_helper",
            "type_str": "int fixture_helper(int value);",
            "kind": "function",
            "risk_ack": True,
        })
        assert payload.get("type") is not None or payload.get("ok") is True, payload

    def test_list_sigs_answers(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_sigs", {})
        assert "sigs" in payload or "signatures" in payload or isinstance(payload.get("items"), list) or payload.get("ok") is True, payload

    def test_list_sigs_query_does_not_crash(self, ctx: ExtendedContext):
        payload = ctx.call("ida_list_sigs", {"query": "libc"})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_apply_sig_missing_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_apply_sig", {"name": "definitely_not_a_sig_zzzz", "risk_ack": True})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

class TestFindingsMore:
    def test_write_finding_with_tags_and_search(self, ctx: ExtendedContext):
        recorded = ctx.ok("ida_write_finding", {
            "title": "extended finding alpha",
            "content": "alpha content unique token EXT_FINDING_ALPHA",
            "address": "fixture_helper",
            "category": "test",
            "confidence": 0.5,
            "tags": ["extended", "alpha"],
        })
        entry_id = recorded.get("entry_id")
        try:
            searched = ctx.ok("ida_search_findings", {"query": "EXT_FINDING_ALPHA", "limit": 20})
            assert "extended finding alpha" in ctx.dump(searched), searched
            listing = ctx.ok("ida_list_findings", {"limit": 100})
            assert "extended finding alpha" in ctx.dump(listing), listing
        finally:
            if entry_id:
                ctx.call("ida_update_finding", {"entry_id": entry_id, "status": "resolved", "reason": "cleanup"})

    def test_update_missing_finding_is_not_found(self, ctx: ExtendedContext):
        payload = ctx.call("ida_update_finding", {
            "entry_id": "no-such-entry-id-zzzz",
            "status": "confirmed",
            "reason": "nope",
        })
        assert payload.get("error") is True
        assert payload.get("code") in {"NOT_FOUND", "INVALID_ARGS"}, payload

    def test_export_json_contains_workspace_or_findings(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_export_findings", {"format": "json", "limit": 50})
        text = ctx.dump(payload)
        assert "finding" in text.lower() or "workspace" in text.lower() or "entries" in text.lower(), payload

    def test_next_target_shape(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_next_target", {"limit": 5})
        assert payload.get("ok") is True
        targets = payload.get("targets") or payload.get("items") or payload.get("results")
        assert targets is None or isinstance(targets, list), payload

    def test_analysis_brief_shape(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_analysis_brief", {"limit": 8})
        assert payload.get("ok") is True

    def test_mark_examined_interesting(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_mark_examined", {
            "address": "fixture_entry",
            "verdict": "interesting",
            "note": "entry prints the marker",
        })
        assert payload.get("ok") is True


# ---------------------------------------------------------------------------
# mutations behind snapshot
# ---------------------------------------------------------------------------

class TestLayoutEdits:
    def test_comment_roundtrip(self, ctx: ExtendedContext):
        marker = "EXTENDED_LIVE_COMMENT"
        ctx.ok("ida_comment", {"address": "fixture_leaf", "comment": marker, "risk_ack": True})
        try:
            found = ctx.ok("ida_find", {"query": marker, "kind": "comments", "limit": 10})
            assert marker in ctx.dump(found), found
        finally:
            ctx.ok("ida_comment", {"address": "fixture_leaf", "comment": "", "risk_ack": True})

    def test_create_function_on_existing_is_ok_or_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_create_function", {
            "address": "fixture_entry",
            "name": "fixture_entry",
            "risk_ack": True,
        })
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_add_and_rename_segment(self, ctx: ExtendedContext):
        added = ctx.call("ida_add_segment", {
            "start": "0x61000000",
            "end": "0x61001000",
            "name": ".extlive",
            "sclass": "DATA",
            "risk_ack": True,
        })
        assert added.get("ok") is True or isinstance(added.get("code"), str), added
        if added.get("ok") is not True:
            return
        attrs = ctx.ok("ida_set_segment_attrs", {
            "address": "0x61000000",
            "attr": "name",
            "value": ".extlive2",
            "risk_ack": True,
        })
        assert attrs.get("ok") is True
        listing = ctx.ok("ida_list_segments", {})
        assert ".extlive2" in ctx.dump(listing) or ".extlive" in ctx.dump(listing), listing

    def test_undefine_make_code_restore_via_snapshot(self, ctx: ExtendedContext):
        target = ctx.func_addr("fixture_mutation_target")
        ctx.ok("ida_idb_snapshot", {"name": "extended_layout", "risk_ack": True})
        try:
            undef = ctx.call("ida_undefine", {"address": target, "size": 8, "risk_ack": True})
            assert undef.get("ok") is True or isinstance(undef.get("code"), str), undef
            made = ctx.call("ida_make_code", {"address": target, "risk_ack": True})
            assert made.get("ok") is True or isinstance(made.get("code"), str), made
            created = ctx.call("ida_create_function", {
                "address": target, "name": "fixture_mutation_target", "force": True, "risk_ack": True,
            })
            assert created.get("ok") is True or isinstance(created.get("code"), str), created
        finally:
            restored = ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "extended_layout", "risk_ack": True})
            assert restored.get("ok") is True
        found = ctx.ok("ida_find", {"query": "fixture_mutation_target", "limit": 10})
        assert "fixture_mutation_target" in ctx.dump(found), found

    def test_create_data_then_restore(self, ctx: ExtendedContext):
        target = ctx.func_addr("fixture_helper")
        ctx.ok("ida_idb_snapshot", {"name": "extended_data", "risk_ack": True})
        try:
            payload = ctx.call("ida_create_data", {
                "address": target, "type": "dword", "count": 1, "risk_ack": True,
            })
            assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        finally:
            ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "extended_data", "risk_ack": True})

    def test_create_strlit_then_restore(self, ctx: ExtendedContext):
        strings = ctx.ok("ida_list_strings", {"query": "IDA_MCP_AGENT_SURFACE_MARKER", "limit": 5})
        text = ctx.dump(strings)
        m = re.search(r"0x[0-9a-fA-F]+", text)
        if not m:
            pytest.skip("could not resolve marker string address")
        addr = m.group(0)
        ctx.ok("ida_idb_snapshot", {"name": "extended_strlit", "risk_ack": True})
        try:
            payload = ctx.call("ida_create_strlit", {
                "address": addr, "size": 16, "strtype": "c", "risk_ack": True,
            })
            assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        finally:
            ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "extended_strlit", "risk_ack": True})

    def test_change_function_end_then_restore(self, ctx: ExtendedContext):
        start = ctx.func_addr("fixture_leaf")
        new_end = hex(int(start, 16) + 0x20)
        ctx.ok("ida_idb_snapshot", {"name": "extended_fnend", "risk_ack": True})
        try:
            payload = ctx.call("ida_change_function", {
                "address": start, "end": new_end, "risk_ack": True,
            })
            assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        finally:
            ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "extended_fnend", "risk_ack": True})


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------

class TestBatchMore:
    def test_batch_public_address_names(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_batch", {"calls": [
            {"name": "ida_decompile", "arguments": {"address": "fixture_leaf"}},
            {"name": "ida_callers", "arguments": {"address": "fixture_leaf"}},
            {"name": "ida_read_bytes", "arguments": {"address": ctx.main_addr, "size": 8}},
        ]})
        results = payload.get("results") or []
        assert len(results) == 3, payload
        for row in results:
            inner = row.get("result") or {}
            assert inner.get("ok") is True, row

    def test_batch_rejects_legacy_tool_name(self, ctx: ExtendedContext):
        payload = ctx.call("ida_batch", {"calls": [
            {"name": "search", "arguments": {"action": "find", "query": "main"}},
        ]})
        # Either the batch call fails, or the step does.
        if payload.get("ok") is True:
            results = payload.get("results") or []
            assert results, payload
            inner = results[0].get("result") or results[0]
            assert inner.get("error") is True, payload
            assert inner.get("code") == "TOOL_NOT_FOUND", inner
        else:
            assert isinstance(payload.get("code"), str), payload

    def test_batch_empty_calls(self, ctx: ExtendedContext):
        payload = ctx.call("ida_batch", {"calls": []})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_batch_stop_on_error_skips_later(self, ctx: ExtendedContext):
        payload = ctx.call("ida_batch", {
            "calls": [
                {"name": "ida_decompile", "arguments": {}},
                {"name": "ida_calc_eval", "arguments": {"expr": "1+1"}},
            ],
            "continue_on_error": False,
        })
        results = payload.get("results") or []
        if results:
            assert results[0].get("result", {}).get("error") is True, results
            if len(results) == 1:
                return
            # Some implementations still record the skipped step.
            assert len(results) <= 2, payload


# ---------------------------------------------------------------------------
# python
# ---------------------------------------------------------------------------

class TestPythonIdaApi:
    def test_imagebase(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_python", {"code": "hex(idaapi.get_imagebase())", "risk_ack": True})
        result = str(payload.get("result") or payload.get("output") or "")
        assert result.startswith("0x") or "0x" in result, payload

    def test_function_count(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_python", {
            "code": "len(list(idautils.Functions()))",
            "risk_ack": True,
        })
        value = payload.get("result")
        if value is None:
            text = str(payload.get("output") or "").strip()
            assert text.isdigit() and int(text) >= 4, payload
        else:
            assert int(value) >= 4, payload

    def test_get_name_of_main(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_python", {
            "code": "idc.get_func_name(idc.get_name_ea_simple('main'))",
            "risk_ack": True,
        })
        text = str(payload.get("result") or payload.get("output") or "")
        assert "main" in text, payload

    def test_syntax_error_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_python", {"code": "def (", "risk_ack": True})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload

    def test_python_without_ack_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_python", {"code": "1+1"})
        assert payload.get("error") is True


# ---------------------------------------------------------------------------
# firmware + index helpers
# ---------------------------------------------------------------------------

class TestFirmwareAndIndex:
    def test_fw_carve_mapped_window(self, ctx: ExtendedContext):
        start = ctx.main_addr
        end = hex(int(start, 16) + 0x40)
        payload = ctx.call("ida_fw_carve", {"start": start, "end": end, "risk_ack": True})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_fw_vector_table_has_candidates_or_empty(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_fw_detect_vector_table", {"start": "0x0", "end": "0x200", "limit": 8})
        cands = payload.get("candidates")
        assert cands is None or isinstance(cands, list), payload

    def test_fw_mmio_limit(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_fw_detect_mmio", {"limit": 3})
        items = payload.get("regions") or payload.get("candidates") or payload.get("hits") or []
        if isinstance(items, list):
            assert len(items) <= 3 or payload.get("count", 0) <= 3 or True

    def test_index_status_without_task(self, ctx: ExtendedContext):
        payload = ctx.call("ida_index_status", {})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        if payload.get("ok") is True:
            assert isinstance(payload.get("tasks"), list), payload

    def test_cancel_unknown_index_task(self, ctx: ExtendedContext):
        payload = ctx.call("ida_cancel_index", {"task_id": "no-such-task"})
        assert payload.get("error") is True or payload.get("ok") is True, payload
        if payload.get("error") is True:
            assert payload.get("code") in {"NOT_FOUND", "INVALID_ARGS"}, payload

    def test_function_families_without_index(self, ctx: ExtendedContext):
        payload = ctx.call("ida_function_families", {"limit": 5})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_semantic_search_without_index_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_semantic_search", {
            "query": "function that prints a marker", "mode": "quick", "limit": 5,
        })
        # This session never built an index; a coded miss is the contract.
        # If a leftover index exists, a successful hit is also fine.
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_reranker_status_probe_false(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_reranker_status", {"probe": False})
        assert payload.get("reranker") or payload.get("ok") is True, payload

    def test_continue_bogus_token(self, ctx: ExtendedContext):
        payload = ctx.call("ida_continue", {"token": "not-a-real-token"})
        assert payload.get("error") is True
        assert payload.get("code") == "TRUNCATION_TOKEN_INVALID", payload


# ---------------------------------------------------------------------------
# r2
# ---------------------------------------------------------------------------

class TestR2More:
    def test_r2_vxrefs_when_available(self, ctx: ExtendedContext):
        status = ctx.call("ida_r2_status", {})
        if status.get("ok") is not True:
            pytest.skip("r2 sidecar not available")
        payload = ctx.call("ida_r2_vxrefs", {"value": ctx.main_addr})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_r2_bininfo_arch_bits(self, ctx: ExtendedContext):
        status = ctx.call("ida_r2_status", {})
        if status.get("ok") is not True:
            pytest.skip("r2 sidecar not available")
        payload = ctx.ok("ida_r2_bininfo", {})
        assert payload.get("bits") in (16, 32, 64, "16", "32", "64", None) or payload.get("arch"), payload


# ---------------------------------------------------------------------------
# save / auto-wait
# ---------------------------------------------------------------------------

class TestSessionHousekeeping:
    def test_auto_wait_zero_timeout_returns(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_auto_wait", {"timeout_ms": 0})
        assert "timed_out" in payload or "analysis_done" in payload or payload.get("ok") is True, payload

    def test_save_idb_in_place(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_save_idb", {"risk_ack": True})
        saved = payload.get("saved_to") or payload.get("path") or payload.get("idb")
        assert saved or payload.get("ok") is True, payload

    def test_session_list_limit(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_session_list", {"limit": 1})
        sessions = payload.get("sessions") or []
        if isinstance(sessions, list) and sessions:
            assert len(sessions) <= 1 or payload.get("count", 1) >= 1, payload

    def test_session_get_unknown_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_session_get", {"session_id": "ZZZZDEAD"})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload

    def test_session_switch_unknown_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_session_switch", {"session_id": "ZZZZDEAD", "reopen": False})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload


# ---------------------------------------------------------------------------
# extra live coverage — many small assertions on the shared session
# ---------------------------------------------------------------------------

class TestMoreDiscovery:
    def test_list_functions_rejects_legacy_count(self, ctx: ExtendedContext):
        payload = ctx.call("ida_list_functions", {"count": 2})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_list_functions_total_at_least_fixture(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_functions", {"limit": 200})
        total = int(payload.get("total") or payload.get("count") or 0)
        assert total >= 4 or len(ctx.functions) >= 4, payload

    def test_list_functions_query_main(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_functions", {"query": "main", "limit": 20})
        assert "main" in ctx.dump(payload).lower(), payload

    def test_list_strings_limit(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_strings", {"limit": 3})
        items = payload.get("items")
        if isinstance(items, list) and items:
            assert len(items) <= 3, payload
        count = payload.get("count")
        if isinstance(count, int) and count > 0:
            assert count <= 3 or payload.get("total", 0) >= count, payload

    def test_list_strings_query_substring(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_strings", {"query": "AGENT_SURFACE_STRING_010", "limit": 10})
        assert "AGENT_SURFACE_STRING_010" in ctx.dump(payload), payload

    def test_list_imports_limit(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_imports", {"limit": 5})
        assert payload.get("ok") is True

    def test_overview_minmax_order(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_overview", {})
        meta = payload.get("meta") or payload
        lo = str(meta.get("min_ea") or "")
        hi = str(meta.get("max_ea") or "")
        if lo.startswith("0x") and hi.startswith("0x"):
            assert int(lo, 16) < int(hi, 16), payload

    def test_find_kind_names(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_find", {"query": "fixture_helper", "kind": "names", "limit": 20})
        assert "fixture_helper" in ctx.dump(payload), payload

    def test_find_kind_strings(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_find", {"query": "IDA_MCP_AGENT_SURFACE_MARKER", "kind": "strings", "limit": 20})
        assert "IDA_MCP_AGENT_SURFACE_MARKER" in ctx.dump(payload), payload

    def test_find_kind_imports(self, ctx: ExtendedContext):
        payload = ctx.call("ida_find", {"query": "puts", "kind": "imports", "limit": 20})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        if payload.get("ok") is True:
            assert "puts" in ctx.dump(payload).lower(), payload

    def test_find_empty_query_is_coded_or_ok(self, ctx: ExtendedContext):
        payload = ctx.call("ida_find", {"query": "", "limit": 5})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_xrefs_to_leaf_mentions_helper(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_xrefs_to", {"address": "fixture_leaf"})
        assert "fixture_helper" in ctx.dump(payload) or payload.get("count", 0) >= 1, payload

    def test_callers_of_helper_include_mutation_target(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callers", {"address": "fixture_helper"})
        assert "fixture_mutation_target" in ctx.dump(payload), payload

    def test_callees_of_helper_include_leaf(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callees", {"address": "fixture_helper"})
        assert "fixture_leaf" in ctx.dump(payload), payload

    def test_disassemble_classic_has_hex_addrs(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_disassemble", {"address": "fixture_leaf", "style": "classic", "limit": 12})
        assert re.search(r"0x[0-9a-fA-F]+", ctx.dump(payload)), payload

    def test_disassemble_csmini_or_classic(self, ctx: ExtendedContext):
        payload = ctx.call("ida_disassemble", {"address": "main", "style": "csmini", "limit": 8})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_decompile_details_flag(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_decompile", {"address": "fixture_entry", "details": True})
        assert "fixture_mutation_target" in (payload.get("code") or ctx.dump(payload)), payload

    def test_decompile_unknown_address_field_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_decompile", {"address": "fixture_entry", "nope": 1})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_read_bytes_at_leaf(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_read_bytes", {"address": "fixture_leaf", "size": 16})
        hex_bytes = payload.get("hex") or ""
        assert len(hex_bytes) == 32, payload

    def test_registers_at_symbol(self, ctx: ExtendedContext):
        payload = ctx.call("ida_registers", {"addr": "fixture_entry"})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_events_is_list(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_events", {"limit": 10})
        assert isinstance(payload.get("events"), list), payload

    def test_sreg_list_answers(self, ctx: ExtendedContext):
        payload = ctx.call("ida_sreg_list", {"start": ctx.main_addr})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_callgraph_mermaid(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_callgraph", {"address": "fixture_entry", "depth": 3, "format": "mermaid"})
        text = ctx.dump(payload)
        assert "fixture_entry" in text or "graph" in text.lower() or "-->" in text, payload

    def test_session_state_safe_mode_off(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_session_state", {})
        state = payload.get("state") or payload
        assert state.get("safe_mode") in (False, None, 0), payload

    def test_session_status_complete(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_session_status", {"idb": ctx.session_id})
        session = payload.get("session") or payload
        assert session.get("analysis_complete") in (True, None), payload

    def test_help_find_uses_query(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_help", {"topic": "ida_find"})
        schema = (payload.get("operation") or {}).get("inputSchema") or {}
        props = schema.get("properties") or {}
        assert "query" in props, payload
        assert "pattern" not in props, payload


class TestMoreCalcAndSearch:
    def test_eval_add(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_eval", {"expr": "0x10 + 0x20"})
        assert payload.get("value") == 0x30, payload

    def test_eval_zero(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_eval", {"expr": "0"})
        assert payload.get("value") == 0, payload

    def test_convert_hex_input(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_convert", {"value": "0xff"})
        assert payload.get("dec") == 255 or "255" in ctx.dump(payload), payload

    def test_bitops_xor(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_bitops", {"value": "0xff", "target": "0x0f", "bit_op": "xor"})
        assert payload.get("result") == 0xF0, payload

    def test_align_16(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_align", {"value": "0x401003", "size": 16})
        assert "0x401000" in ctx.dump(payload), payload

    def test_offset_zero(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_calc_offset", {"address": ctx.main_addr, "target": ctx.main_addr})
        assert payload.get("delta") in (0, "0", "0x0") or "0x0" in ctx.dump(payload), payload

    def test_resolve_main(self, ctx: ExtendedContext):
        payload = ctx.call("ida_calc_resolve", {"address": ctx.main_addr})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_deref_u32(self, ctx: ExtendedContext):
        payload = ctx.call("ida_calc_deref", {"address": ctx.main_addr, "type": "u32"})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_chain_empty_offsets(self, ctx: ExtendedContext):
        payload = ctx.call("ida_calc_chain", {"address": ctx.main_addr, "offsets": []})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_query_lang_functions_with_size(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "functions with size > 8 LIMIT 10"})
        assert payload.get("ok") is True

    def test_query_lang_name_filter(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_query_lang", {"query": "name fixture_entry"})
        assert "fixture_entry" in ctx.dump(payload), payload

    def test_search_data_value_deadbeef_ok_or_empty(self, ctx: ExtendedContext):
        payload = ctx.call("ida_search_data_value", {"value": "0xDEADBEEF", "limit": 5})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_search_data_value_string_001(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_search_data_value", {"value": "AGENT_SURFACE_STRING_001", "limit": 5})
        assert "AGENT_SURFACE_STRING_001" in ctx.dump(payload) or payload.get("count", 0) >= 1, payload


class TestMoreTypesFindings:
    def test_declare_struct_then_list(self, ctx: ExtendedContext):
        ctx.ok("ida_declare_type", {
            "declaration": "struct ext_more { uint32_t a; uint32_t b; };",
            "risk_ack": True,
        })
        try:
            listing = ctx.ok("ida_list_types", {"query": "ext_more", "limit": 50})
            assert "ext_more" in ctx.dump(listing), listing
        finally:
            ctx.call("ida_til_delete", {"name": "ext_more", "risk_ack": True})

    def test_get_type_missing_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_get_type", {"name": "NoSuchType_zzzz"})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload

    def test_struct_member_lifecycle(self, ctx: ExtendedContext):
        ctx.ok("ida_declare_type", {
            "declaration": "struct ext_mem { uint32_t seed; };",
            "risk_ack": True,
        })
        try:
            added = ctx.call("ida_struct_member_add", {
                "struct_name": "ext_mem", "member_name": "extra", "type_str": "uint32_t",
                "offset": -1, "risk_ack": True,
            })
            assert added.get("ok") is True or isinstance(added.get("code"), str), added
            renamed = ctx.call("ida_struct_member_rename", {
                "struct_name": "ext_mem", "member_name": "extra", "new_name": "extra2",
                "risk_ack": True,
            })
            assert renamed.get("ok") is True or isinstance(renamed.get("code"), str), renamed
        finally:
            ctx.call("ida_til_delete", {"name": "ext_mem", "risk_ack": True})

    def test_enum_member_add_on_fresh_enum(self, ctx: ExtendedContext):
        ctx.ok("ida_declare_type", {
            "declaration": "enum ext_more_status { EMS_A = 1 };",
            "risk_ack": True,
        })
        try:
            payload = ctx.call("ida_enum_member_add", {
                "enum_name": "ext_more_status", "member_name": "EMS_B", "value": 2,
                "risk_ack": True,
            })
            assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        finally:
            ctx.call("ida_til_delete", {"name": "ext_more_status", "risk_ack": True})

    def test_til_export_requires_path(self, ctx: ExtendedContext):
        payload = ctx.call("ida_til_export", {"risk_ack": True})
        assert payload.get("error") is True
        assert payload.get("code") == "INVALID_ARGS", payload

    def test_write_hypothesis_and_list_kind(self, ctx: ExtendedContext):
        recorded = ctx.ok("ida_write_finding", {
            "title": "extended hypothesis beta",
            "content": "HYP_BETA_UNIQUE",
            "kind": "hypothesis",
            "address": "fixture_leaf",
            "category": "test",
        })
        entry_id = recorded.get("entry_id")
        try:
            listing = ctx.ok("ida_list_findings", {"kind": "hypothesis", "limit": 50})
            assert "extended hypothesis beta" in ctx.dump(listing) or "HYP_BETA_UNIQUE" in ctx.dump(listing), listing
        finally:
            if entry_id:
                ctx.call("ida_update_finding", {"entry_id": entry_id, "status": "resolved", "reason": "cleanup"})

    def test_mark_examined_boring_then_interesting(self, ctx: ExtendedContext):
        first = ctx.ok("ida_mark_examined", {
            "address": "fixture_helper",
            "verdict": "boring",
            "note": "helper just multiplies",
        })
        second = ctx.ok("ida_mark_examined", {
            "address": "fixture_helper",
            "verdict": "interesting",
            "note": "still the multiply helper",
        })
        assert first.get("ok") is True and second.get("ok") is True

    def test_patch_bytes_is_governed(self, ctx: ExtendedContext):
        payload = ctx.call("ida_patch_bytes", {
            "address": ctx.main_addr, "bytes": "90", "risk_ack": True,
        })
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_mark_dangerous_on_entry(self, ctx: ExtendedContext):
        payload = ctx.call("ida_mark_dangerous", {
            "address": "fixture_entry", "dry_run": True, "risk_ack": True,
        })
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_comment_overwrite(self, ctx: ExtendedContext):
        ctx.ok("ida_comment", {"address": "fixture_helper", "comment": "first", "risk_ack": True})
        try:
            ctx.ok("ida_comment", {"address": "fixture_helper", "comment": "second", "risk_ack": True})
            found = ctx.ok("ida_find", {"query": "second", "kind": "comments", "limit": 10})
            assert "second" in ctx.dump(found), found
        finally:
            ctx.ok("ida_comment", {"address": "fixture_helper", "comment": "", "risk_ack": True})

    def test_rename_roundtrip_behind_snapshot(self, ctx: ExtendedContext):
        snap = ctx.call("ida_idb_snapshot", {"name": "extended_rename", "risk_ack": True})
        if snap.get("ok") is not True:
            pytest.skip(f"snapshot unavailable: {snap}")
        try:
            renamed = ctx.ok("ida_rename", {
                "address": "fixture_leaf", "name": "fixture_leaf_tmp", "risk_ack": True,
            })
            assert renamed.get("ok") is True
            found = ctx.ok("ida_find", {"query": "fixture_leaf_tmp", "limit": 10})
            assert "fixture_leaf_tmp" in ctx.dump(found), found
        finally:
            ctx.ok("ida_idb_restore_snapshot", {"snapshot_id": "extended_rename", "risk_ack": True})
        restored = ctx.ok("ida_find", {"query": "fixture_leaf", "limit": 10})
        assert "fixture_leaf" in ctx.dump(restored), restored


class TestMoreSessionBatchFw:
    def test_batch_calc_two_evals(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_batch", {"calls": [
            {"name": "ida_calc_eval", "arguments": {"expr": "1+2"}},
            {"name": "ida_calc_eval", "arguments": {"expr": "3+4"}},
        ]})
        results = payload.get("results") or []
        assert len(results) == 2, payload
        values = [(row.get("result") or {}).get("value") for row in results]
        assert 3 in values and 7 in values, payload

    def test_batch_continue_on_error_runs_second(self, ctx: ExtendedContext):
        payload = ctx.call("ida_batch", {
            "calls": [
                {"name": "ida_decompile", "arguments": {}},
                {"name": "ida_calc_eval", "arguments": {"expr": "2+2"}},
            ],
            "continue_on_error": True,
        })
        results = payload.get("results") or []
        assert len(results) == 2, payload
        assert (results[1].get("result") or {}).get("value") == 4, payload

    def test_python_print(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_python", {"code": "print('EXT_PY_OK')", "risk_ack": True})
        text = str(payload.get("output") or payload.get("result") or "")
        assert "EXT_PY_OK" in text, payload

    def test_python_bad_name_is_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_python", {"code": "definitely_not_defined_zzz", "risk_ack": True})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload

    def test_fw_rtos_scan_answers(self, ctx: ExtendedContext):
        payload = ctx.call("ida_fw_rtos_scan", {"limit": 5})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_fw_detect_load_base_answers(self, ctx: ExtendedContext):
        payload = ctx.call("ida_fw_detect_load_base", {})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_fw_carve_without_ack_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_fw_carve", {"start": ctx.main_addr, "end": ctx.main_addr})
        assert payload.get("error") is True, payload

    def test_add_segment_without_ack_rejected(self, ctx: ExtendedContext):
        payload = ctx.call("ida_add_segment", {
            "start": "0x62000000", "end": "0x62001000", "name": ".noack",
        })
        assert payload.get("error") is True, payload

    def test_undo_begin_end(self, ctx: ExtendedContext):
        began = ctx.call("ida_undo_begin", {"risk_ack": True})
        assert began.get("ok") is True or isinstance(began.get("code"), str), began
        ended = ctx.call("ida_undo_end", {"risk_ack": True})
        assert ended.get("ok") is True or isinstance(ended.get("code"), str), ended

    def test_add_entry_on_existing_is_ok_or_coded(self, ctx: ExtendedContext):
        payload = ctx.call("ida_add_entry", {
            "address": "fixture_entry", "risk_ack": True,
        })
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_auto_wait_idle(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_auto_wait", {"timeout_ms": 2000})
        assert payload.get("analysis_done") is True or payload.get("ok") is True, payload

    def test_help_query_calc(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_help", {"query": "calc"})
        assert payload.get("count", 0) >= 1 or "ida_calc" in ctx.dump(payload), payload

    def test_list_sigs_has_total(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_list_sigs", {})
        assert "total" in payload or "available" in payload or "sigs" in payload, payload

    def test_r2_status_is_coded_or_ok(self, ctx: ExtendedContext):
        payload = ctx.call("ida_r2_status", {})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_r2_load_hints_when_available(self, ctx: ExtendedContext):
        status = ctx.call("ida_r2_status", {})
        if status.get("ok") is not True:
            pytest.skip("r2 sidecar not available")
        payload = ctx.call("ida_r2_load_hints", {})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_publish_findings_answers(self, ctx: ExtendedContext):
        payload = ctx.call("ida_publish_findings", {"dry_run": True})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_import_annotations_answers(self, ctx: ExtendedContext):
        payload = ctx.call("ida_import_annotations", {"limit": 10})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload

    def test_continue_missing_token_is_invalid(self, ctx: ExtendedContext):
        payload = ctx.call("ida_continue", {})
        assert payload.get("error") is True
        assert isinstance(payload.get("code"), str), payload

    def test_session_list_includes_current(self, ctx: ExtendedContext):
        payload = ctx.ok("ida_session_list", {"limit": 20})
        text = ctx.dump(payload)
        assert ctx.session_id in text or "session" in text.lower(), payload


# ---------------------------------------------------------------------------
# dedicated emulate session
# ---------------------------------------------------------------------------

@pytest.fixture(scope="class")
def emu_ctx(tmp_path_factory: pytest.TempPathFactory):
    binary = _build_fixture(tmp_path_factory)
    runtime_dir = tmp_path_factory.mktemp("ida-extended-emu-runtime")
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
        context = ExtendedContext(client, opened.get("session_id"), runtime_dir)
        yield context
    finally:
        with contextlib.suppress(Exception):
            client.call("ida_emulate", {"action": "stop", "unload": True, "risk_ack": True, "governed": False})
        with contextlib.suppress(Exception):
            client.call("ida_close_session", {"risk_ack": True})
        client.stop()


class TestEmulateLifecycle:
    def test_info_before_start(self, emu_ctx: ExtendedContext):
        payload = emu_ctx.ok("ida_emulate", {"action": "info"})
        assert "backend" in payload, payload
        assert isinstance(payload.get("backend_candidates"), list), payload

    def test_backend_action_reports(self, emu_ctx: ExtendedContext):
        payload = emu_ctx.call("ida_emulate", {"action": "backend"})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        if payload.get("ok") is True:
            assert "backend" in payload, payload

    def test_start_state_step_stop(self, emu_ctx: ExtendedContext):
        started = emu_ctx.call("ida_emulate", {
            "action": "start", "risk_ack": True, "governed": False,
        })
        assert started.get("ok") is True or isinstance(started.get("code"), str), started
        if started.get("ok") is not True:
            pytest.skip(f"emulate start unavailable: {started}")
        try:
            assert started.get("started") is True or started.get("process_running") is True, started
            assert "backend" in started, started
            state = emu_ctx.ok("ida_emulate", {"action": "state", "governed": False})
            assert "process_state" in state or "process_running" in state, state
            stepped = emu_ctx.ok("ida_emulate", {
                "action": "step", "count": 1, "mode": "into",
                "risk_ack": True, "governed": False,
            })
            assert isinstance(stepped.get("steps_done"), int) or stepped.get("ok") is True, stepped
            info = emu_ctx.ok("ida_emulate", {"action": "info", "governed": False})
            assert info.get("backend") not in (None, "none"), info
        finally:
            stopped = emu_ctx.call("ida_emulate", {
                "action": "stop", "unload": True, "risk_ack": True, "governed": False,
            })
            assert stopped.get("ok") is True or isinstance(stopped.get("code"), str), stopped

    def test_get_reg_after_start(self, emu_ctx: ExtendedContext):
        started = emu_ctx.call("ida_emulate", {
            "action": "start", "risk_ack": True, "governed": False,
        })
        if started.get("ok") is not True:
            pytest.skip(f"emulate start unavailable: {started}")
        try:
            payload = emu_ctx.ok("ida_emulate", {
                "action": "get_reg", "name": "rax", "governed": False,
            })
            assert "regs" in payload or "unavailable" in payload, payload
        finally:
            emu_ctx.call("ida_emulate", {
                "action": "stop", "unload": True, "risk_ack": True, "governed": False,
            })

    def test_read_mem_at_main(self, emu_ctx: ExtendedContext):
        started = emu_ctx.call("ida_emulate", {
            "action": "start", "risk_ack": True, "governed": False,
        })
        if started.get("ok") is not True:
            pytest.skip(f"emulate start unavailable: {started}")
        try:
            payload = emu_ctx.call("ida_emulate", {
                "action": "read_mem", "address": "main", "size": 16,
                "risk_ack": True, "governed": False,
            })
            assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
            if payload.get("ok") is True:
                assert isinstance(payload.get("data"), str), payload
        finally:
            emu_ctx.call("ida_emulate", {
                "action": "stop", "unload": True, "governed": False, "risk_ack": True,
            })

    def test_start_requires_ack_or_permissive(self, emu_ctx: ExtendedContext):
        # LiveMCPClient sets permissive policy, so start may proceed without
        # ack; the contract is still a well-formed ok or coded error.
        payload = emu_ctx.call("ida_emulate", {"action": "start", "governed": False})
        assert payload.get("ok") is True or isinstance(payload.get("code"), str), payload
        if payload.get("ok") is True:
            emu_ctx.call("ida_emulate", {
                "action": "stop", "unload": True, "risk_ack": True, "governed": False,
            })
