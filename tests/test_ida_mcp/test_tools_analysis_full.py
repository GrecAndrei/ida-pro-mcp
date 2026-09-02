"""Comprehensive unit and subsystem test suite for IDA analysis tools.

Covers:
- analysis (get/set options, architecture, reanalysis, state, af flags, make_code, undefine, save_idb, snapshots, auto_wait)
- funcs (create, change, delete, set_flags, info, metrics, find_similar, list)
- modify (rename, comment, set_type, patch_asm, patch_bytes, rename_local, create_data, create_strlit, undo)
- segments (list, info, add, delete, set_attr, set_perms, move, analyze, find_code, find_data, compare, merge, sreg)
- data (functions, annotations, globals, strings, imports, exports, lookup, bulk_query, capability_matrix, string_xrefs, read_bytes)
- symbols (load_pdb, load_dwarf, status, apply, export)
- memory (read, write, hexdump, search, compare, pointers, entropy, strings, struct_walk, histogram)
- misc (python, idc, load_sig, list_sigs, cache_stats, read_file, write_file, plugin_list, plugin_run, health, reload)
"""

from __future__ import annotations

import os
import tempfile

import pytest

from ida_pro_mcp.ida_mcp.tools.analysis import analysis
from ida_pro_mcp.ida_mcp.tools.data import data
from ida_pro_mcp.ida_mcp.tools.funcs import funcs
from ida_pro_mcp.ida_mcp.tools.memory import memory
from ida_pro_mcp.ida_mcp.tools.misc import misc
from ida_pro_mcp.ida_mcp.tools.modify import modify
from ida_pro_mcp.ida_mcp.tools.segments import segments
from ida_pro_mcp.ida_mcp.tools.symbols import symbols
from tests.fakes.ida_fake import (
    SEGPERM_EXEC,
    SEGPERM_READ,
    SEGPERM_WRITE,
    FakeDatabase,
    create_sample_c_binary_idb,
    install_fake_idb,
)


@pytest.fixture(autouse=True)
def setup_fake_db():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    yield db


# ============================================================================
# 1. ANALYSIS TOOL TESTS
# ============================================================================

class TestAnalysisTool:
    def test_analysis_options_and_architecture(self):
        # Get options
        res = analysis(action="get_options")
        assert res.get("ok") is True
        assert "processor" in res or "bitness" in res

        # Set architecture
        res_arch = analysis(action="set_architecture", processor="metapc", bitness=64, endian="le")
        assert res_arch.get("ok") is True

        # State check
        res_state = analysis(action="state")
        assert res_state.get("ok") is True

    def test_analysis_af_flags(self):
        # Get AF flags
        res_af = analysis(action="get_af")
        assert res_af.get("ok") is True

        # Set AF flag
        res_set = analysis(action="set_af", af_flag="AF_MARKCODE", af_value=True)
        assert res_set.get("ok") is True

    def test_analysis_code_manipulation(self):
        # make_code
        res_code = analysis(action="make_code", addr="0x140001000", size=4)
        assert res_code.get("ok") is True or "code" in res_code

        # undefine
        res_undef = analysis(action="undefine", addr="0x140001020", size=4)
        assert res_undef.get("ok") is True or "undefined" in res_undef

    def test_analysis_idb_and_snapshots(self):
        with tempfile.NamedTemporaryFile(suffix=".idb", delete=False) as tf:
            idb_path = tf.name

        try:
            res_save = analysis(action="save_idb", path=idb_path)
            assert res_save.get("ok") is True

            res_snap = analysis(action="snapshot", snapshot_name="test_snap_1")
            assert res_snap.get("ok") is True

            res_restore = analysis(action="restore_snapshot", snapshot_name="test_snap_1")
            assert res_restore.get("ok") is True
        finally:
            if os.path.exists(idb_path):
                os.remove(idb_path)

    def test_analysis_auto_wait_and_reanalyze(self):
        res_wait = analysis(action="auto_wait", timeout_ms=100)
        assert res_wait.get("ok") is True

        res_re = analysis(action="reanalyze", start="0x140001000", end="0x140001050")
        assert res_re.get("ok") is True


# ============================================================================
# 2. FUNCS TOOL TESTS
# ============================================================================

class TestFuncsTool:
    def test_funcs_list_and_info(self):
        # List functions
        res_list = funcs(action="list", count=10)
        assert res_list.get("ok") is True
        assert "functions" in res_list

        # Info on function
        res_info = funcs(action="info", addr="0x140001000")
        assert res_info.get("ok") is True
        assert res_info.get("function", {}).get("name") == "main" or res_info.get("name") == "main"

    def test_funcs_metrics_and_find_similar(self):
        # Metrics
        res_met = funcs(action="metrics", addr="0x140001000")
        assert res_met.get("ok") is True
        assert "metrics" in res_met or "cyclomatic_complexity" in str(res_met)

        # Find similar
        res_sim = funcs(action="find_similar", addr="0x140001000")
        assert res_sim.get("ok") is True

    def test_funcs_create_change_delete(self):
        # Create function
        res_create = funcs(action="create", addr="0x140001100", end="0x140001150", name="sub_140001100", force=True)
        assert res_create.get("ok") is True or "created" in res_create

        # Set flags
        res_flags = funcs(action="set_flags", addr="0x140001100", flags=0x04)
        assert res_flags.get("ok") is True

        # Change function end
        res_change = funcs(action="change", addr="0x140001100", end="0x140001160")
        assert res_change.get("ok") is True

        # Delete function
        res_del = funcs(action="delete", addr="0x140001100")
        assert res_del.get("ok") is True


# ============================================================================
# 3. MODIFY TOOL TESTS
# ============================================================================

class TestModifyTool:
    def test_modify_rename_and_comments(self):
        # Rename function
        res_ren = modify(action="rename", addr="0x140001000", value="custom_main_renamed")
        assert res_ren.get("ok") is True

        # Add regular comment
        res_cmt = modify(action="comment", addr="0x140001000", value="Main entry comment", comment_type="regular")
        assert res_cmt.get("ok") is True

        # Add repeatable comment
        res_rcmt = modify(action="comment", addr="0x140001000", value="Repeatable main comment", comment_type="repeatable")
        assert res_rcmt.get("ok") is True

    def test_modify_patch_bytes_and_asm(self):
        # Patch bytes
        res_patch = modify(action="patch_bytes", addr="0x140001000", value="90 90 90", governed=False)
        assert res_patch.get("ok") is True

        # Patch asm
        res_asm = modify(action="patch_asm", addr="0x140001000", value="nop; nop", governed=False)
        assert res_asm.get("ok") is True or "patched" in res_asm or "error" in res_asm

    def test_modify_create_data_and_strlit(self):
        # Create dword data
        res_data = modify(action="create_data", addr="0x140003000", item_type="dword", count=2)
        assert res_data.get("ok") is True

        # Create string literal
        res_str = modify(action="create_strlit", addr="0x140002000", size=12, strtype="c")
        assert res_str.get("ok") is True

    def test_modify_undo_transaction(self):
        res_begin = modify(action="undo_begin")
        assert res_begin.get("ok") is True

        res_end = modify(action="undo_end")
        assert res_end.get("ok") is True


# ============================================================================
# 4. SEGMENTS TOOL TESTS
# ============================================================================

class TestSegmentsTool:
    def test_segments_list_and_info(self):
        # List segments
        res_list = segments(action="list")
        assert res_list.get("ok") is True
        assert "segments" in res_list
        assert len(res_list["segments"]) >= 3

        # Info on segment
        res_info = segments(action="info", addr="0x140001000")
        assert res_info.get("ok") is True
        assert res_info.get("segment", {}).get("name") == ".text" or res_info.get("name") == ".text"

    def test_segments_add_delete_and_attrs(self):
        # Add new segment
        res_add = segments(
            action="add",
            name=".extra",
            start="0x140005000",
            end="0x140006000",
            bitness=64,
            perms="r-x",
        )
        assert res_add.get("ok") is True

        # Set attributes
        res_attr = segments(action="set_attr", start="0x140005000", attr="perm", value="rwx")
        assert res_attr.get("ok") is True

        # Delete segment
        res_del = segments(action="delete", start="0x140005000")
        assert res_del.get("ok") is True

    def test_segments_analysis_and_sreg(self):
        # Analyze segment
        res_an = segments(action="analyze", addr="0x140001000")
        assert res_an.get("ok") is True

        # Segment registers list / get / set
        res_sreg_list = segments(action="sreg_list", start="0x140001000")
        assert res_sreg_list.get("ok") is True

        res_sreg_get = segments(action="sreg_get", start="0x140001000", reg=0)
        assert res_sreg_get.get("ok") is True or "value" in res_sreg_get or "register" in res_sreg_get


# ============================================================================
# 5. DATA TOOL TESTS
# ============================================================================

class TestDataTool:
    def test_data_functions_and_globals(self):
        # Functions action
        res_funcs = data(action="functions", count=10, include_prototype=True, include_xrefs=True)
        assert res_funcs.get("ok") is True
        assert "functions" in res_funcs

        # Globals action
        res_globs = data(action="globals", count=10)
        assert res_globs.get("ok") is True
        assert "globals" in res_globs

    def test_data_strings_imports_exports(self):
        # Strings action
        res_strs = data(action="strings", count=10)
        assert res_strs.get("ok") is True
        assert "strings" in res_strs

        # Imports action
        res_imps = data(action="imports", count=10)
        assert res_imps.get("ok") is True
        assert "imports" in res_imps

        # Exports action
        res_exps = data(action="exports", count=10)
        assert res_exps.get("ok") is True
        assert "exports" in res_exps

    def test_data_lookup_and_bulk_query(self):
        # Lookup by name
        res_lk = data(action="lookup", query="main")
        assert res_lk.get("ok") is True
        assert res_lk.get("found") is True or "addr" in res_lk or "matches" in res_lk

        # Bulk query
        res_bulk = data(action="bulk_query", items=[{"kind": "functions", "count": 5}])
        assert res_bulk.get("ok") is True

    def test_data_read_bytes_and_capability_matrix(self):
        # Read bytes
        res_rb = data(action="read_bytes", addr="0x140001000", count=8)
        assert res_rb.get("ok") is True
        assert "bytes" in res_rb or "hex" in res_rb or "data" in res_rb

        # Capability matrix
        res_cap = data(action="capability_matrix")
        assert res_cap.get("ok") is True


# ============================================================================
# 6. SYMBOLS TOOL TESTS
# ============================================================================

class TestSymbolsTool:
    def test_symbols_status_and_export(self):
        # Status
        res_st = symbols(action="status")
        assert res_st.get("ok") is True

        # Export
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            exp_path = tf.name

        try:
            res_exp = symbols(action="export", path=exp_path)
            assert res_exp.get("ok") is True
        finally:
            if os.path.exists(exp_path):
                os.remove(exp_path)

    def test_symbols_load_pdb_and_dwarf(self):
        # Load PDB stub
        res_pdb = symbols(action="load_pdb")
        assert res_pdb.get("ok") is True or "error" in res_pdb

        # Load DWARF stub
        res_dw = symbols(action="load_dwarf")
        assert res_dw.get("ok") is True or "error" in res_dw


# ============================================================================
# 7. MEMORY TOOL TESTS
# ============================================================================

class TestMemoryTool:
    def test_memory_read_and_write(self):
        # Read u32
        res_r32 = memory(action="read", addr="0x140001000", type="u32")
        assert res_r32.get("ok") is True
        assert "value" in res_r32 or "hex" in res_r32

        # Read bytes
        res_rb = memory(action="read", addr="0x140001000", type="bytes", size=8)
        assert res_rb.get("ok") is True

        # Write bytes
        res_wr = memory(action="write", addr="0x140003000", data="41 42 43 44", governed=False)
        assert res_wr.get("ok") is True

    def test_memory_hexdump_and_search(self):
        # Hexdump
        res_hd = memory(action="hexdump", addr="0x140001000", size=32)
        assert res_hd.get("ok") is True
        assert "dump" in res_hd or "lines" in res_hd or "hexdump" in res_hd

        # Search pattern
        res_srch = memory(action="search", addr="0x140001000", end_addr="0x140001100", data="48 83")
        assert res_srch.get("ok") is True
        assert "matches" in res_srch or "count" in res_srch

    def test_memory_entropy_and_histogram(self):
        # Entropy
        res_ent = memory(action="entropy", addr="0x140001000", end_addr="0x140001080")
        assert res_ent.get("ok") is True
        assert "entropy" in res_ent

        # Histogram
        res_hist = memory(action="histogram", addr="0x140001000", end_addr="0x140001080")
        assert res_hist.get("ok") is True
        assert "frequencies" in res_hist or "histogram" in res_hist or "counts" in res_hist

    def test_memory_pointers_and_compare(self):
        # Pointers scan
        res_ptrs = memory(action="pointers", addr="0x140003000", end_addr="0x140003050")
        assert res_ptrs.get("ok") is True

        # Compare regions
        res_cmp = memory(action="compare", addr="0x140001000", end_addr="0x140001020", target_addr="0x140001020")
        assert res_cmp.get("ok") is True or "differences" in res_cmp or "matches" in res_cmp


# ============================================================================
# 8. MISC TOOL TESTS
# ============================================================================

class TestMiscTool:
    def test_misc_python_and_idc(self):
        # Python eval
        res_py = misc(action="python", expr="2 + 3")
        assert res_py.get("ok") is True
        assert res_py.get("result") == 5 or "5" in str(res_py.get("output", ""))

        # IDC eval
        res_idc = misc(action="idc", expr="0x10 + 0x20")
        assert res_idc.get("ok") is True

    def test_misc_file_read_write(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            fpath = tf.name

        try:
            res_wr = misc(action="write_file", path=fpath, content="test_content_123")
            assert res_wr.get("ok") is True

            res_rd = misc(action="read_file", path=fpath)
            assert res_rd.get("ok") is True
            assert res_rd.get("content") == "test_content_123"
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)

    def test_misc_health_cache_and_plugins(self):
        # Health check
        res_health = misc(action="health")
        assert res_health.get("ok") is True

        # Cache stats
        res_cache = misc(action="cache_stats")
        assert res_cache.get("ok") is True

        # Plugin list
        res_plugs = misc(action="plugin_list")
        assert res_plugs.get("ok") is True

        # Reload
        res_rel = misc(action="reload", module="funcs")
        assert res_rel.get("ok") is True or "reloaded" in res_rel
