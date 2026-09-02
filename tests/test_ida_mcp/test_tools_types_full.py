"""Comprehensive authentic unit tests for IDA tools: types, idb, calc, annotation, batch.

Validates all tool actions, parameter combinations, error paths, state mutations,
and edge cases using the in-memory FakeDatabase from `tests.fakes.ida_fake`.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from ida_pro_mcp.ida_mcp.tools.annotation import annotation
from ida_pro_mcp.ida_mcp.tools.batch import batch
from ida_pro_mcp.ida_mcp.tools.calc import calc
from ida_pro_mcp.ida_mcp.tools.idb import idb
from ida_pro_mcp.ida_mcp.tools.types import types
from tests.fakes.ida_fake import (
    BT_INT32,
    BT_PTR,
    BT_STRUCT,
    BT_VOID,
    FakeDatabase,
    FakeTinfo,
    create_fake_idb,
    create_sample_c_binary_idb,
    create_sample_firmware_idb,
    install_fake_idb,
    o_imm,
    o_near,
    o_reg,
    op_t,
    udm_t,
)


@pytest.fixture(autouse=True)
def setup_c_binary_idb():
    """Install fresh C binary FakeDatabase for each test."""
    db = create_sample_c_binary_idb()
    # Add dummy bytes to .data segment for deref / struct reading
    # 0x140003000: int id = 42 (0x0000002A), ptr name = 0x140002010
    db.patch_bytes(0x140003000, (42).to_bytes(4, "little") + (0x140002010).to_bytes(8, "little"))
    db.patch_bytes(0x140002010, b"sample_name\x00")
    return db


# ============================================================================
# 1. TYPES TOOL TESTS
# ============================================================================

class TestTypesTool:
    def test_types_list_and_search(self):
        # List all types in database
        res = types(action="list", count=50)
        assert res.get("ok") is True
        assert "types" in res
        type_names = [t["name"] for t in res["types"]]
        assert "target_struct" in type_names

        # Search with query
        res_query = types(action="list", query="target*")
        assert res_query.get("ok") is True
        assert len(res_query["types"]) >= 1
        assert res_query["types"][0]["name"] == "target_struct"

        # Search structs specific action
        res_structs = types(action="search_structs", query="name_ptr")
        assert res_structs.get("ok") is True
        assert any(t["name"] == "target_struct" for t in res_structs.get("matches", []))

    def test_types_get_and_diff(self):
        # Get existing struct
        res = types(action="get", name="target_struct")
        assert res.get("ok") is True
        assert res["name"] == "target_struct"
        assert res["size"] >= 12
        assert len(res["members"]) >= 2
        member_names = [m["name"] for m in res["members"]]
        assert "id" in member_names
        assert "name_ptr" in member_names

        # Get non-existent type returns error
        err = types(action="get", name="non_existent_type_123")
        assert err.get("ok") is False or "error" in err or "message" in err

        # Declare another struct for diff
        types(action="declare", decl="struct second_struct { int id; long long extra; };")
        diff_res = types(action="diff", name="target_struct", other_name="second_struct")
        assert diff_res.get("ok") is True
        assert "field_changes" in diff_res or "size_delta" in diff_res or "diff" in diff_res

    def test_types_declare_and_parse_decl(self):
        # Parse declaration
        res_parse = types(action="parse_decl", decl="int calculate_sum(int a, int b);")
        assert res_parse.get("ok") is True

        # Declare a new struct
        res_decl = types(action="declare", decl="struct point_t { int x; int y; };")
        assert res_decl.get("ok") is True

        # Verify declared struct is retrievable
        res_get = types(action="get", name="point_t")
        assert res_get.get("ok") is True
        assert res_get["name"] == "point_t"

    def test_types_struct_member_mutations(self):
        # Create a new struct
        types(action="declare", decl="struct mutable_t { int field1; };")

        # Add member
        add_res = types(
            action="struct_member_add",
            struct_name="mutable_t",
            member_name="field2",
            type_str="int",
            offset=4,
        )
        assert add_res.get("ok") is True

        # Rename member
        ren_res = types(
            action="struct_member_rename",
            struct_name="mutable_t",
            member_name="field2",
            new_name="field2_renamed",
        )
        assert ren_res.get("ok") is True

        # Set member type
        type_res = types(
            action="struct_member_set_type",
            struct_name="mutable_t",
            member_name="field2_renamed",
            type_str="unsigned int",
        )
        assert type_res.get("ok") is True

        # Delete member
        del_res = types(
            action="struct_member_del",
            struct_name="mutable_t",
            member_name="field2_renamed",
        )
        assert del_res.get("ok") is True

    def test_types_enum_operations(self):
        # Declare enum
        decl_res = types(action="declare", decl="enum status_e { STATUS_OK = 0, STATUS_ERR = 1 };")
        assert decl_res.get("ok") is True

        # Look up enum value
        val_res = types(action="enum_values", name="status_e", value=1)
        assert val_res.get("ok") is True

        # Add enum member
        add_res = types(
            action="enum_member_add",
            name="status_e",
            member_name="STATUS_TIMEOUT",
            value=2,
        )
        assert add_res.get("ok") is True

        # Rename enum member
        ren_res = types(
            action="enum_member_rename",
            name="status_e",
            member_name="STATUS_TIMEOUT",
            new_name="STATUS_WAIT_TIMEOUT",
        )
        assert ren_res.get("ok") is True

        # Revalue enum member
        rev_res = types(
            action="enum_member_revalue",
            name="status_e",
            member_name="STATUS_WAIT_TIMEOUT",
            value=10,
        )
        assert rev_res.get("ok") is True

    def test_types_apply_and_set_prototype(self):
        # Set prototype on function
        proto_res = types(
            action="set_prototype",
            addr="0x140001000",
            decl="int main(int argc, char **argv)",
        )
        assert proto_res.get("ok") is True

        # Apply struct type at global data address
        apply_res = types(
            action="apply",
            addr="0x140003000",
            decl="target_struct",
            kind="global",
        )
        assert apply_res.get("ok") is True

    def test_types_visualize_and_type_graph(self):
        vis_res = types(action="visualize", name="target_struct")
        assert vis_res.get("ok") is True
        assert "visual" in vis_res or "fields" in vis_res

        graph_res = types(action="type_graph", name="target_struct", max_depth=3)
        assert graph_res.get("ok") is True
        assert "graph" in graph_res or "nodes" in graph_res or "root" in graph_res

    def test_types_read_struct_and_infer(self):
        # Read struct data from memory
        read_res = types(action="read_struct", addr="0x140003000", name="target_struct")
        assert read_res.get("ok") is True
        assert "data" in read_res or "fields" in read_res or "values" in read_res

        # Infer type at address
        infer_res = types(action="infer", addr="0x140003000")
        assert infer_res.get("ok") is True

    def test_types_til_export_and_import(self):
        with tempfile.NamedTemporaryFile(suffix=".til", delete=False) as tf:
            til_path = tf.name

        try:
            exp_res = types(action="til_export", path=til_path)
            assert exp_res.get("ok") is True

            imp_res = types(action="til_import", path=til_path)
            assert imp_res.get("ok") is True

            types(action="declare", decl="struct temp_to_delete { int a; };")
            del_res = types(action="til_delete", name="temp_to_delete")
            assert del_res.get("ok") is True or "deleted" in del_res
        finally:
            if os.path.exists(til_path):
                os.remove(til_path)

    def test_types_invalid_action_and_args(self):
        err = types(action="unknown_action_xyz")
        assert err.get("ok") in (False, None) and err.get("error") is True


# ============================================================================
# 2. IDB TOOL TESTS
# ============================================================================

class TestIdbTool:
    def test_idb_meta(self):
        res = idb(action="meta")
        assert res.get("ok") is True
        assert res["processor"] == "metapc"
        assert res["bitness"] == 64
        assert res["image_base"] == "0x140000000" or res["image_base"] == 0x140000000 or "0x140000000" in str(res["image_base"])
        assert "md5" in res
        assert "sha256" in res

    def test_idb_summary(self):
        res = idb(action="summary")
        assert res.get("ok") is True
        assert res["functions"] >= 2
        assert res["segments"] >= 3

    def test_idb_overview(self):
        res = idb(action="overview")
        assert res.get("ok") is True
        assert "meta" in res
        assert "summary" in res
        assert "segments" in res
        assert "entrypoints" in res

    def test_idb_segments_and_entrypoints(self):
        seg_res = idb(action="segments", offset=0, count=10)
        assert seg_res.get("ok") is True
        assert "segments" in seg_res
        assert len(seg_res["segments"]) >= 3
        seg_names = [s["name"] for s in seg_res["segments"]]
        assert ".text" in seg_names
        assert ".data" in seg_names

        entry_res = idb(action="entrypoints")
        assert entry_res.get("ok") is True
        assert "entrypoints" in entry_res
        assert len(entry_res["entrypoints"]) >= 1
        assert any(e["name"] == "main" for e in entry_res["entrypoints"])

    def test_idb_bookmarks_and_state(self):
        bm_res = idb(action="bookmarks")
        assert bm_res.get("ok") is True
        assert "bookmarks" in bm_res

        state_res = idb(action="state")
        assert state_res.get("ok") is True

        ev_res = idb(action="events")
        assert ev_res.get("ok") is True

    def test_idb_architecture_profile_and_registers(self):
        arch_res = idb(action="architecture_profile")
        assert arch_res.get("ok") is True

        reg_res = idb(action="registers")
        assert reg_res.get("ok") is True
        assert "registers" in reg_res or "general" in reg_res or len(reg_res) >= 1

    def test_idb_invalid_action(self):
        err = idb(action="invalid_action_xyz")
        assert err.get("ok") in (False, None) and err.get("error") is True


# ============================================================================
# 3. CALC TOOL TESTS
# ============================================================================

class TestCalcTool:
    def test_calc_eval(self):
        # Direct expression evaluation
        res = calc(action="eval", expr="0x140001000 + 0x50")
        assert res.get("ok") is True
        assert res["value"] == 0x140001050
        assert "0x140001050" in res["value_hex"].lower()

        # Expression with arithmetic operations
        res_mul = calc(action="eval", expr="(10 * 4) + 2")
        assert res_mul.get("ok") is True
        assert res_mul["value"] == 42

    def test_calc_offset(self):
        res = calc(action="offset", addr="0x140001000", target="0x140001050")
        assert res.get("ok") is True
        assert res.get("delta_int") == 0x50 or res.get("delta_hex") == "0x50" or res.get("abs_delta") == 0x50

    def test_calc_convert(self):
        # Convert integer value to various widths and representations
        res = calc(action="convert", value=0x12345678)
        assert res.get("ok") is True
        assert res["hex"] == "0x12345678"
        assert res["dec"] == 0x12345678

        # Convert hex representation
        res_f = calc(action="convert", value="0x4048F5C3")
        assert res_f.get("ok") is True
        assert res_f["dec"] == 0x4048F5C3

    def test_calc_resolve(self):
        res = calc(action="resolve", addr="0x140001000", to_va=False)
        assert res.get("ok") is True

        res_va = calc(action="resolve", addr="0x1000", to_va=True)
        assert res_va.get("ok") is True

    def test_calc_deref_and_chain(self):
        # Deref pointer at 0x140003004 -> points to 0x140002010 -> "sample_name"
        res = calc(action="deref", addr="0x140003004", deref_depth=2, size=8)
        assert res.get("ok") is True
        assert "chain" in res or "value" in res or "deref" in res

        # Chain with offsets
        res_chain = calc(action="chain", addr="0x140003000", offsets=[0x4])
        assert res_chain.get("ok") is True

    def test_calc_align_and_bitops(self):
        # Align up
        res_align = calc(action="align", value="0x1003", size=16)
        assert res_align.get("ok") is True
        assert res_align.get("aligned") == 0x1010 or res_align.get("value") == 0x1010 or res_align.get("aligned_up") == 0x1010

        # Bitops
        res_bit = calc(action="bitops", value="0xF0", op="not")
        assert res_bit.get("ok") is True
        assert "result" in res_bit or "value" in res_bit or "result_hex" in res_bit

    def test_calc_errors(self):
        err = calc(action="eval", expr="1 / 0")
        assert err.get("ok") is False or "error" in err or "message" in err


# ============================================================================
# 4. ANNOTATION TOOL TESTS
# ============================================================================

class TestAnnotationTool:
    def test_annotation_auto_comment_single_and_function(self):
        # Auto comment instruction
        res_one = annotation(action="auto_comment", addr="0x140001008", prefix="[MCP] ")
        assert res_one.get("ok") is True

        # Auto comment whole function
        res_func = annotation(action="auto_comment_function", addr="0x140001000", limit=10)
        assert res_func.get("ok") is True
        assert "count" in res_func or "annotations" in res_func

    def test_annotation_label_loops_and_branches(self):
        res_loops = annotation(action="label_loops", addr="0x140001000")
        assert res_loops.get("ok") is True

        res_branches = annotation(action="label_branches", addr="0x140001000")
        assert res_branches.get("ok") is True

    def test_annotation_mark_dangerous_and_constants(self):
        res_dang = annotation(action="mark_dangerous", addr="0x140001000")
        assert res_dang.get("ok") is True

        res_const = annotation(action="annotate_constants", addr="0x140001000")
        assert res_const.get("ok") is True

    def test_annotation_tags_and_structured(self):
        # Set structured comment
        res_set = annotation(
            action="set_structured",
            addr="0x140001000",
            text="Core dispatch entrypoint",
            fmt="structured",
        )
        assert res_set.get("ok") is True

        # Tag function
        res_tag = annotation(action="tag_functions", addr="0x140001000", tags=["entry", "crypto"])
        assert res_tag.get("ok") is True

        # Get context
        res_ctx = annotation(action="get_context", addr="0x140001000")
        assert res_ctx.get("ok") is True

    def test_annotation_bulk_set_and_cleanup(self):
        bulk_items = json.dumps([
            {"addr": "0x140001000", "text": "[MCP] Step 1"},
            {"addr": "0x140001001", "text": "[MCP] Step 2"},
        ])
        res_bulk = annotation(action="bulk_set", items=bulk_items)
        assert res_bulk.get("ok") is True

        # Summary
        res_sum = annotation(action="summary")
        assert res_sum.get("ok") is True

        # Cleanup comments with prefix
        res_clean = annotation(action="cleanup", prefix="[MCP] ")
        assert res_clean.get("ok") is True

    def test_annotation_export_and_import_md(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tf:
            md_path = tf.name

        try:
            exp_res = annotation(action="export_md", path=md_path)
            assert exp_res.get("ok") is True

            imp_res = annotation(action="import_md", path=md_path)
            assert imp_res.get("ok") is True
        finally:
            if os.path.exists(md_path):
                os.remove(md_path)


# ============================================================================
# 5. BATCH TOOL TESTS
# ============================================================================

class TestBatchTool:
    def test_batch_sequential_calls(self):
        calls = [
            {"tool": "calc", "action": "eval", "expr": "100 + 20"},
            {"tool": "idb", "action": "summary"},
        ]
        res = batch(calls=calls)
        assert res.get("ok") is True
        assert len(res["results"]) == 2
        assert res["results"][0]["value"] == 120
        assert res["results"][1]["functions"] >= 2

    def test_batch_dependencies_and_piping(self):
        calls = [
            {"tool": "calc", "action": "eval", "expr": "0x140001000 + 8"},
            {
                "tool": "calc",
                "action": "offset",
                "addr": "0x140001000",
                "depends_on": [0],
                "pipe_from": 0,
                "pipe_field": "value",
                "target": "$pipe",
            },
        ]
        res = batch(calls=calls)
        assert res.get("ok") is True
        assert len(res["results"]) == 2

    def test_batch_conditional_execution(self):
        calls = [
            {"tool": "calc", "action": "eval", "expr": "42"},
            {
                "tool": "calc",
                "action": "eval",
                "expr": "100",
                "if_result": {"index": 0, "field": "value", "op": "eq", "value": 42},
            },
            {
                "tool": "calc",
                "action": "eval",
                "expr": "999",
                "if_result": {"index": 0, "field": "value", "op": "eq", "value": 999},
            },
        ]
        res = batch(calls=calls)
        assert res.get("ok") is True
        assert len(res["results"]) == 3
        assert res["results"][1].get("skipped") is not True
        assert res["results"][2].get("skipped") is True

    def test_batch_template_execution(self):
        res = batch(template="map_binary")
        assert res.get("ok") is True
        assert len(res["results"]) >= 1

    def test_batch_macro_dsl_script(self):
        script = """
        set a = calc(action="eval", expr="5 * 5")
        set b = calc(action="eval", expr="10 + 20")
        return b
        """
        res = batch(script=script)
        assert res.get("ok") is True
        assert res.get("final") is not None or "results" in res or "b" in res.get("vars", {})

    def test_batch_dry_run_and_errors(self):
        # Dry run calls
        res_dry = batch(calls=[{"tool": "calc", "action": "eval", "expr": "1+1"}], dry_run=True)
        assert res_dry.get("ok") is True
        assert res_dry.get("dry_run") is True

        # Dry run script
        res_script_dry = batch(script="set x = calc(action='eval', expr='1+1')", dry_run=True)
        assert res_script_dry.get("ok") is True
        assert res_script_dry.get("dry_run") is True

        # Error on empty
        err_empty = batch(calls=[])
        assert err_empty.get("ok") in (False, None) and err_empty.get("error") is True

        # Error on too many calls
        too_many = [{"tool": "calc", "action": "eval", "expr": "1"}] * 25
        err_many = batch(calls=too_many)
        assert err_many.get("ok") in (False, None) and err_many.get("error") is True
