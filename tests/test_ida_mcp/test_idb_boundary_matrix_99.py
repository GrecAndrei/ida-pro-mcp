"""Cross-version and failure-mode coverage for the IDB inspection surface."""

from __future__ import annotations

import importlib
import json
import types

import pytest

from tests.fakes.ida_fake import create_sample_c_binary_idb, install_fake_idb

idb_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.idb")


@pytest.fixture(autouse=True)
def sample_idb():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    return db


def _clear_read_cache():
    from ida_pro_mcp.ida_mcp.sync import _tool_cache

    cache = _tool_cache()
    if cache is not None:
        cache.clear()


def test_path_and_info_getters_cover_fallback_and_failure_modes(monkeypatch):
    module = types.SimpleNamespace(first=lambda: "first", second=lambda: "second")
    assert idb_mod._get_path(module, ["missing", "second"]) == "second"
    assert idb_mod._get_path(types.SimpleNamespace(), ["missing"]) is None

    monkeypatch.setattr(idb_mod.ida_ida, "inf_get_min_ea", lambda: (_ for _ in ()).throw(RuntimeError("old")))
    monkeypatch.setattr(idb_mod.idc, "INF_MIN_EA", 9, raising=False)
    monkeypatch.setattr(idb_mod.idc, "get_inf_attr", lambda attr: attr + 1)
    assert idb_mod._safe_inf_get("min_ea", 0) == 10
    monkeypatch.delattr(idb_mod.idc, "INF_MIN_EA", raising=False)
    assert idb_mod._safe_inf_get("min_ea", 7) == 7


def test_meta_reports_hashes_compiler_and_raw_loader_correction(monkeypatch):
    monkeypatch.setattr(idb_mod.ida_nalt, "get_input_file_path", lambda: "/tmp/image.bin")
    monkeypatch.setattr(idb_mod.idaapi, "get_idb_path", lambda: "/tmp/image.i64")
    monkeypatch.setattr(idb_mod.ida_nalt, "retrieve_input_file_md5", lambda: b"md5", raising=False)
    monkeypatch.setattr(idb_mod.ida_nalt, "retrieve_input_file_sha256", lambda: b"sha", raising=False)
    monkeypatch.setattr(idb_mod.ida_nalt, "retrieve_input_file_crc32", lambda: 0xCAFE, raising=False)
    monkeypatch.setattr(idb_mod, "_safe_inf_get", lambda name, fallback=0: {
        "min_ea": 0x1000,
        "max_ea": 0x1200,
        "baseaddr": 0x1000,
        "cc_id": 6,
    }.get(name, fallback))
    monkeypatch.setattr(idb_mod, "_inf_filetype_id", lambda: 2)
    monkeypatch.setattr(idb_mod, "_filetype_name", lambda _value: "obj")
    monkeypatch.setattr(idb_mod, "_inf_procname", lambda: "riscv")
    monkeypatch.setattr(idb_mod, "_inf_bitness", lambda: 64)
    monkeypatch.setattr(idb_mod.ida_ida, "inf_is_dll", lambda: True, raising=False)
    monkeypatch.setattr(idb_mod.ida_ida, "inf_is_be", lambda: False, raising=False)
    monkeypatch.setattr(idb_mod, "infer_binary_arch_profile", lambda _path: {"file_kind": "raw"})

    result = idb_mod.idb_meta()
    assert result["file_type_effective"] == "raw"
    assert result["file_type_info"]["note"]
    assert result["compiler"] == "gnu"
    assert result["md5"] == "6d6435" and result["sha256"] == "736861"
    assert result["crc32"] == "0xcafe" and result["is_dll"] is True

    monkeypatch.setattr(idb_mod, "infer_binary_arch_profile", lambda _path: (_ for _ in ()).throw(RuntimeError("scan")))
    _clear_read_cache()
    assert idb_mod.idb_meta()["inferred_arch_profile"] == {}


def test_segments_entrypoints_and_bookmarks_cover_compatibility_shapes(monkeypatch):
    seg = types.SimpleNamespace(
        start_ea=0x1000,
        end_ea=0x1004,
        name=".text",
        perm=idb_mod.idaapi.SEGPERM_READ | idb_mod.idaapi.SEGPERM_EXEC,
    )
    monkeypatch.setattr(idb_mod.idautils, "Segments", lambda: iter([0x1000, 0x2000]))
    monkeypatch.setattr(idb_mod._compat, "get_segment", lambda ea: seg if ea == 0x1000 else None)
    monkeypatch.setattr(idb_mod._compat, "get_segment_perm", lambda _ea: seg.perm)
    monkeypatch.setattr(idb_mod._compat, "get_segment_type", lambda _ea: 999)
    monkeypatch.setattr(idb_mod._compat, "get_segment_align", lambda _ea: 4)
    monkeypatch.setattr(idb_mod._compat, "get_segment_bitness", lambda _ea: 3)
    monkeypatch.setattr(idb_mod._compat, "get_segment_name", lambda _ea: ".text")
    monkeypatch.setattr(idb_mod._compat, "get_segment_class", lambda _ea: "CODE")
    monkeypatch.setattr(idb_mod.ida_bytes, "get_flags", lambda ea: 1 if ea == 0x1000 else 2)
    monkeypatch.setattr(idb_mod.ida_bytes, "is_code", lambda flags: flags == 1)
    monkeypatch.setattr(idb_mod.ida_bytes, "is_data", lambda flags: flags == 2)
    monkeypatch.setattr(idb_mod.idc, "next_head", lambda ea, _end: ea + 1)
    segments = idb_mod.idb_segments_detailed()
    assert len(segments) == 1
    assert segments[0]["perms"] == "rx"
    assert segments[0]["type"] == "type_999"
    assert segments[0]["bitness"] == 48
    assert segments[0]["code_heads"] == 1 and segments[0]["data_heads"] == 3
    assert idb_mod.idb_segments_detailed(include_head_counts=False)[0]["code_heads"] is None

    entries = [(1, 0x1000, "start"), (2, 0x1010, "main"), (3, 0x1020, "DllCustom"), (4, 0x1030, "other")]
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry_qty", lambda: len(entries))
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry_ordinal", lambda i: entries[i][0])
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry", lambda ordinal: next(e for o, e, _n in entries if o == ordinal))
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry_name", lambda ordinal: next(n for o, _e, n in entries if o == ordinal))
    monkeypatch.setattr(
        idb_mod._compat,
        "get_func_info",
        lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 8) if ea != 0x1030 else None,
    )
    result = idb_mod.idb_entrypoints_detailed()
    assert [e["type"] for e in result["entrypoints"]] == ["entry_point", "main", "dll_entry", "export"]
    assert result["entrypoints"][1]["func_size"] == "0x8"

    bookmarks = {0: (0x1000, "first"), 1: (0x1010, "")}
    monkeypatch.setattr(idb_mod.idc, "get_bookmark", lambda i: bookmarks[i][0] if i in bookmarks else idb_mod.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idb_mod.idc, "get_bookmark_desc", lambda i: bookmarks[i][1], raising=False)
    monkeypatch.setattr(idb_mod._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(idb_mod.idc, "get_func_name", lambda ea: f"fn_{ea:x}")
    result = idb_mod.idb_bookmarks()
    assert result["count"] == 2 and result["bookmarks"][1]["desc"] == ""
    monkeypatch.delattr(idb_mod.idc, "get_bookmark", raising=False)
    _clear_read_cache()
    assert idb_mod.idb_bookmarks() == {"bookmarks": [], "count": 0}


def test_summary_covers_full_scan_comments_imports_and_fast_mode(monkeypatch):
    monkeypatch.setattr(idb_mod.idautils, "Functions", lambda: iter([0x1000, 0x1010]))
    monkeypatch.setattr(idb_mod.idc, "get_func_name", lambda ea: "sub_auto" if ea == 0x1000 else "named")
    monkeypatch.setattr(idb_mod.idaapi, "get_strlist_qty", lambda: 4)
    monkeypatch.setattr(idb_mod.ida_nalt, "get_import_module_qty", lambda: 1)
    monkeypatch.setattr(idb_mod.ida_nalt, "enum_import_names", lambda _i, cb: (cb(0x2000, "imp", 1), cb(0x2001, "imp2", 2))[-1])
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry_qty", lambda: 3)
    seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1004)
    monkeypatch.setattr(idb_mod.idautils, "Segments", lambda: iter([0x1000]))
    monkeypatch.setattr(idb_mod._compat, "get_segment", lambda _ea: seg)
    monkeypatch.setattr(idb_mod._compat, "get_segment_perm", lambda _ea: idb_mod.idaapi.SEGPERM_EXEC)
    monkeypatch.setattr(idb_mod.ida_bytes, "get_flags", lambda ea: 1 if ea in (0x1000, 0x1002) else 0)
    monkeypatch.setattr(idb_mod.ida_bytes, "is_code", bool)
    monkeypatch.setattr(idb_mod.ida_bytes, "is_data", lambda _flags: False)
    monkeypatch.setattr(idb_mod.idc, "get_cmt", lambda ea, rpt: "comment" if ea == 0x1001 and rpt == 1 else None)
    monkeypatch.setattr(idb_mod.idc, "next_head", lambda ea, _end: idb_mod.idaapi.BADADDR if ea >= 0x1003 else ea + 1)
    monkeypatch.setattr(idb_mod.idc, "get_item_size", lambda _ea: 2)
    monkeypatch.setattr(idb_mod.idaapi, "auto_is_ok", lambda: False)

    fast = idb_mod.idb_summary(fast=True)
    assert fast["approximate"] is True and fast["imports"] == 2
    full = idb_mod.idb_summary()
    assert full["comments"] == 1
    assert full["defined_code_bytes"] == 4 and full["total_code_bytes"] == 4
    assert full["code_coverage_pct"] == 100.0 and full["analysis_ok"] is False


def test_architecture_profile_covers_raw_guidance_and_gp_detection(monkeypatch):
    meta = {
        "binary_path": "/tmp/raw.bin",
        "processor": "riscv",
        "bitness": 32,
        "is_be": False,
        "file_type_id": 17,
        "file_type_info": {"effective": "raw", "loader": "obj"},
        "inferred_arch_profile": {"file_kind": "raw", "warning": "set arch", "load_base": "0x80000000"},
    }
    monkeypatch.setattr(idb_mod, "detect_riscv_gp", lambda: {"found": True, "gp": 0x80001000})
    result = idb_mod.idb_architecture_profile(meta=meta, summary={"imports": 0, "exports": 0})
    assert result["raw_binary_mode"] is True
    assert result["raw_binary_warning"] == "set arch"
    assert result["inferred_load_base"] == "0x80000000"
    assert result["entrypoints_note"] and result["riscv_gp"]["found"] is True
    assert any("0x80001000" in rec for rec in result["recommendations"])

    monkeypatch.setattr(idb_mod, "detect_riscv_gp", lambda: {"found": False})
    legacy = idb_mod.idb_architecture_profile(
        meta={"binary_path": "", "processor": "x86", "bitness": 64, "is_be": False, "file_type": "pe"},
        summary={"imports": 2, "exports": 1},
    )
    assert legacy["raw_binary_mode"] is False and legacy["inferred_from_binary"] == {}
    monkeypatch.setattr(idb_mod, "infer_binary_arch_profile", lambda _p: {"file_kind": "raw"})
    monkeypatch.setattr(idb_mod.os.path, "exists", lambda _p: True)
    fallback = idb_mod.idb_architecture_profile(
        meta={"binary_path": "/tmp/x", "processor": "x86", "bitness": 64, "is_be": False, "file_type": "pe"},
        summary={"imports": 2, "exports": 1},
    )
    assert fallback["inferred_from_binary"]["file_kind"] == "raw"


def test_audit_helpers_parse_tail_limit_partial_lines_and_errors(tmp_path, monkeypatch):
    assert idb_mod._safe_audit_dir() is None
    audit = tmp_path / "audit" / "2026-09"
    audit.mkdir(parents=True)
    path = audit / "audit_2026-09-02.jsonl"
    path.write_text("partial\n" + json.dumps({"tool": "idb", "ok": True}) + "\nnot-json\n" + json.dumps({"tool": "two"}) + "\n", encoding="utf-8")
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))
    assert idb_mod._safe_audit_dir() == str(tmp_path / "audit")
    assert idb_mod._read_audit_tail(str(tmp_path / "audit"), 0) == []
    records = idb_mod._read_audit_tail(str(tmp_path / "audit"), 1)
    assert records == [{"tool": "two"}]
    monkeypatch.setattr(idb_mod.glob, "glob", lambda _pattern: (_ for _ in ()).throw(OSError("glob")))
    assert idb_mod._read_audit_tail(str(tmp_path / "audit"), 2) == []
    monkeypatch.setattr(idb_mod.os.path, "isdir", lambda _p: (_ for _ in ()).throw(OSError("stat")))
    assert idb_mod._safe_audit_dir() is None


def test_state_degrades_across_sdk_filesystem_and_audit_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(idb_mod.idaapi, "auto_state", lambda: 99, raising=False)
    monkeypatch.setattr(idb_mod.idaapi, "get_auto_display", lambda: (_ for _ in ()).throw(RuntimeError("display")), raising=False)
    monkeypatch.setattr(idb_mod.idaapi, "auto_is_ok", lambda: False)
    monkeypatch.setattr(idb_mod.idaapi, "get_idb_path", lambda: str(tmp_path / "db.i64"))
    monkeypatch.setattr(idb_mod.idaapi, "get_input_file_path", lambda: str(tmp_path / "raw.bin"))
    (tmp_path / "db.i64").write_bytes(b"idb")
    (tmp_path / "raw.bin").write_bytes(b"raw data")
    monkeypatch.setattr(idb_mod.idaapi, "get_func_qty", lambda: 0, raising=False)
    monkeypatch.setattr(idb_mod.idaapi, "get_strlist_qty", lambda: 0)
    monkeypatch.setattr(idb_mod.ida_nalt, "get_import_module_qty", lambda: (_ for _ in ()).throw(RuntimeError("imports")))
    monkeypatch.setattr(idb_mod.ida_entry, "get_entry_qty", lambda: (_ for _ in ()).throw(RuntimeError("exports")))
    monkeypatch.setattr(idb_mod.ida_kernwin, "get_cursor_ea", lambda: 0x140001000, raising=False)
    monkeypatch.setattr(idb_mod.idaapi, "is_debugger_on", lambda: True, raising=False)
    monkeypatch.setattr(idb_mod.idaapi, "get_process_state", lambda: 9, raising=False)
    monkeypatch.setattr(idb_mod, "_safe_audit_dir", lambda: str(tmp_path / "audit"))
    monkeypatch.setattr(idb_mod, "_read_audit_tail", lambda *_args: [{"tool": "x", "error": True}, object()])

    result = idb_mod.idb_state(audit_tail=2)
    assert result["analysis"]["state"] == "STATE_99"
    assert result["database"]["input_size"] == 8 and result["database"]["open_seconds"] >= 60
    assert result["ui"]["cursor_ea"] == "0x140001000"
    assert result["debugger"] == {"active": True, "process_state": "STATE_9"}
    assert result["indicators"]["raw_blob"] is True and result["indicators"]["arch_unverified"] is True
    assert result["audit_tail"][0]["guardrail_blocked"] is False


def test_register_classes_cover_native_ranges_synthesis_and_filters(monkeypatch):
    ida_idp = idb_mod.ida_idp
    monkeypatch.setattr(idb_mod, "_inf_procname", lambda: "riscv64")
    monkeypatch.setattr(
        ida_idp,
        "ph",
        types.SimpleNamespace(reg_names=["x0", "x1", "cs", "other"], reg_first_ireg=0, reg_last_ireg=1, reg_first_sreg=2, reg_last_sreg=2),
        raising=False,
    )
    result = idb_mod.idb_registers()
    assert {c["reg_class"] for c in result["classes"]} == {"gpr", "segment", "other", "csr"}
    assert idb_mod.idb_registers(reg_class="segment")["registers"] == ["cs"]
    assert idb_mod.idb_registers(reg_class="missing")["code"] == "INVALID_ARGS"

    names = {0: "rax", 1: "rbx", 2: "cs"}
    monkeypatch.setattr(ida_idp, "ph", types.SimpleNamespace(reg_names=[]), raising=False)
    monkeypatch.setattr(ida_idp, "get_reg_name", lambda reg, width: names.get(reg) if width == 8 else None, raising=False)
    monkeypatch.setattr(ida_idp, "ph_get_reg_first_sreg", lambda: 2, raising=False)
    monkeypatch.setattr(ida_idp, "ph_get_reg_last_sreg", lambda: 2, raising=False)
    synthesized = idb_mod._register_classes("x86")
    assert [item["reg_class"] for item in synthesized[:2]] == ["gpr", "segment"]
    monkeypatch.setattr(ida_idp, "get_reg_name", lambda _reg, _width: (_ for _ in ()).throw(RuntimeError("no names")), raising=False)
    assert idb_mod._register_classes("x86") == []
    monkeypatch.setattr(idb_mod, "ida_idp", None)
    _clear_read_cache()
    assert idb_mod.idb_registers()["code"] == "IDA_ERROR"
