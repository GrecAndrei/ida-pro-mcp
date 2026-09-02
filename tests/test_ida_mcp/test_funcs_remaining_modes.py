"""Additional function-management coverage for mutation and analysis modes."""

from __future__ import annotations

import importlib
import sys
import types

from tests.fakes.ida_fake import BADADDR

funcs_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.funcs")
services_mod = importlib.import_module("ida_pro_mcp.services")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_function_helpers_cover_xrefs_raw_mapping_and_code_creation(monkeypatch, fresh_fake_idb):
    fn = types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020, flags=0)
    other = types.SimpleNamespace(start_ea=0x140001010, end_ea=0x140001030, flags=0)
    monkeypatch.setattr(funcs_mod.idautils, "Functions", lambda: [fn.start_ea, other.start_ea])
    monkeypatch.setattr(funcs_mod._compat, "get_func_info", lambda ea: fn if ea == fn.start_ea else other)
    assert list(funcs_mod._iter_overlapping_functions(0x140001018, 0x140001028)) == [fn, other]

    deleted = []
    monkeypatch.setattr(funcs_mod.ida_funcs, "get_func_name", lambda ea: f"f_{ea:x}")
    monkeypatch.setattr(funcs_mod.ida_funcs, "del_func", lambda ea: deleted.append(ea) or True)
    removed = funcs_mod._remove_overlapping_functions(0x140001000, 0x140001020)
    assert len(removed) == 1 and deleted == [0x140001010]

    monkeypatch.setattr(funcs_mod.ida_bytes, "is_code", lambda _flags: True)
    monkeypatch.setattr(funcs_mod.ida_bytes, "get_flags", lambda _ea: 1)
    assert funcs_mod._ensure_code_at(0x140001000) is True
    monkeypatch.setattr(funcs_mod.ida_bytes, "is_code", lambda _flags: False)
    monkeypatch.setattr(funcs_mod, "_try_create_insn", lambda _ea: 0)
    monkeypatch.setattr(funcs_mod, "_inf_procname", lambda: "arm")
    assert funcs_mod._ensure_code_at(0x140001000) is False

    callers = [0x140002000, 0x140001000]
    monkeypatch.setattr(funcs_mod.idautils, "CodeRefsTo", lambda _ea, _flow: callers)
    monkeypatch.setattr(funcs_mod.idautils, "FuncItems", lambda _ea: [0x140001000, 0x140001004])
    monkeypatch.setattr(funcs_mod.idautils, "CodeRefsFrom", lambda _ea, _flow: [0x140003000])
    monkeypatch.setattr(funcs_mod._compat, "get_func_start", lambda ea: ea)
    assert funcs_mod._collect_callers(0x140001000) == [0x140002000]
    assert funcs_mod._collect_callees(0x140001000) == [0x140003000]

    monkeypatch.setattr(funcs_mod.idaapi, "is_mapped", lambda _ea: False)
    monkeypatch.setattr(funcs_mod._compat, "get_first_segment_ea", lambda: 0)
    monkeypatch.setattr(funcs_mod._compat, "get_next_segment_ea", lambda _ea: None)
    monkeypatch.setattr(funcs_mod._compat, "get_segment", lambda _ea: types.SimpleNamespace(start_ea=0, end_ea=0x2000))
    monkeypatch.setattr(funcs_mod.idaapi, "is_mapped", lambda ea: ea == 0x1000)
    mapped, note = funcs_mod._try_map_raw_runtime_addr(0x401000)
    assert mapped == 0x1000 and "runtime_va" in note


def test_function_create_change_and_failure_modes(monkeypatch, fresh_fake_idb):
    # Existing start is an idempotent rename, while an interior address needs
    # an explicit force before the containing function can be replaced.
    renamed = _ok(funcs_mod.funcs(action="create", address="0x140001000", name="entry"))
    assert renamed["note"] == "Function already exists at this address"
    inside = funcs_mod.funcs(action="create", address="0x140001010")
    assert inside["error"] is True
    forced = _ok(
        funcs_mod.funcs(
            action="create",
            address="0x140001010",
            end="0x140001040",
            name="split_entry",
            force=True,
        )
    )
    assert forced["name"] == "split_entry"

    monkeypatch.setattr(funcs_mod, "_ensure_code_at", lambda _ea: False)
    bad = funcs_mod.funcs(action="create", address="0x140003500")
    assert bad["error"] is True and "cannot be converted" in bad["message"]

    monkeypatch.setattr(funcs_mod, "_ensure_code_at", lambda _ea: True)
    monkeypatch.setattr(funcs_mod.ida_funcs, "add_func", lambda *_args: None)
    failed = funcs_mod.funcs(action="create", address="0x140003500")
    assert failed["error"] is True and "Failed to create" in failed["message"]


def test_function_info_prototype_metrics_and_similarity_modes(monkeypatch, fresh_fake_idb):
    class Location:
        reg = "rcx"
        offset = None

    params = [
        types.SimpleNamespace(name="buffer", type="char *", loc=Location()),
        types.SimpleNamespace(name="length", type="size_t", loc=types.SimpleNamespace(reg=None, offset=0x20)),
    ]

    class FuncData:
        rettype = "int"
        cc = "__cdecl"

        def size(self):
            return len(params)

        def __getitem__(self, index):
            return params[index]

    class Tinfo:
        def is_func(self):
            return True

        def get_func_details(self, out):
            out.__dict__.update(FuncData().__dict__)
            out.size = FuncData().size
            out.__getitem__ = FuncData().__getitem__
            return True

    monkeypatch.setattr(funcs_mod.ida_typeinf, "tinfo_t", Tinfo)
    monkeypatch.setattr(funcs_mod.ida_typeinf, "func_type_data_t", FuncData, raising=False)
    monkeypatch.setattr(funcs_mod.ida_nalt, "get_tinfo", lambda _out, _ea: True)
    monkeypatch.setattr(funcs_mod.idc, "get_func_cmt", lambda _ea, repeat: "repeat" if repeat else "comment")
    monkeypatch.setattr(
        funcs_mod,
        "get_stack_frame_variables_internal",
        lambda *_args, **_kwargs: [{"name": "buffer", "offset": 0x20}],
    )
    info = _ok(
        funcs_mod.funcs(
            action="info",
            address="0x140001000",
            include_prototype=True,
            include_xrefs=True,
            include_stack=True,
        )
    )
    assert info["function"]["parameters"][0]["location"] == "reg:rcx"
    assert info["function"]["parameters"][1]["location"] == "stack:0x20"
    assert info["function"]["return_type"] == "int"
    assert info["function"]["comment"] == "comment"

    funcs_mod.idc.print_insn_mnem = lambda ea: {0x140001000: "call", 0x140001004: "jnz", 0x140001008: "jmp"}.get(ea, "ret")
    funcs_mod.idc.generate_disasm_line = lambda ea, _flags: funcs_mod.idc.print_insn_mnem(ea)
    funcs_mod.idc.next_head = lambda ea, _end: ea + 4 if ea < 0x140001008 else BADADDR
    metrics = _ok(funcs_mod.funcs(action="metrics", address="0x140001000"))
    assert metrics["metrics"]["call_count"] == 1
    assert metrics["metrics"]["conditional_jump_count"] == 1

    funcs_mod.ida_bytes.get_bytes = lambda _ea, size: b"A" * size
    funcs_mod.idautils.Functions = lambda: [0x140001000, 0x140001100, 0x140001200]
    funcs_mod.idautils.FuncItems = lambda _ea: [1, 2, 3]
    functions = {
        0x140001000: types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001050),
        0x140001100: types.SimpleNamespace(start_ea=0x140001100, end_ea=0x140001150),
        0x140001200: types.SimpleNamespace(start_ea=0x140001200, end_ea=0x140001250),
    }
    monkeypatch.setattr(funcs_mod._compat, "get_func_info", functions.get)
    similar = _ok(funcs_mod.funcs(action="find_similar", address="0x140001000", limit=2, min_score=0))
    assert similar["count"] >= 1


def test_function_symbol_persistence_and_embedding_rename_modes(monkeypatch, fresh_fake_idb):
    class SymbolDB:
        rows = []

        def upsert_symbol(self, row):
            self.rows.append(row)

    monkeypatch.setattr(services_mod, "SymbolDB", SymbolDB, raising=False)
    monkeypatch.setattr(funcs_mod.idc, "get_idb_path", lambda: "/tmp/demo.i64")
    monkeypatch.setattr(funcs_mod._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(funcs_mod.idautils, "CodeRefsTo", lambda *_args: [])
    monkeypatch.setattr(funcs_mod.idautils, "CodeRefsFrom", lambda *_args: [])
    monkeypatch.setattr(funcs_mod.idautils, "FuncItems", lambda _ea: [])
    funcs_mod._persist_symbol_knowledge(0x140001000, "known_handler")
    funcs_mod._persist_symbol_knowledge(0x140001000, "sub_140001000")
    assert SymbolDB.rows and SymbolDB.rows[0]["symbol_name"] == "known_handler"

    class Embedder:
        backend = "fake"

    class Index:
        size = 2

        def __init__(self, *_args):
            pass

        def similar(self, *_args, **_kwargs):
            return [
                {"ea": "0x140001100", "name": "packet_handler", "similarity": 0.95},
                {"ea": "0x140001200", "name": "other_handler", "similarity": 0.80},
            ]

    monkeypatch.setattr(services_mod, "BgeCodeEmbedder", Embedder)
    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", Index)
    monkeypatch.setattr(services_mod, "_extract_signature", lambda text, max_idents: f"sig:{text}:{max_idents}")
    monkeypatch.setattr(funcs_mod.idc, "get_idb_path", lambda: "/tmp/demo.i64")
    monkeypatch.setattr(funcs_mod.idc, "get_func_name", lambda ea: "sub_140001000" if ea == 0x140001000 else "packet_handler")
    monkeypatch.setattr(funcs_mod.idautils, "Functions", lambda: [0x140001000])
    monkeypatch.setattr(funcs_mod.ida_hexrays, "decompile", lambda _ea: "int f(void)")
    suggestions = _ok(funcs_mod.funcs(action="suggest_names", limit=1, threshold=0.8))
    assert suggestions["suggestions"][0]["suggested_name"] == "packet_handler"
    assert funcs_mod._embedding_rename_suggestions() ["count"] == 1


def test_function_create_and_mutation_error_modes(monkeypatch, fresh_fake_idb):
    assert funcs_mod._funcs_impl(action="create", addr="0x140003500", end="0x140003500")["error"] is True
    assert funcs_mod._funcs_impl(action="create", addr="0x140003500", name=" ")["error"] is True

    existing = types.SimpleNamespace(start_ea=0x140003500, end_ea=0x140003540, flags=0)
    monkeypatch.setattr(
        funcs_mod._compat,
        "get_func_info",
        lambda ea: existing if 0x140003500 <= ea < 0x140003540 else None,
    )
    monkeypatch.setattr(funcs_mod.idc, "set_name", lambda *_args: False)
    assert funcs_mod._funcs_impl(action="create", addr="0x140003500", name="entry")["error"] is True
    monkeypatch.setattr(funcs_mod.ida_funcs, "del_func", lambda _ea: False)
    assert funcs_mod._funcs_impl(action="create", addr="0x140003510", force=True)["error"] is True

    monkeypatch.setattr(funcs_mod._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(funcs_mod, "_ensure_code_at", lambda _ea: True)
    monkeypatch.setattr(funcs_mod.idaapi, "auto_mark_range", lambda *_args: None, raising=False)
    calls = []
    monkeypatch.setattr(funcs_mod.ida_funcs, "add_func", lambda *_args: calls.append(1) or (None if len(calls) == 1 else existing))
    created = funcs_mod._funcs_impl(action="create", addr="0x140003500", end="0x140003540")
    assert created["ok"] is True

    monkeypatch.setattr(funcs_mod.ida_funcs, "add_func", lambda *_args: existing)
    monkeypatch.setattr(funcs_mod.idc, "set_name", lambda *_args: False)
    assert funcs_mod._funcs_impl(action="create", addr="0x140003600", name="new")["error"] is True
    monkeypatch.setattr(funcs_mod.idc, "set_name", lambda *_args: True)
    monkeypatch.setattr(funcs_mod._compat, "get_func_flags", lambda _ea: None)
    assert funcs_mod._funcs_impl(action="create", addr="0x140003600", flags=1)["error"] is True
    monkeypatch.setattr(funcs_mod._compat, "get_func_flags", lambda _ea: 0)
    monkeypatch.setattr(funcs_mod._compat, "set_func_flags", lambda *_args: False)
    assert funcs_mod._funcs_impl(action="create", addr="0x140003600", flags=1)["error"] is True


def test_function_delete_change_flags_and_info_failure_modes(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(funcs_mod._compat, "get_func_start", lambda _ea: None)
    assert funcs_mod._funcs_impl(action="delete", addr="0x140003500")["error"] is True
    assert funcs_mod._funcs_impl(action="change", addr="0x140003500")["error"] is True
    assert funcs_mod._funcs_impl(action="set_flags", addr="0x140003500", flags=1)["error"] is True

    fn = types.SimpleNamespace(start_ea=0x140003500, end_ea=0x140003540, flags=0)
    monkeypatch.setattr(funcs_mod._compat, "get_func_start", lambda _ea: 0x140003500)
    monkeypatch.setattr(funcs_mod._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(funcs_mod.ida_funcs, "del_func", lambda _ea: False)
    assert funcs_mod._funcs_impl(action="delete", addr="0x140003500")["error"] is True
    assert funcs_mod._funcs_impl(action="change", addr="0x140003500")["error"] is True
    assert funcs_mod._funcs_impl(action="change", addr="0x140003500", end="0x140003400")["error"] is True
    monkeypatch.setattr(funcs_mod.ida_funcs, "set_func_end", lambda *_args: False)
    assert funcs_mod._funcs_impl(action="change", addr="0x140003500", end="0x140003550")["error"] is True
    monkeypatch.setattr(funcs_mod._compat, "get_func_flags", lambda _ea: 1)
    monkeypatch.setattr(funcs_mod._compat, "set_func_flags", lambda *_args: False)
    assert funcs_mod._funcs_impl(action="set_flags", addr="0x140003500", flags=2)["error"] is True
    assert funcs_mod._funcs_impl(action="info", addr="0x140003500")["ok"] is True


def test_function_metrics_and_similarity_filter_modes(monkeypatch, fresh_fake_idb):
    fn = types.SimpleNamespace(start_ea=0x140003500, end_ea=0x140003510, flags=0)
    monkeypatch.setattr(funcs_mod._compat, "get_func_start", lambda _ea: fn.start_ea)
    monkeypatch.setattr(funcs_mod._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(funcs_mod._compat, "get_flow_chart", lambda _ea: (_ for _ in ()).throw(RuntimeError("no flow")))
    monkeypatch.setattr(funcs_mod.ida_funcs, "get_func_name", lambda _ea: "fn")
    metrics = funcs_mod._funcs_impl(action="metrics", addr="0x140003500")
    assert metrics["ok"] is True and metrics["metrics"]["instruction_count"] == 0

    funcs = [0x140003500, 0x140003520, 0x140003540, 0x140003560]
    monkeypatch.setattr(funcs_mod.idautils, "Functions", lambda: funcs)
    monkeypatch.setattr(funcs_mod._compat, "get_func_info", lambda ea: fn if ea == fn.start_ea else types.SimpleNamespace(start_ea=ea, end_ea=ea + 4))
    monkeypatch.setattr(funcs_mod.ida_bytes, "get_bytes", lambda ea, size: b"A" * size if ea != 0x140003540 else b"")
    monkeypatch.setattr(funcs_mod.idautils, "FuncItems", lambda ea: [] if ea == 0x140003540 else [ea])
    similar = funcs_mod._funcs_impl(action="find_similar", addr="0x140003500", limit=1, min_score=101)
    assert similar["ok"] is True and similar["similar_functions"] == []
    assert funcs_mod._funcs_impl(action="unknown", addr="0x140003500")["error"] is True
