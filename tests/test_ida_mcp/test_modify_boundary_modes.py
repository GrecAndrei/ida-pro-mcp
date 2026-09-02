"""Composed authoring, governance, and compatibility-mode coverage."""

from __future__ import annotations

import sys
import types

from ida_pro_mcp.ida_mcp.tools.modify import modify

modify_module = __import__("ida_pro_mcp.ida_mcp.tools.modify", fromlist=["*"])


def _error(result):
    assert result.get("error") is True, result
    return result


def test_modify_aliases_comment_modes_and_type_failures(monkeypatch, fresh_fake_idb):
    import ida_lines
    import ida_typeinf
    import idc

    # Public aliases and all comment channels share the same governed write
    # boundary, then remain observable through the IDB read surface.
    assert modify(action="rename", address="0x140001000", name="renamed_main", governed=False)["ok"] is True
    assert modify(action="comment", address="0x140001000", text="regular", governed=False)["ok"] is True
    assert modify(action="comment", address="0x140001000", value="repeat", comment_type="repeatable", governed=False)["ok"] is True
    monkeypatch.delattr(ida_lines, "add_extra_cmt", raising=False)
    assert modify(action="comment", address="0x140001000", value="above", comment_type="anterior", governed=False)["ok"] is True
    assert modify(action="comment", address="0x140001000", value="below", comment_type="posterior", governed=False)["ok"] is True
    assert "regular" in (idc.get_cmt(0x140001000, 0) or "")

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda *_args: None)
    failed_parse = modify(action="set_type", address="0x140001000", type_str="broken", governed=False)
    assert failed_parse["error"] is True
    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda tif, *_args: setattr(tif, "kind", 1) or True)
    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: False)
    failed_apply = modify(action="set_type", address="0x140001000", value="int", governed=False)
    assert failed_apply["error"] is True


def test_modify_asm_and_bytes_cover_partial_and_architecture_modes(monkeypatch, fresh_fake_idb):
    import ida_idp

    patches = []
    monkeypatch.setattr(modify_module.ida_bytes, "patch_bytes", lambda ea, raw: patches.append((ea, bytes(raw))), raising=False)
    monkeypatch.setattr(ida_idp, "assemble", lambda ea, *_args: (True, b"\x90"), raising=False)
    multiple = modify(action="patch_asm", address="0x140001000", asm="nop; nop", governed=False)
    assert multiple["ok"] is True
    assert multiple["count"] == 2
    assert [ea for ea, _raw in patches[:2]] == [0x140001000, 0x140001001]

    calls = iter([(True, b"\x90"), (False, b"")])
    monkeypatch.setattr(ida_idp, "assemble", lambda *_args: next(calls), raising=False)
    partial = modify(action="patch_asm", address="0x140001010", value="nop; bad", governed=False)
    assert partial["error"] is True
    assert "already patched" in partial["hint"]
    assert _error(modify(action="patch_asm", address="0x140001010", value=";", governed=False))
    assert _error(modify(action="patch_bytes", address="0x140001010", hex_bytes="not-hex", governed=False))

    for proc, expected in (("riscv", b"\x13\x00\x00\x00"), ("arm", b"\x00\xf0\x20\xe3"), ("x86", b"\x90\x90\x90\x90")):
        monkeypatch.setattr(modify_module, "_inf_procname", lambda proc=proc: proc)
        result = modify(action="patch_bytes", address="0x140001020", nop=True, count=4, governed=False)
        assert result["ok"] is True
        assert patches[-1][1] == expected

    monkeypatch.setattr(modify_module, "_inf_procname", lambda: (_ for _ in ()).throw(RuntimeError("no processor")))
    fallback = modify(action="patch_bytes", address="0x140001030", nop=True, count=2, governed=False)
    assert fallback["ok"] is True
    assert patches[-1][1] == b"\x90\x90"


def test_modify_rename_local_and_data_authoring_failures(monkeypatch, fresh_fake_idb):
    import ida_hexrays

    assert _error(modify(action="rename_local", address="0x140001000", new_name="x", governed=False))
    assert _error(modify(action="rename_local", address="0x140003000", var_name="v1", new_name="x", governed=False))
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: None, raising=False)
    failed = modify(action="rename_local", address="0x140001000", var_name="v1", new_name="x", governed=False)
    assert failed["error"] is True

    assert _error(modify(action="create_data", address="0x140003000", item_type="dword", count=-1, governed=False))
    assert _error(modify(action="create_data", address="0x140003000", item_type="unknown", governed=False))
    assert _error(modify(action="create_strlit", address="0x140003000", size=0, governed=False))
    assert _error(modify(action="create_strlit", address="0x140003000", size=4, strtype="utf8", governed=False))

    # The final branch is the public unknown-action envelope, after the
    # address/value validation layer has accepted the request.
    unknown = modify(action="not-a-real-action", address="0x140003000", value="x", governed=False)
    assert unknown["error"] is True


def test_modify_governance_redaction_and_warning_results(monkeypatch, fresh_fake_idb):
    responses = iter([
        {
            "approved": True,
            "verdict": "warned",
            "violations": [],
            "warnings": ["review rename"],
            "redacted_content": "safe_name",
            "ontology_class": "MisleadingRename",
            "axiom_score": 0.8,
        },
        {
            "approved": False,
            "verdict": "blocked",
            "violations": [{"rule": "R1", "description": "unsafe"}],
            "warnings": [],
            "redacted_content": "x",
        },
    ])
    monkeypatch.setattr(modify_module, "evaluate_operation", lambda **_kwargs: next(responses))
    warning = modify(action="rename", address="0x140001000", value="bad_name")
    assert warning["ok"] is True
    assert warning["name"] == "safe_name"
    assert warning["governance_warnings"] == ["review rename"]
    blocked = modify(action="comment", address="0x140001000", value="unsafe")
    assert blocked["error"] is True
    assert blocked["code"] == "GOVERNANCE_BLOCKED"


def test_modify_metadata_and_symbol_knowledge_modes(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import ida_segment
    import ida_typeinf
    import idautils
    import idc

    import ida_pro_mcp.services as services

    text_meta = modify_module._gather_governance_metadata("patch_bytes", 0x140001000, "90")
    assert text_meta["section_type"] == ".text"
    assert text_meta["modifies_control_flow"] is True
    monkeypatch.setattr(ida_segment, "SEGPERM_X", 4, raising=False)
    fresh_fake_idb.segments[0].perm = 0
    assert modify_module._gather_governance_metadata("patch_asm", 0x140001000, "nop")["modifies_control_flow"] is True

    monkeypatch.setattr(modify_module._compat, "get_func_info", lambda _ea: types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020))
    monkeypatch.setattr(modify_module._compat, "get_func_flags", lambda _ea: modify_module.ida_funcs.FUNC_LIB)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001000]))
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001040]))
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "callee")
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda _tif, _ea: False)
    rename_meta = modify_module._gather_governance_metadata("rename", 0x140001000, "library_alias")
    assert rename_meta["is_library_function"] is True
    assert rename_meta["api_calls"] == "callee"
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda tif, _ea: setattr(tif, "kind", 1) or True)
    class _FuncInfo:
        def size(self):
            return 2

    monkeypatch.setattr(modify_module.idaapi, "func_type_data_t", _FuncInfo, raising=False)
    monkeypatch.setattr(ida_typeinf.tinfo_t, "get_func_details", lambda _self, _fi: True, raising=False)
    rename_meta = modify_module._gather_governance_metadata("rename_local", 0x140001000, "local_alias")
    assert rename_meta["arg_count"] == 2
    set_type_meta = modify_module._gather_governance_metadata("set_type", 0x140001000, "int __frame")
    assert set_type_meta == {"targets_stack": True, "changes_frame_size": True}

    class _Recorder:
        rows = []

        def upsert_symbol(self, row):
            self.rows.append(row)

    recorder = _Recorder()
    monkeypatch.setattr(services, "SymbolDB", lambda: recorder)
    monkeypatch.setattr(idautils, "CodeRefsTo", lambda _ea, _flow: iter([0x140001010]))
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000]))
    monkeypatch.setattr(idautils, "DataRefsFrom", lambda _ea: iter([0x140002010]))
    monkeypatch.setattr(idc, "get_strlit_contents", lambda *_args: b"hello")
    monkeypatch.setattr(idc, "get_idb_path", lambda: "/tmp/sample.i64")
    modify_module._persist_symbol_knowledge(0x140001000, "renamed_main")
    assert recorder.rows and recorder.rows[0]["symbol_name"] == "renamed_main"
    assert recorder.rows[0]["strings"] == ["hello"]
    modify_module._persist_symbol_knowledge(0x140001000, "sub_140001000")
    modify_module._persist_symbol_knowledge(0x140009000, "orphan")


def test_modify_commit_and_failure_modes(monkeypatch, fresh_fake_idb):
    import ida_hexrays
    import ida_idp
    import ida_lines
    import ida_typeinf
    import idc

    ida_undo = types.ModuleType("ida_undo")
    monkeypatch.setitem(sys.modules, "ida_undo", ida_undo)

    monkeypatch.setattr(idc, "set_name", lambda *_args: False)
    assert modify(action="rename", addr="0x140001000", value="bad", governed=False)["error"] is True
    monkeypatch.setattr(idc, "set_name", lambda *_args: True)
    monkeypatch.setattr(modify_module, "_persist_symbol_knowledge", lambda *_args: None)
    assert modify(action="rename", addr="0x140001000", value="good", governed=False)["ok"] is True

    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False)
    assert modify(action="comment", addr="0x140001000", value="bad", governed=False)["code"] == "ANNOTATION_ERROR"
    monkeypatch.setattr(ida_lines, "add_extra_cmt", lambda *_args: False, raising=False)
    assert modify(action="comment", addr="0x140001000", value="bad", comment_type="anterior", governed=False)["error"] is True

    monkeypatch.setattr(ida_typeinf, "parse_decl", lambda tif, *_args: setattr(tif, "kind", 1) or True)
    monkeypatch.setattr(ida_typeinf, "apply_tinfo", lambda *_args: True)
    assert modify(action="set_type", addr="0x140001000", value="int", governed=False)["ok"] is True

    monkeypatch.setattr(ida_idp, "assemble", lambda *_args: b"\x90", raising=False)
    one = modify(action="patch_asm", addr="0x140001000", value="nop", governed=False)
    assert one["ok"] is True and one["size"] == 1
    monkeypatch.setattr(ida_idp, "assemble", lambda *_args: 0, raising=False)
    assert modify(action="patch_asm", addr="0x140001000", value="bad", governed=False)["error"] is True
    assert modify(action="patch_bytes", addr="0x140001000", governed=False)["error"] is True
    monkeypatch.setattr(modify_module.idaapi, "insn_t", type("_Insn", (), {}), raising=False)
    monkeypatch.setattr(modify_module.idaapi, "decode_insn", lambda *_args: 3, raising=False)
    decoded_nop = modify(action="patch_bytes", addr="0x140001000", nop=True, governed=False)
    assert decoded_nop.get("size") == 3, decoded_nop

    lvars = [types.SimpleNamespace(name="old")]
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: types.SimpleNamespace(lvars=lvars), raising=False)
    monkeypatch.setattr(ida_hexrays, "modify_user_lvars", lambda _ea, modifier: modifier.modify_lvars(types.SimpleNamespace(lvvec=lvars)), raising=False)
    renamed = modify(action="rename_local", addr="0x140001000", var_name="old", new_name="new", governed=False)
    assert renamed["ok"] is True and lvars[0].name == "new"
    monkeypatch.setattr(ida_hexrays, "modify_user_lvars", lambda *_args: False, raising=False)
    assert modify(action="rename_local", addr="0x140001000", var_name="new", new_name="other", governed=False)["error"] is True

    monkeypatch.setattr(ida_undo, "undo_begin", lambda: True, raising=False)
    monkeypatch.setattr(ida_undo, "undo_end", lambda: True, raising=False)
    assert modify(action="undo_begin")["mechanism"] == "ida_undo"
    assert modify(action="undo_end")["mechanism"] == "ida_undo"
    monkeypatch.setattr(ida_undo, "undo_begin", lambda: False, raising=False)
    assert modify(action="undo_begin")["error"] is True
