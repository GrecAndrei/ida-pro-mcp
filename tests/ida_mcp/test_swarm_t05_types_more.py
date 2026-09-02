"""Offline mode coverage for the public ``types`` operation.

The tests use a small type-library model instead of mocking the operation
itself.  This keeps the assertions on the wire-level result while exercising
the same branches that the IDA bindings take for structs, enums, pointers,
declarations, propagation, and TIL carry.
"""

from __future__ import annotations

import struct
import sys
import types as pytypes
from pathlib import Path

import pytest

from tests._isolated_repo_loader import load_ida_module, load_tool_module

REPO = Path(__file__).resolve().parents[2]


class _Value:
    def __init__(self, text, size, *, kind="other", name=None, pointed=None):
        self.text = text
        self.size = size
        self.kind = kind
        self.name = name
        self.pointed = pointed

    def __str__(self):
        return self.text

    def get_size(self):
        return self.size

    def get_type_name(self):
        return self.name

    def is_union(self):
        return self.kind == "union"

    def is_struct(self):
        return self.kind == "struct"

    def is_enum(self):
        return self.kind == "enum"

    def is_func(self):
        return self.kind == "function"

    def is_typedef(self):
        return self.kind == "typedef"

    def is_ptr(self):
        return self.kind == "pointer"

    def is_array(self):
        return self.kind == "array"

    def get_pointed_object(self):
        return self.pointed

    def get_array_element(self):
        return self.pointed


class _Member:
    def __init__(self, name, offset, typ, *, gap=False):
        self.name = name
        self.offset = offset * 8
        self.type = typ
        self._gap = gap

    def is_gap(self):
        return self._gap


class _EnumMember:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _Details:
    def __init__(self, items=()):
        self.items = list(items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, index):
        return self.items[index]

    def size(self):
        return len(self.items)


class _Spec(_Value):
    def __init__(self, text, size, *, kind="other", members=(), enum=(),
                 next_name=None, name=None):
        super().__init__(text, size, kind=kind, name=name)
        self.members = list(members)
        self.enum = list(enum)
        self.next_name = next_name


class _FakeTif:
    registry = {}
    ordinals = {}
    saved = []

    def __init__(self, other=None):
        self.spec = other.spec if isinstance(other, _FakeTif) else other

    def get_named_type(self, _til, name):
        self.spec = self.registry.get(name)
        return self.spec is not None

    def get_type_by_tid(self, tid):
        self.spec = self.registry.get(tid)
        return self.spec is not None

    def get_numbered_type(self, _til, ordinal):
        self.spec = self.ordinals.get(ordinal)
        return self.spec is not None

    def get_type_name(self):
        return self.spec.name if self.spec else None

    def get_size(self):
        return self.spec.size if self.spec else -1

    def __str__(self):
        return str(self.spec) if self.spec else "<unresolved>"

    def __getattr__(self, name):
        if self.spec is None:
            raise AttributeError(name)
        return getattr(self.spec, name)

    def get_udt_details(self, details):
        if not self.spec or not (self.is_struct() or self.is_union()):
            return False
        details.items = list(self.spec.members)
        return True

    def get_enum_details(self, details):
        if not self.spec or not self.is_enum():
            return False
        details.items = list(self.spec.enum)
        return True

    def get_next_type_name(self):
        return self.spec.next_name if self.spec else None


def _struct(name, size, members):
    return _Spec(name, size, kind="struct", members=members, name=name)


def _make_fixture():
    child = _struct("Child", 8, [_Member("value", 0, _Value("int32_t", 4))])
    root = _struct(
        "Root",
        16,
        [
            _Member("count", 0, _Value("int32_t", 4)),
            _Member("child", 4, _Value("Child *", 8, kind="pointer", pointed=child)),
            _Member("gap", 12, _Value("char", 4), gap=True),
        ],
    )
    other = _struct(
        "Other",
        12,
        [
            _Member("count", 4, _Value("int64_t", 8)),
            _Member("extra", 0, _Value("char", 1)),
        ],
    )
    flags = _Spec(
        "Flags",
        4,
        kind="enum",
        enum=[_EnumMember("READ", 1), _EnumMember("WRITE", 2),
              _EnumMember("BOTH", 3), _EnumMember("NEG", -1)],
        name="Flags",
    )
    function = _Spec("int (int)", 8, kind="function", name="Function")
    concrete = _Spec("struct Concrete", 4, kind="struct", name="Concrete")
    alias = _Spec("Concrete", 4, kind="typedef", next_name="Concrete", name="Alias")
    registry = {s.name: s for s in (root, child, other, flags, function, concrete, alias)}
    return registry, root, flags


def _load():
    mod = load_tool_module("types")
    error = load_ida_module("error_handling")
    mod.make_error = error.make_error
    mod.handle_error = error.handle_error
    mod.MCPError = error.MCPError
    mod.ERROR_HINTS = error.ERROR_HINTS

    registry, root, flags = _make_fixture()
    _FakeTif.registry = registry
    _FakeTif.ordinals = {
        1: root,
        2: flags,
        3: registry["Child"],
        4: registry["Function"],
        5: registry["Alias"],
        6: registry["Other"],
    }
    _FakeTif.saved = []
    mod.ida_typeinf.tinfo_t = _FakeTif
    mod.ida_typeinf.udt_type_data_t = _Details
    mod.ida_typeinf.enum_type_data_t = _Details
    mod.ida_typeinf.get_idati = object
    mod.ida_typeinf.get_ordinal_qty = lambda _til: 6
    mod.ida_typeinf.PT_SIL = 1
    mod.ida_typeinf.PT_TYP = 2
    mod.ida_typeinf.TINFO_DEFINITE = 4
    mod.ida_typeinf.NTF_TYPE = 8
    mod.ida_typeinf.BADORD = -1
    mod.ida_typeinf.get_named_type_tid = lambda name: name if name in registry else mod.idaapi.BADADDR
    mod.ida_typeinf.alloc_type_ordinal = lambda _til: 9
    mod.ida_typeinf.set_numbered_type = lambda _til, ordinal, _flags, name, tif: (
        _FakeTif.saved.append((ordinal, name, tif)) or True
    )
    mod.ida_typeinf.get_named_type = lambda _til, name, _flags=0: registry.get(name)
    mod.ida_typeinf.print_tinfo = lambda *_args: "struct Root { int count; };"
    mod.ida_typeinf.apply_tinfo = lambda *_args: True
    mod.ida_typeinf.del_named_type = lambda *_args: True
    mod.idc.parse_decls = lambda *_args: 0
    mod.idc.get_name = lambda ea: f"name_{ea:x}"
    mod.idc.get_name_ea_simple = lambda _name: mod.idaapi.BADADDR
    mod.idc.INF_SHORT_DN = 1
    mod.idc.get_inf_attr = lambda _attr: 0
    mod.idc.demangle_name = lambda name, _mask: name
    mod.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    mod.idaapi.inf_is_64bit = lambda: True
    mod._inf_is_64bit = lambda: True
    mod._inf_is_be = lambda: False
    mod.validate_addr = lambda value, require_func=False: (int(value, 0), None)
    mod.parse_address = lambda value: mod.idaapi.BADADDR if value == "bad" else int(value, 0)
    mod._resolve_type_by_name = lambda name, tif: (
        setattr(tif, "spec", registry.get(name)) or registry.get(name) is not None
    )
    mod.compile_smart_pattern = lambda query, case_sensitive=False: (
        lambda text: query.lower() in text.lower()
    )
    mod._compat.get_func_start = lambda _ea: None
    mod._compat.get_func_info = lambda _ea: None
    return mod, registry, root, flags


def test_list_get_and_type_kinds_cover_pagination_and_typedef_chain():
    mod, _registry, _root, _flags = _load()

    listed = mod.types(action="list", query="r", offset=0, count=1)
    assert listed["ok"] is True
    assert listed["types"][0]["name"] == "Root"
    all_matching = mod.types(action="list", query="r", offset=0, count=0)
    assert all_matching["total"] == 2

    struct = mod.types(action="get", name="Root")
    assert struct["kind"] == "struct"
    assert struct["total_members"] == 2
    assert struct["members"][0]["offset"] == 0

    enum = mod.types(action="get", name="Flags")
    assert enum["kind"] == "enum"
    assert enum["members"][-1] == {"name": "NEG", "value": -1}

    function = mod.types(action="get", name="Function")
    assert function["kind"] == "function"
    alias = mod.types(action="get", name="Alias")
    assert alias["typedef_chain"] == ["Concrete", "struct Concrete"]
    assert alias["resolved_type"] == "struct Concrete"


def test_type_validation_and_declaration_actions_cover_success_and_failures():
    mod, registry, _root, _flags = _load()

    assert mod.types(action="get")["error"] is True
    assert mod.types(action="get", name="Missing")["code"] == "TYPE_ERROR"

    def parse_decl(tif, _til, decl, _flags):
        if decl.endswith(";"):
            tif.spec = registry["Root"]
            return "Root"
        return None

    mod.ida_typeinf.parse_decl = parse_decl
    parsed = mod.types(action="parse_decl", decl="struct Root;")
    assert parsed["ok"] is True
    assert parsed["is_struct"] is True
    assert mod.types(action="parse_decl", decl="bad")["error"] is True

    imported = mod.types(action="import_header", decl="struct Root { int count; };")
    assert imported["ok"] is True
    assert mod.types(action="import_header")["code"] == "INVALID_ARGS"

    declared = mod.types(action="declare", decl="struct Root")
    assert declared["ok"] is True
    assert declared["name"] == "Root"
    assert _FakeTif.saved
    mod.ida_typeinf.set_numbered_type = lambda *_args: False
    mod.ida_typeinf.tinfo_t = _FakeTif
    mod.ida_typeinf.get_named_type = lambda *_args: None
    mod.ida_typeinf.tinfo_t.set_named_type = lambda self, _til, _name, _flags: True
    # The fallback is exercised by the action's lookup verification path.
    failed_save = mod.types(action="declare", decl="struct Root", name="Fallback")
    assert failed_save["error"] is True


def test_set_prototype_and_apply_cover_address_parse_and_local_modes():
    mod, registry, _root, _flags = _load()
    calls = []

    def parse_decl(tif, _til, decl, _flags):
        if decl == "bad":
            return False
        tif.spec = registry["Function"]
        return True

    mod.ida_typeinf.parse_decl = parse_decl
    mod.ida_typeinf.apply_tinfo = lambda *args: calls.append(args) or True
    mod._compat.get_func_start = lambda ea: ea if ea == 0x401000 else None
    prototype = mod.types(action="set_prototype", addr="0x401000", decl="int f(int)")
    assert prototype["ok"] is True
    assert mod.types(action="set_prototype", addr="0x401000", decl="bad")["code"] == "INVALID_ARGS"

    applied = mod.types(action="apply", addr="0x401000", decl="int f(int)")
    assert applied["kind"] == "function"
    global_apply = mod.types(action="apply", addr="0x402000", decl="int")
    assert global_apply["kind"] == "global"
    assert len(calls) == 3

    mod.ida_hexrays.decompile = lambda _ea: pytypes.SimpleNamespace(
        lvars=[pytypes.SimpleNamespace(name="local")]
    )
    mod.ida_hexrays.modify_user_lvars = lambda *_args: True
    mod.my_modifier_t = lambda name, tif: (name, tif)
    mod.refresh_decompiler_ctext = lambda _ea: None
    local = mod.types(action="apply", addr="0x401000", decl="int", kind="local", name="local")
    assert local["ok"] is True
    missing_local = mod.types(action="apply", addr="0x401000", decl="int", kind="local", name="gone")
    assert missing_local["code"] == "INVALID_ARGS"
    no_name = mod.types(action="apply", addr="0x401000", decl="int", kind="local")
    assert no_name["code"] == "INVALID_ARGS"


def test_infer_covers_stack_heap_existing_and_empty_fallbacks():
    mod, registry, _root, _flags = _load()
    mod.idc.get_frame_id = lambda _ea: 7
    mod.idc.get_first_member = lambda _frame: 0
    mod.idc.get_next_member = lambda _frame, offset: offset + 1 if offset < 2 else -1
    mod.idc.get_member_name = lambda _frame, offset: f"local{offset}"
    mod.idc.get_member_size = lambda _frame, _offset: 4
    mod._compat.get_func_info = lambda _ea: pytypes.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
    mod.idautils.Heads = lambda _start, _end: iter([0x1000])
    mod.idc.generate_disasm_line = lambda _head, _flags: "call malloc"
    mod.ida_lines.tag_remove = lambda text: text
    inferred = mod.types(action="infer", addr="0x1000")
    assert {entry["kind"] for entry in inferred["inferred_types"]} == {"stack_frame", "heap_object"}
    assert inferred["confidence"] == 0.65

    mod.idc.get_frame_id = lambda _ea: mod.idaapi.BADADDR
    mod._compat.get_func_info = lambda _ea: None
    mod.ida_nalt.get_tinfo = lambda tif, _ea: setattr(tif, "spec", registry["Root"]) or True
    existing = mod.types(action="infer", addr="0x1000")
    assert existing["inferred_types"][0]["kind"] == "existing"
    mod.ida_nalt.get_tinfo = lambda *_args: False
    empty = mod.types(action="infer", addr="0x1000")
    assert empty["inferred_types"] == []
    assert mod.types(action="infer", addr="not-an-address")["error"] is True


def test_read_struct_covers_scalar_pointer_text_and_unmapped_paths():
    mod, _registry, _root, _flags = _load()
    mod.ida_bytes.is_loaded = lambda _ea: True
    mod._compat.get_segment = lambda _ea: pytypes.SimpleNamespace(end_ea=0x2000)
    mod.ida_bytes.get_byte = lambda _ea: 0x11
    mod.ida_bytes.get_word = lambda _ea: 0x2233
    mod.ida_bytes.get_dword = lambda _ea: 0x44556677
    mod.ida_bytes.get_qword = lambda _ea: 0x8899AABBCCDDEEFF
    mod.ida_bytes.get_bytes = lambda _ea, size: b"A" * size
    good = mod.types(action="read_struct", addr="0x1000", name="Root")
    assert good["ok"] is True
    assert good["fields"][0]["value"] == "0x44556677"
    assert good["fields"][1]["value"] == "0x8899aabbccddeeff"
    text = _struct("Text", 3, [_Member("text", 0, _Value("char[3]", 3))])
    _FakeTif.registry["Text"] = text
    text_result = mod.types(action="read_struct", addr="0x1000", name="Text")
    assert text_result["fields"][0]["value"] == "'AAA'"

    assert mod.types(action="read_struct")["code"] == "INVALID_ARGS"
    assert mod.types(action="read_struct", addr="bad", name="Root")["code"] == "INVALID_ARGS"
    mod.ida_bytes.is_loaded = lambda _ea: False
    assert mod.types(action="read_struct", addr="0x1000", name="Root")["code"] == "INVALID_ARGS"
    mod.ida_bytes.is_loaded = lambda _ea: True
    mod._compat.get_segment = lambda _ea: pytypes.SimpleNamespace(end_ea=0x1004)
    assert mod.types(action="read_struct", addr="0x1000", name="Root")["code"] == "INVALID_ARGS"


def test_diff_visualize_and_graph_cover_struct_enum_union_and_mismatch():
    mod, registry, _root, _flags = _load()
    diff = mod.types(action="diff", name="Root", other_name="Other")
    assert diff["ok"] is True
    assert diff["summary"]["changed_fields"] == 1
    assert diff["summary"]["fields_added"] == 1
    enum_diff = mod.types(action="diff", name="Flags", other_name="Flags")
    assert enum_diff["summary"]["changed_values"] == 0
    mismatch = mod.types(action="diff", name="Root", other_name="Flags")
    assert mismatch["type_mismatch"] is True
    assert mod.types(action="diff", name="Root")["code"] == "INVALID_ARGS"

    view = mod.types(action="visualize", name="Root")
    assert view["kind"] == "struct"
    assert "STRUCT Root" in view["visual"]
    assert view["fields"][-1]["is_gap"] is True
    union = _Spec("Union", 8, kind="union", members=[_Member("x", 0, _Value("int", 4))], name="Union")
    registry["Union"] = union
    visual_union = mod.types(action="visualize", name="Union")
    assert visual_union["kind"] == "union"
    assert "Total:" not in visual_union["visual"]
    assert mod.types(action="visualize", name="Flags")["code"] == "INVALID_ARGS"

    graph = mod.types(action="type_graph", name="Root", max_depth=2)
    assert graph["total_structs"] == 2
    assert graph["edges"] == [{"from": "Root", "to": "Child", "field": "child"}]
    assert "via field 'child'" in graph["visual"]
    assert mod.types(action="type_graph", name="Flags")["code"] == "INVALID_ARGS"


def test_propagate_records_code_skips_data_success_and_data_error():
    mod, _registry, _root, _flags = _load()
    mod.ida_bytes.get_flags = lambda _ea: 1
    mod.ida_bytes.is_data = lambda _flags: True
    mod._compat.get_func_start = lambda ea: 0x400000 if ea == 0x1000 else None
    mod.idautils.XrefsTo = lambda _ea, _flags: iter([
        pytypes.SimpleNamespace(frm=0x1000, type=1, iscode=True),
        pytypes.SimpleNamespace(frm=0x2000, type=2, iscode=False),
        pytypes.SimpleNamespace(frm=0x3000, type=3, iscode=False),
        pytypes.SimpleNamespace(frm=0x4000, type=4, iscode=False),
    ])
    mod.ida_funcs.get_func_name = lambda _ea: "caller"
    mod.ida_typeinf.apply_tinfo = lambda ea, *_args: ea == 0x2000
    result = mod.types(action="propagate", addr="0x1000", name="Root")
    assert result["ok"] is True
    assert result["propagated_to"] == ["0x2000"]
    assert result["skipped"] == 2
    assert result["call_sites"][0]["func_name"] == "caller"
    assert result["locations"][-1]["status"] == "skipped"

    mod.ida_bytes.is_data = lambda _flags: False
    skipped = mod.types(action="propagate", addr="0x1000", name="Root")
    assert all(item["status"] == "skipped" for item in skipped["locations"])
    assert mod.types(action="propagate", addr="0x1000", name="Missing")["code"] == "TYPE_ERROR"


def test_enum_values_covers_exact_bitmask_partial_and_no_match():
    mod, _registry, _root, _flags = _load()
    exact = mod.types(action="enum_values", name="Flags", value=1)
    assert exact["value_lookup"]["match_type"] == "exact"
    bitmask = mod.types(action="enum_values", name="Flags", value=3)
    assert bitmask["value_lookup"]["match_type"] == "exact"
    partial = mod.types(action="enum_values", name="Flags", value=5)
    assert partial["value_lookup"]["match_type"] == "partial_bitmask"
    no_match = mod.types(action="enum_values", name="Flags", value=8)
    assert no_match["value_lookup"]["match_type"] == "no_match"
    assert mod.types(action="enum_values")["code"] == "INVALID_ARGS"
    assert mod.types(action="enum_values", name="Root")["code"] == "INVALID_ARGS"


def test_vtable_covers_symbol_resolution_empty_table_and_bad_inputs():
    mod, _registry, _root, _flags = _load()
    slots = {0x1000: 0x2000, 0x1008: 0x2000, 0x1010: 0}
    mod.ida_bytes.get_bytes = lambda ea, size: struct.pack("<Q", slots.get(ea, 0))
    mod.ida_bytes.is_loaded = lambda ea: ea != 0
    mod._compat.get_func_info = lambda ea: pytypes.SimpleNamespace(start_ea=ea, end_ea=ea + 4)
    mod.idc.get_name = lambda ea: "_ZN4Demo3runEv" if ea == 0x2000 else "_ZTV4Demo"
    mod.idc.demangle_name = lambda _name, _mask: "Demo::run()"
    mod.idc.get_name_ea_simple = lambda name: 0x1000 if "Demo" in name else mod.idaapi.BADADDR
    table = mod.types(action="vtable", name="Demo")
    assert table["count"] == 1
    assert table["entries"][0]["name"] == "Demo::run"
    assert table["entries"][0]["size"] == 4

    mod.idc.get_name_ea_simple = lambda _name: mod.idaapi.BADADDR
    mod.idautils.Names = lambda: iter([(0x3000, "unrelated")])
    assert mod.types(action="vtable", name="Missing")["code"] == "NOT_FOUND"
    assert mod.types(action="vtable")["code"] == "INVALID_ARGS"

    mod.idc.get_name_ea_simple = lambda _name: 0x4000
    mod.idc.get_name = lambda _ea: "empty"
    mod.ida_bytes.get_bytes = lambda *_args: b"\x00" * 8
    empty = mod.types(action="vtable", addr="0x4000")
    assert empty["ok"] is True
    assert empty["count"] == 0


def test_type_helpers_cover_resolution_kinds_data_bounds_and_name_aliases():
    mod, registry, _root, _flags = _load()
    tif = _FakeTif()
    assert mod._resolve_type_by_name("Root", tif) is True
    assert mod._resolve_type_by_name("Missing", _FakeTif()) is False
    assert mod._type_kind(registry["Root"]) == "struct"
    assert mod._type_kind(_Value("p", 8, kind="pointer")) == "pointer"
    assert mod._type_kind(_Value("a", 8, kind="array")) == "array"
    assert mod._type_kind(_Value("x", 1)) == "other"
    ptr = _Value("Child *", 8, kind="pointer", pointed=registry["Child"])
    assert mod._extract_struct_name(ptr) == "Child"
    assert mod._extract_struct_name(_Value("int", 4)) is None
    assert mod._struc_error_text(-2).startswith("invalid")
    assert mod._struc_error_text(-99) == "unknown error"
    mod.ida_bytes.is_loaded = lambda ea: ea in (0x1000, 0x1003)
    mod._compat.get_segment = lambda _ea: pytypes.SimpleNamespace(end_ea=0x1004)
    assert mod._is_fully_mapped(0x1000, 4) is True
    assert mod._is_fully_mapped(0x1000, 5) is False
    assert mod._is_fully_mapped(0x1000, 0) is True
    assert mod._is_fully_mapped(0x1000, -1) is False
    mod._compat.get_func_start = lambda _ea: None
    mod.ida_bytes.get_flags = lambda _ea: 1
    mod.ida_bytes.is_data = lambda _flags: True
    assert mod._is_data_location(0x1000) is True
    mod.ida_bytes.is_data = lambda _flags: False
    assert mod._is_data_location(0x1000) is False
    mod._compat.get_func_start = lambda _ea: 0x1000
    assert mod._is_data_location(0x1000) is False


def test_struct_member_actions_cover_ida9_udm_success_and_failures():
    mod, _registry, _root, _flags = _load()
    calls = []

    def add_udm(self, name, typ, offset):
        calls.append(("add", name, str(typ), offset))
        return 0

    def del_udm(self, index):
        calls.append(("del", index))
        return 0

    def rename_udm(self, index, name):
        calls.append(("rename", index, name))
        return 0

    def set_udm_type(self, index, typ):
        calls.append(("type", index, str(typ)))
        return 0

    _FakeTif.add_udm = add_udm
    _FakeTif.del_udm = del_udm
    _FakeTif.rename_udm = rename_udm
    _FakeTif.set_udm_type = set_udm_type
    mod.ida_struct = None

    added = mod.types(action="struct_member_add", struct_name="Root", name="tail",
                      offset=-1, type_str="Child")
    assert added["ok"] is True
    assert added["size"] == 8
    deleted = mod.types(action="struct_member_del", name="Root", member_name="count")
    assert deleted["offset"] == 0
    renamed = mod.types(action="struct_member_rename", struct_name="Root", name="count",
                        new_name="items")
    assert renamed["new_name"] == "items"
    retyped = mod.types(action="struct_member_set_type", struct_name="Root", member_name="count",
                        type_str="Child")
    assert retyped["size"] == 8
    assert [call[0] for call in calls] == ["add", "del", "rename", "type"]

    assert mod.types(action="struct_member_add", struct_name="Root", name="bad")["code"] == "INVALID_ARGS"
    assert mod.types(action="struct_member_del", struct_name="Root", member_name="missing")["code"] == "TYPE_ERROR"
    original = _FakeTif.rename_udm
    del _FakeTif.rename_udm
    unavailable = mod.types(action="struct_member_rename", struct_name="Root", name="count",
                            new_name="x")
    assert unavailable["code"] == "IDA_ERROR"
    _FakeTif.rename_udm = original


def test_classic_struct_member_helpers_cover_resolution_and_ida_errors():
    mod, _registry, _root, _flags = _load()
    classic = pytypes.SimpleNamespace()
    mod.ida_struct = classic
    classic.add_struc_member = lambda *_args: -2
    classic.get_struc_id = lambda _name: 7
    classic.get_struc = lambda _sid: object()
    assert mod._has_classic_struct_api() is True
    tif = _FakeTif()
    tif.spec = _FakeTif.registry["Root"]
    nbytes, error = mod._add_struct_member(tif, "Root", "bad", 0, "Child", None)
    assert nbytes is None
    assert "invalid member offset" in error["message"]
    classic.add_struc_member = lambda *_args: 0
    nbytes, error = mod._add_struct_member(tif, "Root", "ok", 0, "Child", None)
    assert (nbytes, error) == (8, None)
    classic.del_struc_member = lambda *_args: 0
    classic.set_member_name = lambda *_args: 0
    classic.get_member = lambda *_args: object()
    classic.set_member_tinfo = lambda *_args: 0
    assert mod._del_struct_member(tif, "Root", "count") == (0, None)
    assert mod._rename_struct_member(tif, "Root", "count", "n") == (0, None)
    assert mod._set_struct_member_type(tif, "Root", "count", "Child") == (0, 8, None)
    classic.get_struc = lambda _sid: None
    assert mod._struct_sptr("Root") is None


def test_enum_member_actions_cover_classic_and_modern_paths():
    mod, _registry, _root, _flags = _load()
    enum_calls = []
    mod.ida_typeinf.add_enum_member = lambda tid, name, value, bitmask: (
        enum_calls.append(("add", tid, name, value, bitmask)) or 0
    )
    mod.ida_typeinf.set_enum_member_name = lambda tid, old, new: (
        enum_calls.append(("rename", tid, old, new)) or 0
    )
    mod.ida_typeinf.set_enum_member_value = lambda tid, name, value, bitmask: (
        enum_calls.append(("value", tid, name, value, bitmask)) or 0
    )
    _FakeTif.get_tid = lambda self: 42
    added = mod.types(action="enum_member_add", enum_name="Flags", member_name="NEW", enum_value=8)
    assert added["ok"] is True
    renamed = mod.types(action="enum_member_rename", enum_name="Flags", member_name="READ", new_name="R")
    assert renamed["ok"] is True
    revalued = mod.types(action="enum_member_revalue", name="Flags", member_name="READ", value=16)
    assert revalued["value"] == 16
    assert [call[0] for call in enum_calls] == ["add", "rename", "value"]
    assert mod.types(action="enum_member_add", enum_name="Flags", member_name="X")["code"] == "INVALID_ARGS"
    assert mod.types(action="enum_member_rename", enum_name="Flags", member_name="X")["code"] == "INVALID_ARGS"

    del mod.ida_typeinf.add_enum_member
    del mod.ida_typeinf.set_enum_member_name
    del mod.ida_typeinf.set_enum_member_value
    modern_calls = []
    enum_tif = _FakeTif()
    enum_tif.spec = _FakeTif.registry["Flags"]
    _FakeTif.add_edm = lambda self, name, value, bitmask, *args: modern_calls.append(("add", name, value)) or 0
    _FakeTif.rename_edm = lambda self, index, name: modern_calls.append(("rename", index, name)) or 0
    _FakeTif.del_edm = lambda self, index: modern_calls.append(("del", index)) or 0
    assert mod._add_enum_member(enum_tif, "X", 9) is None
    assert mod._rename_enum_member(enum_tif, "READ", "R2") is None
    assert mod._revalue_enum_member(enum_tif, "READ", 10) is None
    assert [call[0] for call in modern_calls] == ["add", "rename", "del", "add"]


def test_til_delete_export_and_import_cover_filters_and_error_modes(tmp_path):
    mod, _registry, _root, _flags = _load()
    mod.validate_path_safe = lambda value: (value, None)
    deleted = mod.types(action="til_delete", name="Root")
    assert deleted["deleted"] is True
    assert mod.types(action="til_delete")["code"] == "INVALID_ARGS"
    mod.ida_typeinf.get_idati = lambda: None
    assert mod.types(action="til_delete", name="Root")["code"] == "IDA_ERROR"
    mod.ida_typeinf.get_idati = object

    exported_path = tmp_path / "types.h"
    exported = mod.types(action="til_export", path=str(exported_path), til_filter="Root")
    assert exported["exported_count"] == 1
    assert "struct Root" in exported_path.read_text(encoding="utf-8")
    assert mod.types(action="til_export")["code"] == "INVALID_ARGS"
    del mod.ida_typeinf.get_ordinal_qty
    assert mod.types(action="til_export", path=str(tmp_path / "none.h"))["code"] == "IDA_ERROR"
    mod.ida_typeinf.get_ordinal_qty = lambda _til: 6

    own_path = tmp_path / "own.h"
    own_path.write_text(
        "/* Exported from IDA type library. Import with types(action='til_import'). */\n\n"
        "struct Root\n{\n  int count;\n};\n",
        encoding="utf-8",
    )
    mod.ida_typeinf.parse_decl = lambda tif, _til, _decl, _flags: setattr(tif, "spec", _root) or "Root"
    mod.ida_typeinf.tinfo_t = _FakeTif
    _FakeTif.set_named_type = lambda self, _til, name, _flags: True
    imported = mod.types(action="til_import", path=str(own_path))
    assert imported["ok"] is True
    assert imported["imported"] == ["Root"]

    plain_path = tmp_path / "plain.h"
    plain_path.write_text("struct Plain {};", encoding="utf-8")
    mod.idc.parse_decls = lambda _content, _flags: 0
    assert mod.types(action="til_import", path=str(plain_path))["ok"] is True
    plain_path.write_text("", encoding="utf-8")
    assert mod.types(action="til_import", path=str(plain_path))["code"] == "INVALID_ARGS"
    assert mod.types(action="til_import", path=str(tmp_path / "missing.h"))["code"] == "FILE_NOT_FOUND"
    mod.idc.parse_decls = lambda _content, _flags: 1
    plain_path.write_text("bad", encoding="utf-8")
    assert mod.types(action="til_import", path=str(plain_path))["code"] == "TYPE_ERROR"


@pytest.mark.parametrize("action", ["unknown", "list", "get"])
def test_types_boundary_errors_remain_explicit(action):
    mod, _registry, _root, _flags = _load()
    if action == "unknown":
        result = mod.types(action=action)
        assert result["code"] == "INVALID_ARGS"
    elif action == "list":
        mod.ida_typeinf.get_idati = lambda: None
        assert mod.types(action=action)["code"] == "IDA_ERROR"
    else:
        mod._resolve_type_by_name = lambda *_args: False
        assert mod.types(action=action, name="Nope")["code"] == "TYPE_ERROR"
