"""Regression tests for p05_type_members (WO-S4).

Covers per-member struct/enum editing + TIL delete/export/import on the
`types` tool (paper section 3.19 item 4 and section 3.2):

- struct_member_add / struct_member_rename / struct_member_del mutate a named
  struct and are observable through types(get).
- struct_member_set_type retypes a member from a C type string.
- enum_member_add / enum_member_rename / enum_member_revalue mutate a named
  enum and are observable through types(get).
- til_delete removes a named type from the local type library.
- til_export writes a C header file (filtered and unfiltered).
- til_import loads a C header back into the local type library.
- The IDA 9 fallback path (no `ida_struct` module / no classic enum member
  functions) still works via tinfo_t methods (add_udm/del_udm/rename_udm/
  set_udm_type, add_edm/rename_edm/del_edm).

All tests are hermetic: they run on fake IDA modules (no live IDA).
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

BADADDR = 0xFFFFFFFFFFFFFFFF

# ---------------------------------------------------------------------------
# Fake IDA modules (classic IDA 7/8 surface + IDA 9 tinfo_t fallback surface)
# ---------------------------------------------------------------------------


class FakeTypeLib:
    """In-memory type library holding FakeTinfo objects by name/ordinal/tid."""

    def __init__(self):
        self.types = {}          # name -> FakeTinfo
        self._ordinal_map = {}   # ordinal -> name
        self._next_ordinal = 1
        self.calls = []          # record of every struct/enum/til mutation

    def get(self, name):
        return self.types.get(name)

    def by_tid(self, tid):
        for t in self.types.values():
            if t._tid == tid:
                return t
        return None

    def by_ordinal(self, ordinal):
        name = self._ordinal_map.get(ordinal)
        return self.types.get(name) if name else None

    def alloc_ordinal(self):
        n = self._next_ordinal
        self._next_ordinal += 1
        return n

    def register(self, tif, ordinal=None):
        if tif.name is None:
            return None
        if ordinal is None:
            ordinal = self.alloc_ordinal()
        self.types[tif.name] = tif
        self._ordinal_map[ordinal] = tif.name
        tif._ordinal = ordinal
        return ordinal


class FakeTinfo:
    _tid_counter = [1000]

    def __init__(self, lib, name=None, kind=None, members=None, size=None):
        self.lib = lib
        self.name = name
        self.kind = kind
        self.members = members if members is not None else []
        self._size = size
        self._decl = None
        self._ordinal = None
        self._tid = FakeTinfo._tid_counter[0]
        FakeTinfo._tid_counter[0] += 1

    # ---- tinfo_t read protocol used by types.py ----
    def _copy_from(self, t):
        self.name = t.name
        self.kind = t.kind
        self.members = t.members
        self._size = t._size
        self._tid = t._tid
        self._decl = t._decl
        self._ordinal = t._ordinal

    def get_named_type(self, til, type_name):
        t = self.lib.get(type_name)
        if t is None:
            return False
        self._copy_from(t)
        return True

    def get_type_by_tid(self, tid):
        t = self.lib.by_tid(tid)
        if t is None:
            return False
        self._copy_from(t)
        return True

    def get_numbered_type(self, til, ordinal):
        t = self.lib.by_ordinal(ordinal)
        if t is None:
            return False
        self._copy_from(t)
        return True

    def get_type_name(self):
        return self.name

    def get_tid(self):
        return self._tid

    def get_ordinal(self):
        return self._ordinal or 0

    def is_struct(self):
        return self.kind == "struct"

    def is_union(self):
        return self.kind == "union"

    def is_enum(self):
        return self.kind == "enum"

    def get_size(self):
        if self._size is not None:
            return self._size
        if self.kind == "enum":
            return 4
        if self.kind in ("struct", "union"):
            return max((m["offset"] + m.get("size", 0) for m in self.members), default=0)
        return 4

    def get_udt_details(self, udt):
        if self.kind not in ("struct", "union"):
            return False
        udt._fill(self.members)
        return True

    def get_enum_details(self, ei):
        if self.kind != "enum":
            return False
        ei._fill(self.members)
        return True

    # ---- IDA 9 tinfo_t mutation methods (fallback path) ----
    def add_udm(self, name, typ, bit_offset):
        mtype = getattr(typ, "_decl", None) or str(typ)
        msize = getattr(typ, "get_size", lambda: 4)()
        off = bit_offset // 8
        self.members.append({"name": name, "type": mtype, "size": msize, "offset": off})
        self.members.sort(key=lambda m: m["offset"])
        self._size = None
        return 0

    def del_udm(self, index, etf_flags=0):
        if 0 <= index < len(self.members):
            del self.members[index]
            self._size = None
            return 0
        return -5

    def rename_udm(self, index, name, etf_flags=0):
        if 0 <= index < len(self.members):
            self.members[index]["name"] = name
            return 0
        return -5

    def set_udm_type(self, index, tif, etf_flags=0, **kw):
        if 0 <= index < len(self.members):
            m = self.members[index]
            m["type"] = getattr(tif, "_decl", None) or str(tif)
            m["size"] = getattr(tif, "get_size", lambda: 4)()
            self._size = None
            return 0
        return -5

    def add_edm(self, name, value, bmask=-1, etf_flags=0, idx=-1):
        nm = {"name": name, "value": value}
        if idx == -1:
            self.members.append(nm)
        else:
            self.members.insert(min(idx, len(self.members)), nm)
        return 0

    def rename_edm(self, idx, name, etf_flags=0):
        if 0 <= idx < len(self.members):
            self.members[idx]["name"] = name
            return 0
        return -5

    def set_named_type(self, til, name, ntf_flags=0):
        """Mirror tinfo_t.set_named_type: save this type into the til by name."""
        self.name = name
        til.register(self)
        return 1

    def del_edm(self, idx, etf_flags=0):
        if 0 <= idx < len(self.members):
            del self.members[idx]
            return 0
        return -5

    def __str__(self):
        if self.kind in ("struct", "union") and self.name:
            body = ";\n  ".join(f"{m.get('type', 'int')} {m['name']}" for m in self.members)
            kw = "union" if self.kind == "union" else "struct"
            return f"{kw} {self.name}\n{{\n  {body};\n}};"
        if self.kind == "enum" and self.name:
            body = ",\n  ".join(f"{m['name']} = {m.get('value', 0)}" for m in self.members)
            return f"enum {self.name}\n{{\n  {body}\n}};"
        return self._decl or "int"


class FakeUdt:
    def __init__(self):
        self.items = []

    def _fill(self, members):
        self.items = [FakeMember(m["name"], m.get("offset", 0) * 8,
                                 m.get("type", "int"), m.get("size", 0)) for m in members]

    def size(self):
        return len(self.items)

    def __getitem__(self, i):
        return self.items[i]

    def __iter__(self):
        return iter(self.items)


class FakeEnumData:
    def __init__(self):
        self.items = []

    def _fill(self, members):
        self.items = [FakeMember(m["name"], 0, "int", 0, m.get("value", 0)) for m in members]

    def size(self):
        return len(self.items)

    def __getitem__(self, i):
        return self.items[i]

    def __iter__(self):
        return iter(self.items)


class FakeMember:
    def __init__(self, name, offset_bits, type_str, size=0, value=None):
        self.name = name
        self.offset = offset_bits
        self.type_str = type_str
        self.size = size
        self.value = value
        self.gap = False

    def is_gap(self):
        return self.gap

    @property
    def type(self):
        return FakeTypeRef(self.type_str, self.size)


class FakeTypeRef:
    def __init__(self, type_str, size):
        self.type_str = type_str
        self.size = size

    def get_size(self):
        return self.size

    def __str__(self):
        return self.type_str


# Mini C-type model used by the fake parse_decl.
_TYPES = {
    "char": 1, "signed char": 1, "unsigned char": 1, "int8_t": 1, "uint8_t": 1,
    "short": 2, "unsigned short": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "unsigned int": 4, "int32_t": 4, "uint32_t": 4, "float": 4,
    "long": 8, "unsigned long": 8, "long long": 8, "int64_t": 8, "uint64_t": 8, "double": 8,
}


def _type_size(t):
    t = t.strip()
    if t.endswith("*"):
        return 8
    arr = re.match(r"([\w ]+)\s*\[\s*(\d+)\s*\]", t)
    if arr:
        return _TYPES.get(arr.group(1).strip(), 1) * int(arr.group(2))
    return _TYPES.get(t, 0)


def _parse_decl_fake(tif, decl):
    d = (decl or "").strip()
    m = re.match(r"enum\s+(\w+)\s*\{(.*)\}", d, re.S)
    if m:
        name = m.group(1)
        members = []
        for part in m.group(2).split(","):
            part = part.strip()
            if not part:
                continue
            mm = re.match(r"(\w+)\s*(?:=\s*(-?\d+))?", part)
            if mm:
                members.append({"name": mm.group(1), "value": int(mm.group(2) or 0)})
        tif.name = name
        tif.kind = "enum"
        tif.members = members
        tif._size = 4
        tif._decl = d
        return True
    m = re.match(r"(struct|union)\s+(\w+)\s*\{(.*)\}", d, re.S)
    if m:
        kind = m.group(1)
        name = m.group(2)
        members = []
        off = 0
        for part in m.group(3).split(";"):
            part = part.strip()
            if not part:
                continue
            fm = re.match(r"(.+?)\s+(\w+)\s*$", part)
            if fm:
                mtype = fm.group(1).strip()
                mname = fm.group(2).strip()
                msize = _type_size(mtype)
                if msize:
                    members.append({"name": mname, "type": mtype, "size": msize, "offset": off})
                    off += msize
        tif.name = name
        tif.kind = kind
        tif.members = members
        tif._size = off
        tif._decl = d
        return True
    sz = _type_size(d)
    if sz:
        tif.kind = "int"
        tif.name = None
        tif._size = sz
        tif._decl = d
        return True
    return None


def _make_typeinf_module(lib, *, classic_enum=True):
    m = types.ModuleType("ida_typeinf")
    m.NTF_TYPE = 1
    m.PT_SIL = 1
    m.PT_TYP = 2
    m.TERR_OK = 0
    m.tinfo_t = lambda: FakeTinfo(lib)
    m.get_idati = lambda: lib
    m.get_ordinal_qty = lambda til: len(til._ordinal_map)
    m.get_ordinal_count = lambda til: len(til._ordinal_map)
    m.udt_type_data_t = FakeUdt
    m.enum_type_data_t = FakeEnumData
    m.get_named_type_tid = lambda name: (lib.get(name)._tid if lib.get(name) else BADADDR)
    m.parse_decl = lambda tif, til, decl, flags: _parse_decl_fake(tif, decl)
    m.alloc_type_ordinal = lambda til: til.alloc_ordinal()

    def _set_numbered_type(til, ordinal, ntf, name, tif):
        tif.name = name
        til.register(tif, ordinal)
        return True

    m.set_numbered_type = _set_numbered_type

    def _del_named_type(til, name, ntf):
        lib.calls.append(("del_named_type", name, ntf))
        if name in til.types:
            del til.types[name]
            return True
        return False

    m.del_named_type = _del_named_type

    if classic_enum:
        def _add_enum_member(eid, name, value, bmask=-1):
            lib.calls.append(("add_enum_member", eid, name, value, bmask))
            t = lib.by_tid(eid)
            if t is None:
                return -1
            t.members.append({"name": name, "value": value})
            return 0

        def _set_enum_member_name(eid, name, newname):
            lib.calls.append(("set_enum_member_name", eid, name, newname))
            t = lib.by_tid(eid)
            if t is None:
                return -1
            for mm in t.members:
                if mm["name"] == name:
                    mm["name"] = newname
                    return 0
            return -5

        def _set_enum_member_value(eid, name, value, bmask=-1):
            lib.calls.append(("set_enum_member_value", eid, name, value, bmask))
            t = lib.by_tid(eid)
            if t is None:
                return -1
            for mm in t.members:
                if mm["name"] == name:
                    mm["value"] = value
                    return 0
            return -5

        m.add_enum_member = _add_enum_member
        m.set_enum_member_name = _set_enum_member_name
        m.set_enum_member_value = _set_enum_member_value
    return m


def _make_struct_module(lib):
    m = types.ModuleType("ida_struct")

    def _get_struc_id(name):
        t = lib.get(name)
        if t and t.kind in ("struct", "union"):
            return t._tid
        return BADADDR

    m.get_struc_id = _get_struc_id

    class _Struc:
        def __init__(self, tif):
            self.tif = tif

    def _get_struc(sid):
        t = lib.by_tid(sid)
        return _Struc(t) if t else None

    m.get_struc = _get_struc

    class _Member:
        def __init__(self, offset_bits):
            self.offset = offset_bits

    def _get_member(sptr, offset):
        return _Member(offset * 8)

    m.get_member = _get_member

    def _add_struc_member(sptr, name, offset, flags, mt, nbytes):
        lib.calls.append(("add_struc_member", sptr.tif.name, name, offset, flags,
                          getattr(mt, "_decl", None), nbytes))
        tif = sptr.tif
        off = tif.get_size() if offset < 0 else offset
        if any(mm["offset"] == off for mm in tif.members):
            return -2
        mtype = getattr(mt, "_decl", None) or str(mt)
        tif.members.append({"name": name, "type": mtype, "size": nbytes, "offset": off})
        tif.members.sort(key=lambda x: x["offset"])
        tif._size = None
        return 0

    m.add_struc_member = _add_struc_member

    def _del_struc_member(sptr, offset):
        lib.calls.append(("del_struc_member", sptr.tif.name, offset))
        tif = sptr.tif
        for i, mm in enumerate(tif.members):
            if mm["offset"] == offset:
                del tif.members[i]
                tif._size = None
                return 0
        return -5

    m.del_struc_member = _del_struc_member

    def _set_member_name(sptr, offset, name):
        lib.calls.append(("set_member_name", sptr.tif.name, offset, name))
        tif = sptr.tif
        for mm in tif.members:
            if mm["offset"] == offset:
                mm["name"] = name
                return 0
        return -5

    m.set_member_name = _set_member_name

    def _set_member_tinfo(sptr, member, offset, mt, flags):
        lib.calls.append(("set_member_tinfo", sptr.tif.name, member, offset,
                          getattr(mt, "_decl", None), flags))
        tif = sptr.tif
        for mm in tif.members:
            if mm["offset"] == offset:
                mm["type"] = getattr(mt, "_decl", None) or str(mt)
                mm["size"] = mt.get_size()
                tif._size = None
                return 0
        return -5

    m.set_member_tinfo = _set_member_tinfo
    return m


def _make_idc_module(lib):
    m = types.ModuleType("idc")

    def _get_struc_id(name):
        t = lib.get(name)
        if t and t.kind in ("struct", "union"):
            return t._tid
        return BADADDR

    m.get_struc_id = _get_struc_id
    m.parse_decls = lambda content, flags=0: (lib.calls.append(("parse_decls", content, flags)) or 0)
    return m


def _make_idaapi():
    m = types.ModuleType("idaapi")
    m.BADADDR = BADADDR
    m.MFF_FAST = 0
    m.MFF_READ = 1
    m.MFF_WRITE = 2
    m.execute_sync = lambda fn, flags=0: fn()
    return m


class _FakeMCPError:
    """Full MCPError code set (the isolated-loader stub omits TYPE_ERROR)."""

    INVALID_ARGS = "INVALID_ARGS"
    DECOMPILER_FAILED = "DECOMPILER_FAILED"
    DECOMPILER_UNAVAILABLE = "DECOMPILER_UNAVAILABLE"
    FUNCTION_NOT_FOUND = "FUNCTION_NOT_FOUND"
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    NO_RESULTS = "NO_RESULTS"
    NOT_FOUND = "NOT_FOUND"
    IDA_ERROR = "IDA_ERROR"
    TYPE_ERROR = "TYPE_ERROR"


def _load_types(*, classic_enum=True, struct_api=True):
    """Build the shared fake state and load the types tool module."""
    lib = FakeTypeLib()
    idaapi = _make_idaapi()
    idc = _make_idc_module(lib)
    typeinf = _make_typeinf_module(lib, classic_enum=classic_enum)
    sys.modules["idaapi"] = idaapi
    sys.modules["idc"] = idc
    sys.modules["ida_typeinf"] = typeinf
    if struct_api:
        sys.modules["ida_struct"] = _make_struct_module(lib)
    else:
        # A blank module: `import ida_struct` succeeds but has no member API,
        # so the tinfo_t fallback path is exercised (the IDA 9 situation).
        sys.modules["ida_struct"] = types.ModuleType("ida_struct")
    overrides = {
        "idaapi": idaapi,
        "idc": idc,
        "ida_typeinf": typeinf,
        "validate_path_safe": lambda path, **kw: (path, None),
        "MCPError": _FakeMCPError,
    }
    mod = load_tool_module("types", common_overrides=overrides)
    return mod, lib


def _member_names(mod, struct_name):
    r = mod.types(action="get", name=struct_name)
    assert r.get("ok"), r
    return {m["name"]: (m["offset"], m["size"]) for m in r["members"]}


def _enum_members(mod, enum_name):
    r = mod.types(action="get", name=enum_name)
    assert r.get("ok"), r
    return {m["name"]: m["value"] for m in r["members"]}


# ---------------------------------------------------------------------------
# struct member lifecycle (classic ida_struct path)
# ---------------------------------------------------------------------------

def test_struct_member_add_rename_del_lifecycle():
    mod, lib = _load_types()

    r = mod.types(action="declare", decl="struct Periph { uint32_t ctrl; };")
    assert r.get("ok"), r
    assert r["name"] == "Periph"

    # add a member at offset 4
    r = mod.types(action="struct_member_add", struct_name="Periph",
                  member_name="data", offset=4, type_str="uint8_t[8]")
    assert r.get("ok"), r
    assert r["member"] == "data"
    assert r["size"] == 8
    assert r["offset"] == 4
    assert ("add_struc_member", "Periph", "data", 4, 0, "uint8_t[8]", 8) in lib.calls

    names = _member_names(mod, "Periph")
    assert names == {"ctrl": (0, 4), "data": (4, 8)}

    # rename data -> payload
    r = mod.types(action="struct_member_rename", struct_name="Periph",
                  member_name="data", new_name="payload")
    assert r.get("ok"), r
    assert r["new_name"] == "payload"
    names = _member_names(mod, "Periph")
    assert names == {"ctrl": (0, 4), "payload": (4, 8)}

    # delete ctrl
    r = mod.types(action="struct_member_del", struct_name="Periph", member_name="ctrl")
    assert r.get("ok"), r
    assert r["offset"] == 0
    assert ("del_struc_member", "Periph", 0) in lib.calls
    assert _member_names(mod, "Periph") == {"payload": (4, 8)}


def test_struct_member_set_type():
    mod, lib = _load_types()
    mod.types(action="declare", decl="struct Pkt { uint32_t len; };")

    r = mod.types(action="struct_member_set_type", struct_name="Pkt",
                  member_name="len", type_str="uint16_t")
    assert r.get("ok"), r
    assert r["type"] == "uint16_t"
    assert r["size"] == 2
    call = lib.calls[-1]
    assert call[0] == "set_member_tinfo"
    assert call[1] == "Pkt"
    assert call[3] == 0      # member byte offset
    assert call[4] == "uint16_t"
    assert _member_names(mod, "Pkt") == {"len": (0, 2)}


def test_struct_member_add_size_only_uses_byte_blob():
    mod, lib = _load_types()
    mod.types(action="declare", decl="struct Blob { uint32_t hdr; };")

    r = mod.types(action="struct_member_add", struct_name="Blob",
                  member_name="raw", offset=-1, size=16)
    assert r.get("ok"), r
    assert r["size"] == 16
    assert ("add_struc_member", "Blob", "raw", -1, 0, "char[16]", 16) in lib.calls
    assert _member_names(mod, "Blob") == {"hdr": (0, 4), "raw": (4, 16)}


def test_struct_member_edit_errors():
    mod, _lib = _load_types()

    # missing struct
    r = mod.types(action="struct_member_add", member_name="x", offset=0, type_str="int")
    assert r.get("ok") is False and r["code"] == "INVALID_ARGS"

    # missing member
    r = mod.types(action="struct_member_del", struct_name="Nope", member_name="x")
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"

    # unknown struct
    r = mod.types(action="struct_member_add", struct_name="Nope",
                  member_name="x", offset=0, type_str="int")
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"

    # missing type_str/size
    r = mod.types(action="struct_member_add", struct_name="Nope", member_name="x", offset=0)
    assert r.get("ok") is False and r["code"] == "INVALID_ARGS"

    # member not in declared struct
    mod.types(action="declare", decl="struct S { int a; };")
    r = mod.types(action="struct_member_del", struct_name="S", member_name="nope")
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"
    assert "not found" in r["message"]


def test_struct_member_alias_args_name_for_member():
    # `name=` can carry the member name when `struct_name` is given explicitly.
    mod, _lib = _load_types()
    mod.types(action="declare", decl="struct S { int a; };")
    r = mod.types(action="struct_member_add", struct_name="S", name="b",
                  offset=4, type_str="char[2]")
    assert r.get("ok"), r
    assert r["member"] == "b"
    assert _member_names(mod, "S") == {"a": (0, 4), "b": (4, 2)}


# ---------------------------------------------------------------------------
# enum member lifecycle (classic ida_typeinf path)
# ---------------------------------------------------------------------------

def test_enum_member_add_rename_revalue_lifecycle():
    mod, lib = _load_types()

    r = mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")
    assert r.get("ok"), r
    assert r["name"] == "Mode"

    # add AUTO = 2
    r = mod.types(action="enum_member_add", enum_name="Mode",
                  member_name="AUTO", enum_value=2)
    assert r.get("ok"), r
    assert r["value"] == 2
    assert any(c[0] == "add_enum_member" and c[2] == "AUTO" and c[3] == 2 for c in lib.calls)
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "AUTO": 2}

    # rename AUTO -> HOLD
    r = mod.types(action="enum_member_rename", enum_name="Mode",
                  member_name="AUTO", new_name="HOLD")
    assert r.get("ok"), r
    assert r["new_name"] == "HOLD"
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "HOLD": 2}

    # revalue HOLD = 5
    r = mod.types(action="enum_member_revalue", enum_name="Mode",
                  member_name="HOLD", enum_value=5)
    assert r.get("ok"), r
    assert r["value"] == 5
    assert any(c[0] == "set_enum_member_value" and c[2] == "HOLD" and c[3] == 5 for c in lib.calls)
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "HOLD": 5}


def test_enum_member_value_param_alias():
    # `value=` is accepted as an alias for `enum_value=` (the shared legacy
    # enum-value parameter).
    mod, _lib = _load_types()
    mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")
    r = mod.types(action="enum_member_add", enum_name="Mode",
                  member_name="AUTO", value=7)
    assert r.get("ok"), r
    assert r["value"] == 7
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "AUTO": 7}


def test_enum_member_edit_errors():
    mod, _lib = _load_types()

    r = mod.types(action="enum_member_add", enum_name="Mode", member_name="X", enum_value=1)
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"

    r = mod.types(action="enum_member_revalue", enum_name="Mode",
                  member_name="X", enum_value=1)
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"

    mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")
    r = mod.types(action="enum_member_add", enum_name="Mode", member_name="X")
    assert r.get("ok") is False and r["code"] == "INVALID_ARGS"


# ---------------------------------------------------------------------------
# TIL delete / export / import
# ---------------------------------------------------------------------------

def test_til_delete_removes_named_type():
    mod, lib = _load_types()
    mod.types(action="declare", decl="struct Gone { int a; };")
    assert _member_names(mod, "Gone") == {"a": (0, 4)}  # declared

    r = mod.types(action="til_delete", name="Gone")
    assert r.get("ok"), r
    assert r["deleted"] is True
    assert ("del_named_type", "Gone", 1) in lib.calls

    r = mod.types(action="get", name="Gone")
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"


def test_til_delete_missing_type_errors():
    mod, _lib = _load_types()
    r = mod.types(action="til_delete", name="DoesNotExist")
    assert r.get("ok") is False and r["code"] == "TYPE_ERROR"

    r = mod.types(action="til_delete")
    assert r.get("ok") is False and r["code"] == "INVALID_ARGS"


def test_til_export_writes_filtered_header(tmp_path):
    mod, lib = _load_types()
    mod.types(action="declare", decl="struct Periph { uint32_t ctrl; };")
    mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")

    out = tmp_path / "periph.h"
    r = mod.types(action="til_export", path=str(out), til_filter="Periph")
    assert r.get("ok"), r
    assert r["exported_count"] == 1
    assert r["types"] == [{"name": "Periph", "ordinal": 1}]
    assert out.exists()

    content = out.read_text(encoding="utf-8")
    assert "struct Periph" in content
    assert "ctrl" in content
    assert "Mode" not in content  # filtered out


def test_til_export_default_filter_exports_all(tmp_path):
    mod, _lib = _load_types()
    mod.types(action="declare", decl="struct Periph { uint32_t ctrl; };")
    mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")

    out = tmp_path / "all.h"
    r = mod.types(action="til_export", path=str(out))
    assert r.get("ok"), r
    assert r["exported_count"] == 2
    content = out.read_text(encoding="utf-8")
    assert "struct Periph" in content
    assert "enum Mode" in content


def test_til_import_loads_header_back(tmp_path):
    mod, lib = _load_types()
    mod.types(action="declare", decl="struct Periph { uint32_t ctrl; };")

    out = tmp_path / "periph.h"
    mod.types(action="til_export", path=str(out), til_filter="Periph")

    r = mod.types(action="til_import", path=str(out))
    assert r.get("ok"), r
    assert r["errors"] == 0
    assert "Periph" in r["imported"]
    # The exported type is present in the til after import (idc.parse_decls
    # silently creates nothing on IDA 9.x, so import goes per-declaration).
    assert lib.get("Periph") is not None


def test_til_import_missing_file_errors(tmp_path):
    mod, _lib = _load_types()
    r = mod.types(action="til_import", path=str(tmp_path / "nope.h"))
    assert r.get("ok") is False and r["code"] == "FILE_NOT_FOUND"

    r = mod.types(action="til_import")
    assert r.get("ok") is False and r["code"] == "INVALID_ARGS"


def test_til_carry_riscv_firmware_peripheral_types(tmp_path):
    """Opaque raw-blob firmware workflow: build RISC-V MMIO peripheral types
    (the iterative-firmware-peripheral loop), carry them across sessions via
    til_export, then re-import them into the next session's local TIL."""
    mod, lib = _load_types()

    # Session A: a bare-metal RISC-V firmware engineer names the MMIO block
    # registers and their mode constants directly from the datasheet.
    r = mod.types(action="declare",
                  decl="struct mmio_gpio { uint32_t MODER; uint32_t OTYPER; uint32_t BSRR; };")
    assert r.get("ok"), r
    mod.types(action="declare", decl="enum gpio_mode { INPUT = 0, OUTPUT = 1, ALTERNATE = 2 };")

    # Carry: export the peripheral types to a header for the next session.
    out = tmp_path / "gpio_types.h"
    r = mod.types(action="til_export", path=str(out), til_filter="mmio_gpio")
    assert r.get("ok"), r
    assert r["exported_count"] == 1
    content = out.read_text(encoding="utf-8")
    assert "struct mmio_gpio" in content
    assert "MODER" in content and "BSRR" in content

    # Session B (fresh local TIL): the header is re-imported.
    r = mod.types(action="til_import", path=str(out))
    assert r.get("ok"), r
    assert r["errors"] == 0
    assert "mmio_gpio" in r["imported"]
    assert lib.get("mmio_gpio") is not None

    # And a fresh raw blob can be shaped against the carried struct.
    mod.types(action="declare", decl="struct mmio_gpio { uint32_t MODER; uint32_t OTYPER; uint32_t BSRR; };")
    r = mod.types(action="struct_member_add", struct_name="mmio_gpio",
                  member_name="IDR", offset=12, type_str="uint32_t")
    assert r.get("ok"), r
    assert _member_names(mod, "mmio_gpio") == {
        "MODER": (0, 4), "OTYPER": (4, 4), "BSRR": (8, 4), "IDR": (12, 4),
    }


# ---------------------------------------------------------------------------
# IDA 9 fallback path (no ida_struct module / no classic enum functions)
# ---------------------------------------------------------------------------

def test_ida9_struct_fallback_uses_tinfo_methods():
    mod, lib = _load_types(struct_api=False)
    mod.types(action="declare", decl="struct S { int a; };")

    r = mod.types(action="struct_member_add", struct_name="S",
                  member_name="b", offset=4, type_str="char[2]")
    assert r.get("ok"), r
    assert r["size"] == 2
    assert _member_names(mod, "S") == {"a": (0, 4), "b": (4, 2)}

    r = mod.types(action="struct_member_rename", struct_name="S",
                  member_name="b", new_name="c")
    assert r.get("ok"), r
    assert _member_names(mod, "S") == {"a": (0, 4), "c": (4, 2)}

    r = mod.types(action="struct_member_set_type", struct_name="S",
                  member_name="c", type_str="uint16_t")
    assert r.get("ok"), r
    assert _member_names(mod, "S") == {"a": (0, 4), "c": (4, 2)}

    r = mod.types(action="struct_member_del", struct_name="S", member_name="a")
    assert r.get("ok"), r
    assert _member_names(mod, "S") == {"c": (4, 2)}

    # No classic ida_struct call should have happened.
    assert all(not c[0].startswith("add_struc_member") and
               not c[0].startswith("del_struc_member") and
               not c[0].startswith("set_member_name") and
               not c[0].startswith("set_member_tinfo") for c in lib.calls)


def test_ida9_enum_fallback_uses_tinfo_methods():
    mod, lib = _load_types(classic_enum=False)
    mod.types(action="declare", decl="enum Mode { OFF = 0, ON = 1 };")

    r = mod.types(action="enum_member_add", enum_name="Mode",
                  member_name="AUTO", enum_value=2)
    assert r.get("ok"), r
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "AUTO": 2}

    r = mod.types(action="enum_member_rename", enum_name="Mode",
                  member_name="AUTO", new_name="HOLD")
    assert r.get("ok"), r
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "HOLD": 2}

    r = mod.types(action="enum_member_revalue", enum_name="Mode",
                  member_name="HOLD", enum_value=5)
    assert r.get("ok"), r
    assert _enum_members(mod, "Mode") == {"OFF": 0, "ON": 1, "HOLD": 5}

    assert all(not c[0].startswith("add_enum_member") and
               not c[0].startswith("set_enum_member_name") and
               not c[0].startswith("set_enum_member_value") for c in lib.calls)


def test_ida9_til_carries_over(tmp_path):
    # The TIL export/import is version-agnostic (C-header text) and works with
    # the IDA 9 fallback modules in place too.
    mod, lib = _load_types(struct_api=False, classic_enum=False)
    mod.types(action="declare", decl="struct Periph { uint32_t ctrl; };")

    out = tmp_path / "periph.h"
    r = mod.types(action="til_export", path=str(out), til_filter="Periph")
    assert r.get("ok"), r
    assert out.exists()
    assert "struct Periph" in out.read_text(encoding="utf-8")

    r = mod.types(action="til_import", path=str(out))
    assert r.get("ok"), r
    assert r["errors"] == 0
