"""Regression tests for work order WO-S2 — raw-blob authoring + undo (paper §3.19 item 2).

Pins the four cheapest "make raw blobs analyzable + reversible" primitives added
to the modify tool:

- create_data: define a data item (or a run of them) over raw bytes so a blob
  becomes analyzable without redeclaring types. ``item_type`` selects the item
  kind (byte|word|dword|qword|pointer|array); ``count`` lays that many
  consecutive items. ``pointer`` and ``array`` both lay FF_DWORD (4-byte)
  elements — the vector-table / MMIO-table case on headerless firmware.
- create_strlit: define a C/UTF-16/UTF-32 string literal over [addr, addr+size)
  for blobs where IDA's auto-analysis found no strlit marks.
- undo_begin / undo_end: bracket a batch-patch or experiment; ``undo_end``
  commits. Recommended around ida_batch runs. These two take no address.
- All four ride the existing ``governed`` pre-check (create_data/create_strlit
  map to the type_change governance operation; undo_begin/undo_end bracket edits
  and carry no address).

All tests run standalone with _FakeIda-style fakes — no live IDA, no MCP server.
"""
import os
import struct
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module

# ---------------------------------------------------------------------------
# Fake IDA bytes surface (in-memory IDB)
# ---------------------------------------------------------------------------

class _FakeIdb:
    """In-memory fake of the ida_bytes surface modify.py touches."""

    def __init__(self, base=0x1000, length=0x1000):
        self.base = base
        self.mem = bytearray(length)
        self.items = {}       # item start ea -> {"flags": int, "size": int, "tid": int}
        self.strlits = {}     # item start ea -> {"strtype": int, "size": int}
        self.undo_depth = 0
        self.undo_events = []  # "begin" / "end" in call order

    # ---- ida_bytes API used by modify ----
    def patch_bytes(self, ea, data):
        off = ea - self.base
        for i, b in enumerate(data):
            self.mem[off + i] = b

    def _overlaps(self, ea, size):
        for start, info in self.items.items():
            if ea < start + info["size"] and start < ea + size:
                return True
        return False

    def create_data(self, ea, flags, size, tid):
        if self._overlaps(ea, size):
            return 0
        self.items[ea] = {"flags": flags, "size": size, "tid": tid}
        # Real IDA returns the created item's full flags, which include the
        # FF_DATA (0x2) type bit even for a byte item (FF_BYTE == 0x0), so a
        # successful byte item is nonzero.
        return flags | 0x2

    def create_strlit(self, ea, length, strtype):
        size = length
        if self._overlaps(ea, size):
            return 0
        self.items[ea] = {"flags": 0xC000, "size": size, "tid": 0}
        self.strlits[ea] = {"strtype": strtype, "size": size}
        return size

    def undo_begin(self):
        self.undo_depth += 1
        self.undo_events.append("begin")
        return True

    def undo_end(self):
        if self.undo_depth <= 0:
            return False
        self.undo_depth -= 1
        self.undo_events.append("end")
        return True

    # ---- read back helpers ----
    def read(self, ea, size):
        off = ea - self.base
        return bytes(self.mem[off:off + size])

    def dwords(self, ea, count):
        return struct.unpack("<" + "I" * count, self.read(ea, 4 * count))


def _load_modify(idb=None):
    """Load governance_engine + modify with the ida_* surface stubbed."""
    load_tool_module("governance_engine")
    mod = load_tool_module("modify")
    mod.MCPError.GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    mod.MCPError.ANNOTATION_ERROR = "ANNOTATION_ERROR"
    mod.MCPError.TYPE_ERROR = "TYPE_ERROR"
    mod.MCPError.ADDRESS_INVALID = "ADDRESS_INVALID"
    mod.ida_name.SN_FORCE = 1
    mod.ida_segment.SEGPERM_X = 1
    # Metadata-gathering safety valves (avoid AttributeError on blank ida stubs).
    mod.ida_nalt.get_tinfo = lambda *a, **k: False
    mod.ida_typeinf.tinfo_t = lambda: None
    mod.idautils.Heads = lambda *a, **k: iter(())
    mod.idautils.CodeRefsFrom = lambda *a, **k: iter(())
    mod.idautils.CodeRefsTo = lambda *a, **k: iter(())
    mod.idautils.FuncItems = lambda *a, **k: iter(())
    mod.idautils.DataRefsFrom = lambda *a, **k: iter(())
    mod.idc.get_strlit_contents = lambda *a, **k: None
    mod.idc.get_idb_path = lambda: ""
    mod.idc.set_name = lambda *a, **k: True
    mod.ida_funcs.get_func = lambda ea: None
    mod.ida_funcs.FUNC_LIB = 0x200
    mod.ida_funcs.FUNC_THUNK = 0x40
    # Raw-blob default: no segments, no functions, no symbols.
    mod.ida_segment.getseg = lambda ea: None
    # Replace the blank ida_bytes / idc with the fake surface.
    idb = idb or _FakeIdb()
    mod.ida_bytes = idb
    mod.idc.STRTYPE_C = 0
    mod.idc.STRTYPE_C_16 = 2
    mod.idc.STRTYPE_C_32 = 3
    return mod, idb


# ---------------------------------------------------------------------------
# create_data — write bytes, lay a dword array, read it back
# ---------------------------------------------------------------------------

class TestCreateData(unittest.TestCase):
    def test_create_data_dword_array_roundtrip(self):
        mod, idb = _load_modify()
        # Write a 16-byte region: 4 dwords of "vector table" entries.
        idb.patch_bytes(0x1000, struct.pack("<4I", 0x08000000, 0x08000080, 0x080000C0, 0))
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword", count=4)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["item_type"], "dword")
        self.assertEqual(r["count"], 4)
        self.assertEqual(r["size"], 16)
        self.assertEqual(r["end"], "0x1010")
        # One 4-byte item was laid at each element address.
        self.assertEqual(set(idb.items), {0x1000, 0x1004, 0x1008, 0x100C})
        for ea in (0x1000, 0x1004, 0x1008, 0x100C):
            self.assertEqual(idb.items[ea]["size"], 4)
        # Bytes are untouched and read back as the same dwords.
        self.assertEqual(idb.dwords(0x1000, 4), (0x08000000, 0x08000080, 0x080000C0, 0))

    def test_create_data_item_type_flags_and_sizes(self):
        cases = {
            "byte": (0x0, 1),
            "word": (0x1000, 2),
            "dword": (0x2000, 4),
            "qword": (0x3000, 8),
            "pointer": (0x2000, 4),  # ff_dword for pointer
        }
        for item_type, (flag_low_bits, size) in cases.items():
            with self.subTest(item_type=item_type):
                mod, idb = _load_modify()
                r = mod.modify(action="create_data", addr="0x2000", item_type=item_type, count=1)
                self.assertIs(r["ok"], True, r)
                info = idb.items[0x2000]
                self.assertEqual(info["size"], size)
                # Fake ORs FF_DATA (0x2); the data-type nibble must match.
                self.assertEqual(info["flags"] & 0xF000, flag_low_bits)
                self.assertEqual(r["size"], size)
                self.assertEqual(r["end"], hex(0x2000 + size))

    def test_create_data_array_item_type_lays_dword_elements(self):
        mod, idb = _load_modify()
        r = mod.modify(action="create_data", addr="0x1000", item_type="array", count=8)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["count"], 8)
        self.assertEqual(r["size"], 32)
        expected = {0x1000 + 4 * i for i in range(8)}
        self.assertEqual(set(idb.items), expected)

    def test_create_data_count_defaults_to_single_item(self):
        mod, idb = _load_modify()
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword")
        self.assertIs(r["ok"], True)
        self.assertEqual(r["count"], 1)
        self.assertEqual(set(idb.items), {0x1000})

    def test_create_data_partial_lay_reports_partial(self):
        mod, idb = _load_modify()
        # Pre-define a dword at 0x1004 so laying [0x1000, 0x1008) stops after 0x1000.
        idb.create_data(0x1004, 0x2000, 4, 0)
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword", count=2)
        self.assertIs(r["ok"], True)
        self.assertTrue(r.get("partial"))
        self.assertEqual(r["count"], 1)
        self.assertEqual(r["size"], 4)

    def test_create_data_unknown_item_type_rejected(self):
        mod, _ = _load_modify()
        r = mod.modify(action="create_data", addr="0x1000", item_type="float", count=1)
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "INVALID_ARGS")

    def test_create_data_bad_count_rejected(self):
        mod, _ = _load_modify()
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword", count="x")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "INVALID_ARGS")

    def test_create_data_failure_returns_ida_error(self):
        mod, idb = _load_modify()
        idb.create_data = lambda ea, flags, size, tid: 0  # always fails
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "IDA_ERROR")


# ---------------------------------------------------------------------------
# create_strlit — mark a raw string region
# ---------------------------------------------------------------------------

class TestCreateStrlit(unittest.TestCase):
    def test_create_strlit_c16_c32(self):
        cases = {"c": 0, "c16": 2, "c32": 3}
        for strtype, expected_const in cases.items():
            with self.subTest(strtype=strtype):
                mod, idb = _load_modify()
                idb.patch_bytes(0x1000, b"hello\x00")
                r = mod.modify(action="create_strlit", addr="0x1000", size=6, strtype=strtype)
                self.assertIs(r["ok"], True, r)
                self.assertEqual(r["size"], 6)
                self.assertEqual(r["strtype"], strtype)
                self.assertEqual(idb.strlits[0x1000]["strtype"], expected_const)
                self.assertEqual(idb.strlits[0x1000]["size"], 6)

    def test_create_strlit_defaults_to_c(self):
        mod, idb = _load_modify()
        r = mod.modify(action="create_strlit", addr="0x1000", size=4)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["strtype"], "c")
        self.assertEqual(idb.strlits[0x1000]["strtype"], 0)

    def test_create_strlit_requires_size(self):
        mod, _ = _load_modify()
        r = mod.modify(action="create_strlit", addr="0x1000")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "INVALID_ARGS")

    def test_create_strlit_bad_strtype_rejected(self):
        mod, _ = _load_modify()
        r = mod.modify(action="create_strlit", addr="0x1000", size=4, strtype="utf8")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "INVALID_ARGS")

    def test_create_strlit_failure_returns_ida_error(self):
        mod, idb = _load_modify()
        idb.create_strlit = lambda ea, length, strtype: 0  # always fails
        r = mod.modify(action="create_strlit", addr="0x1000", size=4)
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "IDA_ERROR")


# ---------------------------------------------------------------------------
# undo_begin / undo_end — reversible batch-patch, commit on undo_end
# ---------------------------------------------------------------------------

class TestUndoPair(unittest.TestCase):
    def test_undo_roundtrip_leaves_committed_state(self):
        mod, idb = _load_modify()
        idb.patch_bytes(0x1000, b"\x00\x00\x00\x00")
        r = mod.modify(action="undo_begin")
        self.assertIs(r["ok"], True)
        self.assertEqual(r["action"], "undo_begin")
        # Patch inside the transaction, then commit.
        r = mod.modify(action="patch_bytes", addr="0x1000", hex_bytes="deadbeef")
        self.assertIs(r["ok"], True)
        r = mod.modify(action="undo_end")
        self.assertIs(r["ok"], True)
        self.assertEqual(r["action"], "undo_end")
        # undo_end commits: the patched bytes are the committed state.
        self.assertEqual(idb.read(0x1000, 4), bytes.fromhex("deadbeef"))
        self.assertEqual(idb.undo_events, ["begin", "end"])
        self.assertEqual(idb.undo_depth, 0)

    def test_undo_actions_take_no_address(self):
        mod, _ = _load_modify()
        # No addr argument at all — the address requirement must not fire.
        r = mod.modify(action="undo_begin")
        self.assertIs(r["ok"], True)
        r = mod.modify(action="undo_end")
        self.assertIs(r["ok"], True)

    def test_undo_end_without_begin_errors(self):
        mod, _ = _load_modify()
        r = mod.modify(action="undo_end")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "IDA_ERROR")


# ---------------------------------------------------------------------------
# Governance gating — create_data/create_strlit ride the governed pre-check
# ---------------------------------------------------------------------------

class TestGovernanceGating(unittest.TestCase):
    def test_create_data_runs_type_change_precheck(self):
        mod, _ = _load_modify()
        calls = []

        def recording(operation_type, addr=None, proposed_value="", **kw):
            calls.append((operation_type, addr))
            return {
                "approved": True,
                "verdict": "approved",
                "violations": [],
                "warnings": [],
                "redacted_content": proposed_value,
                "ontology_class": "CompliantOperation",
                "axiom_score": 1.0,
            }

        mod.evaluate_operation = recording
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword", count=2)
        self.assertIs(r["ok"], True)
        self.assertEqual(calls, [("type_change", 0x1000)])

    def test_create_data_rejected_check_blocks(self):
        mod, _ = _load_modify()
        mod.evaluate_operation = lambda operation_type, addr=None, proposed_value="", **kw: {
            "approved": False,
            "verdict": "blocked",
            "violations": [{"rule_id": "R999", "severity": "HIGH", "description": "blocked"}],
            "warnings": [],
            "redacted_content": proposed_value,
            "ontology_class": "UnsafeStackFrameChange",
            "axiom_score": 0.0,
        }
        r = mod.modify(action="create_data", addr="0x1000", item_type="dword")
        self.assertIs(r["ok"], False)
        self.assertEqual(r["code"], "GOVERNANCE_BLOCKED")

    def test_create_strlit_runs_precheck_and_bypasses_when_governed_false(self):
        mod, _ = _load_modify()
        calls = []

        def recording(operation_type, addr=None, proposed_value="", **kw):
            calls.append(operation_type)
            return {
                "approved": True,
                "verdict": "approved",
                "violations": [],
                "warnings": [],
                "redacted_content": proposed_value,
                "ontology_class": "CompliantOperation",
                "axiom_score": 1.0,
            }

        mod.evaluate_operation = recording
        r = mod.modify(action="create_strlit", addr="0x1000", size=4)
        self.assertIs(r["ok"], True)
        self.assertEqual(calls, ["type_change"])
        # governed=False bypasses the pre-check entirely (fresh address).
        calls.clear()
        r = mod.modify(action="create_strlit", addr="0x2000", size=4, governed=False)
        self.assertIs(r["ok"], True)
        self.assertEqual(calls, [])


# ---------------------------------------------------------------------------
# Opaque raw-blob / RISC-V scenario
# ---------------------------------------------------------------------------

class TestRiscVRawBlob(unittest.TestCase):
    def test_vector_table_and_string_on_headerless_riscv_blob(self):
        # A headerless RISC-V firmware blob: no segments, no functions, no
        # strlit marks from auto-analysis. create_data + create_strlit make the
        # vector table readable and the embedded string searchable.
        mod, idb = _load_modify()
        base = 0x1000
        # 8 vector-table entries (dwords) at the reset vector table.
        entries = [0x08000000 + 0x100 * i for i in range(8)]
        idb.patch_bytes(base, struct.pack("<8I", *entries))
        # An embedded C string at the end of the blob.
        blob_end = base + 0x800
        idb.patch_bytes(blob_end, b"reset_handler\0")

        r = mod.modify(action="create_data", addr=hex(base), item_type="array", count=8)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["count"], 8)
        self.assertEqual(r["size"], 32)
        self.assertEqual({ea for ea in idb.items if ea < base + 32},
                         {base + 4 * i for i in range(8)})
        # The array read back still equals the written vector table.
        self.assertEqual(idb.dwords(base, 8), tuple(entries))

        r = mod.modify(action="create_strlit", addr=hex(blob_end), size=14, strtype="c")
        self.assertIs(r["ok"], True)
        self.assertEqual(idb.strlits[blob_end]["strtype"], 0)
        self.assertEqual(idb.read(blob_end, 14), b"reset_handler\0")


class TestModifyCompatibilityBoundaries(unittest.TestCase):
    def test_metadata_persistence_aliases_and_governance_redaction(self):
        mod, idb = _load_modify()
        self.assertEqual(mod._gather_governance_metadata("rename", 0x1000, "x"), {})
        self.assertEqual(mod._gather_governance_metadata("set_type", 0x1000, "int"), {})

        fn = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010)
        mod._compat.get_func_info = lambda _ea: fn
        mod._compat.get_func_flags = lambda _ea: 0
        mod._compat.get_func_start = lambda _ea: 0x1000
        mod.idautils.Heads = lambda *_args: iter([0x1000])
        mod.idautils.CodeRefsFrom = lambda *_args: iter([0x2000])
        mod.idc.get_func_name = lambda _ea: ""
        mod.ida_nalt.get_tinfo = lambda *_args: True

        class Tinfo:
            def get_func_details(self, _out):
                return False

        mod.ida_typeinf.tinfo_t = Tinfo
        mod.idaapi.func_type_data_t = object
        metadata = mod._gather_governance_metadata("rename", 0x1000, "x")
        self.assertEqual(metadata["api_calls"], "")
        self.assertEqual(mod._gather_governance_metadata("set_type", 0x1000, "int __sp"), {
            "targets_stack": True,
            "changes_frame_size": True,
        })

        # The public compatibility aliases are resolved before the action
        # branches, including the generic `type` and `comment` spellings.
        idb.create_data = lambda *_args: 1
        self.assertTrue(mod.modify(action="create_data", address="0x1000", type="dword", governed=False)["ok"])
        mod.idc.set_cmt = lambda *_args: True
        self.assertTrue(mod.modify(action="comment", address="0x1000", comment="via kw", governed=False)["ok"])

        warnings = ["review this edit"]

        def approved(**_kwargs):
            return {
                "approved": True,
                "verdict": "warned",
                "violations": [],
                "warnings": warnings,
                "redacted_content": "safe",
            }

        mod.evaluate_operation = approved
        mod.idc.set_name = lambda *_args: True
        mod._persist_symbol_knowledge = lambda *_args: None
        self.assertEqual(mod.modify(action="rename", address="0x1000", value="unsafe")["name"], "safe")
        self.assertEqual(mod.modify(action="comment", address="0x1000", value="unsafe")["governance_warnings"], warnings)

        mod.ida_typeinf.parse_decl = lambda *_args: True
        mod.ida_typeinf.apply_tinfo = lambda *_args: True
        self.assertEqual(mod.modify(action="set_type", address="0x1000", value="unsafe")["governance_warnings"], warnings)
        import ida_idp
        mod.ida_bytes.patch_bytes = lambda *_args: None
        ida_idp.assemble = lambda *_args: (True, b"\x90")
        self.assertEqual(mod.modify(action="patch_asm", address="0x1000", value="unsafe")["governance_warnings"], warnings)
        mod.evaluate_operation = lambda **_kwargs: {
            "approved": True,
            "verdict": "warned",
            "violations": [],
            "warnings": warnings,
            "redacted_content": "90",
        }
        self.assertTrue(mod.modify(action="patch_bytes", address="0x1000", value="9090")["ok"])

        mod.evaluate_operation = lambda **_kwargs: {
            "approved": True,
            "verdict": "warned",
            "violations": [],
            "warnings": warnings,
            "redacted_content": "",
        }
        self.assertEqual(mod.modify(action="create_data", address="0x1000", count=1)["governance_warnings"], warnings)
        self.assertEqual(mod.modify(action="create_strlit", address="0x1100", size=2)["governance_warnings"], warnings)

    def test_persistence_fallback_loop_limits_and_validation_errors(self):
        mod, _idb = _load_modify()
        real_import = __import__("builtins").__import__
        service = types.ModuleType("ida_pro_mcp.services")
        records = []

        class SymbolDB:
            def upsert_symbol(self, row):
                records.append(row)

        service.SymbolDB = SymbolDB

        def import_service(name, *args, **kwargs):
            if name == "ida_pro_mcp.services":
                return service
            return real_import(name, *args, **kwargs)

        mod._compat.get_func_start = lambda ea: ea
        mod.idc.get_idb_path = lambda: "/tmp/test.i64"
        mod.idautils.CodeRefsTo = lambda *_args: iter(())
        mod.idautils.FuncItems = lambda _ea: iter([0x1000])
        refs = iter([0x4000, 0x4004, 0x4008])
        mod.idautils.DataRefsFrom = lambda _ea: refs
        strings = {0x4000: None, 0x4004: b"same", 0x4008: b"same"}
        mod.idc.get_strlit_contents = lambda ea, *_args: strings[ea]
        with patch.object(__import__("builtins"), "__import__", import_service):
            mod._persist_symbol_knowledge(0x1000, "known")
        self.assertEqual(records[-1]["strings"], ["same"])

        refs = iter(range(24))
        mod.idautils.DataRefsFrom = lambda _ea: refs
        mod.idc.get_strlit_contents = lambda ea, *_args: f"s{ea}".encode()
        with patch.object(__import__("builtins"), "__import__", import_service):
            mod._persist_symbol_knowledge(0x1000, "many")
        self.assertEqual(len(records[-1]["strings"]), 24)

        class BrokenDB:
            def upsert_symbol(self, _row):
                raise RuntimeError("database unavailable")

        service.SymbolDB = BrokenDB
        with patch.object(__import__("builtins"), "__import__", import_service):
            mod._persist_symbol_knowledge(0x1000, "broken")

        def import_missing(name, *args, **kwargs):
            if name in {"ida_pro_mcp.services", "host.stores.symbol_db"}:
                raise ImportError("store unavailable")
            return real_import(name, *args, **kwargs)

        with patch.object(__import__("builtins"), "__import__", import_missing):
            mod._persist_symbol_knowledge(0x1000, "no_store")

        error = {"error": True, "code": "ADDRESS_INVALID"}
        mod.validate_addr = lambda *_args, **_kwargs: (None, error)
        self.assertIs(mod.modify(action="rename", addr="bad", value="x", governed=False), error)

    def test_patch_nop_local_variable_and_strlit_failure_edges(self):
        mod, idb = _load_modify()
        mod._compat.get_func_start = lambda _ea: 0x1000
        patches = []
        mod.ida_bytes.patch_bytes = lambda ea, raw: patches.append((ea, bytes(raw)))
        mod.idaapi.insn_t = object
        mod.idaapi.decode_insn = lambda *_args: 0
        mod._inf_procname = lambda: "riscv"
        decoded_default = mod.modify(action="patch_bytes", addr="0x1000", nop=True, governed=False)
        self.assertEqual(decoded_default["size"], 1)
        riscv = mod.modify(action="patch_bytes", addr="0x1000", nop=True, count=5, governed=False)
        self.assertEqual(riscv["size"], 5)
        self.assertEqual(patches[-1][1], b"\x13\x00\x00\x00\x00")
        mod._inf_procname = lambda: "arm"
        arm = mod.modify(action="patch_bytes", addr="0x1000", nop=True, count=5, governed=False)
        self.assertEqual(arm["size"], 5)
        self.assertEqual(patches[-1][1], b"\x00\xf0\x20\xe3\x00")
        self.assertEqual(mod.modify(action="patch_bytes", addr="0x1000", value=0, governed=False)["code"], "INVALID_ARGS")

        mod.ida_hexrays.decompile = lambda _ea: types.SimpleNamespace(
            lvars=[types.SimpleNamespace(name="existing")]
        )
        missing = mod.modify(action="rename_local", addr="0x1000", var_name="missing", new_name="x", governed=False)
        self.assertIn("Available: existing", missing["message"])
        mod.ida_hexrays.user_lvar_modifier_t = type("Base", (), {})
        mod.ida_hexrays.modify_user_lvars = lambda _ea, modifier: modifier.modify_lvars(
            types.SimpleNamespace(lvvec=[types.SimpleNamespace(name="other")])
        )
        failed = mod.modify(action="rename_local", addr="0x1000", var_name="existing", new_name="x", governed=False)
        self.assertEqual(failed["code"], "IDA_ERROR")
        mod.ida_hexrays.decompile = lambda _ea: (_ for _ in ()).throw(RuntimeError("decompile crash"))
        self.assertFalse(mod.modify(action="rename_local", addr="0x1000", var_name="x", new_name="y", governed=False)["ok"])

        idb.create_strlit = lambda *_args: (_ for _ in ()).throw(RuntimeError("strlit failure"))
        self.assertFalse(mod.modify(action="create_strlit", addr="0x1000", size=2, governed=False)["ok"])

    def test_undo_fallback_and_exception_modes(self):
        mod, _idb = _load_modify()
        undo = types.ModuleType("ida_undo")
        with patch.dict(sys.modules, {"ida_undo": undo}):
            mod.ida_bytes = types.ModuleType("ida_bytes")
            self.assertTrue(mod.modify(action="undo_end")["ok"])
            mod.ida_bytes.undo_end = lambda: (_ for _ in ()).throw(RuntimeError("undo failure"))
            self.assertFalse(mod.modify(action="undo_end")["ok"])
            undo.create_undo_point = lambda *_args: (_ for _ in ()).throw(RuntimeError("begin failure"))
            self.assertFalse(mod.modify(action="undo_begin")["ok"])
            undo.create_undo_point = lambda *_args: True
            self.assertTrue(mod.modify(action="undo_begin")["ok"])

        mod.validate_addr = lambda value, **_kwargs: (int(str(value), 0), None)
        mod.idc.set_name = lambda *_args: (_ for _ in ()).throw(RuntimeError("rename crash"))
        self.assertFalse(mod.modify(action="rename", addr="0x1000", value="x", governed=False)["ok"])
