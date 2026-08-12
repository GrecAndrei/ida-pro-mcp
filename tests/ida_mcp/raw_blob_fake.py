"""Shared _FakeIda 'raw flat blob' single-segment fake for opaque-binary tests.

A raw (.bin) firmware image has no ELF/PE headers and no sections — when IDA
loads it with the bin loader it maps the whole file as one flat segment
``[base, base + len(data))`` with a generic name/class and no loader metadata.
This module installs blank ``ida_*`` modules into ``sys.modules`` in exactly
that shape, parameterized by ``arch``/``bitness``/``base``, so any p-wave
opaque-binary test can load the real IDA-side tools against a fixture without
a live IDA runtime.

Usage::

    from tests.ida_mcp.raw_blob_fake import install_raw_blob, fixture_bytes

    blob = install_raw_blob(fixture_bytes(), processor="riscv", bitness=64,
                            base=0x80000000)
    mod = blob.load_tool("analysis", overrides={...})
    result = mod.analysis(action="set_architecture", processor="riscv", ...)

``install_raw_blob`` mutates ``sys.modules`` freely; the repo conftest's
autouse ``_isolate_sys_modules`` fixture snapshots/restores ``sys.modules`` and
``sys.path`` around every test, so the pollution is cleaned up automatically.

The ``RawBlob.state`` dict is the observation surface: entries registered via
``ida_entry.add_entry``, functions via ``ida_funcs.add_func``, segment
registers via the ida_segregs fake, data/strlit items via ``ida_bytes``, and
the arch switches applied via ``set_processor_type`` / ``inf_set_*``.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

from tests._isolated_repo_loader import load_tool_module

# ---------------------------------------------------------------------------
# Fixture location / provenance
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
RISCV_BLOB_PATH = _FIXTURES_DIR / "riscv_blob.bin"

# Offsets inside riscv_blob.bin (derived from the assembly in the "Fixture
# provenance" appendix of docs/wiki/riscv_firmware.md; the binary is the
# 0x80000000-linked RV64IMAC firmware slice, 300 bytes: 0x000 text + rodata).
RISCV_TEXT_LEN = 0xA4                      # 164 bytes of code
RISCV_RESET_VEC = 0x00                     # j reset_handler (jal x0)
RISCV_VECTOR_TABLE = 0x08                  # LE u32 ISR pointer table
RISCV_RESET_HANDLER = 0x20                 # auipc gp, 0x80000; addi gp,gp,0; auipc/jalr
RISCV_MAIN = 0x34                          # RV64 C entry point
RISCV_ISR_DEFAULT = 0x58
RISCV_ISR_TIMER = 0x78                     # RV64 ld/sd evidence
RISCV_ISR_UART = 0x94
RISCV_UART_BASE = RISCV_TEXT_LEN + 0x00    # rodata: .word 0x10003000
RISCV_MSG = RISCV_TEXT_LEN + 0x21          # rodata: .asciz "RV64FW"


def fixture_bytes() -> bytes:
    """Return the committed RISC-V raw-blob fixture bytes."""
    return RISCV_BLOB_PATH.read_bytes()


def fixture_path() -> str:
    """Return the absolute path to the committed fixture."""
    return str(RISCV_BLOB_PATH)


def _blank_modules(names: list[str]) -> None:
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


# ---------------------------------------------------------------------------
# Segment-register model (mirrors the ida_segregs 9.x Python API)
# ---------------------------------------------------------------------------

BADSEL = -1
_SR_INHERIT = 0
_SR_USER = 1
_SR_AUTO = 2


class _SregRange:
    def __init__(self):
        self.start_ea = 0
        self.end_ea = 0
        self.val = BADSEL
        self.tag = _SR_INHERIT


class _FakeSegregs:
    """Sorted non-overlapping [start, end, val, tag] ranges per register.

    Seeded with one inherited range covering the whole flat segment.  Mirrors
    ``split_sreg_range(ea, rg, v, tag, silent)`` / ``get_sreg_range(out, ea,
    rg)`` / ``get_sreg_ranges_qty`` / ``getn_sreg_range`` (IDA 9.x surface).
    """

    SR_inherit = _SR_INHERIT
    SR_user = _SR_USER
    SR_auto = _SR_AUTO

    def __init__(self, max_ea: int):
        self._max_ea = max_ea
        self._ranges: dict[int, list] = {}

    def _ensure(self, reg: int) -> list:
        if reg not in self._ranges:
            self._ranges[reg] = [[0, self._max_ea, BADSEL, _SR_INHERIT]]
        return self._ranges[reg]

    def _containing(self, reg: int, ea: int):
        for s, e, v, t in self._ensure(reg):
            if s <= ea < e:
                return (s, e, v, t)
        return None

    def _split(self, reg: int, ea: int) -> None:
        lst = self._ensure(reg)
        for i, (s, e, v, t) in enumerate(lst):
            if s < ea < e:
                lst[i] = [s, ea, v, t]
                lst.insert(i + 1, [ea, e, v, t])
                return

    def get_sreg(self, ea: int, rg: int) -> int:
        found = self._containing(rg, ea)
        return found[2] if found else BADSEL

    def split_sreg_range(self, ea: int, rg: int, v: int, tag: int = _SR_USER,
                         silent: bool = False) -> bool:
        if ea < 0:
            return False
        found = self._containing(rg, ea)
        end = found[1] if found else self._max_ea
        # overwrite [ea, end) with the new value/tag
        self._split(rg, ea)
        lst = self._ensure(rg)
        out = []
        for s, e, ov, t in lst:
            if e <= ea or s >= end:
                out.append([s, e, ov, t])
            elif s >= ea:
                out.append([ea, e, v, tag])
            else:
                out.append([s, ea, ov, t])
        self._ranges[rg] = out
        return True

    def get_sreg_range(self, out: _SregRange, ea: int, rg: int) -> bool:
        found = self._containing(rg, ea)
        if not found:
            return False
        out.start_ea, out.end_ea, out.val, out.tag = found
        return True

    def sreg_range_t(self):
        return _SregRange()

    def get_sreg_ranges_qty(self, rg: int) -> int:
        return len(self._ensure(rg))

    def getn_sreg_range(self, out: _SregRange, rg: int, n: int) -> bool:
        lst = self._ensure(rg)
        if not (0 <= n < len(lst)):
            return False
        out.start_ea, out.end_ea, out.val, out.tag = lst[n]
        return True


# ---------------------------------------------------------------------------
# The raw-flat-blob fake
# ---------------------------------------------------------------------------

class RawBlob:
    """Handle to an installed single-segment raw-blob fake IDA environment."""

    def __init__(self, data: bytes, *, processor: str, bitness: int, base: int,
                 endian: str, segment_name: str, segment_class: str,
                 insn_map: dict, state: dict, mods: dict, seg):
        self.data = data
        self.processor = processor
        self.bitness = bitness
        self.base = base
        self.endian = endian
        self.segment_name = segment_name
        self.segment_class = segment_class
        self.insn_map = insn_map
        self.state = state
        self.mods = mods
        self.seg = seg

    # -- convenience --------------------------------------------------------
    @property
    def end_ea(self) -> int:
        return self.base + len(self.data)

    def module(self, name: str):
        return self.mods[name]

    def load_tool(self, name: str, overrides: dict | None = None):
        """Load an IDA-side tool module against the installed fake."""
        common = dict(self.mods)
        if overrides:
            common.update(overrides)
        return load_tool_module(name, common_overrides=common)


def install_raw_blob(
    data: bytes,
    *,
    processor: str = "riscv",
    bitness: int = 64,
    base: int = 0x80000000,
    endian: str = "little",
    segment_name: str = "ROM",
    segment_class: str = "CODE",
    insn_map: dict | None = None,
    reg_names: list[str] | None = None,
) -> RawBlob:
    """Install blank ida_* modules in single-segment raw-flat-blob mode.

    Maps ``[base, base + len(data))`` as one flat segment with no headers,
    sections, or loader metadata.  ``insn_map`` is ``{ea: (mnemonic, [op0,
    op1, op2])}`` used by the idc disasm helpers; absent entries decode as
    unknown.  ``reg_names`` seeds the ida_idp processor-register table
    (defaults to the sreg registers plus GP, the RISC-V global pointer).
    """
    state: dict = {
        "entries": [],           # (ordinal, ea, name)
        "functions": [],         # e.a. created via ida_funcs.add_func
        "sregs": {},             # reg name -> _FakeSegregs
        "data_items": [],        # (ea, size, kind)
        "strlits": [],           # (start, end, strtype)
        "processor_applied": None,
        "bitness_applied": None,
        "endian_applied": None,
        "gp_set": None,
        "planned_ranges": [],
        "snapshots": set(),
        "processor_options": [],  # idc.set_processor_options calls
    }
    insn_map = dict(insn_map or {})
    n = len(data)
    start_ea = base
    end_ea = base + n

    # ---- mutable arch state (set_processor_type / inf_set_* update these) --
    _proc = processor
    _bits = bitness
    _be = endian in ("big", "be")

    # ---- idaapi -----------------------------------------------------------
    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    idaapi.BADSEL = BADSEL
    idaapi.SEGPERM_READ = 1
    idaapi.SEGPERM_WRITE = 2
    idaapi.SEGPERM_EXEC = 4
    idaapi.f_BIN = 17
    idaapi.f_BINARY = 17
    idaapi.SETPROC_LOADER = 0
    idaapi.SETPROC_LOADER_NON_FATAL = 1
    idaapi.AU_FINAL = 0
    idaapi.REF_OFF32 = 0x400
    idaapi.REF_OFF64 = 0x800
    idaapi.MFF_FAST = 0
    idaapi.MFF_READ = 1
    idaapi.MFF_WRITE = 2

    inf = types.SimpleNamespace(
        procname=_proc,
        filetype=idaapi.f_BIN,
        min_ea=start_ea,
        max_ea=end_ea,
        start_ea=start_ea,
    )

    def _is_64():
        return bool(_bits == 64)

    def _is_32_exactly():
        return bool(_bits == 32)

    inf.is_64bit = _is_64
    inf.is_32bit_exactly = _is_32_exactly
    inf.is_be = lambda: _be
    inf.get_min_ea = lambda: start_ea
    inf.get_max_ea = lambda: end_ea
    inf.get_start_ea = lambda: start_ea

    def _set_proc(proc: str):
        nonlocal _proc
        _proc = str(proc)
        inf.procname = _proc
        state["processor_applied"] = _proc
        return True

    def _set_bits(bits: int):
        nonlocal _bits
        _bits = int(bits)
        state["bitness_applied"] = _bits
        return True

    def _set_be(be: bool):
        nonlocal _be
        _be = bool(be)
        state["endian_applied"] = "be" if _be else "le"
        return True

    netnode_calls = []

    def _netnode(name, _tag=0, _create=False):
        store = {"altset": [], "altget": []}
        netnode_calls.append((name, store))
        return types.SimpleNamespace(altset=lambda tag, val: store["altset"].append((tag, val)),
                                     altget=lambda tag: None)

    idaapi.get_inf_structure = lambda: inf
    idaapi.inf_get_min_ea = lambda: start_ea
    idaapi.inf_get_max_ea = lambda: end_ea
    idaapi.inf_get_start_ea = lambda: start_ea
    idaapi.inf_is_be = lambda: _be
    idaapi.inf_is_64bit = _is_64
    idaapi.inf_get_app_bitness = lambda: _bits
    idaapi.auto_is_ok = lambda: True
    idaapi.get_func = lambda ea: None
    idaapi.get_idb = lambda: None
    idaapi.get_idb_path = lambda: ""
    idaapi.get_input_file_path = lambda: ""
    idaapi.execute_sync = lambda fn, flags=0: fn()
    idaapi.set_processor_type = lambda proc, flags=0: _set_proc(proc)
    idaapi.netnode = _netnode

    def _in_segment(ea: int) -> bool:
        return start_ea <= ea < end_ea

    idaapi.is_mapped = _in_segment
    idaapi.getseg = lambda ea: None  # replaced below via ida_segment

    # ---- idc --------------------------------------------------------------
    idc = types.ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF
    idc.INF_MIN_EA = 1
    idc.INF_MAX_EA = 2
    idc.INF_PROCNAME = 3
    idc.INF_FILETYPE = 4
    idc.STRTYPE_C = 0
    idc.STRTYPE_C_16 = 2
    idc.STRTYPE_C_32 = 3
    idc.INF_AF = 5
    idc.INF_AF2 = 6

    def _get_inf_attr(attr):
        if attr in (idc.INF_MIN_EA, 1):
            return start_ea
        if attr in (idc.INF_MAX_EA, 2):
            return end_ea
        if attr in (idc.INF_PROCNAME, 3):
            return processor
        if attr in (idc.INF_FILETYPE, 4):
            return idaapi.f_BIN
        return 0

    idc.get_inf_attr = _get_inf_attr

    def _print_insn_mnem(ea):
        hit = insn_map.get(ea)
        return hit[0] if hit else ""

    def _get_operand_value(ea, n):
        hit = insn_map.get(ea)
        if not hit:
            return idaapi.BADADDR
        ops = hit[1] if len(hit) > 1 else []
        return ops[n] if n < len(ops) else idaapi.BADADDR

    def _next_head(ea, _end):
        nxt = ea + 2
        while nxt < end_ea and nxt not in insn_map:
            nxt += 2
        return nxt if nxt < end_ea else idaapi.BADADDR

    idc.print_insn_mnem = _print_insn_mnem

    def _print_operand(ea, n):
        hit = insn_map.get(ea)
        if not hit:
            return ""
        ops = hit[1] if len(hit) > 1 else []
        return str(ops[n]) if n < len(ops) else ""

    idc.generate_disasm_line = lambda ea, flags: (insn_map.get(ea, ("", ""))[0] or "unknown")
    idc.get_operand_value = _get_operand_value
    idc.print_operand = _print_operand
    idc.next_head = _next_head
    idc.get_name_ea_simple = lambda name: -1
    idc.create_insn = lambda ea: state.__setitem__("last_create_insn", ea) or 1
    idc.set_processor_options = lambda opts: state["processor_options"].append(opts) or None
    idc.get_flags = lambda ea: 0
    idc.is_data = lambda f: False
    idc.is_code = lambda f: False
    idc.get_item_size = lambda ea: 2

    # ---- ida_bytes --------------------------------------------------------
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.FF_BYTE = 0x00
    ida_bytes.FF_WORD = 0x1000
    ida_bytes.FF_DWORD = 0x2000
    ida_bytes.FF_QWORD = 0x3000
    ida_bytes.FF_ARRAY = 0x4000
    ida_bytes.get_flags = lambda ea: 0
    ida_bytes.is_code = lambda f: False
    ida_bytes.is_data = lambda f: False

    def _get_bytes(ea, size):
        off = ea - start_ea
        if off < 0 or off >= n:
            return None
        return data[off:off + size]

    ida_bytes.get_bytes = _get_bytes
    ida_bytes.create_data = lambda ea, flag, size, tid=0: state.__setitem__("data_items", state["data_items"] + [(ea, size, flag)]) or True
    # Real signature: (start, length, strtype); the tool passes the byte
    # length (not an end address).
    ida_bytes.create_strlit = lambda ea, length, st: state.__setitem__("strlits", state["strlits"] + [(ea, length, st)]) or length
    ida_bytes.undo_begin = lambda: True
    ida_bytes.undo_end = lambda: True

    # ---- ida_segment ------------------------------------------------------
    ida_segment = types.ModuleType("ida_segment")
    seg = types.SimpleNamespace(
        start_ea=start_ea, end_ea=end_ea, name=segment_name,
        sclass=segment_class, perm=7, align=0, comb=0, type=2, flags=0,
        bitness=32 if bitness == 32 else 64,
    )
    ida_segment.SEGPERM_X = 4
    ida_segment.getseg = lambda ea: seg if _in_segment(ea) else None
    ida_segment.get_segm_name = lambda s, flags=0: getattr(s, "name", "")
    ida_segment.get_segm_class = lambda s: getattr(s, "sclass", "DATA")
    ida_segment.get_segm_start = lambda s: getattr(s, "start_ea", 0)
    ida_segment.get_segm_end = lambda s: getattr(s, "end_ea", 0)
    idaapi.getseg = ida_segment.getseg

    # ---- idautils ---------------------------------------------------------
    idautils = types.ModuleType("idautils")

    def _functions():
        return iter(list(state["functions"]))

    def _segments():
        return iter([seg])

    def _entries():
        return iter([(o, ea, nm, False) for (o, ea, nm) in state["entries"]])

    idautils.Functions = _functions
    idautils.Segments = _segments
    idautils.Entries = _entries
    idautils.CodeRefsTo = lambda ea: iter([])

    # ---- ida_funcs / ida_ua / ida_entry -----------------------------------
    ida_funcs = types.ModuleType("ida_funcs")

    def _add_func(start, end=None):
        if start not in state["functions"]:
            state["functions"].append(start)
        return True

    ida_funcs.add_func = _add_func
    ida_funcs.get_func = lambda ea: None
    ida_funcs.get_func_qty = lambda: len(state["functions"])
    ida_funcs.getn_func = lambda i: None

    ida_ua = types.ModuleType("ida_ua")
    ida_ua.create_insn = lambda ea: state.__setitem__("last_create_insn", ea) or 1

    ida_entry = types.ModuleType("ida_entry")

    def _add_entry(ordinal, ea, name, is_manual=False):
        state["entries"].append((ordinal, ea, name or ""))
        return True

    ida_entry.add_entry = _add_entry
    ida_entry.get_entry_qty = lambda: len(state["entries"])
    ida_entry.get_entry = lambda ordinal: next((ea for o, ea, _n in state["entries"] if o == ordinal), idaapi.BADADDR)
    ida_entry.get_entry_ordinal = lambda ea: next((o for o, e, _n in state["entries"] if e == ea), idaapi.BADADDR)
    ida_entry.get_entry_name = lambda ea: next((n for o, e, n in state["entries"] if e == ea), "")

    # ---- ida_ida ----------------------------------------------------------
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: start_ea
    ida_ida.inf_get_max_ea = lambda: end_ea
    ida_ida.inf_get_start_ea = lambda: start_ea
    ida_ida.inf_get_procname = lambda: _proc
    ida_ida.inf_get_filetype = lambda: idaapi.f_BIN
    ida_ida.inf_is_be = lambda: _be
    ida_ida.inf_is_64bit = _is_64
    ida_ida.inf_is_16bit = lambda: _bits == 16
    ida_ida.inf_is_32bit_exactly = _is_32_exactly
    ida_ida.inf_get_app_bitness = lambda: _bits
    ida_ida.inf_set_app_bitness = _set_bits
    ida_ida.inf_set_be = _set_be
    ida_ida.inf_get_af = lambda: 0
    ida_ida.inf_get_af2 = lambda: 0
    ida_ida.inf_set_af = lambda v: True
    ida_ida.inf_set_af2 = lambda v: True

    # ---- ida_nalt / ida_loader / ida_auto ---------------------------------
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_input_file_path = lambda: ""

    ida_loader = types.ModuleType("ida_loader")
    ida_loader.get_loader_name = lambda *a, **k: "bin"
    ida_loader.set_loader_options = lambda name, opts, *a, **k: True
    ida_loader.DBFL_SNAPSHOT = 0x20
    ida_loader.save_snapshot = lambda name, flags=0: state["snapshots"].add(name) or True
    ida_loader.restore_snapshot = lambda name: (name in state["snapshots"])

    ida_auto = types.ModuleType("ida_auto")
    ida_auto.plan_range = lambda s, e: state["planned_ranges"].append((s, e)) or None
    ida_auto.auto_make_step = lambda *a, **k: True
    ida_auto.auto_is_ok = lambda: True
    ida_auto.AU_FINAL = 0

    # ---- ida_idp / ida_segregs --------------------------------------------
    ida_idp = types.ModuleType("ida_idp")
    _reg_names = reg_names if reg_names is not None else ["T", "CS", "DS", "SS", "FS", "GS", "GP"]
    _reg_map = {name: i for i, name in enumerate(_reg_names)}
    ida_idp.ph = types.SimpleNamespace(
        reg_names=list(_reg_names),
        reg_first_sreg=0,
        reg_last_sreg=len(_reg_names) - 1,
    )
    ida_idp.str2reg = lambda name: _reg_map.get(str(name), -1)
    ida_idp.reg2str = lambda reg: _reg_names[reg] if 0 <= reg < len(_reg_names) else ""

    segregs = _FakeSegregs(max_ea=end_ea)
    state["sregs"] = {"_fake": segregs}

    # ---- remaining blank modules ------------------------------------------
    _blank_modules([
        "ida_name", "ida_lines", "ida_typeinf", "ida_hexrays", "ida_frame",
        "ida_struct", "ida_kernwin", "ida_dbg", "ida_netnode",
    ])

    mods = {
        "idaapi": idaapi, "idc": idc, "idautils": idautils,
        "ida_bytes": ida_bytes, "ida_segment": ida_segment,
        "ida_funcs": ida_funcs, "ida_ua": ida_ua, "ida_entry": ida_entry,
        "ida_ida": ida_ida, "ida_nalt": ida_nalt, "ida_loader": ida_loader,
        "ida_auto": ida_auto, "ida_idp": ida_idp, "ida_segregs": segregs,
    }
    for name, mod in mods.items():
        sys.modules[name] = mod

    # Point the cached arch_utils at the fresh idaapi so get_arch() /
    # is_riscv_family() resolve through the fake (not a stale stub).  The
    # loader's namespace-aware load keeps ida_mcp/__init__.py (which would run
    # the IDA-runtime sync/version chain) out of the picture.
    try:
        from tests._isolated_repo_loader import load_support_module
        _au = load_support_module("arch_utils")
        _au.idaapi = idaapi
    except Exception:
        pass

    return RawBlob(
        data=data, processor=processor, bitness=bitness, base=base,
        endian=endian, segment_name=segment_name, segment_class=segment_class,
        insn_map=insn_map, state=state, mods=mods, seg=seg,
    )
