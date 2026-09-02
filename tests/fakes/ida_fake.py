"""Unified, authentic Fake IDA Pro SDK harness and in-memory IDB simulation.

Provides high-fidelity emulation of the IDA Pro SDK modules (`idaapi`, `idc`,
`idautils`, `ida_bytes`, `ida_funcs`, `ida_segment`, `ida_name`, `ida_typeinf`,
`ida_hexrays`, `ida_ua`, `ida_lines`, `ida_frame`, `ida_struct`, `ida_ida`,
`ida_loader`, `ida_entry`, `ida_nalt`, `ida_auto`, `ida_dbg`, `ida_fixup`,
`ida_kernwin`, `ida_idp`, `ida_segregs`, `ida_netnode`) and stateful
`FakeDatabase` for authentic offline reverse-engineering tool testing.
"""

from __future__ import annotations

import collections
import copy
import re
import struct
import sys
import types
from typing import Any, Callable, Iterator, Sequence

# ---------------------------------------------------------------------------
# Global Constants & Enums (mirrors Hex-Rays / IDA Pro SDK)
# ---------------------------------------------------------------------------

BADADDR = 0xFFFFFFFFFFFFFFFF
BADSEL = -1

# Segment Permissions
SEGPERM_READ = 1
SEGPERM_WRITE = 2
SEGPERM_EXEC = 4
SEGPERM_X = 4

# File Types
f_EXE = 2
f_PE = 11
f_BIN = 17
f_BINARY = 17
f_ELF = 18
f_MACHO = 25
f_COFF = 1
f_HEX = 2

# Operand Types (ida_ua / idc)
o_void = 0
o_reg = 1
o_mem = 2
o_phrase = 3
o_displ = 4
o_imm = 5
o_far = 6
o_near = 7
o_idpspec0 = 8

# Item Flags (ida_bytes / idc)
FF_BYTE = 0x00000000
FF_WORD = 0x10000000
FF_DWORD = 0x20000000
FF_QWORD = 0x30000000
FF_STRLIT = 0x50000000
FF_STRUCT = 0x60000000
FF_ARRAY = 0x00004000
FF_CODE = 0x00000600
FF_DATA = 0x00000400
FF_TAIL = 0x00000200
FF_UNK = 0x00000000

# String Types (idc / ida_nalt)
STRTYPE_C = 0
STRTYPE_PASCAL = 1
STRTYPE_C_16 = 2
STRTYPE_C_32 = 3
STRTYPE_LEN2 = 4
STRTYPE_LEN4 = 5

# Function Flags (ida_funcs)
FUNC_NORET = 0x00000001
FUNC_FAR = 0x00000002
FUNC_LIB = 0x00000004
FUNC_STATIC = 0x00000008
FUNC_FRAME = 0x00000010
FUNC_USERFAR = 0x00000020
FUNC_HIDDEN = 0x00000040
FUNC_THUNK = 0x00000080
FUNC_BOTTOMBP = 0x00000100

# Flowchart Block Types (ida_gdl)
FCB_NORMAL = 0
FCB_INDJUMP = 1
FCB_RET = 2
FCB_CNDRET = 3
FCB_NORET = 4
FCB_ENORET = 5
FCB_EXTERN = 6
FCB_ERROR = 7

# Hex-Rays AST Item Types (cinsn_t / cexpr_t)
cit_empty = 0
cit_block = 1
cit_expr = 2
cit_if = 3
cit_for = 4
cit_while = 5
cit_do = 6
cit_switch = 7
cit_return = 8
cit_goto = 9
cit_asm = 10
cit_break = 11
cit_continue = 12

cot_empty = 0
cot_comma = 1
cot_asg = 2
cot_asgbor = 3
cot_asgband = 4
cot_asgadd = 5
cot_asgsub = 6
cot_asgmul = 7
cot_asgdiv = 8
cot_postinc = 9
cot_postdec = 10
cot_preinc = 11
cot_predec = 12
cot_bor = 13
cot_xor = 14
cot_band = 15
cot_eq = 16
cot_ne = 17
cot_sge = 18
cot_uge = 19
cot_sle = 20
cot_ule = 21
cot_sgt = 22
cot_ugt = 23
cot_slt = 24
cot_ult = 25
cot_sar = 26
cot_shr = 27
cot_shl = 28
cot_add = 29
cot_sub = 30
cot_mul = 31
cot_sdiv = 32
cot_udiv = 33
cot_smod = 34
cot_umod = 35
cot_fadd = 36
cot_fsub = 37
cot_fmul = 38
cot_fdiv = 39
cot_fneg = 40
cot_neg = 41
cot_cast = 42
cot_lnot = 43
cot_bnot = 44
cot_ptr = 45
cot_ref = 46
cot_memref = 47
cot_memptr = 48
cot_idx = 49
cot_num = 50
cot_fnum = 51
cot_str = 52
cot_obj = 53
cot_var = 54
cot_insn = 55
cot_sizeof = 56
cot_helper = 57
cot_type = 58
cot_call = 59

# Visitor Control Flags
CV_PARENTS = 0x01
CV_FAST = 0x02
CV_POSTORDER = 0x04

# Type Base Types (BT_*)
BT_VOID = 0
BT_INT = 1
BT_INT8 = 2
BT_INT16 = 3
BT_INT32 = 4
BT_INT64 = 5
BT_FLOAT = 6
BT_DOUBLE = 14
BT_BOOL = 15
BT_PTR = 7
BT_ARRAY = 8
BT_STRUCT = 9
BT_UNION = 10
BT_ENUM = 11
BT_FUNC = 12
BT_TYPEDEF = 13

# Sreg Tags
_SR_INHERIT = 0
_SR_USER = 1
_SR_AUTO = 2

# Auto-analysis
AU_FINAL = 0

# Sync Flags
MFF_FAST = 0
MFF_READ = 1
MFF_WRITE = 2

# Comments
E_PREV = 1000
E_NEXT = 2000


# ---------------------------------------------------------------------------
# Segments, Memory & Segment Registers
# ---------------------------------------------------------------------------

class segment_t:
    """Simulated IDA segment header."""

    def __init__(
        self,
        start_ea: int = 0,
        end_ea: int = 0,
        name: str = ".text",
        sclass: str = "CODE",
        perm: int = SEGPERM_READ | SEGPERM_EXEC,
        align: int = 0,
        comb: int = 0,
        type_: int = 2,
        flags: int = 0,
        bitness: int = 64,
    ):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)
        self.name = str(name)
        self.sclass = str(sclass)
        self.perm = int(perm)
        self.align = int(align)
        self.comb = int(comb)
        self.type = int(type_)
        self.flags = int(flags)
        self.bitness = int(bitness)
        self.color = 0xFFFFFFFF
        self.orgbase = 0

    def size(self) -> int:
        return max(0, self.end_ea - self.start_ea)

    def contains(self, ea: int) -> bool:
        return self.start_ea <= ea < self.end_ea

    def get_perm(self) -> int:
        return self.perm

    def set_perm(self, p: int) -> None:
        self.perm = int(p)

    def get_name(self) -> str:
        return self.name

    def set_name(self, n: str) -> None:
        self.name = str(n)

    def get_sclass(self) -> str:
        return self.sclass

    def set_sclass(self, s: str) -> None:
        self.sclass = str(s)

    def get_color(self) -> int:
        return self.color

    def set_color(self, c: int) -> None:
        self.color = int(c)

    def get_orgbase(self) -> int:
        return self.orgbase

    def set_orgbase(self, o: int) -> None:
        self.orgbase = int(o)

    def get_start_ea(self) -> int:
        return self.start_ea

    def set_start_ea(self, ea: int) -> None:
        self.start_ea = int(ea)

    def get_end_ea(self) -> int:
        return self.end_ea

    def set_end_ea(self, ea: int) -> None:
        self.end_ea = int(ea)

    def get_bitness(self) -> int:
        return self.bitness

    def set_bitness(self, b: int) -> None:
        self.bitness = int(b)

    def get_align(self) -> int:
        return self.align

    def set_align(self, a: int) -> None:
        self.align = int(a)

    def get_comb(self) -> int:
        return self.comb

    def set_comb(self, c: int) -> None:
        self.comb = int(c)

    def get_type(self) -> int:
        return self.type

    def set_type(self, t: int) -> None:
        self.type = int(t)

    def __repr__(self) -> str:
        return f"<segment_t {self.name} [0x{self.start_ea:x}, 0x{self.end_ea:x}) {self.sclass} perm={self.perm}>"


class _SregRange:
    def __init__(self, start_ea: int = 0, end_ea: int = 0, val: int = BADSEL, tag: int = _SR_INHERIT):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)
        self.val = int(val)
        self.tag = int(tag)


class _FakeSegregs:
    """Segment register table simulation supporting IDA 9.x / 8.x segment register API."""

    SR_inherit = _SR_INHERIT
    SR_user = _SR_USER
    SR_auto = _SR_AUTO

    def __init__(self, max_ea: int = 0xFFFFFFFFFFFFFFFF):
        self._max_ea = max_ea
        self._ranges: dict[int, list[list[int]]] = {}

    def _ensure(self, reg: int) -> list[list[int]]:
        if reg not in self._ranges:
            self._ranges[reg] = [[0, self._max_ea, BADSEL, _SR_INHERIT]]
        return self._ranges[reg]

    def _containing(self, reg: int, ea: int) -> list[int] | None:
        for r in self._ensure(reg):
            if r[0] <= ea < r[1]:
                return r
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

    def split_sreg_range(self, ea: int, rg: int, v: int, tag: int = _SR_USER, silent: bool = False) -> bool:
        if ea < 0:
            return False
        found = self._containing(rg, ea)
        end = found[1] if found else self._max_ea
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
        out.start_ea, out.end_ea, out.val, out.tag = found[0], found[1], found[2], found[3]
        return True

    def sreg_range_t(self) -> _SregRange:
        return _SregRange()

    def get_sreg_ranges_qty(self, rg: int) -> int:
        return len(self._ensure(rg))

    def getn_sreg_range(self, out: _SregRange, rg: int, n: int) -> bool:
        lst = self._ensure(rg)
        if not (0 <= n < len(lst)):
            return False
        item = lst[n]
        out.start_ea, out.end_ea, out.val, out.tag = item[0], item[1], item[2], item[3]
        return True


# ---------------------------------------------------------------------------
# Functions, FlowCharts & Basic Blocks
# ---------------------------------------------------------------------------

class qbasic_block_t:
    """Basic block simulation for IDA FlowChart analysis."""

    def __init__(
        self,
        start_ea: int,
        end_ea: int,
        id_: int = 0,
        type_: int = FCB_NORMAL,
        succs: Sequence[int] | None = None,
        preds: Sequence[int] | None = None,
    ):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)
        self.id = int(id_)
        self.type = int(type_)
        self._succs: list[int] = list(succs or [])
        self._preds: list[int] = list(preds or [])

    def succs(self) -> Iterator[qbasic_block_t]:
        return iter(self._resolved_succs if hasattr(self, "_resolved_succs") else [])

    def preds(self) -> Iterator[qbasic_block_t]:
        return iter(self._resolved_preds if hasattr(self, "_resolved_preds") else [])

    def nsucc(self) -> int:
        return len(self._succs)

    def npred(self) -> int:
        return len(self._preds)

    def succ(self, idx: int) -> int:
        return self._succs[idx] if idx < len(self._succs) else 0

    def pred(self, idx: int) -> int:
        return self._preds[idx] if idx < len(self._preds) else 0

    def __repr__(self) -> str:
        return f"<qbasic_block_t #{self.id} [0x{self.start_ea:x}, 0x{self.end_ea:x})>"


class FlowChart:
    """IDA FlowChart simulation yielding basic blocks with control-flow relations."""

    def __init__(self, f: Any = None, bounds: Any = None, blocks: list[qbasic_block_t] | None = None, *args, **kwargs):
        self.blocks: list[qbasic_block_t] = []
        if blocks:
            self.blocks = list(blocks)
        elif f is not None:
            start_ea = getattr(f, "start_ea", 0)
            end_ea = getattr(f, "end_ea", start_ea + 16)
            blk = qbasic_block_t(start_ea, end_ea, id_=0, type_=FCB_NORMAL)
            self.blocks.append(blk)
        elif bounds is not None and isinstance(bounds, (tuple, list)) and len(bounds) >= 2:
            blk = qbasic_block_t(bounds[0], bounds[1], id_=0, type_=FCB_NORMAL)
            self.blocks.append(blk)
        elif len(args) >= 3:
            blk = qbasic_block_t(args[1], args[2], id_=0, type_=FCB_NORMAL)
            self.blocks.append(blk)

        # Wire up block succs/preds object references
        block_by_id = {b.id: b for b in self.blocks}
        for b in self.blocks:
            b._resolved_succs = [block_by_id[sid] for sid in b._succs if sid in block_by_id]
            b._resolved_preds = [block_by_id[pid] for pid in b._preds if pid in block_by_id]

    def size(self) -> int:
        return len(self.blocks)

    def __len__(self) -> int:
        return len(self.blocks)

    def __iter__(self) -> Iterator[qbasic_block_t]:
        return iter(self.blocks)

    def __getitem__(self, idx: int) -> qbasic_block_t:
        return self.blocks[idx]


class func_t:
    """IDA Pro function record structure."""

    def __init__(
        self,
        start_ea: int = 0,
        end_ea: int = 0,
        flags: int = 0,
        name: str = "",
        tails: list[tuple[int, int]] | None = None,
    ):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)
        self.flags = int(flags)
        self.name = str(name)
        self.tails: list[tuple[int, int]] = list(tails or [])
        self.color = 0xFFFFFFFF
        self.pntqty = 0
        self.regvarqty = 0
        self.points = []
        self.frame = 0
        self.frsize = 64
        self.frregs = 8
        self.fpd = 0

    def size(self) -> int:
        return max(0, self.end_ea - self.start_ea)

    def contains(self, ea: int) -> bool:
        if self.start_ea <= ea < self.end_ea:
            return True
        return any(s <= ea < e for s, e in self.tails)

    def __repr__(self) -> str:
        return f"<func_t '{self.name}' [0x{self.start_ea:x}, 0x{self.end_ea:x}) flags=0x{self.flags:x}>"


# ---------------------------------------------------------------------------
# Instructions & Disassembly
# ---------------------------------------------------------------------------

class op_t:
    """Instruction operand representation."""

    def __init__(
        self,
        n: int = 0,
        type_: int = o_void,
        reg: int = 0,
        value: int = 0,
        addr: int = 0,
        specval: int = 0,
        dtype: int = 0,
        soff: int | None = None,
        text: str = "",
    ):
        self.n = int(n)
        self.type = int(type_)
        self.reg = int(reg)
        self.value = int(value)
        self.addr = int(addr)
        self.specval = int(specval)
        self.dtype = int(dtype)
        self.soff = soff
        self.flags = 0
        self.offb = 0
        self._text = str(text)

    def clr_shown(self) -> None:
        self.flags &= ~0x01

    def __repr__(self) -> str:
        return f"<op_t #{self.n} type={self.type} addr=0x{self.addr:x} val=0x{self.value:x} text='{self._text}'>"


class insn_t:
    """Decoded instruction representation."""

    def __init__(
        self,
        ea: int = 0,
        size: int = 4,
        itype: int = 0,
        mnem: str = "nop",
        ops: Sequence[op_t] | None = None,
        disasm: str = "",
    ):
        self.ea = int(ea)
        self.size = int(size)
        self.itype = int(itype)
        self._mnem = str(mnem)
        self._disasm = disasm or (f"{mnem} {', '.join(op._text for op in ops)}" if ops else mnem)
        self.ops = list(ops or [])
        while len(self.ops) < 8:
            self.ops.append(op_t(n=len(self.ops), type_=o_void))

    def get_canon_mnem(self) -> str:
        return self._mnem

    def get_canon_feature(self) -> int:
        return 0

    @property
    def Op1(self) -> op_t:
        return self.ops[0]

    @property
    def Op2(self) -> op_t:
        return self.ops[1]

    @property
    def Op3(self) -> op_t:
        return self.ops[2]

    @property
    def Op4(self) -> op_t:
        return self.ops[3]

    def __repr__(self) -> str:
        return f"<insn_t 0x{self.ea:x} '{self._disasm}'>"


# ---------------------------------------------------------------------------
# Type System, Structures & Enums (ida_typeinf / ida_struct)
# ---------------------------------------------------------------------------

class udm_t:
    """User-defined struct / union member descriptor (IDA 9.x / 8.x UDM)."""

    def __init__(
        self,
        name: str = "",
        type_: FakeTinfo | None = None,
        offset: int = 0,
        size: int = 4,
        cmt: str = "",
    ):
        self.name = str(name)
        self.type = type_
        self.offset = int(offset)
        self.size = int(size)
        self.cmt = str(cmt)

    def is_gap(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"<udm_t {self.name} offset={self.offset} size={self.size}>"


class edm_t:
    """Enum member descriptor."""

    def __init__(self, name: str = "", value: int = 0, cmt: str = ""):
        self.name = str(name)
        self.value = int(value)
        self.cmt = str(cmt)

    def __repr__(self) -> str:
        return f"<edm_t {self.name} = {self.value}>"


class udt_type_data_t(list):
    """List container of struct/union members."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_size = 0

    def size(self) -> int:
        return len(self)


class enum_type_data_t(list):
    """List container of enum members."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def size(self) -> int:
        return len(self)


class FakeTinfo:
    """Simulation of `tinfo_t` supporting structs, enums, ptrs, arrays, functions and typedefs."""

    _tid_counter = [1000]

    def __init__(
        self,
        lib: Any = None,
        name: str | None = None,
        kind: int | None = None,
        members: list[udm_t | edm_t] | None = None,
        size: int | None = None,
        decl: str | None = None,
        target_tinfo: FakeTinfo | None = None,
        ret_type: FakeTinfo | None = None,
        arg_types: list[FakeTinfo] | None = None,
    ):
        if isinstance(lib, int):
            kind = lib
            lib = None
        elif isinstance(lib, str):
            name = lib
            lib = None
        elif isinstance(lib, FakeTinfo):
            self._copy_from(lib)
            return

        self.lib = lib
        self.name = name
        self.kind = kind if kind is not None else BT_VOID
        self.members: list[udm_t | edm_t] = list(members or [])
        self._size = size if size is not None else 0
        self._decl = decl
        self._ordinal: int | None = None
        self._tid = FakeTinfo._tid_counter[0]
        FakeTinfo._tid_counter[0] += 1
        self._target_tinfo = target_tinfo
        self._ret_type = ret_type
        self._arg_types = list(arg_types or [])

    def _copy_from(self, t: FakeTinfo) -> None:
        self.name = t.name
        self.kind = t.kind
        self.members = list(t.members)
        self._size = t._size
        self._tid = t._tid
        self._decl = t._decl
        self._ordinal = t._ordinal
        self._target_tinfo = t._target_tinfo
        self._ret_type = t._ret_type
        self._arg_types = list(t._arg_types)

    def get_named_type(self, til: Any, name: str, flags: int = 0) -> bool:
        lib = til or (self.lib if self.lib is not None else None)
        if lib is None:
            try:
                import sys
                ida_typeinf = sys.modules.get("ida_typeinf")
                if ida_typeinf and hasattr(ida_typeinf, "get_idati"):
                    lib = ida_typeinf.get_idati()
            except Exception:
                pass
        if lib is not None and hasattr(lib, "by_name"):
            found = lib.by_name(name)
            if found:
                self._copy_from(found)
                return True
        return False

    def get_numbered_type(self, til: Any, ordinal: int, flags: int = 0) -> bool:
        lib = til or (self.lib if self.lib is not None else None)
        if lib is None:
            try:
                import sys
                ida_typeinf = sys.modules.get("ida_typeinf")
                if ida_typeinf and hasattr(ida_typeinf, "get_idati"):
                    lib = ida_typeinf.get_idati()
            except Exception:
                pass
        if lib is not None and hasattr(lib, "by_ordinal"):
            found = lib.by_ordinal(ordinal)
            if found:
                self._copy_from(found)
                return True
        return False

    def get_type_by_tid(self, tid: int) -> bool:
        lib = self.lib
        if lib is None:
            try:
                import sys
                ida_typeinf = sys.modules.get("ida_typeinf")
                if ida_typeinf and hasattr(ida_typeinf, "get_idati"):
                    lib = ida_typeinf.get_idati()
            except Exception:
                pass
        if lib is not None and hasattr(lib, "by_tid"):
            found = lib.by_tid(tid)
            if found:
                self._copy_from(found)
                return True
        return False

    def get_udt_details(self, udt: Any) -> bool:
        if not (self.is_struct() or self.is_union()):
            return False
        if hasattr(udt, "clear"):
            udt.clear()
        for m in self.members:
            if isinstance(m, udm_t):
                bit_offset = m.offset * 8 if m.offset < 1000000 else m.offset
                udm_copy = udm_t(
                    name=m.name,
                    type_=m.type or FakeTinfo(kind=BT_INT32, size=m.size),
                    offset=bit_offset,
                    size=m.size,
                    cmt=m.cmt,
                )
                udt.append(udm_copy)
        if hasattr(udt, "total_size"):
            udt.total_size = self.get_size()
        return True

    def get_enum_details(self, ei: Any) -> bool:
        if not self.is_enum():
            return False
        if hasattr(ei, "clear"):
            ei.clear()
        for m in self.members:
            if isinstance(m, edm_t):
                ei.append(edm_t(name=m.name, value=m.value, cmt=m.cmt))
        return True

    def set_named_type(self, til: Any, name: str, flags: int = 0) -> bool:
        self.name = name
        lib = til or self.lib
        if lib is None:
            try:
                import sys
                ida_typeinf = sys.modules.get("ida_typeinf")
                if ida_typeinf and hasattr(ida_typeinf, "get_idati"):
                    lib = ida_typeinf.get_idati()
            except Exception:
                pass
        if lib and hasattr(lib, "register"):
            lib.register(self)
            return True
        return True

    def __bool__(self) -> bool:
        if self.kind != BT_VOID:
            return True
        return bool(self.name and self.lib and self.lib.get(self.name))

    # Type query methods
    def is_struct(self) -> bool:
        return self.kind == BT_STRUCT

    def is_union(self) -> bool:
        return self.kind == BT_UNION

    def is_enum(self) -> bool:
        return self.kind == BT_ENUM

    def is_ptr(self) -> bool:
        return self.kind == BT_PTR

    def is_array(self) -> bool:
        return self.kind == BT_ARRAY

    def create_array(self, element_type: "FakeTinfo", count: int) -> bool:
        """Create a sized array type, matching the IDA ``tinfo_t`` API."""
        if count <= 0 or not hasattr(element_type, "get_size"):
            return False
        self.kind = BT_ARRAY
        self._target_tinfo = element_type
        self._size = element_type.get_size() * int(count)
        return self._size > 0

    def is_func(self) -> bool:
        return self.kind == BT_FUNC

    def is_void(self) -> bool:
        return self.kind == BT_VOID

    def is_integral(self) -> bool:
        return self.kind in (BT_INT, BT_INT8, BT_INT16, BT_INT32, BT_INT64)

    def is_floating(self) -> bool:
        return self.kind == BT_FLOAT

    def is_typedef(self) -> bool:
        return self.kind == BT_TYPEDEF

    def get_size(self) -> int:
        if self._size:
            return self._size
        if self.kind == BT_INT8:
            return 1
        if self.kind == BT_INT16:
            return 2
        if self.kind in (BT_INT, BT_INT32, BT_FLOAT):
            return 4
        if self.kind in (BT_INT64, BT_DOUBLE):
            return 8
        if self.kind == BT_VOID:
            return 0
        if self.is_struct():
            return max((m.offset + m.size for m in self.members if isinstance(m, udm_t)), default=0)
        if self.is_ptr():
            return 8
        if self.is_enum():
            return 4
        return 4

    def get_type_name(self) -> str:
        return self.name or ""

    def get_decl(self) -> str:
        if self._decl:
            return self._decl
        if self.is_struct():
            members = [f"int {m.name}" for m in self.members if hasattr(m, "name") and m.name]
            members_str = "; ".join(members)
            return f"struct {self.name} {{ {members_str}; }};" if members_str else f"struct {self.name} {{ int dummy; }};"
        if self.is_enum():
            members = [f"{m.name} = {m.value}" for m in self.members if hasattr(m, "name") and m.name]
            members_str = ", ".join(members)
            return f"enum {self.name} {{ {members_str} }};" if members_str else f"enum {self.name} {{ DUMMY = 0 }};"
        return f"typedef int {self.name};"

    def get_ordinal(self) -> int:
        return self._ordinal or 0

    def get_tid(self) -> int:
        return self._tid

    # Pointer / Array / Function getters
    def get_pointed_object(self) -> FakeTinfo:
        return self._target_tinfo or FakeTinfo(kind=BT_VOID)

    def get_array_element(self) -> FakeTinfo:
        return self._target_tinfo or FakeTinfo(kind=BT_INT8)

    def get_rettype(self) -> FakeTinfo:
        return self._ret_type or FakeTinfo(kind=BT_VOID)

    def get_nargs(self) -> int:
        return len(self._arg_types)

    def get_nth_arg(self, n: int) -> FakeTinfo:
        if 0 <= n < len(self._arg_types):
            return self._arg_types[n]
        return FakeTinfo(kind=BT_VOID)

    # Struct UDM manipulation
    def get_udm_qty(self) -> int:
        return len([m for m in self.members if isinstance(m, udm_t)])

    def get_udm(self, n: int) -> udm_t | None:
        udms = [m for m in self.members if isinstance(m, udm_t)]
        return udms[n] if 0 <= n < len(udms) else None

    def get_udt_member(self, flags: int, offset_or_name: int | str) -> udm_t | None:
        for m in self.members:
            if isinstance(m, udm_t):
                if isinstance(offset_or_name, str) and m.name == offset_or_name:
                    return m
                if isinstance(offset_or_name, int) and m.offset == offset_or_name:
                    return m
        return None

    def _sync_to_lib(self):
        lib = self.lib
        if lib is None:
            try:
                import sys
                ida_typeinf = sys.modules.get("ida_typeinf")
                if ida_typeinf and hasattr(ida_typeinf, "get_idati"):
                    lib = ida_typeinf.get_idati()
            except Exception:
                pass
        if lib and self.name and hasattr(lib, "types") and self.name in lib.types:
            stored = lib.types[self.name]
            if stored is not self:
                stored.members = list(self.members)

    def add_udm(self, *args, **kwargs) -> int:
        if len(args) == 1 and isinstance(args[0], udm_t):
            member = args[0]
        elif len(args) >= 3:
            name, type_, bit_offset = args[0], args[1], args[2]
            sz = type_.get_size() if hasattr(type_, "get_size") else 4
            byte_offset = bit_offset // 8 if bit_offset > 0 else len(self.members) * 4
            member = udm_t(name=name, type_=type_, offset=byte_offset, size=sz)
        elif "member" in kwargs:
            member = kwargs["member"]
        else:
            member = udm_t(name=str(args[0] if args else "field"), size=4)

        if any(isinstance(m, udm_t) and m.name == member.name for m in self.members):
            return 1
        self.members.append(member)
        self._sync_to_lib()
        if self.lib:
            self.lib.calls.append(("add_udm", self.name, member.name, member.offset, member.size))
        return 0

    def del_udm(self, name_or_offset_or_idx: str | int) -> int:
        if isinstance(name_or_offset_or_idx, int) and 0 <= name_or_offset_or_idx < len(self.members):
            self.members.pop(name_or_offset_or_idx)
            self._sync_to_lib()
            return 0
        for i, m in enumerate(self.members):
            if isinstance(m, udm_t) and (name_or_offset_or_idx in (m.name, m.offset)):
                self.members.pop(i)
                self._sync_to_lib()
                if self.lib:
                    self.lib.calls.append(("del_udm", self.name, name_or_offset_or_idx))
                return 0
        return 1

    def rename_udm(self, old_name_or_idx: str | int, new_name: str) -> int:
        if isinstance(old_name_or_idx, int) and 0 <= old_name_or_idx < len(self.members):
            self.members[old_name_or_idx].name = new_name
            self._sync_to_lib()
            return 0
        for m in self.members:
            if isinstance(m, udm_t) and m.name == old_name_or_idx:
                m.name = new_name
                self._sync_to_lib()
                if self.lib:
                    self.lib.calls.append(("rename_udm", self.name, old_name_or_idx, new_name))
                return 0
        return 1

    def set_udm_type(self, member_name_or_idx: str | int, new_type: FakeTinfo) -> int:
        if isinstance(member_name_or_idx, int) and 0 <= member_name_or_idx < len(self.members):
            self.members[member_name_or_idx].type = new_type
            self.members[member_name_or_idx].size = new_type.get_size()
            self._sync_to_lib()
            return 0
        for m in self.members:
            if isinstance(m, udm_t) and m.name == member_name_or_idx:
                m.type = new_type
                m.size = new_type.get_size()
                self._sync_to_lib()
                if self.lib:
                    self.lib.calls.append(("set_udm_type", self.name, member_name_or_idx, new_type))
                return 0
        return 1

    # Enum EDM manipulation
    def get_edm_qty(self) -> int:
        return len([m for m in self.members if isinstance(m, edm_t)])

    def get_edm(self, n: int) -> edm_t | None:
        edms = [m for m in self.members if isinstance(m, edm_t)]
        return edms[n] if 0 <= n < len(edms) else None

    def add_edm(self, *args, **kwargs) -> int:
        if len(args) == 1 and isinstance(args[0], edm_t):
            member = args[0]
        elif len(args) >= 2:
            name, value = args[0], args[1]
            member = edm_t(name=name, value=value)
        else:
            member = edm_t(name=str(args[0] if args else "ENUM_VAL"), value=0)

        if any(isinstance(m, edm_t) and m.name == member.name for m in self.members):
            return 1

        self.members.append(member)
        self._sync_to_lib()
        if self.lib:
            self.lib.calls.append(("add_edm", self.name, member.name, member.value))
        return 0

    def del_edm(self, name_or_idx: str | int) -> int:
        if isinstance(name_or_idx, int) and 0 <= name_or_idx < len(self.members):
            self.members.pop(name_or_idx)
            self._sync_to_lib()
            return 0
        for i, m in enumerate(self.members):
            if isinstance(m, edm_t) and m.name == name_or_idx:
                self.members.pop(i)
                self._sync_to_lib()
                if self.lib:
                    self.lib.calls.append(("del_edm", self.name, name_or_idx))
                return 0
        return 1

    def rename_edm(self, old_name_or_idx: str | int, new_name: str) -> int:
        if isinstance(old_name_or_idx, int) and 0 <= old_name_or_idx < len(self.members):
            self.members[old_name_or_idx].name = new_name
            self._sync_to_lib()
            return 0
        for m in self.members:
            if isinstance(m, edm_t) and m.name == old_name_or_idx:
                m.name = new_name
                self._sync_to_lib()
                if self.lib:
                    self.lib.calls.append(("rename_edm", self.name, old_name_or_idx, new_name))
                return 0
        return 1

    def __repr__(self) -> str:
        return f"<FakeTinfo '{self.name}' kind={self.kind} size={self.get_size()} members={len(self.members)}>"


class FakeTypeLib:
    """In-memory type library (TIL) managing structures, enums, and types."""

    def __init__(self):
        self.types: dict[str, FakeTinfo] = {}
        self._ordinal_map: dict[int, str] = {}
        self._next_ordinal = 1
        self.calls: list[tuple[Any, ...]] = []

    def get(self, name: str) -> FakeTinfo | None:
        return self.types.get(name)

    def by_name(self, name: str) -> FakeTinfo | None:
        return self.types.get(name)

    def by_tid(self, tid: int) -> FakeTinfo | None:
        for t in self.types.values():
            if t._tid == tid:
                return t
        return None

    def by_ordinal(self, ordinal: int) -> FakeTinfo | None:
        name = self._ordinal_map.get(ordinal)
        return self.types.get(name) if name else None

    def alloc_ordinal(self) -> int:
        n = self._next_ordinal
        self._next_ordinal += 1
        return n

    def register(self, tif: FakeTinfo, ordinal: int | None = None) -> int | None:
        if tif.name is None:
            return None
        if tif.name in self.types:
            old_tif = self.types[tif.name]
            if old_tif._ordinal in self._ordinal_map:
                del self._ordinal_map[old_tif._ordinal]
        if ordinal is None:
            ordinal = self.alloc_ordinal()
        tif.lib = self
        self.types[tif.name] = tif
        self._ordinal_map[ordinal] = tif.name
        tif._ordinal = ordinal
        return ordinal


    def delete(self, name: str) -> bool:
        if name in self.types:
            tif = self.types.pop(name)
            if tif._ordinal in self._ordinal_map:
                del self._ordinal_map[tif._ordinal]
            self.calls.append(("delete", name))
            return True
        return False

    def export_header(self, type_names: Sequence[str] | None = None) -> str:
        """Export types to C header definitions."""
        lines = ["#pragma once", ""]
        targets = [self.types[k] for k in (type_names or self.types.keys()) if k in self.types]
        for t in targets:
            if t.is_struct():
                lines.append(f"struct {t.name} {{")
                for m in t.members:
                    if isinstance(m, udm_t):
                        type_str = m.type.name if m.type and m.type.name else "unsigned char"
                        lines.append(f"    {type_str} {m.name};")
                lines.append("};")
                lines.append("")
            elif t.is_enum():
                lines.append(f"enum {t.name} {{")
                for m in t.members:
                    if isinstance(m, edm_t):
                        lines.append(f"    {m.name} = {m.value},")
                lines.append("};")
                lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hex-Rays Decompiler & AST (cfunc_t, cinsn_t, cexpr_t, visitors)
# ---------------------------------------------------------------------------

class hexrays_failure_t(Exception):
    """Exception raised when decompiler fails on a function."""


class lvar_t:
    """Local variable descriptor in decompiled function."""

    def __init__(
        self,
        name: str = "var_0",
        type_: FakeTinfo | None = None,
        width: int = 4,
        def_ea: int = 0,
        used: bool = True,
        is_arg_var: bool = False,
    ):
        self.name = str(name)
        self.type = type_ or FakeTinfo(kind=BT_INT32, size=width)
        self.width = int(width)
        self.def_ea = int(def_ea)
        self.used = bool(used)
        self.is_arg_var = bool(is_arg_var)
        self.is_result_var = False

    def is_used(self) -> bool:
        return self.used

    def __repr__(self) -> str:
        return f"<lvar_t '{self.name}' width={self.width} arg={self.is_arg_var}>"


class carglist_t(list):
    """Argument list for `cot_call` expressions."""


class cnumber_t:
    def __init__(self, value: int = 0):
        self._value = int(value)

    def value(self) -> int:
        return self._value


class var_ref_t:
    def __init__(self, idx: int = 0):
        self.idx = int(idx)


class cexpr_t:
    """Hex-Rays C-tree expression node."""

    def __init__(
        self,
        op: int = cot_empty,
        ea: int = BADADDR,
        type_: FakeTinfo | None = None,
        x: cexpr_t | None = None,
        y: cexpr_t | None = None,
        z: cexpr_t | None = None,
        v: var_ref_t | None = None,
        n: cnumber_t | None = None,
        string: str = "",
        obj_ea: int = BADADDR,
        m: int = 0,
        a: Sequence[cexpr_t] | None = None,
        helper: str = "",
    ):
        self.op = int(op)
        self.ea = int(ea)
        self.type = type_
        self.x = x
        self.y = y
        self.z = z
        self.v = v if v is not None else var_ref_t(0)
        self.n = n if n is not None else cnumber_t(0)
        self.string = str(string)
        self.obj_ea = int(obj_ea)
        self.m = int(m)
        self.a = carglist_t(a or [])
        self.helper = str(helper)

    def is_expr(self) -> bool:
        return True

    def __repr__(self) -> str:
        return f"<cexpr_t op={self.op} ea=0x{self.ea:x}>"


class cinsn_t:
    """Hex-Rays C-tree statement node."""

    def __init__(
        self,
        op: int = cit_expr,
        ea: int = BADADDR,
        cblock: Sequence[cinsn_t] | None = None,
        cexpr: cexpr_t | None = None,
        cif: Any = None,
        cfor: Any = None,
        cwhile: Any = None,
        cdo: Any = None,
        cswitch: Any = None,
        creturn: Any = None,
    ):
        self.op = int(op)
        self.ea = int(ea)
        self.cblock = list(cblock or [])
        self.cexpr = cexpr
        self.cif = cif
        self.cfor = cfor
        self.cwhile = cwhile
        self.cdo = cdo
        self.cswitch = cswitch
        self.creturn = creturn

    def is_expr(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"<cinsn_t op={self.op} ea=0x{self.ea:x}>"


class cfunc_t:
    """Hex-Rays decompiled function container."""

    def __init__(
        self,
        entry_ea: int = 0,
        body: cinsn_t | None = None,
        lvars: Sequence[lvar_t] | None = None,
        pseudocode: Sequence[str] | None = None,
    ):
        self.entry_ea = int(entry_ea)
        self.body = body or cinsn_t(op=cit_block, ea=entry_ea)
        self.lvars = list(lvars or [])
        self._pseudocode = list(pseudocode or ["void sub() {", "    return;", "}"])
        self.maturity = 7  # CMAT_FINAL
        self.hdkey = 1

    def get_lvars(self) -> list[lvar_t]:
        return self.lvars

    def get_pseudocode(self) -> list[types.SimpleNamespace]:
        return [types.SimpleNamespace(line=line) for line in self._pseudocode]

    def get_func_type(self) -> FakeTinfo:
        return FakeTinfo(kind=BT_FUNC)

    def __repr__(self) -> str:
        return f"<cfunc_t entry=0x{self.entry_ea:x} lvars={len(self.lvars)}>"


class ctree_visitor_t:
    """Base visitor for depth-first AST traversal."""

    def __init__(self, flags: int = 0):
        self.flags = flags

    def visit_insn(self, insn: cinsn_t) -> int:
        return 0

    def visit_expr(self, expr: cexpr_t) -> int:
        return 0

    def leave_insn(self, insn: cinsn_t) -> int:
        return 0

    def leave_expr(self, expr: cexpr_t) -> int:
        return 0

    def apply_to(self, item: cinsn_t | cexpr_t, parent: Any = None) -> int:
        if isinstance(item, cinsn_t):
            rc = self.visit_insn(item)
            if rc != 0:
                return rc
            if item.cexpr:
                rc = self.apply_to(item.cexpr, item)
                if rc != 0:
                    return rc
            for attr in ("cblock", "cif", "cfor", "cwhile", "cdo", "cswitch", "creturn"):
                child_val = getattr(item, attr, None)
                if child_val is not None:
                    if isinstance(child_val, (list, tuple)):
                        for child in child_val:
                            if isinstance(child, (cinsn_t, cexpr_t)):
                                rc = self.apply_to(child, item)
                                if rc != 0:
                                    return rc
                    elif isinstance(child_val, (cinsn_t, cexpr_t)):
                        rc = self.apply_to(child_val, item)
                        if rc != 0:
                            return rc
            return self.leave_insn(item)
        elif isinstance(item, cexpr_t):
            rc = self.visit_expr(item)
            if rc != 0:
                return rc
            for child in (item.x, item.y, item.z):
                if child is not None:
                    rc = self.apply_to(child, item)
                    if rc != 0:
                        return rc
            if item.a:
                for arg in item.a:
                    rc = self.apply_to(arg, item)
                    if rc != 0:
                        return rc
            return self.leave_expr(item)
        return 0


class cfunc_parentee_t(ctree_visitor_t):
    """Visitor maintaining parent hierarchy stack during AST traversal."""

    def __init__(self, flags: int = CV_PARENTS):
        super().__init__(flags)
        self.parents: list[Any] = []

    def apply_to(self, item: cinsn_t | cexpr_t, parent: Any = None) -> int:
        if parent is not None:
            self.parents.append(parent)
        try:
            return super().apply_to(item, parent)
        finally:
            if parent is not None and self.parents:
                self.parents.pop()


# ---------------------------------------------------------------------------
# Netnode Simulation (IDA internal key-value storage)
# ---------------------------------------------------------------------------

class Netnode:
    def __init__(self, name: str):
        self.name = str(name)
        self.alts: dict[int, int] = {}
        self.sups: dict[int, bytes | str] = {}
        self.hashes: dict[str, bytes | str] = {}
        self.blobs: dict[str, bytes] = {}

    def altset(self, tag: int, val: int) -> bool:
        self.alts[int(tag)] = int(val)
        return True

    def altget(self, tag: int) -> int | None:
        return self.alts.get(int(tag))

    def supset(self, tag: int, val: bytes | str) -> bool:
        self.sups[int(tag)] = val
        return True

    def supval(self, tag: int) -> bytes | str | None:
        return self.sups.get(int(tag))

    def supdel(self, tag: int) -> bool:
        return bool(self.sups.pop(int(tag), None))

    def hashset(self, key: str, val: bytes | str) -> bool:
        self.hashes[str(key)] = val
        return True

    def hashval(self, key: str) -> bytes | str | None:
        return self.hashes.get(str(key))

    def hashdel(self, key: str) -> bool:
        return bool(self.hashes.pop(str(key), None))

    def setblob(self, blob: bytes, tag: str) -> bool:
        self.blobs[str(tag)] = bytes(blob)
        return True

    def getblob(self, tag: str) -> bytes | None:
        return self.blobs.get(str(tag))

    def blobsize(self, tag: str) -> int:
        return len(self.blobs.get(str(tag), b""))


# ---------------------------------------------------------------------------
# Authentic In-Memory Database (FakeDatabase)
# ---------------------------------------------------------------------------

class FakeDatabase:
    """Complete, mutable in-memory IDB database simulating an IDA Pro session."""

    def __init__(
        self,
        processor: str = "metapc",
        bitness: int = 64,
        base: int = 0x140000000,
        endian: str = "little",
        filetype: int = f_PE,
    ):
        self.processor = str(processor)
        self.bitness = int(bitness)
        self.base = int(base)
        self.endian = str(endian)
        self.filetype = int(filetype)

        # Segments & raw memory
        self.segments: list[segment_t] = []
        self._memory: dict[int, bytearray] = {}  # base_ea -> bytearray

        # Analysis flags & metadata per address
        self.flags: dict[int, int] = {}
        self.names: dict[int, str] = {}
        self._name_to_ea: dict[str, int] = {}
        self.comments: dict[int, str] = {}
        self.rpt_comments: dict[int, str] = {}
        self.extra_comments: dict[tuple[int, int], str] = {}

        # Functions & CFG
        self.functions: dict[int, func_t] = {}
        self.flowcharts: dict[int, FlowChart] = {}
        self.instructions: dict[int, insn_t] = {}

        # Cross References
        self.crefs_to: dict[int, list[int]] = collections.defaultdict(list)
        self.crefs_from: dict[int, list[int]] = collections.defaultdict(list)
        self.drefs_to: dict[int, list[int]] = collections.defaultdict(list)
        self.drefs_from: dict[int, list[int]] = collections.defaultdict(list)

        # Types & Structs
        self.type_lib = FakeTypeLib()
        self.tinfos_by_ea: dict[int, FakeTinfo] = {}

        # Hex-Rays Decompiler
        self.cfuncs: dict[int, cfunc_t] = {}
        self.decompiler_failures: set[int] = set()

        # Loader & Snapshots
        self.entries: list[tuple[int, int, str, bool]] = []
        self.snapshots: dict[str, dict[str, Any]] = {}
        self.idb_path: str = "/tmp/test.i64"
        self.input_file_path: str = "/tmp/test.exe"

        # Sregs & Options
        self.segregs = _FakeSegregs()
        self.af = 0x1FFFFFF
        self.af2 = 0
        self.processor_options: list[str] = []
        self.planned_ranges: list[tuple[int, int]] = []
        self.netnodes: dict[str, Netnode] = {}

    # Memory Operations
    def add_segment(
        self,
        start_ea: int,
        size: int,
        name: str = ".text",
        sclass: str = "CODE",
        perm: int = SEGPERM_READ | SEGPERM_EXEC,
        data: bytes | bytearray | None = None,
    ) -> segment_t:
        end_ea = start_ea + size
        seg = segment_t(
            start_ea=start_ea,
            end_ea=end_ea,
            name=name,
            sclass=sclass,
            perm=perm,
            bitness=self.bitness,
        )
        self.segments.append(seg)
        self.segments.sort(key=lambda s: s.start_ea)
        raw = bytearray(data) if data is not None else bytearray(size)
        if len(raw) < size:
            raw.extend(b"\x00" * (size - len(raw)))
        self._memory[start_ea] = raw[:size]
        return seg

    def get_segment(self, ea: int) -> segment_t | None:
        for seg in self.segments:
            if seg.contains(ea):
                return seg
        return None

    def get_bytes(self, ea: int, size: int) -> bytes | None:
        seg = self.get_segment(ea)
        if not seg or seg.start_ea not in self._memory:
            return None
        off = ea - seg.start_ea
        mem = self._memory[seg.start_ea]
        if off < 0 or off >= len(mem):
            return None
        return bytes(mem[off:off + size])

    def patch_bytes(self, ea: int, data: bytes) -> int:
        seg = self.get_segment(ea)
        if not seg or seg.start_ea not in self._memory:
            return 0
        off = ea - seg.start_ea
        mem = self._memory[seg.start_ea]
        if off < 0 or off + len(data) > len(mem):
            return 0
        mem[off:off + len(data)] = data
        return len(data)

    # Function Operations
    def add_func(self, start_ea: int, end_ea: int, name: str = "", flags: int = 0) -> func_t:
        f = func_t(start_ea=start_ea, end_ea=end_ea, name=name, flags=flags)
        self.functions[start_ea] = f
        if name:
            self.set_name(start_ea, name)
        # Seed basic FlowChart if not present
        if start_ea not in self.flowcharts:
            self.flowcharts[start_ea] = FlowChart(f=f)
        return f

    def get_func(self, ea: int) -> func_t | None:
        if ea in self.functions:
            return self.functions[ea]
        for f in self.functions.values():
            if f.contains(ea):
                return f
        return None

    def del_func(self, ea: int) -> bool:
        f = self.get_func(ea)
        if f:
            self.functions.pop(f.start_ea, None)
            self.flowcharts.pop(f.start_ea, None)
            return True
        return False

    # Names & Comments
    def set_name(self, ea: int, name: str) -> bool:
        if not name:
            old = self.names.pop(ea, None)
            if old:
                self._name_to_ea.pop(old, None)
            return True
        old = self.names.get(ea)
        if old and old != name:
            self._name_to_ea.pop(old, None)
        self.names[ea] = name
        self._name_to_ea[name] = ea
        return True

    def get_name(self, ea: int) -> str:
        return self.names.get(ea, "")

    def get_name_ea(self, name: str) -> int:
        return self._name_to_ea.get(name, BADADDR)

    def set_cmt(self, ea: int, cmt: str, rpt: bool = False) -> bool:
        if rpt:
            self.rpt_comments[ea] = cmt
        else:
            self.comments[ea] = cmt
        return True

    def get_cmt(self, ea: int, rpt: bool = False) -> str | None:
        return self.rpt_comments.get(ea) if rpt else self.comments.get(ea)

    # Instructions & Decoding
    def add_insn(self, ea: int, mnem: str, ops: Sequence[op_t] | None = None, size: int = 4, disasm: str = "") -> insn_t:
        insn = insn_t(ea=ea, size=size, itype=0, mnem=mnem, ops=ops, disasm=disasm)
        self.instructions[ea] = insn
        self.flags[ea] = FF_CODE
        return insn

    def decode_insn(self, out: insn_t, ea: int) -> int:
        insn = self.instructions.get(ea)
        if not insn:
            return 0
        out.ea = insn.ea
        out.size = insn.size
        out.itype = insn.itype
        out._mnem = insn._mnem
        out._disasm = insn._disasm
        out.ops = copy.deepcopy(insn.ops)
        return insn.size

    # Xrefs
    def add_cref(self, from_ea: int, to_ea: int) -> None:
        self.crefs_from[from_ea].append(to_ea)
        self.crefs_to[to_ea].append(from_ea)

    def add_dref(self, from_ea: int, to_ea: int) -> None:
        self.drefs_from[from_ea].append(to_ea)
        self.drefs_to[to_ea].append(from_ea)

    # Decompiler
    def set_decompile_result(self, ea: int, cfunc: cfunc_t) -> None:
        self.cfuncs[ea] = cfunc

    def decompile(self, ea: int) -> cfunc_t:
        if ea in self.decompiler_failures:
            raise hexrays_failure_t(f"Decompilation failed at 0x{ea:x}")
        f = self.get_func(ea)
        if not f:
            raise hexrays_failure_t(f"No function at 0x{ea:x}")
        if f.start_ea in self.cfuncs:
            return self.cfuncs[f.start_ea]
        # Auto-generate synthetic cfunc_t
        cfunc = cfunc_t(
            entry_ea=f.start_ea,
            body=cinsn_t(op=cit_block, ea=f.start_ea),
            lvars=[lvar_t("a1", is_arg_var=True), lvar_t("var_4", is_arg_var=False)],
            pseudocode=[
                f"// Decompiled function {f.name or hex(f.start_ea)}",
                f"int __cdecl {f.name or 'sub_' + hex(f.start_ea)[2:]}(int a1) {{",
                "    int var_4 = a1 + 1;",
                "    return var_4;",
                "}",
            ],
        )
        self.cfuncs[f.start_ea] = cfunc
        return cfunc

    # Snapshots
    def save_snapshot(self, name: str) -> bool:
        self.snapshots[name] = {
            "functions": copy.deepcopy(self.functions),
            "names": dict(self.names),
            "_name_to_ea": dict(self._name_to_ea),
            "comments": dict(self.comments),
            "rpt_comments": dict(self.rpt_comments),
            "flags": dict(self.flags),
            "_memory": {k: bytearray(v) for k, v in self._memory.items()},
        }
        return True

    def restore_snapshot(self, name: str) -> bool:
        if name not in self.snapshots:
            return False
        snap = self.snapshots[name]
        self.functions = copy.deepcopy(snap["functions"])
        self.names = dict(snap["names"])
        self._name_to_ea = dict(snap.get("_name_to_ea", {}))
        self.comments = dict(snap["comments"])
        self.rpt_comments = dict(snap.get("rpt_comments", {}))
        self.flags = dict(snap["flags"])
        if "_memory" in snap:
            self._memory = {k: bytearray(v) for k, v in snap["_memory"].items()}
        return True


# ---------------------------------------------------------------------------
# Module Stubs Builder & Installer
# ---------------------------------------------------------------------------

def _get_or_create_module(name: str) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
    return mod


def install_fake_idb(
    db: FakeDatabase | None = None,
    *,
    data: bytes | None = None,
    processor: str = "metapc",
    bitness: int = 64,
    base: int = 0x140000000,
    endian: str = "little",
    filetype: int = f_PE,
) -> FakeDatabase:
    """Install authentic fake IDA SDK modules into `sys.modules` mapped to `db`."""
    if db is None:
        db = FakeDatabase(
            processor=processor,
            bitness=bitness,
            base=base,
            endian=endian,
            filetype=filetype,
        )
        if data is not None:
            db.add_segment(base, len(data), data=data)

    # 1. idaapi
    idaapi = _get_or_create_module("idaapi")
    idaapi.BADADDR = BADADDR
    idaapi.BADSEL = BADSEL
    idaapi.SEGPERM_READ = SEGPERM_READ
    idaapi.SEGPERM_WRITE = SEGPERM_WRITE
    idaapi.SEGPERM_EXEC = SEGPERM_EXEC
    idaapi.f_BIN = f_BIN
    idaapi.f_BINARY = f_BINARY
    idaapi.f_ELF = f_ELF
    idaapi.f_PE = f_PE
    idaapi.f_MACHO = f_MACHO
    idaapi.f_COFF = f_COFF
    idaapi.f_HEX = f_HEX
    idaapi.AU_FINAL = AU_FINAL
    idaapi.MFF_FAST = MFF_FAST
    idaapi.MFF_READ = MFF_READ
    idaapi.MFF_WRITE = MFF_WRITE
    idaapi.fl_U = 0
    idaapi.fl_CF = 16
    idaapi.fl_CN = 17
    idaapi.fl_JF = 18
    idaapi.fl_JN = 19
    idaapi.fl_US = 20
    idaapi.fl_F = 21
    idaapi.SETPROC_LOADER = 0x0001
    idaapi.SETPROC_LOADER_NON_FATAL = 0x0002
    idaapi.get_kernel_version = lambda: "9.2"
    idaapi.segment_t = segment_t
    idaapi.SEG_NORM = 0
    idaapi.SEG_XTRN = 1
    idaapi.SEG_CODE = 2
    idaapi.SEG_DATA = 3
    idaapi.SEG_IMP = 4
    idaapi.SEG_BSS = 9
    idaapi.SEGMOD_KILL = 0x0001
    idaapi.SEGMOD_SILENT = 0x0002
    idaapi.SEGMOD_KEEP = 0x0004
    idaapi.add_segm_ex = lambda seg, *a, **k: db.segments.append(seg) or 1
    idaapi.del_segm = lambda ea, flags=0: next((db.segments.remove(s) or True for s in list(db.segments) if s.contains(ea)), False)
    idaapi.set_segm_name = lambda seg, name: setattr(seg, "name", name) or 1
    idaapi.set_segm_perms = lambda seg, perms: setattr(seg, "perm", perms) or 1
    idaapi.execute_sync = lambda fn, flags=0: fn()
    idaapi.auto_is_ok = lambda: True
    idaapi.get_idb_path = lambda: db.idb_path
    idaapi.get_input_file_path = lambda: db.input_file_path
    idaapi.getseg = db.get_segment
    idaapi.get_func = db.get_func
    idaapi.is_mapped = lambda ea: db.get_segment(ea) is not None
    idaapi.set_processor_type = lambda proc, flags=0: setattr(db, "processor", str(proc)) or True
    idaapi.netnode = lambda name, _tag=0, _create=False: db.netnodes.setdefault(name, Netnode(name))
    idaapi.get_strlist_qty = lambda: 0
    idaapi.get_strlist_options = lambda: types.SimpleNamespace(flags=0, min_len=5, strtypes=[0])
    idaapi.get_strlist_item = lambda *a, **k: None
    idaapi.build_strlist = lambda *a, **k: None
    idaapi.get_fileregion_offset = lambda ea: ea - db.base if ea >= db.base else BADADDR
    idaapi.get_fileregion_ea = lambda off: db.base + off

    inf = types.SimpleNamespace(
        procname=db.processor,
        filetype=db.filetype,
        min_ea=min((s.start_ea for s in db.segments), default=0),
        max_ea=max((s.end_ea for s in db.segments), default=BADADDR),
        omin_ea=min((s.start_ea for s in db.segments), default=0),
        omax_ea=max((s.end_ea for s in db.segments), default=BADADDR),
        start_ea=db.base,
        is_64bit=lambda: db.bitness == 64,
        is_32bit_exactly=lambda: db.bitness == 32,
        is_16bit=lambda: db.bitness == 16,
        is_be=lambda: db.endian in ("big", "be"),
        get_min_ea=lambda: min((s.start_ea for s in db.segments), default=0),
        get_max_ea=lambda: max((s.end_ea for s in db.segments), default=BADADDR),
        get_start_ea=lambda: db.base,
        baseaddr=db.base,
    )
    idaapi.get_inf_structure = lambda: inf
    idaapi.inf_get_min_ea = inf.get_min_ea
    idaapi.inf_get_max_ea = inf.get_max_ea
    idaapi.inf_get_omin_ea = inf.get_min_ea
    idaapi.inf_get_omax_ea = inf.get_max_ea
    idaapi.inf_get_start_ea = inf.get_start_ea
    idaapi.inf_get_baseaddr = lambda: db.base
    idaapi.get_image_base = lambda: db.base
    idaapi.inf_is_be = inf.is_be
    idaapi.inf_is_64bit = inf.is_64bit
    idaapi.inf_get_app_bitness = lambda: db.bitness

    # 2. idc
    idc = _get_or_create_module("idc")
    idc.BADADDR = BADADDR
    idc.INF_MIN_EA = 1
    idc.INF_MAX_EA = 2
    idc.INF_PROCNAME = 3
    idc.INF_FILETYPE = 4
    idc.STRTYPE_C = STRTYPE_C
    idc.STRTYPE_C_16 = STRTYPE_C_16
    idc.STRTYPE_C_32 = STRTYPE_C_32
    idc.STRTYPE_PASCAL = STRTYPE_PASCAL
    idc.INF_AF = 5
    idc.INF_AF2 = 6
    idc.AF_MARKCODE = 0x00000001
    idc.AF_USED = 0x00000002
    idc.AF_UNK = 0x00000004
    idc.AF_CODE = 0x00000008
    idc.AF_PROC = 0x00000010
    idc.eval_idc = lambda expr: eval(expr, {}, {})
    idc.get_func_flags = lambda ea: db.get_func(ea).flags if db.get_func(ea) else 0
    idc.get_inf_attr = lambda attr: (
        inf.get_min_ea() if attr in (1, idc.INF_MIN_EA) else
        inf.get_max_ea() if attr in (2, idc.INF_MAX_EA) else
        db.processor if attr in (3, idc.INF_PROCNAME) else
        db.filetype if attr in (4, idc.INF_FILETYPE) else
        db.af if attr in (5, idc.INF_AF) else
        db.af2 if attr in (6, idc.INF_AF2) else 0
    )
    idc.get_flags = lambda ea: db.flags.get(ea, 0)
    idc.get_full_flags = lambda ea: db.flags.get(ea, 0)
    idc.is_data = lambda f: bool(f & FF_DATA)
    idc.is_code = lambda f: bool(f & FF_CODE)
    idc.is_byte = lambda f: (f & 0xF0000000) == FF_BYTE
    idc.is_word = lambda f: (f & 0xF0000000) == FF_WORD
    idc.is_dword = lambda f: (f & 0xF0000000) == FF_DWORD
    idc.is_qword = lambda f: (f & 0xF0000000) == FF_QWORD
    idc.is_strlit = lambda f: (f & 0xF0000000) == FF_STRLIT
    idc.is_struct = lambda f: (f & 0xF0000000) == FF_STRUCT
    idc.get_item_size = lambda ea: db.instructions.get(ea).size if ea in db.instructions else 1
    idc.print_insn_mnem = lambda ea: db.instructions[ea]._mnem if ea in db.instructions else ""
    idc.print_operand = lambda ea, n: (
        db.instructions[ea].ops[n]._text if ea in db.instructions and n < len(db.instructions[ea].ops) else ""
    )
    idc.get_operand_value = lambda ea, n: (
        db.instructions[ea].ops[n].value if ea in db.instructions and n < len(db.instructions[ea].ops) else BADADDR
    )
    idc.get_operand_type = lambda ea, n: (
        db.instructions[ea].ops[n].type if ea in db.instructions and n < len(db.instructions[ea].ops) else 0
    )
    idc.o_void = 0
    idc.o_reg = 1
    idc.o_mem = 2
    idc.o_phrase = 3
    idc.o_displ = 4
    idc.o_imm = 5
    idc.o_far = 6
    idc.o_near = 7
    idc.get_segm_by_name = lambda name: next((s for s in db.segments if s.name == name), None)
    idc.generate_disasm_line = lambda ea, flags=0: (
        db.instructions[ea]._disasm if ea in db.instructions else "unknown"
    )
    idc.next_head = lambda ea, end=BADADDR: next(
        (addr for addr in sorted(db.instructions.keys()) if ea < addr < end),
        BADADDR
    )
    idc.prev_head = lambda ea, min_ea=0: next(
        (addr for addr in sorted(db.instructions.keys(), reverse=True) if min_ea <= addr < ea),
        BADADDR
    )
    idc.get_name_ea_simple = db.get_name_ea
    idc.set_name = lambda ea, name, flags=0: db.set_name(ea, name)
    idc.get_name = db.get_name
    idc.get_type = lambda ea: ""
    idc.set_cmt = lambda ea, cmt, rpt=0: db.set_cmt(ea, cmt, bool(rpt))
    idc.get_cmt = lambda ea, rpt=0: db.get_cmt(ea, bool(rpt))
    idc.get_func_cmt = lambda ea, rpt=0: db.get_cmt(ea, bool(rpt))
    idc.set_func_cmt = lambda ea, cmt, rpt=0: db.set_cmt(ea, cmt, bool(rpt))
    idc.parse_decls = lambda decl, flags=0: 0
    idc.parse_decl = lambda tif, decl, flags=0: 0
    idc.set_processor_options = lambda opts: db.processor_options.append(opts) or None
    idc.create_insn = lambda ea: (db.flags.__setitem__(ea, FF_CODE) or 1)
    idc.FUNCATTR_START = 0
    idc.FUNCATTR_END = 4
    idc.FUNCATTR_FLAGS = 8
    idc.get_func_name = lambda ea: db.get_name(ea) or (db.get_func(ea).name if db.get_func(ea) else "")
    idc.get_func_attr = lambda ea, attr: (
        getattr(db.get_func(ea), "start_ea", BADADDR) if attr == idc.FUNCATTR_START else
        getattr(db.get_func(ea), "end_ea", BADADDR) if attr == idc.FUNCATTR_END else
        getattr(db.get_func(ea), "flags", 0) if attr == idc.FUNCATTR_FLAGS else 0
    ) if db.get_func(ea) else BADADDR
    idc.get_segm_name = lambda ea: db.get_segment(ea).name if db.get_segment(ea) else ""
    idc.get_segm_start = lambda ea: db.get_segment(ea).start_ea if db.get_segment(ea) else BADADDR
    idc.get_segm_end = lambda ea: db.get_segment(ea).end_ea if db.get_segment(ea) else BADADDR
    idc.get_segm_attr = lambda ea, attr: (db.get_segment(ea).perm if attr == getattr(idc, "SEGATTR_PERM", 0) else 0) if db.get_segment(ea) else 0
    idc.get_first_seg = lambda: db.segments[0].start_ea if db.segments else BADADDR
    idc.get_next_seg = lambda ea: next((s.start_ea for s in db.segments if s.start_ea > ea), BADADDR)
    idc.get_input_file_path = lambda: db.input_file_path
    idc.get_idb_path = lambda: db.idb_path
    idc.get_bytes = db.get_bytes
    idc.patch_bytes = db.patch_bytes
    idc.get_wide_byte = lambda ea: db.get_bytes(ea, 1)[0] if db.get_bytes(ea, 1) else 0
    idc.get_wide_word = lambda ea: struct.unpack("<H", db.get_bytes(ea, 2))[0] if len(db.get_bytes(ea, 2)) == 2 else 0
    idc.get_wide_dword = lambda ea: struct.unpack("<I", db.get_bytes(ea, 4))[0] if len(db.get_bytes(ea, 4)) == 4 else 0
    idc.get_qword = lambda ea: struct.unpack("<Q", db.get_bytes(ea, 8))[0] if len(db.get_bytes(ea, 8)) == 8 else 0
    idc.get_str_type = lambda ea, *a: 0
    idc.get_strlit_contents = lambda ea, length=-1, strtype=0: db.get_bytes(ea, length if length > 0 else 32).split(b"\x00")[0].decode("utf-8", errors="ignore")
    idc.get_extra_cmt = lambda ea, what=0, *a: ""
    idc.update_extra_cmt = lambda ea, what, text, *a: True
    idc.E_PREV = 1000
    idc.E_NEXT = 2000

    # 3. ida_bytes
    ida_bytes = _get_or_create_module("ida_bytes")
    ida_bytes.FF_BYTE = FF_BYTE
    ida_bytes.FF_WORD = FF_WORD
    ida_bytes.FF_DWORD = FF_DWORD
    ida_bytes.FF_QWORD = FF_QWORD
    ida_bytes.FF_STRLIT = FF_STRLIT
    ida_bytes.FF_STRUCT = FF_STRUCT
    ida_bytes.FF_ARRAY = FF_ARRAY
    ida_bytes.FF_CODE = FF_CODE
    ida_bytes.FF_DATA = FF_DATA
    ida_bytes.FF_TAIL = FF_TAIL
    ida_bytes.FF_UNK = FF_UNK
    ida_bytes.DELIT_SIMPLE = 0x0001
    ida_bytes.DELIT_EXPAND = 0x0002
    ida_bytes.get_bytes = db.get_bytes
    ida_bytes.patch_bytes = db.patch_bytes
    ida_bytes.is_loaded = lambda ea: db.get_segment(ea) is not None
    ida_bytes.get_byte = lambda ea: db.get_bytes(ea, 1)[0] if db.get_bytes(ea, 1) else 0
    ida_bytes.get_word = lambda ea: struct.unpack("<H", db.get_bytes(ea, 2))[0] if len(db.get_bytes(ea, 2)) == 2 else 0
    ida_bytes.get_dword = lambda ea: struct.unpack("<I", db.get_bytes(ea, 4))[0] if len(db.get_bytes(ea, 4)) == 4 else 0
    ida_bytes.get_qword = lambda ea: struct.unpack("<Q", db.get_bytes(ea, 8))[0] if len(db.get_bytes(ea, 8)) == 8 else 0
    ida_bytes.get_wide_byte = lambda ea: db.get_bytes(ea, 1)[0] if db.get_bytes(ea, 1) else 0
    ida_bytes.get_wide_word = lambda ea: struct.unpack("<H", db.get_bytes(ea, 2))[0] if len(db.get_bytes(ea, 2)) == 2 else 0
    ida_bytes.get_wide_dword = lambda ea: struct.unpack("<I", db.get_bytes(ea, 4))[0] if len(db.get_bytes(ea, 4)) == 4 else 0
    ida_bytes.get_original_byte = lambda ea: db.get_bytes(ea, 1)[0] if db.get_bytes(ea, 1) else 0
    ida_bytes.get_flags = lambda ea: db.flags.get(ea, 0)
    ida_bytes.is_code = lambda f: bool(f & FF_CODE)
    ida_bytes.is_data = lambda f: bool(f & FF_DATA)
    ida_bytes.is_strlit = lambda f: bool(f & FF_STRLIT)
    ida_bytes.is_struct = lambda f: bool(f & FF_STRUCT)
    ida_bytes.is_byte = lambda f: (f & 0xF0000000) == FF_BYTE
    ida_bytes.is_word = lambda f: (f & 0xF0000000) == FF_WORD
    ida_bytes.is_dword = lambda f: (f & 0xF0000000) == FF_DWORD
    ida_bytes.is_qword = lambda f: (f & 0xF0000000) == FF_QWORD
    ida_bytes.is_head = lambda f: True
    ida_bytes.is_tail = lambda f: bool(f & FF_TAIL)
    ida_bytes.is_unknown = lambda f: bool(f & FF_UNK)
    ida_bytes.create_data = lambda ea, flag, size, tid=0: db.flags.__setitem__(ea, flag | FF_DATA) or True
    ida_bytes.create_strlit = lambda ea, length, st=0: (
        db.flags.__setitem__(ea, FF_STRLIT | FF_DATA) or length
    )
    ida_bytes.del_items = lambda ea, flags=0, nbytes=1: [
        db.flags.pop(ea + i, None) for i in range(nbytes)
    ] or True
    ida_bytes.get_cmt = lambda ea, rpt=False: db.get_cmt(ea, rpt)
    ida_bytes.set_cmt = lambda ea, cmt, rpt=False: db.set_cmt(ea, cmt, rpt)
    ida_bytes.undo_begin = lambda: True
    ida_bytes.undo_end = lambda: True
    ida_bytes.get_item_size = idc.get_item_size
    ida_bytes.next_head = idc.next_head
    ida_bytes.prev_head = lambda ea, min_ea=0: next((addr for addr in sorted(db.instructions.keys(), reverse=True) if min_ea <= addr < ea), BADADDR)

    # 4. ida_segment
    ida_segment = _get_or_create_module("ida_segment")
    ida_segment.ida_idaapi = idaapi
    ida_segment.BADADDR = BADADDR
    ida_segment.SEGPERM_READ = SEGPERM_READ
    ida_segment.SEGPERM_WRITE = SEGPERM_WRITE
    ida_segment.SEGPERM_EXEC = SEGPERM_EXEC
    ida_segment.SEGPERM_X = SEGPERM_X
    ida_segment.SEGMOD_KILL = 0x0001
    ida_segment.SEGMOD_SILENT = 0x0002
    ida_segment.SEGMOD_KEEP = 0x0004
    ida_segment.segment_t = segment_t
    ida_segment.segment_info_t = segment_t
    idaapi.segment_info_t = segment_t
    ida_segment.getseg = db.get_segment
    ida_segment.get_segm_name = lambda seg, flags=0: getattr(seg, "name", "")
    ida_segment.get_segm_class = lambda seg: getattr(seg, "sclass", "CODE")
    ida_segment.get_segm_start = lambda seg: getattr(seg, "start_ea", 0)
    ida_segment.get_segm_end = lambda seg: getattr(seg, "end_ea", 0)
    ida_segment.get_segm_qty = lambda: len(db.segments)
    ida_segment.getn_seg = lambda n: db.segments[n] if 0 <= n < len(db.segments) else None
    ida_segment.add_segm = lambda flags, s, e, name, sclass, align=0: bool(
        db.add_segment(s, e - s, name=name, sclass=sclass)
    )
    ida_segment.add_segm_ex = lambda seg, *a, **k: db.segments.append(seg) or 1
    ida_segment.del_segm = lambda ea, flags=0: next(
        (db.segments.remove(s) or True for s in list(db.segments) if s.contains(ea)), False
    )
    ida_segment.set_segm_name = lambda seg, name: setattr(seg, "name", name) or 1
    ida_segment.set_segm_perms = lambda seg, perms: setattr(seg, "perm", perms) or 1
    ida_segment.set_segm_class = lambda seg, sclass: setattr(seg, "sclass", sclass) or 1
    ida_segment.move_segm = lambda seg, ea, flags=0: setattr(seg, "start_ea", ea) or True
    ida_segment.update_segm = lambda seg: True
    ida_segment.SEG_NORM = 0
    ida_segment.SEG_XTRN = 1
    ida_segment.SEG_CODE = 2
    ida_segment.SEG_DATA = 3
    ida_segment.SEG_IMP = 4
    ida_segment.SEG_BSS = 9
    ida_segment.get_first_seg = lambda: db.segments[0] if db.segments else None
    ida_segment.get_next_seg = lambda ea: next((s for s in db.segments if s.start_ea > ea), None)
    ida_segment.get_segm_by_name = lambda name: next((s for s in db.segments if s.name == name), None)

    # 5. ida_funcs
    ida_funcs = _get_or_create_module("ida_funcs")
    ida_funcs.ida_idaapi = idaapi
    ida_funcs.BADADDR = BADADDR
    ida_funcs.FUNC_NORET = FUNC_NORET
    ida_funcs.FUNC_FAR = FUNC_FAR
    ida_funcs.FUNC_LIB = FUNC_LIB
    ida_funcs.FUNC_STATIC = FUNC_STATIC
    ida_funcs.FUNC_FRAME = FUNC_FRAME
    ida_funcs.FUNC_USERFAR = FUNC_USERFAR
    ida_funcs.FUNC_HIDDEN = FUNC_HIDDEN
    ida_funcs.FUNC_THUNK = FUNC_THUNK
    ida_funcs.FUNC_BOTTOMBP = FUNC_BOTTOMBP
    ida_funcs.get_func = db.get_func
    ida_funcs.get_next_func = lambda ea: next((f for f in sorted(db.functions.values(), key=lambda x: x.start_ea) if f.start_ea > ea), None)
    ida_funcs.get_prev_func = lambda ea: next((f for f in sorted(db.functions.values(), key=lambda x: x.start_ea, reverse=True) if f.start_ea < ea), None)
    ida_funcs.add_func = lambda s, e=BADADDR: bool(db.add_func(s, e if e != BADADDR else s + 16))
    ida_funcs.del_func = db.del_func
    ida_funcs.get_func_qty = lambda: len(db.functions)
    ida_funcs.getn_func = lambda n: (
        list(db.functions.values())[n] if 0 <= n < len(db.functions) else None
    )
    ida_funcs.get_func_name = lambda ea: db.get_name(ea) or (
        db.get_func(ea).name if db.get_func(ea) else ""
    )
    ida_funcs.get_func_flags = lambda ea: db.get_func(ea).flags if db.get_func(ea) else 0
    ida_funcs.set_func_flags = lambda ea, flags: setattr(db.get_func(ea), "flags", flags) or True if db.get_func(ea) else False
    ida_funcs.set_func_bounds = lambda ea, s, e: (
        setattr(db.get_func(ea), "start_ea", s) or setattr(db.get_func(ea), "end_ea", e) or True
        if db.get_func(ea) else False
    )
    ida_funcs.set_func_end = lambda ea, new_end: (
        setattr(db.get_func(ea), "end_ea", new_end) or True if db.get_func(ea) else False
    )
    ida_funcs.update_func = lambda pfn: True
    ida_funcs.reanalyze_function = lambda pfn: True

    # 6. idautils & ida_gdl
    idautils = _get_or_create_module("idautils")
    idautils.peutils_t = lambda: types.SimpleNamespace(header=lambda: b"\x00" * 0x80)
    idautils.Functions = lambda s=0, e=BADADDR, *a, **k: iter(
        [ea for ea in sorted(db.functions.keys()) if s <= ea < e]
    )
    idautils.FuncItems = lambda ea: iter(
        [addr for addr in sorted(db.instructions.keys()) if (db.get_func(ea) and db.get_func(ea).start_ea <= addr < db.get_func(ea).end_ea) or not db.get_func(ea)]
    )
    idautils.Chunks = lambda ea: iter(
        [(db.get_func(ea).start_ea, db.get_func(ea).end_ea)] if db.get_func(ea) else [(ea, ea + 16)]
    )
    idautils.Segments = lambda *a, **k: iter([s.start_ea for s in db.segments])
    idautils.Entries = lambda *a, **k: iter(db.entries)
    idautils.CodeRefsTo = lambda ea, *a, **k: iter(db.crefs_to.get(ea, []))
    idautils.CodeRefsFrom = lambda ea, *a, **k: iter(db.crefs_from.get(ea, []))
    idautils.DataRefsTo = lambda ea, *a, **k: iter(db.drefs_to.get(ea, []))
    idautils.DataRefsFrom = lambda ea, *a, **k: iter(db.drefs_from.get(ea, []))
    idautils.XrefsTo = lambda ea, flags=0, *a, **k: iter(
        [types.SimpleNamespace(frm=f, to=ea, iscode=1, type=0, user=0) for f in db.crefs_to.get(ea, [])]
        + [types.SimpleNamespace(frm=f, to=ea, iscode=0, type=0, user=0) for f in db.drefs_to.get(ea, [])]
    )
    idautils.XrefsFrom = lambda ea, flags=0, *a, **k: iter(
        [types.SimpleNamespace(frm=ea, to=t, iscode=1, type=0, user=0) for t in db.crefs_from.get(ea, [])]
        + [types.SimpleNamespace(frm=ea, to=t, iscode=0, type=0, user=0) for t in db.drefs_from.get(ea, [])]
    )
    idautils.Names = lambda *a, **k: iter([(ea, name) for ea, name in db.names.items()])
    idautils.Heads = lambda s=0, e=BADADDR, *a, **k: iter([ea for ea in sorted(db.instructions.keys()) if s <= ea < e])

    ida_gdl = _get_or_create_module("ida_gdl")
    ida_gdl.FlowChart = FlowChart
    ida_gdl.qflow_chart_t = FlowChart
    idaapi.FlowChart = FlowChart
    _ida_gdl = _get_or_create_module("_ida_gdl")
    _ida_gdl.FlowChart = FlowChart
    _ida_gdl.qflow_chart_t = FlowChart

    # 7. ida_name
    ida_name = _get_or_create_module("ida_name")
    ida_name.SN_FORCE = 0x0001
    ida_name.SN_NODUMMY = 0x0002
    ida_name.SN_NOWARN = 0x0004
    ida_name.get_name = db.get_name
    ida_name.get_name_ea = lambda from_ea, name: db.get_name_ea(name)
    ida_name.set_name = lambda ea, name, flags=0: db.set_name(ea, name)
    ida_name.get_ea_name = db.get_name
    ida_name.validate_name = lambda name, flags=0: str(name)
    ida_name.demangle_name = lambda name, flags=0: None

    # 8. ida_typeinf & ida_struct
    ida_typeinf = _get_or_create_module("ida_typeinf")
    ida_typeinf.tinfo_t = FakeTinfo
    ida_typeinf.udm_t = udm_t
    ida_typeinf.edm_t = edm_t
    ida_typeinf.udt_type_data_t = udt_type_data_t
    ida_typeinf.enum_type_data_t = enum_type_data_t
    ida_typeinf.BT_VOID = BT_VOID
    ida_typeinf.BT_INT = BT_INT
    ida_typeinf.BT_INT8 = BT_INT8
    ida_typeinf.BT_INT16 = BT_INT16
    ida_typeinf.BT_INT32 = BT_INT32
    ida_typeinf.BT_INT64 = BT_INT64
    ida_typeinf.BT_FLOAT = BT_FLOAT
    ida_typeinf.BT_PTR = BT_PTR
    ida_typeinf.BT_ARRAY = BT_ARRAY
    ida_typeinf.BT_STRUCT = BT_STRUCT
    ida_typeinf.BT_UNION = BT_UNION
    ida_typeinf.BT_ENUM = BT_ENUM
    ida_typeinf.BT_FUNC = BT_FUNC
    ida_typeinf.BTF_VOID = BT_VOID
    ida_typeinf.BTF_INT8 = BT_INT8
    ida_typeinf.BTF_UINT8 = BT_INT8
    ida_typeinf.BTF_INT16 = BT_INT16
    ida_typeinf.BTF_UINT16 = BT_INT16
    ida_typeinf.BTF_INT32 = BT_INT32
    ida_typeinf.BTF_UINT32 = BT_INT32
    ida_typeinf.BTF_INT64 = BT_INT64
    ida_typeinf.BTF_UINT64 = BT_INT64
    ida_typeinf.BTF_INT128 = 0x10
    ida_typeinf.BTF_UINT128 = 0x10
    ida_typeinf.BTF_FLOAT = BT_FLOAT
    ida_typeinf.BTF_DOUBLE = BT_DOUBLE
    ida_typeinf.BTF_LDOUBLE = BT_DOUBLE
    ida_typeinf.BTF_BOOL = BT_INT8
    ida_typeinf.BTF_STRUCT = BT_STRUCT
    ida_typeinf.BTF_TYPEDEF = 0x20
    ida_typeinf.BTF_ENUM = BT_ENUM
    ida_typeinf.BTF_UNION = BT_UNION
    ida_typeinf.PT_SIL = 0x0001
    ida_typeinf.PT_TYP = 0x0002
    ida_typeinf.PT_VAR = 0x0004
    ida_typeinf.PT_PAK = 0x0008
    ida_typeinf.TINFO_DEFINITE = 0x0001
    ida_typeinf.TINFO_GUESSED = 0x0002
    ida_typeinf.print_tinfo = lambda pfx, ind, cmt, flags, tif, name, defval: tif.get_decl() if hasattr(tif, "get_decl") else str(tif)
    ida_typeinf.get_idati = lambda: db.type_lib
    ida_typeinf.get_ordinal_qty = lambda til=None: len(db.type_lib.types)
    ida_typeinf.get_ordinal_count = lambda til=None: len(db.type_lib.types)
    ida_typeinf.get_named_type_tid = lambda name: db.type_lib.get(name)._tid if db.type_lib.get(name) else BADADDR
    ida_typeinf.idc_parse_types = lambda decl, flags=0: 0
    ida_typeinf.NTF_TYPE = 0x0001
    ida_typeinf.NTF_REPLACE = 0x0002
    ida_typeinf.alloc_type_ordinal = lambda til=None: db.type_lib.alloc_ordinal()
    ida_typeinf.set_numbered_type = lambda til, ord, flags, name, tif: db.type_lib.register(tif, ord) is not None
    ida_typeinf.set_named_type = lambda til, name, flags, tif: db.type_lib.register(tif) is not None
    ida_typeinf.del_named_type = lambda til, name, flags=0: db.type_lib.delete(name)
    ida_typeinf.save_tinfo = lambda tif, til, name, flags=0: (setattr(tif, "name", name) or db.type_lib.register(tif) is not None)

    def _parse_decl_helper(tif, til, decl, flags=0):
        decl_str = str(decl).strip()
        if not decl_str:
            return None
        m = re.search(r"(?:struct|union|enum)\s+(\w+)", decl_str)
        tname = m.group(1) if m else decl_str.split()[-1].rstrip(";")
        tif.name = tname
        if "struct" in decl_str:
            tif.kind = BT_STRUCT
        elif "enum" in decl_str:
            tif.kind = BT_ENUM
        elif "union" in decl_str:
            tif.kind = BT_UNION
        else:
            tif.kind = BT_INT32
        db.type_lib.register(tif)
        return tname

    ida_typeinf.parse_decl = _parse_decl_helper
    ida_typeinf.apply_tinfo = lambda ea, tif, flags=0: db.tinfos_by_ea.__setitem__(ea, tif) or True
    ida_typeinf.get_tinfo = lambda tif, ea: (
        tif._copy_from(db.tinfos_by_ea[ea]) or True if ea in db.tinfos_by_ea else False
    )

    ida_struct = _get_or_create_module("ida_struct")
    ida_struct.get_struc_qty = lambda: len(db.type_lib.types)
    ida_struct.get_struc_name = lambda tid: db.type_lib.by_tid(tid).name if db.type_lib.by_tid(tid) else None

    # 9. ida_hexrays
    ida_hexrays = _get_or_create_module("ida_hexrays")
    ida_hexrays.ida_idaapi = idaapi
    ida_hexrays.BADADDR = BADADDR
    ida_hexrays.hexrays_failure_t = hexrays_failure_t
    ida_hexrays.cfunc_t = cfunc_t
    ida_hexrays.cfuncptr = cfunc_t
    ida_hexrays.cinsn_t = cinsn_t
    ida_hexrays.cexpr_t = cexpr_t
    ida_hexrays.lvar_t = lvar_t
    ida_hexrays.ctree_visitor_t = ctree_visitor_t
    ida_hexrays.cfunc_parentee_t = cfunc_parentee_t
    ida_hexrays.decompile = lambda ea, flags=0: db.decompile(ea)
    ida_hexrays.init_hexrays_plugin = lambda: True
    ida_hexrays.CV_PARENTS = CV_PARENTS
    ida_hexrays.CV_FAST = CV_FAST
    ida_hexrays.CV_POSTORDER = CV_POSTORDER
    ida_hexrays.cit_block = cit_block
    ida_hexrays.cit_expr = cit_expr
    ida_hexrays.cit_if = cit_if
    ida_hexrays.cit_return = cit_return
    ida_hexrays.cot_call = cot_call
    ida_hexrays.cot_var = cot_var
    ida_hexrays.cot_num = cot_num
    ida_hexrays.cot_str = cot_str
    ida_hexrays.cot_asg = cot_asg
    ida_hexrays.user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})

    # 10. ida_ua & ida_lines & ida_frame
    ida_ua = _get_or_create_module("ida_ua")
    ida_ua.insn_t = insn_t
    ida_ua.op_t = op_t
    ida_ua.o_void = o_void
    ida_ua.o_reg = o_reg
    ida_ua.o_mem = o_mem
    ida_ua.o_phrase = o_phrase
    ida_ua.o_displ = o_displ
    ida_ua.o_imm = o_imm
    ida_ua.o_far = o_far
    ida_ua.o_near = o_near
    ida_ua.decode_insn = db.decode_insn
    ida_ua.create_insn = lambda ea: (db.flags.__setitem__(ea, FF_CODE) or 1)
    ida_ua.print_insn_mnem = lambda ea: db.instructions[ea]._mnem if ea in db.instructions else ""

    ida_lines = _get_or_create_module("ida_lines")
    ida_lines.tag_remove = str

    ida_frame = _get_or_create_module("ida_frame")
    ida_frame.get_frame = lambda f: types.SimpleNamespace(id=1)

    # 11. ida_ida & ida_loader & ida_entry & ida_nalt & ida_auto & ida_dbg & ida_fixup & ida_kernwin & ida_idp & ida_segregs & ida_netnode
    ida_ida = _get_or_create_module("ida_ida")
    ida_ida.AF_MARKCODE = 0x00000001
    ida_ida.AF_USED = 0x00000002
    ida_ida.AF_UNK = 0x00000004
    ida_ida.AF_CODE = 0x00000008
    ida_ida.AF_PROC = 0x00000010
    ida_ida.inf_get_min_ea = inf.get_min_ea
    ida_ida.inf_get_max_ea = inf.get_max_ea
    ida_ida.inf_get_omin_ea = inf.get_min_ea
    ida_ida.inf_get_omax_ea = inf.get_max_ea
    ida_ida.inf_get_start_ea = inf.get_start_ea
    ida_ida.inf_get_baseaddr = lambda: db.base
    ida_ida.inf_get_procname = lambda: db.processor
    ida_ida.inf_get_filetype = lambda: db.filetype
    ida_ida.inf_is_be = inf.is_be
    ida_ida.inf_is_64bit = inf.is_64bit
    ida_ida.inf_is_16bit = inf.is_16bit
    ida_ida.inf_is_32bit_exactly = inf.is_32bit_exactly
    ida_ida.inf_get_app_bitness = lambda: db.bitness
    ida_ida.inf_set_app_bitness = lambda b: setattr(db, "bitness", int(b)) or True
    ida_ida.inf_set_be = lambda be: setattr(db, "endian", "be" if be else "le") or True
    ida_ida.inf_get_af = lambda: db.af
    ida_ida.inf_set_af = lambda v: setattr(db, "af", int(v)) or True
    ida_ida.inf_get_af2 = lambda: db.af2
    ida_ida.inf_set_af2 = lambda v: setattr(db, "af2", int(v)) or True

    ida_loader = _get_or_create_module("ida_loader")
    ida_loader.DBFL_SNAPSHOT = 0x20
    ida_loader.save_database = lambda path, flags=0: setattr(db, "idb_path", str(path)) or True
    ida_loader.save_snapshot = lambda name, flags=0: db.save_snapshot(name)
    ida_loader.restore_snapshot = db.restore_snapshot
    ida_loader.get_loader_name = lambda: "pe" if db.filetype == f_PE else "elf" if db.filetype == f_ELF else "bin"
    ida_loader.set_loader_options = lambda name, opts, *a, **k: True
    ida_loader.get_fileregion_offset = lambda ea: ea - db.base if ea >= db.base else BADADDR
    ida_loader.get_fileregion_ea = lambda off: db.base + off

    ida_entry = _get_or_create_module("ida_entry")
    ida_entry.add_entry = lambda ordinal, ea, name="", is_manual=False: (
        db.entries.append((ordinal, ea, name, is_manual)) or True
    )
    ida_entry.get_entry_qty = lambda: len(db.entries)
    ida_entry.get_entry = lambda ordinal: next((ea for o, ea, _n, _m in db.entries if ordinal in (o, ea)), BADADDR)
    ida_entry.get_entry_ordinal = lambda idx: db.entries[idx][0] if 0 <= idx < len(db.entries) else BADADDR
    ida_entry.get_entry_name = lambda ordinal_or_ea: next((n for o, e, n, _m in db.entries if ordinal_or_ea in (o, e)), "")

    ida_nalt = _get_or_create_module("ida_nalt")
    ida_nalt.get_input_file_path = lambda: db.input_file_path
    ida_nalt.get_idb_path = lambda: db.idb_path
    ida_nalt.get_tinfo = lambda tif, ea: False
    ida_nalt.get_import_module_qty = lambda: 0
    ida_nalt.enum_import_names = lambda *a, **k: 0
    ida_nalt.get_import_module_name = lambda *a, **k: ""
    ida_nalt.get_fileregion_offset = lambda ea: ea - db.base if ea >= db.base else BADADDR
    ida_nalt.get_fileregion_ea = lambda off: db.base + off

    ida_auto = _get_or_create_module("ida_auto")
    ida_auto.plan_range = lambda s, e: db.planned_ranges.append((s, e)) or None
    ida_auto.auto_make_step = lambda *a, **k: True
    ida_auto.auto_is_ok = lambda: True
    ida_auto.AU_FINAL = AU_FINAL

    ida_dbg = _get_or_create_module("ida_dbg")
    ida_dbg.is_debugger_on = lambda: False

    ida_fixup = _get_or_create_module("ida_fixup")
    ida_fixup.get_fixup_qty = lambda: 0

    ida_kernwin = _get_or_create_module("ida_kernwin")
    ida_kernwin.MFF_FAST = MFF_FAST
    ida_kernwin.MFF_READ = MFF_READ
    ida_kernwin.MFF_WRITE = MFF_WRITE
    ida_kernwin.execute_sync = lambda fn, flags=0: fn()

    ida_idp = _get_or_create_module("ida_idp")
    _reg_names = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "GP", "SP", "PC"]
    _reg_map = {n: i for i, n in enumerate(_reg_names)}
    ida_idp.ph = types.SimpleNamespace(reg_names=_reg_names, reg_first_sreg=0, reg_last_sreg=len(_reg_names) - 1)
    ida_idp.str2reg = lambda name: _reg_map.get(str(name).upper(), -1)
    ida_idp.reg2str = lambda r: _reg_names[r] if 0 <= r < len(_reg_names) else ""

    ida_netnode = _get_or_create_module("ida_netnode")
    ida_netnode.netnode = lambda name: db.netnodes.setdefault(name, Netnode(name))

    mods = {
        "idaapi": idaapi,
        "idc": idc,
        "idautils": idautils,
        "ida_bytes": ida_bytes,
        "ida_segment": ida_segment,
        "ida_funcs": ida_funcs,
        "ida_name": ida_name,
        "ida_typeinf": ida_typeinf,
        "ida_hexrays": ida_hexrays,
        "ida_ua": ida_ua,
        "ida_lines": ida_lines,
        "ida_frame": ida_frame,
        "ida_struct": ida_struct,
        "ida_ida": ida_ida,
        "ida_loader": ida_loader,
        "ida_entry": ida_entry,
        "ida_nalt": ida_nalt,
        "ida_auto": ida_auto,
        "ida_dbg": ida_dbg,
        "ida_fixup": ida_fixup,
        "ida_kernwin": ida_kernwin,
        "ida_idp": ida_idp,
        "ida_segregs": db.segregs,
        "ida_netnode": ida_netnode,
        "ida_gdl": ida_gdl,
        "_ida_gdl": _ida_gdl,
    }

    for name, mod in mods.items():
        # The shared isolated-loader uses this marker to distinguish the
        # harness-owned SDK objects from a test's deliberately injected
        # version-shaped module.  That lets collection-time fake-IDB setup
        # remain available to tests that import tools eagerly without leaking
        # mapped bounds into later bare-stub compatibility tests.
        if isinstance(mod, types.ModuleType):
            mod.__ida_mcp_base_stub__ = True
        sys.modules[name] = mod

    seg_mod = sys.modules.get("ida_pro_mcp.ida_mcp.tools.segments")
    if seg_mod:
        seg_mod.ida_idp = ida_idp
        seg_mod.ida_segregs = db.segregs

    try:
        import ida_pro_mcp.ida_mcp.zeromcp
        sys.modules.setdefault("ida_mcp", sys.modules["ida_pro_mcp.ida_mcp"])
        sys.modules.setdefault("zeromcp", sys.modules["ida_pro_mcp.ida_mcp.zeromcp"])
    except Exception:
        pass

    return db


# ---------------------------------------------------------------------------
# Convenience IDB Constructors
# ---------------------------------------------------------------------------

def create_fake_idb(
    processor: str = "metapc",
    bitness: int = 64,
    base: int = 0x140000000,
    endian: str = "little",
    filetype: int = f_PE,
) -> FakeDatabase:
    """Create and install a clean FakeDatabase instance."""
    db = FakeDatabase(
        processor=processor,
        bitness=bitness,
        base=base,
        endian=endian,
        filetype=filetype,
    )
    return install_fake_idb(db)


def create_sample_c_binary_idb() -> FakeDatabase:
    """Create and install a realistic C executable binary IDB fixture."""
    db = FakeDatabase(processor="metapc", bitness=64, base=0x140000000, filetype=f_PE)
    # .text segment
    db.add_segment(0x140001000, 0x1000, name=".text", sclass="CODE", perm=SEGPERM_READ | SEGPERM_EXEC)
    # .rdata segment
    db.add_segment(0x140002000, 0x1000, name=".rdata", sclass="DATA", perm=SEGPERM_READ)
    # .data segment
    db.add_segment(0x140003000, 0x1000, name=".data", sclass="DATA", perm=SEGPERM_READ | SEGPERM_WRITE)

    # main function
    db.add_func(0x140001000, 0x140001050, name="main")
    # helper function
    db.add_func(0x140001050, 0x140001080, name="sub_helper")

    # Instructions in main
    db.add_insn(0x140001000, "push", [op_t(0, o_reg, reg=5, text="rbp")], size=1)
    db.add_insn(0x140001001, "mov", [op_t(0, o_reg, reg=5, text="rbp"), op_t(1, o_reg, reg=4, text="rsp")], size=3)
    db.add_insn(0x140001004, "sub", [op_t(0, o_reg, reg=4, text="rsp"), op_t(1, o_imm, value=32, text="0x20")], size=4)
    db.add_insn(0x140001008, "call", [op_t(0, o_near, addr=0x140001050, text="sub_helper")], size=5)
    db.add_insn(0x14000100D, "xor", [op_t(0, o_reg, reg=0, text="eax"), op_t(1, o_reg, reg=0, text="eax")], size=2)
    db.add_insn(0x14000100F, "ret", size=1)

    # Xrefs & Entry
    db.add_cref(0x140001008, 0x140001050)
    db.entries.append((1, 0x140001000, "main", False))

    # Types
    struct_tif = FakeTinfo(lib=db.type_lib, name="target_struct", kind=BT_STRUCT)
    struct_tif.add_udm(udm_t("id", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4))
    struct_tif.add_udm(udm_t("name_ptr", FakeTinfo(kind=BT_PTR, size=8), offset=8, size=8))
    db.type_lib.register(struct_tif)

    return install_fake_idb(db)


def create_sample_firmware_idb() -> FakeDatabase:
    """Create and install a realistic RISC-V / ARM opaque firmware IDB fixture."""
    db = FakeDatabase(processor="riscv", bitness=32, base=0x80000000, endian="little", filetype=f_BIN)
    db.add_segment(0x80000000, 0x10000, name="ROM", sclass="CODE", perm=SEGPERM_READ | SEGPERM_EXEC | SEGPERM_WRITE)

    # Reset handler & functions
    db.add_func(0x80000000, 0x80000030, name="reset_handler")
    db.add_func(0x80000030, 0x80000090, name="main")

    db.add_insn(0x80000000, "j", [op_t(0, o_near, addr=0x80000030, text="0x80000030")], size=4)
    db.add_insn(0x80000030, "lui", [op_t(0, o_reg, reg=3, text="gp"), op_t(1, o_imm, value=0x80000, text="0x80000")], size=4)
    db.add_insn(0x80000034, "addi", [op_t(0, o_reg, reg=3, text="gp"), op_t(1, o_reg, reg=3, text="gp"), op_t(2, o_imm, value=0, text="0")], size=4)
    db.add_insn(0x80000038, "ret", size=4)

    db.entries.append((0, 0x80000000, "reset_handler", False))
    return install_fake_idb(db)
