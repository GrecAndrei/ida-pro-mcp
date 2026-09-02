"""Adversarial stress-testing suite for tests/fakes/ida_fake.py.

Empirically challenges:
1. Cyclic CFG and complex graph topologies (loops, back-edges, disconnected subgraphs, dangling refs)
2. Multi-segment boundary crossing, gaps, and memory operations
3. Struct mutations, nested types, offset recalculations, and TypeLib lifecycle
4. Deep ctree AST hierarchies, visitor hooks, and parent stack integrity
5. Multi-generation snapshot save/restore rollback idempotency & deep isolation
6. Segment registers and Netnode storage edge cases
7. Canonical SDK contract fidelity (idautils.Segments, idautils.XrefsTo.iscode, ida_bytes.get_item_size, parse_decl)
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest

from tests.fakes.ida_fake import (
    BADADDR,
    BADSEL,
    BT_ARRAY,
    BT_ENUM,
    BT_FUNC,
    BT_INT8,
    BT_INT16,
    BT_INT32,
    BT_INT64,
    BT_PTR,
    BT_STRUCT,
    BT_VOID,
    CV_PARENTS,
    FCB_CNDRET,
    FCB_INDJUMP,
    FCB_NORET,
    FCB_NORMAL,
    FCB_RET,
    FF_CODE,
    FF_DATA,
    FF_DWORD,
    FF_QWORD,
    FF_STRLIT,
    FF_WORD,
    SEGPERM_EXEC,
    SEGPERM_READ,
    SEGPERM_WRITE,
    FakeDatabase,
    FakeTinfo,
    FakeTypeLib,
    FlowChart,
    Netnode,
    _FakeSegregs,
    _SregRange,
    cexpr_t,
    cfunc_parentee_t,
    cfunc_t,
    cinsn_t,
    cit_block,
    cit_expr,
    cit_if,
    cit_return,
    cot_asg,
    cot_call,
    cot_cast,
    cot_idx,
    cot_memref,
    cot_num,
    cot_var,
    create_fake_idb,
    create_sample_c_binary_idb,
    ctree_visitor_t,
    edm_t,
    func_t,
    hexrays_failure_t,
    insn_t,
    install_fake_idb,
    lvar_t,
    o_displ,
    o_far,
    o_imm,
    o_mem,
    o_near,
    o_phrase,
    o_reg,
    o_void,
    op_t,
    qbasic_block_t,
    segment_t,
    udm_t,
)

# ---------------------------------------------------------------------------
# 1. Cyclic CFG & Graph Topologies
# ---------------------------------------------------------------------------

def test_cfg_single_block_self_loop():
    """Basic block with a self-loop (succs=[0], preds=[0])."""
    b0 = qbasic_block_t(0x1000, 0x1010, id_=0, type_=FCB_NORMAL, succs=[0], preds=[0])
    fc = FlowChart(blocks=[b0])

    assert len(fc) == 1
    assert list(b0.succs()) == [b0]
    assert list(b0.preds()) == [b0]


def test_cfg_mutual_two_node_cycle():
    """Two basic blocks mutually referencing each other."""
    b0 = qbasic_block_t(0x1000, 0x1010, id_=0, type_=FCB_NORMAL, succs=[1], preds=[1])
    b1 = qbasic_block_t(0x1010, 0x1020, id_=1, type_=FCB_NORMAL, succs=[0], preds=[0])
    fc = FlowChart(blocks=[b0, b1])

    assert len(fc) == 2
    assert list(b0.succs()) == [b1]
    assert list(b0.preds()) == [b1]
    assert list(b1.succs()) == [b0]
    assert list(b1.preds()) == [b0]


def test_cfg_large_ring_cycle():
    """100-node cycle where block i points to (i+1)%100."""
    n = 100
    blocks = [
        qbasic_block_t(
            0x1000 + i * 0x10,
            0x1000 + (i + 1) * 0x10,
            id_=i,
            succs=[(i + 1) % n],
            preds=[(i - 1 + n) % n],
        )
        for i in range(n)
    ]
    fc = FlowChart(blocks=blocks)

    assert len(fc) == 100
    for i, b in enumerate(fc):
        assert list(b.succs()) == [blocks[(i + 1) % n]]
        assert list(b.preds()) == [blocks[(i - 1 + n) % n]]


def test_cfg_disconnected_subgraphs_and_dangling_edges():
    """CFG with disconnected components and edges referencing non-existent block IDs."""
    # Component A: 0 -> 1
    b0 = qbasic_block_t(0x1000, 0x1010, id_=0, succs=[1, 999])  # 999 is dangling
    b1 = qbasic_block_t(0x1010, 0x1020, id_=1, preds=[0, 888])  # 888 is dangling
    # Component B (disconnected): 10
    b10 = qbasic_block_t(0x2000, 0x2010, id_=10, succs=[], preds=[])

    fc = FlowChart(blocks=[b0, b1, b10])

    assert len(fc) == 3
    # Dangling references must be ignored without raising KeyError
    assert list(b0.succs()) == [b1]
    assert list(b1.preds()) == [b0]
    assert list(b10.succs()) == []
    assert list(b10.preds()) == []


def test_cfg_multi_path_loops_and_exit_types():
    """CFG with loop head, loop body, conditional break, and return block."""
    b0 = qbasic_block_t(0x1000, 0x1010, id_=0, type_=FCB_NORMAL, succs=[1, 2], preds=[1])
    b1 = qbasic_block_t(0x1010, 0x1020, id_=1, type_=FCB_NORMAL, succs=[0], preds=[0])
    b2 = qbasic_block_t(0x1020, 0x1030, id_=2, type_=FCB_RET, succs=[], preds=[0])

    fc = FlowChart(blocks=[b0, b1, b2])

    assert fc.size() == 3
    assert fc[0] == b0
    assert fc[1] == b1
    assert fc[2] == b2
    assert list(b0.succs()) == [b1, b2]
    assert list(b0.preds()) == [b1]


# ---------------------------------------------------------------------------
# 2. Multi-Segment Boundary Crossing & Memory Safety
# ---------------------------------------------------------------------------

def test_multi_segment_boundary_and_gaps():
    """Verify get_bytes, patch_bytes, and get_segment across disjoint segments and unmapped gaps."""
    db = FakeDatabase(bitness=64, base=0x1000)
    seg0 = db.add_segment(0x1000, 0x1000, name=".text", sclass="CODE", perm=SEGPERM_READ | SEGPERM_EXEC, data=b"\x90" * 0x1000)
    seg1 = db.add_segment(0x3000, 0x1000, name=".data", sclass="DATA", perm=SEGPERM_READ | SEGPERM_WRITE, data=b"\xAA" * 0x1000)

    # Within segment 0
    assert db.get_segment(0x1000) == seg0
    assert db.get_segment(0x1FFF) == seg0
    assert db.get_bytes(0x1000, 4) == b"\x90\x90\x90\x90"

    # In unmapped gap
    assert db.get_segment(0x2000) is None
    assert db.get_segment(0x2500) is None
    assert db.get_segment(0x2FFF) is None
    assert db.get_bytes(0x2500, 4) is None
    assert db.patch_bytes(0x2500, b"\x00") == 0

    # Within segment 1
    assert db.get_segment(0x3000) == seg1
    assert db.get_segment(0x3FFF) == seg1
    assert db.get_bytes(0x3000, 4) == b"\xAA\xAA\xAA\xAA"

    # Overflows segment boundary on patch
    assert db.patch_bytes(0x1FFF, b"\x11\x22") == 0
    assert db.patch_bytes(0x1FFF, b"\x11") == 1
    assert db.get_bytes(0x1FFF, 1) == b"\x11"


def test_segment_deletion_and_recreation():
    """Verify segment removal and replacement."""
    db = create_fake_idb()
    sys_seg = sys.modules["ida_segment"]

    seg = db.add_segment(0x5000, 0x200, name=".custom", sclass="DATA")
    assert sys_seg.get_segm_qty() == 1
    assert sys_seg.getseg(0x5050) == seg

    ok = sys_seg.del_segm(0x5050)
    assert ok is True
    assert sys_seg.get_segm_qty() == 0
    assert sys_seg.getseg(0x5050) is None
    assert sys_seg.del_segm(0x5050) is False


# ---------------------------------------------------------------------------
# 3. Struct Mutations & Type System Stress Testing
# ---------------------------------------------------------------------------

def test_struct_complex_mutations_and_recalculations():
    """Test member additions, renames, type changes, offset recalculations, and deletions."""
    lib = FakeTypeLib()
    st = FakeTinfo(lib=lib, name="AdversarialStruct", kind=BT_STRUCT)

    m0 = udm_t("u8_val", FakeTinfo(kind=BT_INT8, size=1), offset=0, size=1)
    m1 = udm_t("u16_val", FakeTinfo(kind=BT_INT16, size=2), offset=2, size=2)
    m2 = udm_t("u32_val", FakeTinfo(kind=BT_INT32, size=4), offset=4, size=4)
    m3 = udm_t("ptr_val", FakeTinfo(kind=BT_PTR, size=8), offset=8, size=8)

    assert st.add_udm(m0) == 0
    assert st.add_udm(m1) == 0
    assert st.add_udm(m2) == 0
    assert st.add_udm(m3) == 0
    assert st.add_udm(udm_t("u8_val", FakeTinfo(kind=BT_INT8, size=1), offset=16, size=1)) != 0

    assert st.get_udm_qty() == 4
    assert st.get_size() == 16

    assert st.get_udt_member(0, 4) == m2
    assert st.get_udt_member(0, "u32_val") == m2
    assert st.get_udt_member(0, "unknown_field") is None

    assert st.set_udm_type("ptr_val", FakeTinfo(kind=BT_INT32, size=4)) == 0
    assert m3.size == 4
    assert st.get_size() == 12

    assert st.rename_udm("u8_val", "header_byte") == 0
    assert st.get_udt_member(0, "header_byte") == m0
    assert st.get_udt_member(0, "u8_val") is None

    assert st.del_udm("u16_val") == 0
    assert st.get_udm_qty() == 3
    assert st.del_udm("u16_val") != 0


def test_nested_structs_and_pointer_chain():
    """Verify struct nesting and pointer resolution."""
    lib = FakeTypeLib()

    inner = FakeTinfo(lib=lib, name="InnerStruct", kind=BT_STRUCT)
    inner.add_udm(udm_t("x", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4))
    inner.add_udm(udm_t("y", FakeTinfo(kind=BT_INT32, size=4), offset=4, size=4))
    ord_inner = lib.register(inner)

    outer = FakeTinfo(lib=lib, name="OuterStruct", kind=BT_STRUCT)
    outer.add_udm(udm_t("inner_obj", inner, offset=0, size=inner.get_size()))
    outer.add_udm(udm_t("inner_ptr", FakeTinfo(kind=BT_PTR, size=8, target_tinfo=inner), offset=8, size=8))
    ord_outer = lib.register(outer)

    assert ord_inner is not None
    assert ord_outer is not None
    assert outer.get_size() == 16

    ptr_member = outer.get_udt_member(0, "inner_ptr")
    assert ptr_member is not None
    assert ptr_member.type.is_ptr()
    assert ptr_member.type.get_pointed_object() == inner

    hdr = lib.export_header()
    assert "struct InnerStruct" in hdr
    assert "struct OuterStruct" in hdr


def test_enum_mutations_and_boundary_values():
    """Verify enum member additions with 0, negative, and large integers."""
    lib = FakeTypeLib()
    enum_t = FakeTinfo(lib=lib, name="StressEnum", kind=BT_ENUM)

    e0 = edm_t("ZERO", 0)
    e1 = edm_t("NEG_ONE", -1)
    e2 = edm_t("MAX_U32", 0xFFFFFFFF)

    assert enum_t.add_edm(e0) == 0
    assert enum_t.add_edm(e1) == 0
    assert enum_t.add_edm(e2) == 0
    assert enum_t.add_edm(edm_t("ZERO", 100)) != 0

    assert enum_t.get_edm_qty() == 3
    assert enum_t.get_edm(0) == e0
    assert enum_t.get_edm(1) == e1
    assert enum_t.get_edm(2) == e2

    assert enum_t.rename_edm("NEG_ONE", "MINUS_ONE") == 0
    assert enum_t.del_edm("ZERO") == 0
    assert enum_t.get_edm_qty() == 2


# ---------------------------------------------------------------------------
# 4. ctree AST & Visitor Transformations
# ---------------------------------------------------------------------------

def test_ctree_deep_block_and_expr_visitor():
    """Verify AST block traversal and expression discovery."""
    var_x = cexpr_t(op=cot_var, ea=0x1000)
    var_y = cexpr_t(op=cot_var, ea=0x1000)
    num_1 = cexpr_t(op=cot_num, ea=0x1000)
    expr_add = cexpr_t(op=cot_asg, x=var_x, y=cexpr_t(op=cot_num, x=var_y, y=num_1))
    stmt0 = cinsn_t(op=cit_expr, ea=0x1000, cexpr=expr_add)

    idx_expr = cexpr_t(op=cot_idx, x=var_x, y=num_1)
    cast_expr = cexpr_t(op=cot_cast, x=var_y)
    call_expr = cexpr_t(op=cot_call, a=[idx_expr, cast_expr])
    stmt1 = cinsn_t(op=cit_expr, ea=0x1004, cexpr=call_expr)

    root_block = cinsn_t(op=cit_block, ea=0x1000, cblock=[stmt0, stmt1])

    visited_ops = []

    class BlockVisitor(ctree_visitor_t):
        def visit_insn(self, insn: cinsn_t) -> int:
            visited_ops.append(("insn", insn.op))
            return 0

        def visit_expr(self, expr: cexpr_t) -> int:
            visited_ops.append(("expr", expr.op))
            return 0

    vis = BlockVisitor()
    vis.apply_to(root_block)

    assert ("insn", cit_block) in visited_ops
    assert ("insn", cit_expr) in visited_ops
    assert ("expr", cot_asg) in visited_ops
    assert ("expr", cot_call) in visited_ops
    assert ("expr", cot_idx) in visited_ops
    assert ("expr", cot_cast) in visited_ops


def test_ctree_parentee_stack_integrity():
    """Verify that cfunc_parentee_t maintains correct parent stack throughout nested traversal."""
    var_a = cexpr_t(op=cot_var, ea=0x1000)
    var_b = cexpr_t(op=cot_var, ea=0x1000)
    asg = cexpr_t(op=cot_asg, ea=0x1000, x=var_a, y=var_b)
    stmt = cinsn_t(op=cit_expr, ea=0x1000, cexpr=asg)
    block = cinsn_t(op=cit_block, ea=0x1000, cblock=[stmt])

    max_depth = [0]

    class StackCheckVisitor(cfunc_parentee_t):
        def visit_expr(self, expr: cexpr_t) -> int:
            max_depth[0] = max(max_depth[0], len(self.parents))
            return 0

    checker = StackCheckVisitor(flags=CV_PARENTS)
    checker.apply_to(block)

    assert max_depth[0] >= 2
    assert len(checker.parents) == 0


def test_ctree_visitor_short_circuit():
    """Verify that returning non-zero from visitor immediately halts traversal."""
    n1 = cexpr_t(op=cot_num, ea=0x1000)
    n2 = cexpr_t(op=cot_num, ea=0x1001)
    n3 = cexpr_t(op=cot_num, ea=0x1002)
    block = cinsn_t(
        op=cit_block,
        cblock=[
            cinsn_t(op=cit_expr, cexpr=n1),
            cinsn_t(op=cit_expr, cexpr=n2),
            cinsn_t(op=cit_expr, cexpr=n3),
        ],
    )

    visited = []

    class StopVisitor(ctree_visitor_t):
        def visit_expr(self, expr: cexpr_t) -> int:
            visited.append(expr.ea)
            if expr.ea == 0x1001:
                return 42
            return 0

    v = StopVisitor()
    rc = v.apply_to(block)
    assert rc == 42
    assert visited == [0x1000, 0x1001]


# ---------------------------------------------------------------------------
# 5. Snapshot Save / Restore Idempotency & Rollback
# ---------------------------------------------------------------------------

def test_snapshot_multi_generation_rollback():
    """Verify saving multiple snapshot generations and restoring in non-chronological order."""
    db = create_fake_idb()

    # Generation 0: Base
    db.add_func(0x1000, 0x1050, name="fn_base")
    db.set_name(0x1000, "fn_base")
    db.set_cmt(0x1000, "Base comment", rpt=False)
    db.flags[0x1000] = FF_CODE
    assert db.save_snapshot("gen0") is True

    # Generation 1: Added fn1, renamed fn_base
    db.add_func(0x2000, 0x2050, name="fn_gen1")
    db.set_name(0x1000, "fn_base_renamed")
    db.set_cmt(0x1000, "Gen1 comment", rpt=False)
    assert db.save_snapshot("gen1") is True

    # Generation 2: Deleted fn_base, added fn2
    db.del_func(0x1000)
    db.add_func(0x3000, 0x3050, name="fn_gen2")
    assert db.save_snapshot("gen2") is True

    # Verification: Currently in gen2
    assert db.get_func(0x1000) is None
    assert db.get_func(0x2000) is not None
    assert db.get_func(0x3000) is not None

    # Rollback to gen0
    assert db.restore_snapshot("gen0") is True
    assert db.get_func(0x1000) is not None
    assert db.get_name(0x1000) == "fn_base"
    assert db.get_cmt(0x1000) == "Base comment"
    assert db.get_func(0x2000) is None
    assert db.get_func(0x3000) is None

    # Jump forward to gen1
    assert db.restore_snapshot("gen1") is True
    assert db.get_name(0x1000) == "fn_base_renamed"
    assert db.get_cmt(0x1000) == "Gen1 comment"
    assert db.get_func(0x2000) is not None
    assert db.get_func(0x3000) is None

    # Invalid snapshot restore does not alter state
    assert db.restore_snapshot("invalid_snapshot") is False
    assert db.get_name(0x1000) == "fn_base_renamed"


# ---------------------------------------------------------------------------
# 6. Segregs & Netnode Storage
# ---------------------------------------------------------------------------

def test_segregs_multiple_contiguous_splits():
    """Verify segment register table splitting and segment register lookup."""
    segregs = _FakeSegregs(max_ea=0x10000)
    rg = 4

    assert segregs.split_sreg_range(0x2000, rg, 0x100) is True
    assert segregs.split_sreg_range(0x4000, rg, 0x200) is True
    assert segregs.split_sreg_range(0x6000, rg, 0x300) is True

    assert segregs.get_sreg(0x1000, rg) == BADSEL
    assert segregs.get_sreg(0x2000, rg) == 0x100
    assert segregs.get_sreg(0x3FFF, rg) == 0x100
    assert segregs.get_sreg(0x4000, rg) == 0x200
    assert segregs.get_sreg(0x5FFF, rg) == 0x200
    assert segregs.get_sreg(0x6000, rg) == 0x300
    assert segregs.get_sreg(0x7000, rg) == 0x300


def test_netnode_binary_blobs_and_overwrite():
    """Verify Netnode binary data handling including embedded nulls."""
    nn = Netnode("adversarial_node")

    raw_payload = b"\x00\xFF\x00\xAA\x55\x00\x01"
    assert nn.setblob(raw_payload, "tag_bin") is True
    assert nn.getblob("tag_bin") == raw_payload
    assert nn.blobsize("tag_bin") == 7

    assert nn.hashset("key_str", "string_val") is True
    assert nn.hashval("key_str") == "string_val"
    assert nn.hashset("key_str", "overwritten_val") is True
    assert nn.hashval("key_str") == "overwritten_val"
    assert nn.hashdel("key_str") is True
    assert nn.hashval("key_str") is None


# ---------------------------------------------------------------------------
# 7. Instruction Decoder & Operands
# ---------------------------------------------------------------------------

def test_instruction_operands_exhaustive_types():
    """Verify instruction operand properties across all 8 operand slots."""
    ops = [
        op_t(0, o_reg, reg=0, text="rax"),
        op_t(1, o_mem, addr=0x140003000, text="[0x140003000]"),
        op_t(2, o_imm, value=0x100, text="0x100"),
        op_t(3, o_displ, reg=5, addr=16, text="[rbp+16]"),
        op_t(4, o_phrase, reg=3, text="[rbx]"),
        op_t(5, o_far, addr=0x140004000, text="far_target"),
        op_t(6, o_near, addr=0x140001050, text="near_target"),
    ]
    insn = insn_t(ea=0x140001000, size=7, mnem="mov", ops=ops)

    assert len(insn.ops) == 8
    assert insn.Op1.type == o_reg
    assert insn.Op2.type == o_mem
    assert insn.Op3.type == o_imm
    assert insn.Op4.type == o_displ
    assert insn.ops[7].type == o_void

    db = FakeDatabase()
    out = insn_t()
    db.instructions[0x140001000] = insn
    assert db.decode_insn(out, 0x140001000) == 7
    assert out.ea == 0x140001000
    assert out.size == 7
    assert out.Op1.type == o_reg
    assert db.decode_insn(out, 0x99999999) == 0


# ---------------------------------------------------------------------------
# 8. Empirical SDK Contract Fidelity & Regression Tests
# ---------------------------------------------------------------------------

def test_bug_idautils_segments_yields_integer_ea():
    """idautils.Segments() in live IDA yields integer start addresses, allowing getseg(seg_ea)."""
    db = create_fake_idb()
    db.add_segment(0x1000, 0x1000, name=".text")
    idautils = sys.modules["idautils"]
    ida_segment = sys.modules["ida_segment"]

    for seg_ea in idautils.Segments():
        assert isinstance(seg_ea, int), f"Expected int EA, got {type(seg_ea)}"
        seg = ida_segment.getseg(seg_ea)
        assert seg is not None


def test_bug_idautils_xrefs_have_iscode_attribute():
    """idautils.XrefsTo() and XrefsFrom() items must supply iscode, type, and user attributes."""
    create_sample_c_binary_idb()
    idautils = sys.modules["idautils"]

    xrefs = list(idautils.XrefsTo(0x140001050))
    assert len(xrefs) > 0
    for xr in xrefs:
        assert hasattr(xr, "iscode"), "Xref item missing .iscode attribute"
        assert xr.iscode in (0, 1, True, False)
        assert hasattr(xr, "type")
        assert hasattr(xr, "user")

    xrefs_from = list(idautils.XrefsFrom(0x140001008))
    assert len(xrefs_from) > 0
    for xr in xrefs_from:
        assert hasattr(xr, "iscode")
        assert xr.iscode in (0, 1, True, False)
        assert hasattr(xr, "type")
        assert hasattr(xr, "user")


def test_bug_ida_bytes_has_get_item_size():
    """ida_bytes.get_item_size is called by segments.py:955."""
    create_sample_c_binary_idb()
    ida_bytes = sys.modules["ida_bytes"]
    assert hasattr(ida_bytes, "get_item_size"), "ida_bytes missing get_item_size"
    size = ida_bytes.get_item_size(0x140001000)
    assert size >= 1


def test_bug_ctree_visitor_recurses_into_if_statements():
    """ctree_visitor_t.apply_to should traverse children of cit_if statements."""
    var_x = cexpr_t(op=cot_var, ea=0x1000)
    call_expr = cexpr_t(op=cot_call, ea=0x1004)
    stmt_call = cinsn_t(op=cit_expr, ea=0x1004, cexpr=call_expr)
    inner_block = cinsn_t(op=cit_block, ea=0x1004, cblock=[stmt_call])
    stmt_if = cinsn_t(op=cit_if, ea=0x1004, cexpr=var_x, cif=inner_block)
    root = cinsn_t(op=cit_block, ea=0x1000, cblock=[stmt_if])

    visited = []

    class Vis(ctree_visitor_t):
        def visit_expr(self, e: cexpr_t) -> int:
            visited.append(e.op)
            return 0

    Vis().apply_to(root)
    assert cot_call in visited, "cot_call inside cit_if statement was not visited"


def test_bug_snapshot_rollback_restores_name_to_ea_index():
    """Snapshot rollback must restore _name_to_ea index, comments, and memory completely."""
    db = create_fake_idb()
    db.add_segment(0x1000, 0x100, name=".data", data=b"\x00" * 0x100)
    db.set_name(0x1000, "name1")
    db.set_cmt(0x1000, "initial cmt", rpt=True)
    db.patch_bytes(0x1000, b"\x11\x22")
    db.save_snapshot("snap1")

    db.set_name(0x1000, "name2")
    db.set_cmt(0x1000, "changed cmt", rpt=True)
    db.patch_bytes(0x1000, b"\x99\x99")
    db.restore_snapshot("snap1")

    assert db.get_name_ea("name1") == 0x1000
    assert db.get_name_ea("name2") == BADADDR, "name2 should not resolve to 0x1000 after restoring snap1"
    assert db.get_cmt(0x1000, rpt=True) == "initial cmt"
    assert db.get_bytes(0x1000, 2) == b"\x11\x22"


def test_bug_parse_decl_empty_string_safe():
    """parse_decl on empty string should not raise unhandled IndexError."""
    create_fake_idb()
    ida_typeinf = sys.modules["ida_typeinf"]
    tif = FakeTinfo()
    try:
        ok = ida_typeinf.parse_decl(tif, None, "")
        assert ok is False or ok is None or ok is True
    except IndexError:
        pytest.fail("parse_decl raised unhandled IndexError on empty string")


def test_idc_get_inf_attr_af_and_af2():
    """idc.get_inf_attr must return db.af and db.af2 for INF_AF and INF_AF2."""
    db = create_fake_idb()
    db.af = 0x12345678
    db.af2 = 0x87654321
    idc = sys.modules["idc"]

    assert idc.get_inf_attr(idc.INF_AF) == 0x12345678
    assert idc.get_inf_attr(5) == 0x12345678
    assert idc.get_inf_attr(idc.INF_AF2) == 0x87654321
    assert idc.get_inf_attr(6) == 0x87654321


def test_typelib_register_cleans_up_old_ordinal():
    """Re-registering a type under the same name must remove the old ordinal mapping."""
    lib = FakeTypeLib()
    t1 = FakeTinfo(kind=BT_STRUCT, name="MyStruct")
    ord1 = lib.register(t1)
    assert ord1 is not None
    assert lib.by_ordinal(ord1) == t1

    t2 = FakeTinfo(kind=BT_STRUCT, name="MyStruct")
    ord2 = lib.register(t2)
    assert ord2 is not None
    assert ord2 != ord1
    assert lib.by_ordinal(ord1) is None
    assert lib.by_ordinal(ord2) == t2
