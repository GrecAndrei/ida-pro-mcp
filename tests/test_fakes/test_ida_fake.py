"""Comprehensive unit tests for tests/fakes/ida_fake.py harness."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.fakes.ida_fake import (
    BADADDR,
    BADSEL,
    BT_ENUM,
    BT_INT32,
    BT_PTR,
    BT_STRUCT,
    BT_VOID,
    CV_PARENTS,
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
    cot_asg,
    cot_call,
    cot_num,
    cot_var,
    create_fake_idb,
    create_sample_c_binary_idb,
    create_sample_firmware_idb,
    ctree_visitor_t,
    edm_t,
    func_t,
    hexrays_failure_t,
    insn_t,
    install_fake_idb,
    lvar_t,
    o_imm,
    o_near,
    o_reg,
    o_void,
    op_t,
    qbasic_block_t,
    segment_t,
    udm_t,
)


def test_segment_t_properties():
    seg = segment_t(start_ea=0x1000, end_ea=0x2000, name=".text", sclass="CODE", perm=5, bitness=64)
    assert seg.start_ea == 0x1000
    assert seg.end_ea == 0x2000
    assert seg.size() == 0x1000
    assert seg.contains(0x1000)
    assert seg.contains(0x1FFF)
    assert not seg.contains(0x2000)
    assert not seg.contains(0x0FFF)
    assert ".text" in repr(seg)


def test_segregs_split_and_lookup():
    segregs = _FakeSegregs(max_ea=0x10000)
    assert segregs.get_sreg(0x100, 3) == BADSEL
    assert segregs.get_sreg_ranges_qty(3) == 1

    ok = segregs.split_sreg_range(0x2000, 3, 0x80000, tag=_FakeSegregs.SR_user)
    assert ok is True
    assert segregs.get_sreg(0x1000, 3) == BADSEL
    assert segregs.get_sreg(0x2000, 3) == 0x80000
    assert segregs.get_sreg(0x3000, 3) == 0x80000

    out = _SregRange()
    assert segregs.get_sreg_range(out, 0x2500, 3) is True
    assert out.start_ea == 0x2000
    assert out.val == 0x80000

    assert segregs.getn_sreg_range(out, 3, 0) is True
    assert segregs.getn_sreg_range(out, 3, 99) is False
    assert segregs.split_sreg_range(-1, 3, 0) is False


def test_flowchart_and_basic_blocks():
    b0 = qbasic_block_t(0x1000, 0x1020, id_=0, succs=[1, 2])
    b1 = qbasic_block_t(0x1020, 0x1040, id_=1, succs=[3], preds=[0])
    b2 = qbasic_block_t(0x1040, 0x1060, id_=2, succs=[3], preds=[0])
    b3 = qbasic_block_t(0x1060, 0x1080, id_=3, preds=[1, 2])
    fc = FlowChart(blocks=[b0, b1, b2, b3])

    assert len(fc) == 4
    assert fc.size() == 4
    assert list(b0.succs()) == [b1, b2]
    assert list(b3.preds()) == [b1, b2]
    assert "#0" in repr(b0)


def test_func_t_structure():
    f = func_t(start_ea=0x1000, end_ea=0x1050, name="target_fn", flags=0x10, tails=[(0x2000, 0x2020)])
    assert f.size() == 0x50
    assert f.contains(0x1020)
    assert f.contains(0x2010)
    assert not f.contains(0x1060)
    assert "target_fn" in repr(f)


def test_instruction_and_operands():
    op0 = op_t(0, o_reg, reg=1, text="rax")
    op1 = op_t(1, o_imm, value=42, text="42")
    insn = insn_t(ea=0x1000, size=5, mnem="mov", ops=[op0, op1])

    assert insn.get_canon_mnem() == "mov"
    assert insn.get_canon_feature() == 0
    assert insn.Op1.type == o_reg
    assert insn.Op2.value == 42
    assert insn.Op3.type == o_void
    op0.clr_shown()
    assert "mov" in repr(insn)
    assert "rax" in repr(op0)


def test_type_library_and_tinfo():
    lib = FakeTypeLib()
    struct_tif = FakeTinfo(lib=lib, name="MyStruct", kind=BT_STRUCT)
    assert struct_tif.is_struct()
    assert not struct_tif.is_enum()

    m0 = udm_t("field_0", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4)
    m1 = udm_t("field_4", FakeTinfo(kind=BT_PTR, size=8), offset=4, size=8)
    assert struct_tif.add_udm(m0) == 0
    assert struct_tif.add_udm(m1) == 0
    assert struct_tif.add_udm(m0) != 0
    assert struct_tif.get_udm_qty() == 2
    assert struct_tif.get_udm(0) == m0
    assert struct_tif.get_udm(5) is None
    assert struct_tif.get_udt_member(0, "field_4") == m1
    assert struct_tif.get_udt_member(0, 0) == m0
    assert struct_tif.get_udt_member(0, 999) is None

    assert struct_tif.rename_udm("field_0", "field_renamed") == 0
    assert struct_tif.rename_udm("not_exist", "x") != 0
    assert struct_tif.set_udm_type("field_renamed", FakeTinfo(kind=BT_VOID, size=1)) == 0
    assert struct_tif.set_udm_type("not_exist", FakeTinfo(kind=BT_VOID)) != 0
    assert struct_tif.del_udm("field_renamed") == 0
    assert struct_tif.del_udm("not_exist") != 0

    # Enum
    enum_tif = FakeTinfo(lib=lib, name="MyEnum", kind=BT_ENUM)
    assert enum_tif.is_enum()
    e0 = edm_t("ENUM_A", 10)
    e1 = edm_t("ENUM_B", 20)
    assert enum_tif.add_edm(e0) == 0
    assert enum_tif.add_edm(e1) == 0
    assert enum_tif.add_edm(e0) != 0
    assert enum_tif.get_edm_qty() == 2
    assert enum_tif.get_edm(0) == e0
    assert enum_tif.get_edm(99) is None
    assert enum_tif.rename_edm("ENUM_A", "ENUM_ALPHA") == 0
    assert enum_tif.rename_edm("NOT_EXIST", "X") != 0
    assert enum_tif.del_edm("ENUM_ALPHA") == 0
    assert enum_tif.del_edm("NOT_EXIST") != 0

    # Register in lib
    ord_s = lib.register(struct_tif)
    ord_e = lib.register(enum_tif)
    assert ord_e is not None
    assert lib.get("MyStruct") == struct_tif
    assert lib.by_ordinal(ord_s) == struct_tif
    assert lib.by_tid(struct_tif.get_tid()) == struct_tif
    assert lib.by_tid(999999) is None
    assert lib.by_ordinal(999999) is None

    hdr = lib.export_header()
    assert "struct MyStruct" in hdr
    assert "enum MyEnum" in hdr

    assert lib.delete("MyStruct") is True
    assert lib.delete("NonExistent") is False
    assert repr(struct_tif).startswith("<FakeTinfo")
    assert repr(m1).startswith("<udm_t")
    assert repr(e1).startswith("<edm_t")


def test_ctree_ast_visitor():
    var_a = cexpr_t(op=cot_var, ea=0x1000)
    num_1 = cexpr_t(op=cot_num, ea=0x1000)
    asg = cexpr_t(op=cot_asg, ea=0x1000, x=var_a, y=num_1)
    call = cexpr_t(op=cot_call, ea=0x1004, a=[var_a])
    stmt1 = cinsn_t(op=cit_expr, ea=0x1000, cexpr=asg)
    stmt2 = cinsn_t(op=cit_expr, ea=0x1004, cexpr=call)
    block = cinsn_t(op=cit_block, ea=0x1000, cblock=[stmt1, stmt2])
    cfunc = cfunc_t(entry_ea=0x1000, body=block, lvars=[lvar_t("a")])

    assert cfunc.entry_ea == 0x1000
    assert len(cfunc.get_lvars()) == 1
    assert len(cfunc.get_pseudocode()) > 0
    assert cfunc.get_func_type().is_func()

    visited_exprs = []
    visited_insns = []

    class TestVisitor(ctree_visitor_t):
        def visit_insn(self, insn: cinsn_t) -> int:
            visited_insns.append(insn.op)
            return 0

        def visit_expr(self, expr: cexpr_t) -> int:
            visited_exprs.append(expr.op)
            return 0

    vis = TestVisitor()
    vis.apply_to(cfunc.body)
    assert cit_block in visited_insns
    assert cit_expr in visited_insns
    assert cot_asg in visited_exprs
    assert cot_var in visited_exprs
    assert cot_num in visited_exprs
    assert cot_call in visited_exprs

    parentee = cfunc_parentee_t(flags=CV_PARENTS)
    parentee.apply_to(cfunc.body)
    assert len(parentee.parents) == 0


def test_netnode_operations():
    node = Netnode("test_node")
    node.altset(1, 100)
    assert node.altget(1) == 100
    assert node.altget(2) is None

    node.supset(10, b"data_val")
    assert node.supval(10) == b"data_val"
    assert node.supdel(10) is True
    assert node.supdel(10) is False

    node.hashset("key1", "val1")
    assert node.hashval("key1") == "val1"
    assert node.hashdel("key1") is True
    assert node.hashdel("key1") is False

    node.setblob(b"\x01\x02\x03", "blob_tag")
    assert node.getblob("blob_tag") == b"\x01\x02\x03"
    assert node.blobsize("blob_tag") == 3


def test_fake_database_and_sdk_installer():
    db = create_sample_c_binary_idb()
    assert sys.modules["idaapi"].BADADDR == BADADDR
    assert sys.modules["ida_funcs"].get_func_name(0x140001000) == "main"
    assert sys.modules["ida_name"].get_name(0x140001000) == "main"
    assert sys.modules["idc"].get_name_ea_simple("main") == 0x140001000

    # Memory inspection & patch
    bytes_before = db.get_bytes(0x140001000, 4)
    assert bytes_before is not None
    assert db.patch_bytes(0x140001000, b"\x90\x90\x90\x90") == 4
    assert db.get_bytes(0x140001000, 4) == b"\x90\x90\x90\x90"

    # Snapshots
    assert db.save_snapshot("snap1") is True
    assert db.patch_bytes(0x140001000, b"\xCC\xCC\xCC\xCC") == 4
    assert db.restore_snapshot("snap1") is True
    assert db.restore_snapshot("non_existent") is False

    # Decompile synthetic
    cfunc = db.decompile(0x140001000)
    assert cfunc.entry_ea == 0x140001000
    assert len(cfunc.get_pseudocode()) > 0

    # Failure path
    db.decompiler_failures.add(0x140001050)
    try:
        db.decompile(0x140001050)
        assert False, "Should have raised hexrays_failure_t"
    except hexrays_failure_t:
        pass


def test_sample_firmware_idb():
    fw_db = create_sample_firmware_idb()
    assert fw_db.processor == "riscv"
    assert fw_db.bitness == 32
    assert fw_db.get_func(0x80000000) is not None
    assert fw_db.get_func(0x80000000).name == "reset_handler"
    assert sys.modules["ida_ida"].inf_get_procname() == "riscv"
    assert sys.modules["ida_entry"].get_entry_qty() == 1
