"""s08-blockers regression tests.

Pins the s08 blocker fixes with standalone _FakeIda-style fakes (no live IDA):

1. ``code_helpers._function_may_reference_apis`` is a conservative SUPERSET of
   ctree detection. On an opaque raw RISC-V blob a function's only call may be
   a register-indirect ``jalr`` — no o_near operand for the cheap disassembly
   scan to resolve, and no API symbol in ``idc.get_name_ea_simple``. The cheap
   scan is therefore *inconclusive*, and the pre-filter must fall through
   (return True) so the ctree detector runs. Skipping on inconclusive evidence
   is what silently dropped legitimate api_chain matches (count==0).

2. ``tests/ida_mcp/test_swarm_q04_search.py`` deadline test patches
   ``time.time`` / ``time.monotonic`` on the SHARED ``time`` module (semantic.py
   does ``import time as _time``). The restore must use the ORIGINAL functions
   captured before patching; the old ``import time as _real_time`` restore was a
   self-referential no-op that froze time globally (hanging
   ``test_pending_work_is_bounded_and_never_calls_auto_wait``).

3. The harness (``tests/conftest.py`` ``_isolate_sys_modules``) restores
   ``sys.path`` per-test. Loading ``server_script.py`` (as q07's bridge tests
   do) inserts ``src/ida_pro_mcp/ida_mcp`` and siblings into ``sys.path`` at
   module scope; without the restore that leaked into later tests, making flat
   ``import cache`` and top-level ``import ida_mcp`` resolve to the real source
   (the q07->t19 flat ``_tool_cache()`` failure and the q07->q01 real
   ``ida_mcp/__init__`` import failure).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import (  # noqa: E402
    install_common_stub,
    load_support_module,
    load_tool_module,
    load_tool_submodule,
)

# ===========================================================================
# 1. api_chain pre-filter: conservative superset on an opaque RISC-V blob
# ===========================================================================

def _load_arch_helpers() -> dict:
    """Real arch_utils helpers so ``code_helpers._is_flow_control_mnemonic``
    classifies RISC-V ``jalr`` as flow control inside the isolated stub."""
    au = load_support_module("arch_utils")
    return {
        "get_arch": lambda: "riscv",
        "is_riscv_family": au.is_riscv_family,
        "is_arm_family": au.is_arm_family,
        "is_return_mnemonic": au.is_return_mnemonic,
        "is_call_mnemonic": au.is_call_mnemonic,
        "is_syscall_mnemonic": au.is_syscall_mnemonic,
        "CONDITIONAL_BRANCH_MNEMONICS": au.CONDITIONAL_BRANCH_MNEMONICS,
        "UNCONDITIONAL_JUMP_MNEMONICS": au.UNCONDITIONAL_JUMP_MNEMONICS,
    }


def _make_code_helpers():
    """Load ``code_helpers`` with the arch helpers bound into ``_common`` so the
    RISC-V flow-control classification works in the isolated stub."""
    install_common_stub()
    return load_tool_module("code_helpers", common_overrides=_load_arch_helpers())


def _install_riscv_blob_fakes(chain_names):
    """Install a FakeIDB for the api_chain detector over an opaque RISC-V blob.

    - one function ``riscv_handler`` at 0x1000 whose only flow instruction is a
      register-indirect ``jalr`` — ``get_operand_type`` never returns an
      o_near/o_far code-ref operand, so ``_flow_target_ea`` resolves nothing;
    - no symbol xrefs: ``idc.get_name_ea_simple`` returns BADADDR for every API
      name (raw blob), so ``api_ea_set`` is empty;
    - ``ida_hexrays.decompile`` yields a ctree whose call chain is the given
      API names in order (e.g. ["recv", "memcpy"]).
    """
    install_common_stub()
    idaapi = sys.modules["idaapi"]
    idc = sys.modules["idc"]
    idautils = sys.modules["idautils"]
    ida_funcs = sys.modules["ida_funcs"]
    ida_hexrays = sys.modules["ida_hexrays"]
    ida_ua = sys.modules["ida_ua"]

    idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    ida_hexrays.CV_FAST = 0
    ida_hexrays.cot_call = 24
    ida_hexrays.cot_obj = 28
    ida_ua.o_near = 7
    ida_ua.o_far = 6

    funcs = {0x1000: {"name": "riscv_handler", "size": 0x40}}
    _func_eas = sorted(funcs)
    call_ea = {name: 0x2000 + i * 0x100 for i, name in enumerate(chain_names)}
    ea_to_name = {v: k for k, v in call_ea.items()}

    def get_next_func(ea):
        for f_ea in _func_eas:
            if f_ea > ea:
                return f_ea
        return idaapi.BADADDR

    def get_func(ea):
        for f_ea, info in funcs.items():
            if f_ea <= ea < f_ea + info["size"]:
                return types.SimpleNamespace(start_ea=f_ea, end_ea=f_ea + info["size"])
        return None

    def func_items(ea):
        info = funcs.get(ea)
        return range(ea, ea + info["size"], 4) if info else []

    def code_refs_from(ea, flow):
        return iter([])  # opaque blob: no resolved code xrefs

    def print_insn_mnem(ea):
        return "jalr"  # register-indirect call — unresolvable by the cheap scan

    def get_operand_type(ea, i):
        return 0  # never an o_near/o_far code-ref operand

    def get_operand_value(ea, i):
        return 0

    def get_name(ea):
        return ea_to_name.get(ea, "")

    def get_name_ea_simple(name):
        return idaapi.BADADDR  # opaque blob: no symbols

    def get_func_name(ea):
        info = funcs.get(ea)
        return info["name"] if info else ""

    ida_funcs.get_next_func = get_next_func
    ida_funcs.get_func = get_func
    ida_funcs.get_func_name = get_func_name
    idc.get_func_name = get_func_name  # code_helpers calls idc.get_func_name
    idautils.FuncItems = func_items
    idautils.CodeRefsFrom = code_refs_from
    idc.print_insn_mnem = print_insn_mnem
    idc.get_operand_type = get_operand_type
    idc.get_operand_value = get_operand_value
    idc.get_name = get_name
    idc.get_name_ea_simple = get_name_ea_simple

    # Ctree mock: ChainCollector walks the body and records call-target names.
    class _Obj:
        def __init__(self, ea):
            self.op = ida_hexrays.cot_obj
            self.obj_ea = ea

    class _Call:
        def __init__(self, ea):
            self.op = ida_hexrays.cot_call
            self.x = _Obj(ea)

    class _Visitor:
        def __init__(self, flags):
            pass

        def apply_to(self, body, item):
            for ea in body:
                self.visit_expr(_Call(ea))
            return 0

        def visit_expr(self, expr):
            return 0

    ida_hexrays.ctree_visitor_t = _Visitor

    def _decompile(ea):
        if ea == 0x1000:
            return types.SimpleNamespace(body=[call_ea[n] for n in chain_names])
        return None

    ida_hexrays.decompile = _decompile


def test_function_may_reference_apis_inconclusive_falls_through():
    """An inconclusive cheap scan (no code xref to a resolved API EA, no
    flow-target name match) must return True so the ctree detector runs — it
    must NOT skip the function."""
    mod = _make_code_helpers()
    _install_riscv_blob_fakes(["recv", "memcpy"])
    # get_name_ea_simple -> BADADDR for every API, so api_ea_set is empty; the
    # jalr target cannot be resolved; the scan finds no positive evidence.
    assert mod._function_may_reference_apis(0x1000, {"recv", "memcpy"}, set()) is True


def test_api_chain_superset_prefilter_finds_raw_riscv_blob():
    """Opaque RISC-V raw blob: the function's only call is a register-indirect
    jalr and no API symbol resolves. The pre-filter must not drop it — the
    ctree detector must find the recv->memcpy chain (count==1)."""
    mod = _make_code_helpers()
    _install_riscv_blob_fakes(["recv", "memcpy"])
    mod._CUSTOM_DETECTORS.clear()
    try:
        result = mod._detect_api_chains(["recv", "memcpy"], strict_order=True, max_items=10)
        assert len(result) == 1, result
        assert result[0]["name"] == "riscv_handler", result
    finally:
        mod._CUSTOM_DETECTORS.clear()


# ===========================================================================
# 2. q04 deadline test: time restore must use the ORIGINAL functions
# ===========================================================================

def _semantic():
    """Return search.semantic via the real search package __init__ so
    ``from . import _query_insight_by_tags`` resolves."""
    load_tool_submodule("search", common_overrides={"os": os})
    return sys.modules["ida_pro_mcp.ida_mcp.tools.search.semantic"]


def test_semantic_time_patch_restore_is_not_a_self_referential_noop():
    """q04's deadline test patches time.time/time.monotonic on the shared time
    module; the restore must use the ORIGINAL functions captured before
    patching. The old ``import time as _real_time`` restore was a no-op
    (``_real_time`` IS the already-patched module) and froze time globally."""
    sem = _semantic()
    assert sem._time is time, "semantic.py does `import time as _time`"

    real_time = time.time
    real_monotonic = time.monotonic
    try:
        # The old (buggy) restore path cannot work: `_real_time` is the same
        # module whose `time` attribute was just replaced.
        def fake_time():
            return 0.0

        sem._time.time = fake_time
        sem._time.monotonic = lambda: 100.0
        import time as _real_time  # noqa: F811 — this IS the patched module
        assert _real_time is time
        sem._time.time = _real_time.time  # the old "restore": a no-op
        assert time.time is fake_time, "old restore leaves the patch in place"

        # Fixed restore: capture the real functions BEFORE patching.
        sem._time.time = fake_time
        sem._time.time = real_time
        sem._time.monotonic = real_monotonic
        assert time.time is real_time
        assert time.monotonic is real_monotonic
        # The module is usable again — time actually advances.
        t0 = time.monotonic()
        t1 = time.monotonic()
        assert t1 >= t0
    finally:
        sem._time.time = real_time
        sem._time.monotonic = real_monotonic


# ===========================================================================
# 3. harness: sys.path restored per test after server_script pollution
# ===========================================================================

def _load_server_script_ut():
    """Load server_script.py standalone (as q07's bridge tests do) and return
    the module. Its module body inserts the repo src dirs into sys.path."""
    for name in ("ida_segment", "idautils", "idc"):
        sys.modules.setdefault(name, types.ModuleType(name))
    spec = importlib.util.spec_from_file_location(
        "s4_server_script_ut",
        str(REPO / "src" / "ida_pro_mcp" / "server_script.py"),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["s4_server_script_ut"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_server_script_load_inserts_src_into_sys_path():
    """Loading server_script.py inserts the repo src dirs into sys.path at
    module scope. Pin the mechanism so the per-test restore below has a real
    leak to undo (this is the leak behind the q07->t19 / q07->q01 failures)."""
    _load_server_script_ut()
    assert str(REPO / "src") in sys.path
    ida_mcp_root = str(REPO / "src" / "ida_pro_mcp" / "ida_mcp")
    assert ida_mcp_root in sys.path


def test_sys_path_is_restored_between_tests():
    """The harness (tests/conftest.py _isolate_sys_modules) restores sys.path
    per test, so the server_script pollution from the previous test is gone
    here. Before the fix it leaked, making flat ``import cache`` and top-level
    ``import ida_mcp`` resolve to the real source in later tests."""
    ida_mcp_root = str(REPO / "src" / "ida_pro_mcp" / "ida_mcp")
    assert ida_mcp_root not in sys.path
    # No flat top-level `cache` module may be resolvable through a leaked path.
    try:
        spec = importlib.util.find_spec("cache")
    except (ImportError, ValueError):
        spec = None
    origin = (spec.origin or "") if spec is not None else ""
    assert "ida_pro_mcp" not in origin, origin
