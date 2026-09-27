"""Regression tests for p14_misc_tools audit fixes.

Covers:
- governance_engine ontology property names aligned with axiom names
  (DangerousCodeSectionPatch / UnsafeStackFrameChange / MisleadingRename now
  actually classify), with regressions that ImportTablePatch and PII redaction
  still work.
- modify: governance-blocked error carries the dict in ``details`` (not
  ``hint``); patch_bytes / rename_local no longer rejected by the value guard
  and now run governance; rename reports its cross-session side effect and no
  longer spawns the unsafe background propagation; thunks are no longer
  mislabelled as FLIRT-identified.
- batch: analyze_function template uses the code action strings_in_func;
  template annotation lists the real registry; macro-DSL tool failures use the
  catalog error path instead of a non-catalog TOOL_ERROR.
- intelligence: dead suggest_next_steps / _parse_register_offset /
  _persist_embedder_state removed.
- wiki: dead _get_wiki_root removed.
- knowledge: fallback imports point at real host modules.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

# ---------------------------------------------------------------------------
# governance_engine — ontology property names now match axiom names
# ---------------------------------------------------------------------------

def test_governance_dangerous_code_section_patch_fires():
    gov = load_tool_module("governance_engine")
    result = gov.evaluate_operation(
        operation_type="patch",
        addr=0x401000,
        proposed_value="nop",
        metadata={"section_type": ".text", "is_import_addr": False, "modifies_control_flow": True},
    )
    assert result["approved"] is False
    assert result["verdict"] == "blocked"
    assert result["ontology_class"] == "DangerousCodeSectionPatch"


def test_governance_unsafe_stack_frame_change_fires():
    gov = load_tool_module("governance_engine")
    result = gov.evaluate_operation(
        operation_type="type_change",
        proposed_value="struct __frame",
        metadata={"targets_stack": True, "changes_frame_size": True},
    )
    assert result["ontology_class"] == "UnsafeStackFrameChange"
    assert result["approved"] is False
    assert result["verdict"] == "blocked"


def test_governance_misleading_rename_fires():
    gov = load_tool_module("governance_engine")
    result = gov.evaluate_operation(
        operation_type="rename",
        proposed_value="safe_parse",
        metadata={"contradicts_api": True},
    )
    assert result["ontology_class"] == "MisleadingRename"
    # WARNED verdict still approves (non-blocking).
    assert result["approved"] is True
    assert result["verdict"] == "warned"


def test_governance_import_table_patch_still_blocks():
    gov = load_tool_module("governance_engine")
    result = gov.evaluate_operation(
        operation_type="patch",
        proposed_value="nop",
        metadata={"section_type": ".idata", "is_import_addr": True},
    )
    assert result["approved"] is False
    assert result["verdict"] == "blocked"
    assert result["ontology_class"] == "ImportTablePatch"


def test_governance_pii_comment_still_redacts():
    gov = load_tool_module("governance_engine")
    result = gov.evaluate_operation(
        operation_type="comment",
        proposed_value="C2 at 192.168.1.1",
    )
    assert result["verdict"] == "redacted"
    assert result["approved"] is True
    assert "[IP_REDACTED]" in result["redacted_content"]


# ---------------------------------------------------------------------------
# modify — value resolution, governance envelope, rename side effects, thunks
# ---------------------------------------------------------------------------

class _Seg:
    def __init__(self, name: str, perm: int):
        self.name = name
        self.perm = perm


def _load_modify(real_make_error: bool = True):
    """Load governance_engine + modify with the ida_* surface stubbed."""
    load_tool_module("governance_engine")
    mod = load_tool_module("modify")
    mod.MCPError.GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    mod.ida_name.SN_FORCE = 1
    mod.ida_segment.SEGPERM_X = 1
    # Metadata-gathering safety valves (avoid AttributeError on blank ida stubs).
    mod.ida_nalt.get_tinfo = lambda *a, **k: False
    mod.ida_typeinf.tinfo_t = lambda: None
    mod.idautils.Heads = lambda *a, **k: iter(())
    mod.idautils.CodeRefsFrom = lambda *a, **k: iter(())
    # Functions used by _persist_symbol_knowledge's callgraph/string walk.
    mod.idautils.CodeRefsTo = lambda *a, **k: iter(())
    mod.idautils.FuncItems = lambda *a, **k: iter(())
    mod.idautils.DataRefsFrom = lambda *a, **k: iter(())
    mod.idc.get_strlit_contents = lambda *a, **k: None
    mod.idc.get_idb_path = lambda: ""
    # Default: no function at the rename address (metadata + persistence skip).
    mod.ida_funcs.get_func = lambda ea: None
    mod.ida_funcs.FUNC_LIB = 0x200
    mod.ida_funcs.FUNC_THUNK = 0x40
    # Isolate the cross-session SymbolDB write (no real DB in tests).
    class _FakeSymbolDB:
        def __init__(self):
            pass

        def upsert_symbol(self, row):
            return 1

    fake = types.ModuleType("ida_pro_mcp.services")
    fake.SymbolDB = _FakeSymbolDB
    sys.modules.setdefault("ida_pro_mcp.services", fake)
    if real_make_error:
        # Exercise modify() against the real error contract so the
        # "dict must go to details, not hint" bug is observable.
        from _isolated_repo_loader import load_ida_module

        err = load_ida_module("error_handling")
        mod.make_error = err.make_error
        mod.ERROR_HINTS = err.ERROR_HINTS
    return mod


def test_modify_patch_bytes_blocked_on_exec_section_with_details():
    mod = _load_modify()
    mod.ida_segment.getseg = lambda ea: _Seg(".text", 1)
    mod.ida_segment.get_segm_name = lambda seg, flags=0: seg.name

    r = mod.modify(action="patch_bytes", addr="0x401000", hex_bytes="9090")
    assert r["error"] is True
    assert r["code"] == "GOVERNANCE_BLOCKED"
    # Violations land in details (not hint) and hint stays a guidance string.
    assert r["details"]["ontology_class"] == "DangerousCodeSectionPatch"
    assert isinstance(r["hint"], str) and "governance" in r["hint"].lower()


def test_modify_patch_bytes_ok_on_non_exec_section():
    mod = _load_modify()
    mod.ida_segment.getseg = lambda ea: _Seg(".data", 2)
    mod.ida_segment.get_segm_name = lambda seg, flags=0: seg.name
    mod.ida_bytes.patch_bytes = lambda *a, **k: None

    r = mod.modify(action="patch_bytes", addr="0x402000", hex_bytes="9090")
    assert r["ok"] is True
    assert r["size"] == 2


def test_modify_rename_local_accepts_new_name_kwarg():
    mod = _load_modify()
    mod.ida_funcs.get_func = lambda ea: types.SimpleNamespace(
        start_ea=0x401000, end_ea=0x402000, flags=0
    )
    mod.ida_funcs.get_func_start = lambda ea: 0x401000
    mod.ida_funcs.ida_idaapi = types.SimpleNamespace(BADADDR=-1)
    mod.ida_funcs.func_entry_info_t = types.SimpleNamespace
    mod.ida_funcs.get_func_entry_info = lambda out, ea, flags=0: False
    mod.ida_funcs.get_func_flags = lambda ea: 0
    mod.ida_funcs.set_func_flags = lambda ea, flags: True

    class _Lv:
        def __init__(self, name):
            self.name = name

    class _Cfunc:
        lvars = [_Lv("v3")]

    class _Base:
        pass

    mod.ida_hexrays.user_lvar_modifier_t = _Base
    mod.ida_hexrays.decompile = lambda ea: _Cfunc()
    mod.ida_hexrays.modify_user_lvars = lambda ea, m: True
    mod.idaapi.get_func = lambda ea: types.SimpleNamespace(start_ea=0x401000)

    r = mod.modify(action="rename_local", addr="0x401000", var_name="v3", new_name="size")
    assert r["ok"] is True
    assert r["new_name"] == "size"


def test_modify_rename_reports_side_effect_and_no_propagation():
    mod = _load_modify()
    mod.ida_segment.getseg = lambda ea: None
    mod.idc.set_name = lambda *a, **k: True

    r = mod.modify(action="rename", addr="0x401000", value="my_func")
    assert r["ok"] is True
    assert r["name"] == "my_func"
    # The cross-session symbol DB upsert is reported, not silent.
    assert "symbol_db" in r["side_effects"]
    # The unsafe background propagation helper is gone entirely.
    assert not hasattr(mod, "_trigger_rename_propagation")


def test_modify_thunk_rename_is_not_flirt_mislabeled():
    mod = _load_modify()

    class _Fn:
        def __init__(self):
            self.start_ea = 0x401000
            self.end_ea = 0x401020
            self.flags = 0x40  # FUNC_THUNK only — no FUNC_LIB

    mod.ida_funcs.get_func = lambda ea: _Fn()
    mod.idc.set_name = lambda *a, **k: True

    r = mod.modify(action="rename", addr="0x401000", value="my_thunk")
    assert r["ok"] is True
    # A thunk is not a FLIRT/library function, so no R006 governance warning.
    assert "governance_warnings" not in r


# ---------------------------------------------------------------------------
# batch — template correctness and macro-DSL error envelope
# ---------------------------------------------------------------------------

def test_batch_analyze_function_template_uses_code_action():
    bat = load_tool_module("batch")
    actions = [(c["tool"], c["action"]) for c in bat._BATCH_TEMPLATES["analyze_function"]]
    assert ("code", "strings_in_func") in actions
    assert not any(tool == "data" and action == "strings_in_func" for tool, action in actions)


def test_batch_template_annotation_matches_registry():
    bat = load_tool_module("batch")
    ann = bat.batch.__annotations__["template"]
    desc = ann.__metadata__[0] if hasattr(ann, "__metadata__") else str(ann)
    for name in bat._BATCH_TEMPLATES:
        assert name in desc
    # Phantom templates removed from the annotation.
    assert "find_vulns_quick" not in desc
    assert "c2_investigation" not in desc


def test_batch_macro_dsl_tool_failure_uses_catalog_error_path():
    bat = load_tool_module("batch")
    interp = bat.MacroDSLInterpreter()

    def _boom(**kwargs):
        raise ValueError("boom")

    interp._get_tool = lambda name: _boom if name == "explode" else None
    res = interp.run("explode(x=1)")
    result = res["results"][0]["result"]
    # handle_error (catalog path) is used, not the non-catalog TOOL_ERROR code.
    assert result.get("code") != "TOOL_ERROR"
    assert result.get("error") or result.get("ok") is False


# ---------------------------------------------------------------------------
# intelligence — dead code removed
# ---------------------------------------------------------------------------

def _register_intelligence_stubs():
    host = types.ModuleType("ida_pro_mcp.host")
    host.__path__ = []  # type: ignore[attr-defined]
    host.__package__ = "ida_pro_mcp.host"
    sys.modules["ida_pro_mcp.host"] = host
    intel_pkg = types.ModuleType("ida_pro_mcp.host.intelligence")
    intel_pkg.__path__ = []  # type: ignore[attr-defined]
    intel_pkg.__package__ = "ida_pro_mcp.host.intelligence"
    sys.modules["ida_pro_mcp.host.intelligence"] = intel_pkg
    emb = types.ModuleType("ida_pro_mcp.host.intelligence.embeddings")
    emb.build_decomp_document = lambda name, pseudo, max_chars=1152: (pseudo or "")[:max_chars]
    sys.modules["ida_pro_mcp.host.intelligence.embeddings"] = emb


def test_intelligence_dead_code_removed():
    _register_intelligence_stubs()
    intel = load_tool_module("intelligence")
    assert hasattr(intel, "intelligence")
    assert not hasattr(intel, "suggest_next_steps")
    assert not hasattr(intel, "_parse_register_offset")
    assert not hasattr(intel, "_persist_embedder_state")


# ---------------------------------------------------------------------------
# wiki — dead helper removed
# ---------------------------------------------------------------------------

def test_wiki_dead_helper_removed():
    wiki = load_tool_module("wiki")
    assert hasattr(wiki, "wiki")
    assert not hasattr(wiki, "_get_wiki_root")


# ---------------------------------------------------------------------------
# knowledge — stale fallback import paths point at real modules
# ---------------------------------------------------------------------------

def test_knowledge_fallback_import_targets_exist():
    import importlib

    # These are the fallback module paths used by knowledge.py (and modify.py)
    # when ida_pro_mcp.services is unavailable. They must resolve to real
    # modules — the old flat host.arch_profile / host.symbol_db paths were
    # deleted in the stores/analysis refactor.
    for name in (
        "ida_pro_mcp.host.analysis.arch_profile",
        "ida_pro_mcp.host.stores.symbol_db",
    ):
        importlib.import_module(name)
