"""Behavioral regression tests for the annotation.mark_dangerous promotion (WO-P1).

The ROADMAP promotion rule for a legacy action is *exact schema + ida_help +
behavioral test*. WO-REG owns the registration (the ``ida_mark_dangerous``
AgentOperation, the annotation TOOL_ARG_SCHEMAS entry, advertisement); this
file is the behavioral half of the promotion:

  - ``annotation(action="mark_dangerous", ...)`` returns the danger-tagged
    annotation shape — ``warnings`` entries carrying
    ``addr / function / api / reason / comment`` — persists those comments
    through ``idc.set_cmt``, honors ``dry_run`` and ``limit``, and dispatches
    through the tool's ``mark_dangerous`` action branch.
  - An opaque raw-flat-blob RISC-V fixture exercises the ``jal`` / ``jalr``
    call detection the firmware case depends on (a headerless ROM mapped flat
    at 0x80000000 with no ELF metadata).
  - The host ``AgentOperation`` for ``ida_mark_dangerous`` carries the exact
    strict schema (``address`` + ``risk_ack`` required), translates to the
    legacy ``annotation/mark_dangerous`` backend via ``to_backend_call``
    (``address``→``addr``, ``risk_ack``→``_risk_ack``), is discoverable
    through ``ida_help``, and its translated backend call drives the tool
    end-to-end once the host dispatcher pops ``_risk_ack``.

Everything runs on per-file _FakeIda-style fakes of ``idc`` / ``idautils`` /
``ida_funcs`` modeled on the IDA Python API — no live IDA is required.
"""
import inspect
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.agent_operations import (  # noqa: E402
    build_agent_help,
    get_agent_operation,
    list_agent_operations,
)
from tests._isolated_repo_loader import load_tool_module  # noqa: E402


class _Func:
    """Minimal stand-in for ida_funcs.func_t (start_ea / end_ea)."""

    def __init__(self, start_ea: int, end_ea: int):
        self.start_ea = start_ea
        self.end_ea = end_ea


def _build(funcs, calls, *, mnemonics=None, functions=None, existing_cmt=None):
    """Build per-file _FakeIda-style fakes and load the annotation tool.

    ``funcs`` maps a function's start address to ``(name, start, end)``; the
    fake resolves both the containing-function query (``ida_funcs.get_func``)
    and callee/function naming (``idc.get_func_name`` / ``idc.get_name``) from
    it.  ``calls`` maps a call-instruction head address to its ``[callee, ...]``
    targets.  ``mnemonics`` overrides the printed mnemonic per head (default:
    ``call`` for every call head, ``lea`` otherwise) so RISC-V ``jal`` /
    ``jalr`` can be modeled.  ``functions`` overrides ``idautils.Functions``
    for the all-functions scan.  ``existing_cmt`` overrides ``idc.get_cmt``.

    Returns ``(mod, writes, idc)`` where ``writes`` records every
    ``idc.set_cmt(ea, comment, repeatable)`` call — the persistence surface.
    """
    writes = []

    idc = types.ModuleType("idc")
    idc.get_func_name = lambda ea: {
        fea: name for fea, (name, _s, _e) in funcs.items()
    }.get(ea, "")
    idc.get_name = idc.get_func_name
    idc.print_insn_mnem = lambda ea: (mnemonics or {}).get(
        ea, "call" if ea in calls else "lea"
    )
    idc.get_cmt = existing_cmt if existing_cmt is not None else (lambda ea, r: "")
    idc.set_cmt = lambda ea, cmt, r: writes.append((ea, cmt, r))

    idautils = types.ModuleType("idautils")
    idautils.Heads = lambda start, end: iter(
        sorted(ea for ea in calls if start <= ea < end)
    )
    idautils.CodeRefsFrom = lambda head, _f: calls.get(head, [])
    idautils.Functions = functions or (lambda: iter(sorted(funcs)))

    ida_funcs = types.ModuleType("ida_funcs")

    def _get_func(ea):
        for _fea, (_name, start, end) in funcs.items():
            if start <= ea < end:
                return _Func(start, end)
        return None

    ida_funcs.get_func = _get_func
    # The compat shims resolve the live ida_funcs via sys.modules; register
    # the fake there and expose both the legacy get_func and the 9.4 EA
    # surface so the function lookup survives either feature-detection result.
    sys.modules["ida_funcs"] = ida_funcs
    ida_funcs.ida_idaapi = types.ModuleType("ida_idaapi")
    ida_funcs.ida_idaapi.BADADDR = -1
    ida_funcs.func_entry_info_t = types.SimpleNamespace

    def _func_start(ea):
        f = _get_func(ea)
        return f.start_ea if f else -1

    def _func_entry_info(out, ea, flags=0):
        f = _get_func(ea)
        if f is None:
            return False
        out.start_ea = f.start_ea
        out.end_ea = f.end_ea
        return True

    ida_funcs.get_func_start = _func_start
    ida_funcs.get_func_entry_info = _func_entry_info
    ida_funcs.get_func_flags = lambda ea: 0
    ida_funcs.set_func_flags = lambda ea, flags: True

    def _validate_addr(addr, *_args, require_func=False, **_kw):
        ea = int(str(addr), 0)
        if require_func and _get_func(ea) is None:
            return None, {
                "ok": False,
                "code": "FUNCTION_NOT_FOUND",
                "message": f"No function at {hex(ea)}",
            }
        return ea, None

    mod = load_tool_module(
        "annotation",
        common_overrides={
            "idc": idc,
            "idautils": idautils,
            "ida_funcs": ida_funcs,
            "validate_addr": _validate_addr,
        },
    )
    return mod, writes, idc


# ---------------------------------------------------------------------------
# Danger-tagged shape, persistence, and dispatch through the annotation tool
# ---------------------------------------------------------------------------
class TestMarkDangerousShapeAndPersistence(unittest.TestCase):
    def setUp(self):
        # sub_main calls strcpy and VirtualAlloc — the two canonical dangerous
        # API categories (unbounded copy, RWX allocation).
        self.funcs = {
            0x401000: ("sub_main", 0x401000, 0x401100),
            0x402000: ("strcpy", 0x402000, 0x402010),
            0x402100: ("VirtualAlloc", 0x402100, 0x402110),
        }
        self.calls = {
            0x401010: [0x402000],
            0x401020: [0x402100],
        }
        self.mod, self.writes, self.idc = _build(self.funcs, self.calls)

    def test_mark_dangerous_returns_the_danger_tagged_annotation_shape(self):
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=10,
            dry_run=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertTrue(result["dry_run"])
        # warnings is a per-entry "\n"-joined repr carrying the full shape.
        self.assertIn("'addr': '0x401010'", result["warnings"])
        self.assertIn("'function': 'sub_main'", result["warnings"])
        self.assertIn("'api': 'strcpy'", result["warnings"])
        self.assertIn("'reason': 'unbounded copy - use strncpy/strlcpy'", result["warnings"])
        self.assertIn(
            "'comment': '[MCP] WARNING: strcpy - unbounded copy - use strncpy/strlcpy'",
            result["warnings"],
        )
        self.assertIn("'api': 'VirtualAlloc'", result["warnings"])
        self.assertIn(
            "'reason': 'check for RWX permissions (PAGE_EXECUTE_READWRITE)'",
            result["warnings"],
        )

    def test_dry_run_never_writes(self):
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=10,
            dry_run=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertEqual(self.writes, [])

    def test_real_run_persists_the_warning_comments(self):
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=10,
            dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(self.writes), 2)
        written = {ea: cmt for ea, cmt, _r in self.writes}
        self.assertEqual(
            written[0x401010],
            "[MCP] WARNING: strcpy - unbounded copy - use strncpy/strlcpy",
        )
        self.assertEqual(
            written[0x401020],
            "[MCP] WARNING: VirtualAlloc - check for RWX permissions (PAGE_EXECUTE_READWRITE)",
        )
        # regular inline comments (repeatable=False)
        self.assertTrue(all(r == 0 for _ea, _c, r in self.writes))

    def test_limit_caps_the_number_of_warnings(self):
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=1,
            dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 1)
        self.assertIn("'api': 'strcpy'", result["warnings"])
        self.assertNotIn("'api': 'VirtualAlloc'", result["warnings"])
        self.assertEqual(len(self.writes), 1)

    def test_omitted_addr_scans_all_functions(self):
        result = self.mod.annotation(
            action="mark_dangerous", prefix="[MCP] ", limit=10, dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        # idautils.Functions() yields every known function; only sub_main has
        # dangerous calls, so the all-functions scan still finds both.
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(self.writes), 2)

    def test_plt_suffix_is_stripped_for_matching(self):
        # A callee imported through the PLT keeps its display name but must
        # still match the danger table after the @plt suffix is stripped.
        funcs = dict(self.funcs)
        funcs[0x402000] = ("strcpy@plt", 0x402000, 0x402010)
        mod, writes, _idc = _build(funcs, self.calls)
        result = mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=10,
            dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertIn("'api': 'strcpy@plt'", result["warnings"])
        self.assertIn("'reason': 'unbounded copy - use strncpy/strlcpy'", result["warnings"])
        self.assertEqual(len(writes), 2)

    def test_existing_prefix_comment_is_not_rewritten(self):
        # Idempotency: a call address already carrying a [MCP]-prefixed warning
        # is left untouched by a second pass.
        def _existing(ea, _r):
            return "[MCP] WARNING: strcpy - unbounded copy - use strncpy/strlcpy" if ea == 0x401010 else ""

        mod, writes, _idc = _build(self.funcs, self.calls, existing_cmt=_existing)
        result = mod.annotation(
            action="mark_dangerous", addr="0x401000", prefix="[MCP] ", limit=10,
            dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        # Only the VirtualAlloc site is new.
        self.assertEqual([ea for ea, _c, _r in writes], [0x401020])


class TestMarkDangerousDispatch(unittest.TestCase):
    def setUp(self):
        self.funcs = {
            0x401000: ("sub_main", 0x401000, 0x401100),
            0x402000: ("strcpy", 0x402000, 0x402010),
        }
        self.calls = {0x401010: [0x402000]}
        self.mod, self.writes, self.idc = _build(self.funcs, self.calls)

    def test_action_literal_includes_mark_dangerous(self):
        param = inspect.signature(self.mod.annotation).parameters["action"]
        ann = param.annotation
        literal_type = getattr(ann, "__args__", (None,))[0]
        choices = tuple(getattr(literal_type, "__args__", ()))
        self.assertIn("mark_dangerous", choices)

    def test_docstring_documents_mark_dangerous(self):
        doc = self.mod.annotation.__doc__ or ""
        self.assertIn("mark_dangerous", doc)
        self.assertIn("{warnings, count}", doc)

    def test_mark_dangerous_dispatches_to_the_warning_branch(self):
        result = self.mod.annotation(action="mark_dangerous", addr="0x401000")
        self.assertTrue(result["ok"], result)
        self.assertIn("warnings", result)
        self.assertIn("count", result)

    def test_unknown_action_returns_invalid_args(self):
        result = self.mod.annotation(action="no_such_action", addr="0x401000")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_ARGS")
        self.assertIn("Unknown action", result["message"])

    def test_address_outside_any_function_is_rejected(self):
        result = self.mod.annotation(action="mark_dangerous", addr="0x999000")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "FUNCTION_NOT_FOUND")


# ---------------------------------------------------------------------------
# Opaque raw-flat-blob RISC-V firmware scenario
# ---------------------------------------------------------------------------
class TestMarkDangerousRiscvRawBlob(unittest.TestCase):
    def setUp(self):
        # A headerless RISC-V firmware image mapped flat at 0x80000000 (no ELF
        # metadata — the raw ".bin" loader case).  reset_handler calls memcpy
        # via `jal` and strcpy via `jalr`, the two call forms the firmware
        # shaping target cares about.
        self.funcs = {
            0x80000000: ("reset_handler", 0x80000000, 0x80000040),
            0x80008000: ("memcpy", 0x80008000, 0x80008020),
            0x80008010: ("strcpy", 0x80008010, 0x80008020),
        }
        self.calls = {
            0x80000010: [0x80008000],
            0x8000001c: [0x80008010],
        }
        self.mnemonics = {
            0x80000010: "jal",
            0x8000001c: "jalr",
            0x80000000: "auipc",
            0x80000004: "addi",
        }
        self.mod, self.writes, self.idc = _build(
            self.funcs, self.calls, mnemonics=self.mnemonics,
        )

    def test_jal_and_jalr_calls_to_dangerous_apis_are_tagged(self):
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x80000000", prefix="[MCP] ", limit=10,
            dry_run=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertIn("'addr': '0x80000010'", result["warnings"])
        self.assertIn("'function': 'reset_handler'", result["warnings"])
        self.assertIn("'api': 'memcpy'", result["warnings"])
        self.assertIn("'reason': 'verify size parameter - potential overflow'", result["warnings"])
        self.assertIn("'api': 'strcpy'", result["warnings"])
        # Both call sites get their warning comment persisted.
        self.assertEqual(len(self.writes), 2)
        self.assertEqual([ea for ea, _c, _r in self.writes], [0x80000010, 0x8000001c])

    def test_non_call_instructions_are_not_flagged(self):
        # auipc/addi heads in the same function are not call instructions and
        # contribute no warnings, but the two real call sites still fire.
        result = self.mod.annotation(
            action="mark_dangerous", addr="0x80000000", limit=10, dry_run=True,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 2)
        self.assertIn("'addr': '0x8000001c'", result["warnings"])


# ---------------------------------------------------------------------------
# Host-side op: exact schema, to_backend_call translation, ida_help
# ---------------------------------------------------------------------------
class TestMarkDangerousOpContract(unittest.TestCase):
    def test_operation_is_registered_category_edit_backend_annotation(self):
        op = get_agent_operation("ida_mark_dangerous")
        self.assertIsNotNone(op)
        self.assertEqual(op.category, "edit")
        self.assertEqual(op.backend_tool, "annotation")
        self.assertEqual(op.backend_action, "mark_dangerous")
        names = {o.name for o in list_agent_operations()}
        self.assertIn("ida_mark_dangerous", names)

    def test_schema_is_strict_and_requires_address_and_risk_ack(self):
        op = get_agent_operation("ida_mark_dangerous")
        schema = op.input_schema
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["required"], ["address", "risk_ack"])
        for key in ("address", "prefix", "limit", "dry_run", "risk_ack", "idb"):
            self.assertIn(key, schema["properties"])
        # risk_ack must be explicitly true; unknown args are rejected.
        self.assertIsNotNone(op.validate({}))
        self.assertIsNotNone(op.validate({"address": "0x401000"}))
        self.assertIsNotNone(op.validate({"address": "0x401000", "risk_ack": False}))
        self.assertIsNotNone(op.validate({"address": "0x401000", "risk_ack": True, "bogus": 1}))
        self.assertIsNone(op.validate({"address": "0x401000", "risk_ack": True}))
        self.assertIsNone(op.validate(op.example))

    def test_to_backend_call_translates_to_the_legacy_dispatcher(self):
        op = get_agent_operation("ida_mark_dangerous")
        tool, args = op.to_backend_call(
            {
                "address": "0x401000",
                "prefix": "[X] ",
                "limit": 7,
                "dry_run": False,
                "risk_ack": True,
            }
        )
        self.assertEqual(tool, "annotation")
        self.assertEqual(
            args,
            {
                "action": "mark_dangerous",
                "addr": "0x401000",
                "prefix": "[X] ",
                "limit": 7,
                "dry_run": False,
                "_risk_ack": True,
            },
        )

    def test_help_exposes_the_exact_schema(self):
        response = build_agent_help({"topic": "ida_mark_dangerous"})
        self.assertTrue(response["ok"])
        operation = response["operation"]
        self.assertEqual(operation["name"], "ida_mark_dangerous")
        self.assertEqual(operation["category"], "edit")
        self.assertEqual(operation["example"], {"address": "0x401000", "risk_ack": True})
        self.assertEqual(operation["inputSchema"]["required"], ["address", "risk_ack"])

    def test_translated_backend_call_drives_the_tool_end_to_end(self):
        funcs = {
            0x401000: ("sub_main", 0x401000, 0x401100),
            0x402000: ("strcpy", 0x402000, 0x402010),
        }
        calls = {0x401010: [0x402000]}
        mod, writes, _idc = _build(funcs, calls)

        op = get_agent_operation("ida_mark_dangerous")
        tool, args = op.to_backend_call(
            {"address": "0x401000", "limit": 10, "risk_ack": True}
        )
        self.assertEqual(tool, "annotation")
        # The host dispatcher pops the acknowledgement before the RPC reaches
        # IDA; the remaining args are exactly the legacy tool call.
        args.pop("_risk_ack", None)
        result = mod.annotation(**args)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 1)
        self.assertIn("'api': 'strcpy'", result["warnings"])
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], "[MCP] WARNING: strcpy - unbounded copy - use strncpy/strlcpy")


if __name__ == "__main__":
    unittest.main()
