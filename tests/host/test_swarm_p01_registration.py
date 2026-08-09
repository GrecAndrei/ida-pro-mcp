"""WO-REG registration regression tests (standalone, no live IDA).

Pins the p01 "unified registration" seam that made every new tool/action from
the feature orders first-class on the agent surface and inside the risk-policy
engine:

  - Every new ``ida_*`` operation dispatches to a backend ``(tool, action)``
    that is actually registered in ``tool_registry._TOOL_ACTIONS``.
  - ``to_backend_call()`` translates public args (address→addr, type→item_type,
    risk_ack→_risk_ack) so the host dispatch receives the legacy shape.
  - ``prepare_rpc_args`` (the pure arg filter) admits every translated backend
    arg for the newly-schema'd tools (modify/types/annotation/r2/firmware) and
    rejects unknown keys — the previously-open tools are now closed.
  - Policy tiers classify the new read/write/filesystem/process ops correctly.
  - ``classify_tool_category`` groups ``r2`` (advanced) and ``firmware``
    (analysis); the legacy 17-tool ADVERTISED_TOOLS cap is preserved.
  - ``adapt_agent_error_payload`` rewrites legacy ``r2(...)``/``firmware(...)``
    references to the public ``ida_r2_*`` / ``ida_fw_*`` names.

All assertions run against the pure host seam modules — no IDA runtime, no
server, no live binary.
"""

from __future__ import annotations

import unittest

from ida_pro_mcp.host.agent_operations import (
    _OPERATIONS_BY_NAME,
    adapt_agent_error_payload,
    list_agent_operations,
)
from ida_pro_mcp.host.policy import (
    PolicyDecision,
    RiskTier,
    classify_tool_action,
    evaluate_policy,
)
from ida_pro_mcp.host.schemas import classify_tool_category
from ida_pro_mcp.host.schemas_data import ADVERTISED_TOOLS, TOOL_ARG_SCHEMAS
from ida_pro_mcp.host.server.rpc_args import prepare_rpc_args
from ida_pro_mcp.host.server.tool_registry import tool_actions

# The 36 operations this registration wave adds on top of the previous 67.
NEW_OPERATION_NAMES = [
    "ida_sreg_get",
    "ida_sreg_set",
    "ida_sreg_list",
    "ida_create_data",
    "ida_create_strlit",
    "ida_undo_begin",
    "ida_undo_end",
    "ida_add_entry",
    "ida_idb_snapshot",
    "ida_idb_restore_snapshot",
    "ida_auto_wait",
    "ida_struct_member_add",
    "ida_struct_member_del",
    "ida_struct_member_rename",
    "ida_struct_member_set_type",
    "ida_enum_member_add",
    "ida_enum_member_rename",
    "ida_enum_member_revalue",
    "ida_til_delete",
    "ida_til_export",
    "ida_til_import",
    "ida_events",
    "ida_registers",
    "ida_search_data_value",
    "ida_search_query_lang",
    "ida_r2_status",
    "ida_r2_bininfo",
    "ida_r2_load_hints",
    "ida_r2_disassemble_hypothesis",
    "ida_r2_vxrefs",
    "ida_mark_dangerous",
    "ida_fw_detect_vector_table",
    "ida_fw_detect_load_base",
    "ida_fw_detect_mmio",
    "ida_fw_rtos_scan",
    "ida_fw_carve",
]

# Ops whose public contract requires risk_ack (every mutating op).
RISK_ACK_OPERATIONS = {
    "ida_sreg_set",
    "ida_create_data",
    "ida_create_strlit",
    "ida_undo_begin",
    "ida_undo_end",
    "ida_add_entry",
    "ida_idb_snapshot",
    "ida_idb_restore_snapshot",
    "ida_struct_member_add",
    "ida_struct_member_del",
    "ida_struct_member_rename",
    "ida_struct_member_set_type",
    "ida_enum_member_add",
    "ida_enum_member_rename",
    "ida_enum_member_revalue",
    "ida_til_delete",
    "ida_til_export",
    "ida_til_import",
    "ida_mark_dangerous",
    "ida_fw_carve",
}


def _fill_public_args(operation):
    """Build valid public args from the operation schema (required keys only)."""
    schema = operation.input_schema
    properties = schema.get("properties", {})
    args = dict(operation.example or {})
    for key in schema.get("required", []):
        if key in args:
            continue
        prop = properties.get(key, {})
        kind = prop.get("type", "string")
        if isinstance(kind, list):
            kind = kind[0]
        if key == "risk_ack" or kind == "boolean":
            args[key] = True
        elif kind == "integer":
            args[key] = 1
        elif isinstance(prop.get("enum"), list):
            args[key] = prop["enum"][0]
        else:
            args[key] = "0x1000"
    return args


class TestNewOperationRegistration(unittest.TestCase):
    """Every new op is registered and dispatches to a known backend pair."""

    @classmethod
    def setUpClass(cls):
        cls.actions = tool_actions()
        cls.all_ops = {operation.name: operation for operation in list_agent_operations()}

    def test_operation_count_grew_to_103(self):
        names = [operation.name for operation in list_agent_operations()]
        self.assertEqual(len(names), 103, "registration wave must add 36 ops on top of 67")
        for name in NEW_OPERATION_NAMES:
            self.assertIn(name, names)

    def test_every_new_op_backend_is_registered(self):
        for name in NEW_OPERATION_NAMES:
            operation = self.all_ops[name]
            self.assertTrue(operation.backend_tool, name)
            self.assertTrue(operation.backend_action, name)
            self.assertIn(
                operation.backend_action,
                self.actions[operation.backend_tool],
                f"{name} -> {operation.backend_tool}/{operation.backend_action} not in TOOL_ACTIONS",
            )

    def test_risk_ack_ops_reject_missing_ack(self):
        for name in RISK_ACK_OPERATIONS:
            operation = self.all_ops[name]
            args = _fill_public_args(operation)
            args.pop("risk_ack", None)
            error = operation.validate(args)
            self.assertIsNotNone(error, f"{name} accepted a call without risk_ack")
            self.assertTrue(error.get("error"), name)
            args["risk_ack"] = False
            self.assertIsNotNone(operation.validate(args), f"{name} accepted risk_ack=False")

    def test_non_mutating_ops_do_not_require_ack(self):
        for name in NEW_OPERATION_NAMES:
            if name in RISK_ACK_OPERATIONS:
                continue
            operation = self.all_ops[name]
            args = _fill_public_args(operation)
            self.assertIsNone(operation.validate(args), name)


class TestBackendTranslation(unittest.TestCase):
    """to_backend_call() maps public args to the legacy dispatcher shape."""

    def test_create_data_maps_address_and_type(self):
        op = _OPERATIONS_BY_NAME["ida_create_data"]
        tool, args = op.to_backend_call(
            {"address": "0x1234", "type": "dword", "count": 4, "risk_ack": True}
        )
        self.assertEqual(tool, "modify")
        self.assertEqual(args["action"], "create_data")
        self.assertEqual(args["addr"], "0x1234")
        self.assertEqual(args["item_type"], "dword")
        self.assertEqual(args["count"], 4)
        self.assertIs(args["_risk_ack"], True)
        self.assertNotIn("risk_ack", args)

    def test_sreg_set_and_r2_hypothesis_translate(self):
        tool, args = _OPERATIONS_BY_NAME["ida_sreg_set"].to_backend_call(
            {"start": "0x401000", "reg": "ds", "value": 0x30, "risk_ack": True}
        )
        self.assertEqual(tool, "segments")
        self.assertEqual(args["action"], "sreg_set")
        self.assertEqual(args["value"], 0x30)

        tool, args = _OPERATIONS_BY_NAME["ida_r2_disassemble_hypothesis"].to_backend_call(
            {"address": "0x1000", "count": 16}
        )
        self.assertEqual(tool, "r2")
        self.assertEqual(args["action"], "disassemble_hypothesis")
        self.assertEqual(args["addr"], "0x1000")

    def test_til_export_maps_name_filter(self):
        tool, args = _OPERATIONS_BY_NAME["ida_til_export"].to_backend_call(
            {"path": "/tmp/x.h", "name": "*", "risk_ack": True}
        )
        self.assertEqual(tool, "types")
        self.assertEqual(args["action"], "til_export")
        self.assertEqual(args["path"], "/tmp/x.h")
        self.assertEqual(args["til_filter"], "*")

    def test_struct_member_add_maps_member_edits(self):
        tool, args = _OPERATIONS_BY_NAME["ida_struct_member_add"].to_backend_call(
            {"struct_name": "S", "member_name": "m", "offset": -1, "risk_ack": True}
        )
        self.assertEqual(tool, "types")
        self.assertEqual(args["action"], "struct_member_add")
        self.assertEqual(args["struct_name"], "S")
        self.assertEqual(args["offset"], -1)


class TestArgFilterAdmission(unittest.TestCase):
    """prepare_rpc_args admits every translated backend arg for the new tools.

    The wave added TOOL_ARG_SCHEMAS entries for the previously-open tools
    (modify/types/annotation) and the new r2/firmware tools, so the translated
    args must survive the filter and unknown keys must now be rejected.
    """

    def test_all_new_ops_pass_through_arg_filter(self):
        for name in NEW_OPERATION_NAMES:
            operation = _OPERATIONS_BY_NAME[name]
            args = _fill_public_args(operation)
            tool, backend_args = operation.to_backend_call(args)
            admitted = prepare_rpc_args(tool, backend_args, TOOL_ARG_SCHEMAS)
            self.assertFalse(admitted.get("error"), f"{name} arg filter error: {admitted}")
            # Host-only underscore keys are dropped before the schema check.
            self.assertNotIn("_risk_ack", admitted, name)

    def test_modify_tool_is_now_closed_to_unknown_keys(self):
        admitted = prepare_rpc_args(
            "modify", {"action": "rename", "addr": "0x1", "bogus": 1}, TOOL_ARG_SCHEMAS
        )
        self.assertTrue(admitted.get("error"))
        self.assertIn("Unknown argument", admitted.get("message", ""))

    def test_types_tool_is_now_closed_to_unknown_keys(self):
        admitted = prepare_rpc_args(
            "types", {"action": "list", "nonsense": True}, TOOL_ARG_SCHEMAS
        )
        self.assertTrue(admitted.get("error"))

    def test_r2_and_firmware_schemas_admit_their_params(self):
        admitted = prepare_rpc_args(
            "r2", {"action": "bininfo", "binary_path": "/tmp/x.bin"}, TOOL_ARG_SCHEMAS
        )
        self.assertFalse(admitted.get("error"))
        admitted = prepare_rpc_args(
            "firmware",
            {"action": "carve", "start": "0x0", "end": "0x1000"},
            TOOL_ARG_SCHEMAS,
        )
        self.assertFalse(admitted.get("error"))


class TestPolicyTiers(unittest.TestCase):
    """New ops land in the right risk tier and ack behavior."""

    def test_write_ops_require_ack(self):
        for tool, action in [
            ("modify", "create_data"),
            ("modify", "create_strlit"),
            ("modify", "undo_begin"),
            ("analysis", "add_entry"),
            ("analysis", "restore_snapshot"),
            ("segments", "sreg_set"),
            ("types", "struct_member_add"),
            ("types", "enum_member_revalue"),
            ("types", "til_delete"),
            ("firmware", "carve"),
        ]:
            tier = classify_tool_action(tool, action)
            self.assertEqual(tier, RiskTier.WRITE_IDB, f"{tool}/{action} was {tier}")
            result = evaluate_policy(tool, action, purpose="oss_audit")
            self.assertEqual(result.decision, PolicyDecision.REQUIRE_ACK, f"{tool}/{action}")

    def test_read_ops_are_allowed(self):
        for tool, action in [
            ("segments", "sreg_get"),
            ("segments", "sreg_list"),
            ("analysis", "auto_wait"),
            ("idb", "events"),
            ("idb", "registers"),
            ("search", "data_value"),
            ("search", "query_lang"),
            ("firmware", "detect_vector_table"),
            ("firmware", "rtos_scan"),
            ("r2", "status"),
            ("r2", "bininfo"),
            ("r2", "load_hints"),
            ("r2", "disassemble_hypothesis"),
            ("r2", "vxrefs"),
        ]:
            tier = classify_tool_action(tool, action)
            self.assertEqual(tier, RiskTier.READ, f"{tool}/{action} was {tier}")
            result = evaluate_policy(tool, action, purpose="oss_audit")
            self.assertEqual(result.decision, PolicyDecision.ALLOW, f"{tool}/{action}")

    def test_til_carry_tiers(self):
        self.assertEqual(classify_tool_action("types", "til_export"), RiskTier.FILESYSTEM_WRITE)
        self.assertEqual(classify_tool_action("types", "til_import"), RiskTier.FILESYSTEM_READ)

    def test_r2_process_lifecycle_forward_declared(self):
        # Not yet registered actions; must never fall through to READ.
        for action in ("start", "attach"):
            self.assertEqual(
                classify_tool_action("r2", action), RiskTier.NETWORK_OR_PROCESS, action
            )


class TestCategoryAndAdvertisedSurface(unittest.TestCase):
    def test_r2_and_firmware_categories(self):
        self.assertEqual(classify_tool_category("r2"), "advanced")
        self.assertEqual(classify_tool_category("firmware"), "analysis")

    def test_advertised_tools_cap_is_preserved(self):
        # test_rpc_args_contract.py caps ADVERTISED_TOOLS at 17; the raw-binary
        # sidecars stay callable by name but off the legacy tools/list surface.
        self.assertLessEqual(len(ADVERTISED_TOOLS), 17)
        self.assertNotIn("r2", ADVERTISED_TOOLS)
        self.assertNotIn("firmware", ADVERTISED_TOOLS)


class TestErrorPayloadAdaptation(unittest.TestCase):
    """Legacy r2(...)/firmware(...) references are rewritten to public names."""

    def test_r2_action_call_rewrites_to_public_operation(self):
        payload = {
            "error": True,
            "code": "r2_engine_start_failed",
            "message": "Use r2(action='bininfo') to inspect the file",
        }
        adapted = adapt_agent_error_payload(payload, "ida_r2_bininfo")
        self.assertIn("ida_r2_bininfo", adapted["message"])
        self.assertNotIn("r2(action=", adapted["message"])

    def test_firmware_action_call_rewrites_to_public_operation(self):
        payload = {
            "error": True,
            "code": "x",
            "message": "Call firmware(action='carve') with start/end first",
        }
        adapted = adapt_agent_error_payload(payload, "ida_fw_carve")
        self.assertIn("ida_fw_carve", adapted["message"])
        self.assertNotIn("firmware(action=", adapted["message"])

    def test_legacy_dot_reference_triggers_public_surface_note(self):
        payload = {
            "error": True,
            "code": "x",
            "message": "Use r2.bininfo on the sidecar",
        }
        adapted = adapt_agent_error_payload(payload, "ida_r2_bininfo")
        self.assertIn("Use ida_help(topic='ida_r2_bininfo')", adapted["message"])


if __name__ == "__main__":
    unittest.main()
