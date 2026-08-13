"""Regression tests for the p01 contract/policy fixes on agent operations.

Covers:
  - risk_ack is now required (and mapped to _risk_ack) on ops that mutate the
    IDB or tear down a session: save_idb, make_code, undefine, close_session,
    set_segment_attrs.
  - set_segment_attrs maps to the real segments/set_attr backend (start/attr/value).
  - list_types limit -> count, list_sigs query -> name, apply_type var_name -> name.
  - calc_bitops no longer exposes the duplicate `op` parameter.
  - open_binary/open_background architecture objects admit the alias keys.
  - Dead blackboard actions are gone and batch's placeholder produces no aliases.
"""

from ida_pro_mcp.host.agent_operations import get_agent_operation
from ida_pro_mcp.host.schemas import ACTION_ALIASES_BY_TOOL
from ida_pro_mcp.host.schemas_data import TOOL_ACTIONS, TOOL_ARG_SCHEMAS

# Dead blackboard actions removed in the contract cleanup.
_DEAD_BLACKBOARD = {
    "add_system", "add_struct", "add_gap", "fill_gap",
    "add_state_machine", "add_peripheral", "add_attack_surface",
    "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
    "kg_state_machines", "kg_attack_surface", "kg_peripherals",
    "export_symbols", "import_symbols",
    "semantic_index", "semantic_rebuild", "related_by_behavior",
    "deref", "chain",
}


def test_idb_mutation_ops_require_and_map_risk_ack():
    cases = [
        ("ida_save_idb", {}, "analysis", "save_idb"),
        ("ida_make_code", {"address": "0x401000"}, "analysis", "make_code"),
        ("ida_undefine", {"address": "0x401000", "size": 4}, "analysis", "undefine"),
        ("ida_close_session", {}, "session", "close"),
    ]
    for name, args, tool, action in cases:
        op = get_agent_operation(name)
        assert "risk_ack" in op.input_schema.get("required", []), f"{name} missing risk_ack"
        # Missing ack -> validation error.
        assert op.validate(dict(args)), f"{name} should reject missing risk_ack"
        args["risk_ack"] = True
        assert not op.validate(args), f"{name} example with ack failed"
        backend_tool, backend_args = op.to_backend_call(args)
        assert backend_tool == tool, name
        assert backend_args["action"] == action, name
        assert backend_args["_risk_ack"] is True, name


def test_set_segment_attrs_maps_to_segments_set_attr():
    op = get_agent_operation("ida_set_segment_attrs")
    assert op.backend_tool == "segments"
    assert op.backend_action == "set_attr"
    arguments = {"address": "0x40000000", "attr": "perm", "value": "rwx", "risk_ack": True}
    assert not op.validate(arguments)
    _, backend_args = op.to_backend_call(arguments)
    assert backend_args == {
        "action": "set_attr",
        "address": "0x40000000",
        "attr": "perm",
        "value": "rwx",
        "_risk_ack": True,
    }
    # The old name/perms/sclass/bitness interface is gone.
    assert "perms" not in op.input_schema["properties"]
    assert "sclass" not in op.input_schema["properties"]


def test_list_types_keeps_public_limit_name():
    op = get_agent_operation("ida_list_types")
    _, backend_args = op.to_backend_call({"kind": "struct", "limit": 5})
    assert backend_args["action"] == "list"
    assert backend_args["limit"] == 5
    assert "count" not in backend_args


def test_list_sigs_keeps_public_query_name():
    op = get_agent_operation("ida_list_sigs")
    _, backend_args = op.to_backend_call({"query": "arm"})
    assert backend_args["action"] == "list_sigs"
    assert backend_args["query"] == "arm"
    assert "name" not in backend_args
    # name remains admitted by the misc schema for legacy callers.
    assert "name" in TOOL_ARG_SCHEMAS["misc"]


def test_apply_type_keeps_public_var_name():
    op = get_agent_operation("ida_apply_type")
    arguments = {
        "address": "0x401000", "type_str": "int", "kind": "local",
        "var_name": "v1", "risk_ack": True,
    }
    _, backend_args = op.to_backend_call(arguments)
    assert backend_args["kind"] == "local"
    assert backend_args["var_name"] == "v1"
    assert backend_args["address"] == "0x401000"
    assert "name" not in backend_args


def test_calc_bitops_drops_duplicate_op_param():
    op = get_agent_operation("ida_calc_bitops")
    assert "op" not in op.input_schema["properties"]
    assert "bit_op" in op.input_schema["properties"]
    assert not op.validate({"value": "0xff", "target": "0xf", "bit_op": "xor"})
    assert op.validate({"value": "0xff", "op": "xor"}), "legacy op param must be rejected"


def test_open_binary_and_background_admit_architecture_aliases():
    for name in ("ida_open_binary", "ida_open_background"):
        op = get_agent_operation(name)
        arch = op.input_schema["properties"]["architecture"]
        props = arch["properties"]
        for alias in ("arch", "proc", "bits", "endianness"):
            assert alias in props, f"{name} architecture missing alias {alias}"
        # A canonical + alias call validates.
        assert not op.validate(
            {"binary_path": "/samples/target", "architecture": {"proc": "arm", "bits": 64}}
        )


def test_dead_blackboard_actions_removed():
    actions = set(TOOL_ACTIONS["blackboard"])
    assert not (_DEAD_BLACKBOARD & actions), f"dead actions still present: {_DEAD_BLACKBOARD & actions}"
    # The live KG/frontier surface is still advertised.
    assert {"write", "read", "list", "search", "next_target", "frontier",
            "decision_card", "stats", "mark_examined", "publish_findings"} <= actions


def test_batch_placeholder_produces_no_action_aliases():
    # The "(pass calls array)" documentation placeholder must not generate
    # snake/camel alias variants polluting the alias map.
    assert ACTION_ALIASES_BY_TOOL["batch"] == {}


def test_dead_session_arg_keys_removed_from_schema():
    dead = {
        "macro", "macro_data", "run_action", "n",
        "include_bookmarks", "include_items", "library_idbs",
        "threshold_cosine", "threshold_structural", "mappings",
    }
    assert not (dead & set(TOOL_ARG_SCHEMAS["session"])), (
        f"dead session keys still present: {dead & set(TOOL_ARG_SCHEMAS['session'])}"
    )
    # Live session args are still admitted.
    assert {"name", "note", "verbose", "session_id", "idb"} <= set(TOOL_ARG_SCHEMAS["session"])


def test_dead_memory_and_analysis_arg_keys_removed():
    memory_schema = TOOL_ARG_SCHEMAS["memory"]
    assert not ({"path", "content", "encoding"} & set(memory_schema))
    assert "data" in memory_schema  # write action reads data
    analysis_schema = TOOL_ARG_SCHEMAS["analysis"]
    assert not ({"timeout", "max_wait"} & set(analysis_schema))
    assert {"blocking", "wait", "pump", "poll_timeout", "name", "arg"} <= set(analysis_schema)


def test_search_admits_rerank_and_intelligence_admits_family_params():
    assert "rerank" in TOOL_ARG_SCHEMAS["search"]
    intel = TOOL_ARG_SCHEMAS["intelligence"]
    assert {"min_similarity", "mark_examined", "verdict"} <= set(intel)
