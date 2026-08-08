"""Regression tests for the p01 contract/policy fixes.

Covers the host policy classification fixes:
  - (tool, action) pairs on read-only tools that actually write the IDB or
    symbol DB are now tiered WRITE_IDB / FILESYSTEM_WRITE instead of READ.
  - Host filesystem writes (symbols/export, knowledge/export_session) require
    an explicit ack instead of sailing through as reads.
  - FILESYSTEM_READ (misc/read_file) now requires an ack.
  - Provably read-only pairs (search/comment, gadgets/*, memory/* reads,
    multi_session reads) classify as READ and need no ack.
  - plugin_run is LOCAL_CODE_EXEC for both analysis and misc.
  - Dead tool names (crypto_id/entropy/protocol/hooks) are gone from the sets.
"""

from ida_pro_mcp.host.policy import (
    READ_ONLY_TOOLS,
    WRITE_IDB_TOOLS,
    PolicyDecision,
    PolicyMode,
    RiskTier,
    classify_tool_action,
    evaluate_policy,
)


def test_read_only_tool_write_pairs_classify_as_write_idb():
    """Pairs on READ_ONLY_TOOLS that mutate the IDB must not be READ."""
    write_pairs = [
        ("types", "declare"),
        ("types", "set_prototype"),
        ("analysis", "set_processor"),
        ("analysis", "set_architecture"),
        ("analysis", "set_loader_options"),
        ("analysis", "reanalyze"),
        ("symbols", "load_pdb"),
        ("symbols", "load_dwarf"),
        ("firmware_view", "auto_retype"),
        ("firmware_view", "smart_carve"),
        ("firmware_view", "rollback_last"),
        ("misc", "load_sig"),
        ("knowledge", "import_symbols"),
        ("session", "untag"),
        ("session", "add_note"),
        ("session", "clear_notes"),
        ("session", "duplicate"),
        ("session", "archive"),
        ("session", "unarchive"),
        ("session", "snapshot"),
    ]
    for tool, action in write_pairs:
        tier = classify_tool_action(tool, action)
        assert tier == RiskTier.WRITE_IDB, f"{tool}/{action} classified as {tier}"
        # Every one of these must require an ack in ASSIST mode.
        result = evaluate_policy(tool, action, purpose="oss_audit")
        assert result.requires_ack is True, f"{tool}/{action} requires_ack was False"
        assert result.decision == PolicyDecision.REQUIRE_ACK, (
            f"{tool}/{action} decision was {result.decision}"
        )


def test_host_filesystem_writes_classify_as_filesystem_write():
    for tool, action in (("symbols", "export"), ("knowledge", "export_session")):
        tier = classify_tool_action(tool, action)
        assert tier == RiskTier.FILESYSTEM_WRITE, f"{tool}/{action} was {tier}"
        result = evaluate_policy(tool, action, purpose="oss_audit")
        assert result.requires_ack is True


def test_filesystem_read_requires_ack():
    assert classify_tool_action("misc", "read_file") == RiskTier.FILESYSTEM_READ
    result = evaluate_policy("misc", "read_file", purpose="oss_audit")
    assert result.decision == PolicyDecision.REQUIRE_ACK
    assert result.requires_ack is True


def test_provably_read_only_pairs_are_read_tier():
    read_pairs = [
        ("search", "comment"),
        ("gadgets", "rop"),
        ("gadgets", "jop"),
        ("gadgets", "cop"),
        ("gadgets", "syscall"),
        ("gadgets", "write_what_where"),
        ("gadgets", "stack_pivot"),
        ("gadgets", "shellcode_space"),
        ("gadgets", "mitigations"),
        ("gadgets", "seh_handlers"),
        ("gadgets", "pivot_chains"),
        ("gadgets", "classify_chain"),
        ("memory", "read"),
        ("memory", "hexdump"),
        ("memory", "search"),
        ("memory", "compare"),
        ("memory", "pointers"),
        ("memory", "entropy"),
        ("memory", "strings"),
        ("memory", "struct_walk"),
        ("memory", "histogram"),
        ("multi_session", "group_list"),
        ("multi_session", "cross_resolve"),
        ("multi_session", "cross_decompile"),
        ("multi_session", "cross_xrefs"),
        ("multi_session", "status"),
    ]
    for tool, action in read_pairs:
        tier = classify_tool_action(tool, action)
        assert tier == RiskTier.READ, f"{tool}/{action} classified as {tier}"
        result = evaluate_policy(tool, action, purpose="oss_audit")
        assert result.decision == PolicyDecision.ALLOW, f"{tool}/{action} was {result.decision}"
        assert result.requires_ack is False


def test_memory_write_stays_write_idb():
    # memory/write patches the IDA database, not live process memory.
    assert classify_tool_action("memory", "write") == RiskTier.WRITE_IDB


def test_plugin_run_is_local_code_exec_for_both_tools():
    for tool in ("analysis", "misc"):
        assert classify_tool_action(tool, "plugin_run") == RiskTier.LOCAL_CODE_EXEC, tool
        result = evaluate_policy(tool, "plugin_run", purpose="firmware_analysis")
        assert result.risk == RiskTier.LOCAL_CODE_EXEC
        assert result.requires_ack is True


def test_dead_tool_names_removed_from_tier_sets():
    assert not ({"crypto_id", "entropy", "protocol"} & READ_ONLY_TOOLS)
    assert not ({"hooks"} & WRITE_IDB_TOOLS)


def test_off_mode_reports_real_risk_tier():
    cases = [
        ("misc", "python", RiskTier.LOCAL_CODE_EXEC),
        ("bookmarks", "delete", RiskTier.DESTRUCTIVE),
        ("modify", "set_name", RiskTier.WRITE_IDB),
        ("search", "strings", RiskTier.READ),
    ]
    for tool, action, expected in cases:
        result = evaluate_policy(tool, action, mode=PolicyMode.OFF)
        assert result.decision == PolicyDecision.ALLOW
        assert result.risk == expected, f"{tool}/{action} risk was {result.risk}"
        assert result.requires_ack is False
        assert result.reasons == ()
        assert result.flags == ()
