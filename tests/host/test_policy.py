from ida_pro_mcp.services import (
    PolicyDecision,
    PolicyMode,
    RiskTier,
    build_audit_record,
    classify_tool_action,
    evaluate_policy,
)


def test_read_only_action_allowed_by_default():
    result = evaluate_policy("search", "strings", purpose="oss_audit")

    assert result.decision == PolicyDecision.ALLOW
    assert result.risk == RiskTier.READ


def test_semantic_indexing_is_read_only_analysis_and_needs_no_ack():
    result = evaluate_policy("intelligence", "index_fast", mode=PolicyMode.ASSIST)

    assert result.decision == PolicyDecision.ALLOW
    assert result.risk == RiskTier.READ
    assert result.requires_ack is False
    assert result.allowed is True
    assert result.requires_ack is False


def test_local_code_execution_requires_ack_in_assist_mode():
    result = evaluate_policy("misc", "python", purpose="firmware_analysis")

    assert result.decision == PolicyDecision.REQUIRE_ACK
    assert result.risk == RiskTier.LOCAL_CODE_EXEC
    assert result.allowed is False
    assert result.requires_ack is True
    assert result.reasons


def test_background_script_is_local_code_execution():
    result = evaluate_policy("background", "script", purpose="firmware_analysis")

    assert result.decision == PolicyDecision.REQUIRE_ACK
    assert result.risk == RiskTier.LOCAL_CODE_EXEC


def test_local_code_execution_allowed_with_ack():
    result = evaluate_policy(
        "misc",
        "python",
        purpose="firmware_analysis",
        ack=True,
    )

    assert result.decision == PolicyDecision.ALLOW
    assert result.risk == RiskTier.LOCAL_CODE_EXEC
    assert result.allowed is True
    assert result.requires_ack is False


def test_filesystem_write_requires_ack():
    result = evaluate_policy("memory", "write_file", purpose="release_verification")

    assert result.decision == PolicyDecision.REQUIRE_ACK
    assert result.risk == RiskTier.FILESYSTEM_WRITE


def test_disallowed_purpose_blocks_in_enforce_mode():
    result = evaluate_policy(
        "code",
        "decompile",
        mode=PolicyMode.ENFORCE,
        purpose="cheating",
    )

    assert result.decision == PolicyDecision.BLOCK
    assert "disallowed_purpose" in result.flags


def test_disallowed_purpose_warns_outside_enforce_for_read_only():
    result = evaluate_policy(
        "code",
        "decompile",
        mode=PolicyMode.ASSIST,
        purpose="cheating",
    )

    assert result.decision == PolicyDecision.ALLOW
    assert "disallowed_purpose" in result.flags
    assert result.allowed is True


def test_unknown_tool_is_conservative():
    result = evaluate_policy("brand_new_tool", "do_it", purpose="oss_audit")

    assert result.risk == RiskTier.UNKNOWN
    assert result.decision == PolicyDecision.REQUIRE_ACK


def test_permissive_mode_warns_instead_of_requiring_ack():
    result = evaluate_policy("analysis", "plugin_run", mode="permissive")

    assert result.risk == RiskTier.LOCAL_CODE_EXEC
    assert result.decision == PolicyDecision.WARN
    assert result.allowed is True


def test_classifier_flags_are_advisory_not_authoritative_for_safe_read():
    result = evaluate_policy(
        "search",
        "strings",
        purpose="oss_audit",
        classifier_flags=["possible_cheating"],
    )

    assert result.risk == RiskTier.READ
    assert result.decision == PolicyDecision.ALLOW
    assert "possible_cheating" in result.flags


def test_classify_tool_action_handles_destructive_actions():
    assert classify_tool_action("bookmarks", "delete") == RiskTier.DESTRUCTIVE


def test_session_destructive_actions_require_ack():
    """Session is READ_ONLY_TOOLS, but close/kill/rebuild/etc. delete real
    state (rebuild does os.remove(idb_path)) — they must require ack in
    ENFORCE mode, not classify as plain READ."""
    for action in (
        "close",
        "kill",
        "rebuild",
        "bulk_delete",
        "cleanup_stale",
        "idle_purge",
        "restore_snapshot",
    ):
        result = evaluate_policy("session", action, mode=PolicyMode.ENFORCE)
        assert result.risk == RiskTier.DESTRUCTIVE, f"session/{action} risk was {result.risk}"
        assert result.requires_ack is True, f"session/{action} ack was {result.requires_ack}"


def test_session_read_actions_stay_read():
    for action in ("health", "list", "get", "status", "state", "logs"):
        result = evaluate_policy("session", action, purpose="oss_audit")
        assert result.risk == RiskTier.READ, f"session/{action} risk was {result.risk}"
        assert result.decision == PolicyDecision.ALLOW


def test_action_level_read_override_for_session_health():
    result = evaluate_policy("session", "health", purpose="oss_audit")

    assert result.risk == RiskTier.READ
    assert result.decision == PolicyDecision.ALLOW


def test_action_level_read_override_for_funcs_info():
    result = evaluate_policy("funcs", "info", purpose="oss_audit")

    assert result.risk == RiskTier.READ
    assert result.decision == PolicyDecision.ALLOW


def test_audit_record_contains_policy_result_fields():
    result = evaluate_policy("misc", "python", purpose="education")
    record = build_audit_record(result, session_id="SID_TEST")

    assert record["event"] == "policy_decision"
    assert record["session_id"] == "SID_TEST"
    assert record["decision"] == "require_ack"
    assert record["risk"] == "local_code_exec"


def test_off_mode_bypasses_all_gates():
    """IDA_MCP_POLICY_MODE=off should allow any tool/action without ack."""
    for tool, action in [
        ("misc", "python"),
        ("modify", "set_name"),
        ("funcs", "create"),
        ("segments", "add"),
        ("bookmarks", "delete"),
    ]:
        result = evaluate_policy(tool, action, mode=PolicyMode.OFF)
        assert result.decision == PolicyDecision.ALLOW, f"{tool}/{action} was {result.decision}"
        assert result.risk == RiskTier.READ, f"{tool}/{action} risk was {result.risk}"
        assert result.requires_ack is False
        assert result.reasons == ()
        assert result.flags == ()


def test_off_mode_bypasses_disallowed_purpose_block():
    result = evaluate_policy(
        "misc", "python", mode=PolicyMode.OFF, purpose="malware_analysis",
    )
    assert result.decision == PolicyDecision.ALLOW
    assert "disallowed_purpose" not in result.flags


def test_off_mode_bypasses_unknown_purpose_flag():
    result = evaluate_policy(
        "analysis", "strings", mode=PolicyMode.OFF, purpose="xyzzy_random",
    )
    assert result.decision == PolicyDecision.ALLOW
    assert "unknown_purpose" not in result.flags


def test_segments_list_and_read_only_new_actions_are_read_tier():
    """segments/list, misc/list_sigs, misc/health, data/read_bytes must be READ tier."""
    read_pairs = [
        ("segments", "list"),
        ("segments", "info"),
        ("segments", "find_code"),
        ("segments", "find_data"),
        ("segments", "analyze"),
        ("misc", "list_sigs"),
        ("misc", "cache_stats"),
        ("misc", "health"),
        ("data", "read_bytes"),
    ]
    for tool, action in read_pairs:
        tier = classify_tool_action(tool, action)
        assert tier == RiskTier.READ, (
            f"{tool}/{action} classified as {tier}, expected READ"
        )


def test_segments_write_actions_remain_write_idb_tier():
    """segments/add, set_attr, set_perms, move, merge must still require write ack."""
    write_pairs = [
        ("segments", "add"),
        ("segments", "set_attr"),
        ("segments", "set_perms"),
        ("segments", "move"),
        ("segments", "merge"),
    ]
    for tool, action in write_pairs:
        tier = classify_tool_action(tool, action)
        assert tier == RiskTier.WRITE_IDB, (
            f"{tool}/{action} classified as {tier}, expected WRITE_IDB"
        )

    # delete/erase/patch/reset are DESTRUCTIVE (supersedes WRITE_IDB)
    assert classify_tool_action("segments", "delete") == RiskTier.DESTRUCTIVE
