from ida_pro_mcp.host.policy import (
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
