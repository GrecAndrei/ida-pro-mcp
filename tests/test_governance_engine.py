#!/usr/bin/env python3
"""
Test suite for deterministic governance engine.

Run with: python3 -m pytest tests/test_governance_engine.py -v
Or standalone: python3 tests/test_governance_engine.py
"""

import sys
import os
import importlib.util

# Load governance engine module via importlib to avoid shadowing stdlib modules.
_governance_engine_path = os.path.join(
    os.path.dirname(__file__), "..",
    "src", "ida_pro_mcp", "ida_mcp", "tools", "governance_engine.py"
)
_spec = importlib.util.spec_from_file_location("_governance_engine_test_mod", _governance_engine_path)
_governance_engine = importlib.util.module_from_spec(_spec)
sys.modules["_governance_engine_test_mod"] = _governance_engine
_spec.loader.exec_module(_governance_engine)

GovernanceEngine = _governance_engine.GovernanceEngine
OperationType = _governance_engine.OperationType
Severity = _governance_engine.Severity
Verdict = _governance_engine.Verdict
evaluate_operation = _governance_engine.evaluate_operation
list_rules = _governance_engine.list_rules
redact_pii = _governance_engine.redact_pii
get_governance = _governance_engine.get_governance


def test_list_rules():
    """Test that all 6 rules are registered."""
    rules = list_rules()
    assert len(rules) >= 5
    rule_ids = {r["rule_id"] for r in rules}
    assert "R001" in rule_ids  # No Import Table Patches
    assert "R002" in rule_ids  # No PII in Comments
    assert "R003" in rule_ids  # No Misleading Renames
    assert "R004" in rule_ids  # No Unsafe Stack Frame Changes
    assert "R005" in rule_ids  # No Unknown Code Execution
    assert "R006" in rule_ids  # No Rename of Library/FLIRT Functions
    print("PASS: test_list_rules")


def test_import_table_patch_blocked():
    """R001: Patches to import table must be blocked."""
    result = evaluate_operation(
        operation_type="patch",
        addr=0x401000,
        proposed_value="nop",
        metadata={"section_type": ".idata", "is_import_addr": True},
    )
    assert result["verdict"] == "blocked"
    assert result["approved"] is False
    assert any("R001" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_import_table_patch_blocked")


def test_plt_patch_blocked():
    """R001: Patches to .plt must be blocked."""
    result = evaluate_operation(
        operation_type="patch",
        addr=0x401000,
        proposed_value="nop",
        metadata={"section_type": ".plt"},
    )
    assert result["verdict"] == "blocked"
    assert result["approved"] is False
    print("PASS: test_plt_patch_blocked")


def test_text_patch_approved():
    """Clean code section patch should be approved."""
    result = evaluate_operation(
        operation_type="patch",
        addr=0x401000,
        proposed_value="mov eax, 1",
        metadata={"section_type": ".text", "is_import_addr": False},
    )
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    assert len(result["violations"]) == 0
    print("PASS: test_text_patch_approved")


def test_pii_in_comment_redacted():
    """R002: Comments with IPs/emails should be redacted."""
    result = evaluate_operation(
        operation_type="comment",
        addr=0x401200,
        proposed_value="C2 server at 192.168.1.100 sends commands via admin@evil.com",
    )
    assert result["verdict"] == "redacted"
    assert result["approved"] is True  # Redacted content can proceed
    assert "[IP_REDACTED]" in result["redacted_content"]
    assert "[EMAIL_REDACTED]" in result["redacted_content"]
    assert "192.168.1.100" not in result["redacted_content"]
    assert any("R002" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_pii_in_comment_redacted")


def test_safe_comment_approved():
    """Comments without PII should be approved."""
    result = evaluate_operation(
        operation_type="comment",
        addr=0x401300,
        proposed_value="This function validates user input before passing to strcpy",
    )
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    assert len(result["violations"]) == 0
    print("PASS: test_safe_comment_approved")


def test_misleading_rename_warned():
    """R003: Renames suggesting safety with dangerous APIs should warn."""
    result = evaluate_operation(
        operation_type="rename",
        addr=0x401400,
        proposed_value="safe_function_that_uses_memcpy",
        context={"api_calls": "memcpy, strcpy, malloc"},
    )
    assert result["verdict"] == "warned"
    assert result["approved"] is True  # Warned but allowed
    assert any("R003" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_misleading_rename_warned")


def test_main_rename_signature_mismatch():
    """R003_main: Renaming to main with >3 args should be flagged (LOW severity)."""
    result = evaluate_operation(
        operation_type="rename",
        addr=0x401400,
        proposed_value="my_main_function",
        metadata={"arg_count": 5},
    )
    # Should NOT warn because "main" is not in the name
    assert result["verdict"] == "approved"

    result = evaluate_operation(
        operation_type="rename",
        addr=0x401400,
        proposed_value="main_handler",
        metadata={"arg_count": 5},
    )
    # LOW severity violation -> still approved (not warned)
    assert result["verdict"] == "approved"
    assert any("main" in v.get("description", "") for v in result["violations"])
    print("PASS: test_main_rename_signature_mismatch")


def test_unknown_code_execution_blocked():
    """R005: Execution of unknown code should be blocked."""
    result = evaluate_operation(
        operation_type="execution",
        addr=0xDEADBEEF,
        proposed_value="run shellcode",
        metadata={"unknown_origin": True, "writes_to_disk": True},
    )
    assert result["verdict"] == "blocked"
    assert result["approved"] is False
    assert any("R005" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_unknown_code_execution_blocked")


def test_known_code_execution_approved():
    """Execution of known code should be approved."""
    result = evaluate_operation(
        operation_type="execution",
        addr=0x401800,
        proposed_value="run_known_test_vector",
        metadata={"unknown_origin": False},
    )
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    print("PASS: test_known_code_execution_approved")


def test_stack_frame_change_blocked():
    """R004: Stack frame changes without validation should be blocked."""
    result = evaluate_operation(
        operation_type="type_change",
        addr=0x401500,
        proposed_value="set_frame_size 0x100",
        metadata={"targets_stack": True, "changes_frame_size": True},
    )
    assert result["verdict"] == "blocked"
    assert result["approved"] is False
    assert any("R004" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_stack_frame_change_blocked")


def test_library_rename_warned():
    """R006: Renaming library/FLIRT functions without override should warn."""
    result = evaluate_operation(
        operation_type="rename",
        addr=0x401600,
        proposed_value="my_malloc",
        metadata={"is_library_function": True, "is_flirt_identified": True},
    )
    assert result["verdict"] == "warned"
    assert result["approved"] is True  # Warned but allowed
    assert any("R006" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_library_rename_warned")


def test_library_rename_with_override_approved():
    """R006: Renaming library functions WITH override should be approved."""
    result = evaluate_operation(
        operation_type="rename",
        addr=0x401600,
        proposed_value="my_malloc",
        metadata={"is_library_function": True, "override_library_rename": True},
    )
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    print("PASS: test_library_rename_with_override_approved")


def test_redact_pii():
    """Test standalone PII redaction."""
    text = "Contact admin@example.com at 10.0.0.1 with password=secret123"
    redacted = redact_pii(text)
    assert "[EMAIL_REDACTED]" in redacted
    assert "[IP_REDACTED]" in redacted
    assert "[CREDENTIAL_REDACTED]" in redacted
    assert "admin@example.com" not in redacted
    print("PASS: test_redact_pii")


def test_annotation_with_hash_redacted():
    """Annotations containing hashes should be redacted."""
    result = evaluate_operation(
        operation_type="annotation",
        addr=0x401700,
        proposed_value="MD5 of payload: d41d8cd98f00b204e9800998ecf8427e",
    )
    assert result["verdict"] == "redacted"
    assert "d41d8cd98f00b204e9800998ecf8427e" not in result["redacted_content"]
    print("PASS: test_annotation_with_hash_redacted")


def test_empty_operation_approved():
    """Empty operations should be approved."""
    result = evaluate_operation(
        operation_type="comment",
        addr=0x401000,
        proposed_value="",
    )
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    print("PASS: test_empty_operation_approved")


def test_stats_tracking():
    """Statistics should be tracked across evaluations."""
    gov = get_governance()
    gov.reset_stats()

    evaluate_operation("patch", metadata={"section_type": ".idata", "is_import_addr": True})
    evaluate_operation("comment", proposed_value="safe comment")
    evaluate_operation("comment", proposed_value="IP: 10.0.0.1")

    stats = gov.get_stats()
    assert stats["total_evaluations"] == 3
    assert stats["blocked"] == 1
    assert stats["redacted"] == 1
    assert stats["approved"] == 1
    print("PASS: test_stats_tracking")


def test_performance_target():
    """Each check should complete in under 1ms."""
    import time

    gov = get_governance()
    gov.reset_stats()

    start = time.time()
    for _ in range(100):
        evaluate_operation(
            operation_type="comment",
            proposed_value="C2 at 192.168.1.1 and admin@test.com",
        )
    elapsed = (time.time() - start) * 1000
    avg_ms = elapsed / 100

    assert avg_ms < 1.0, f"Average processing time {avg_ms:.3f}ms exceeds 1ms target"
    print(f"PASS: test_performance_target ({avg_ms:.3f}ms avg)")


def test_unknown_operation_type_blocked():
    """Unknown operation types should be blocked."""
    result = evaluate_operation("invalid_type")
    assert result["verdict"] == "blocked"
    assert result["approved"] is False
    assert any("R000" in v.get("rule_id", "") for v in result["violations"])
    print("PASS: test_unknown_operation_type_blocked")


def run_all_tests():
    """Run all tests and report results."""
    tests = [
        test_list_rules,
        test_import_table_patch_blocked,
        test_plt_patch_blocked,
        test_text_patch_approved,
        test_pii_in_comment_redacted,
        test_safe_comment_approved,
        test_misleading_rename_warned,
        test_main_rename_signature_mismatch,
        test_unknown_code_execution_blocked,
        test_known_code_execution_approved,
        test_stack_frame_change_blocked,
        test_library_rename_warned,
        test_library_rename_with_override_approved,
        test_redact_pii,
        test_annotation_with_hash_redacted,
        test_empty_operation_approved,
        test_stats_tracking,
        test_performance_target,
        test_unknown_operation_type_blocked,
    ]

    passed = 0
    failed = 0

    print("=" * 60)
    print("Governance Engine Test Suite")
    print("=" * 60)

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {test.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"ERROR: {test.__name__}: {e}")

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
