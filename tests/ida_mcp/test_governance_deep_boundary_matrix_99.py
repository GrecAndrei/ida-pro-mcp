"""Deep offline coverage for governance rules and MCP fallback wiring."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

governance = load_tool_module("governance_engine")


def _load_standalone(name: str):
    path = (
        Path(__file__).resolve().parents[2]
        / "src/ida_pro_mcp/ida_mcp/tools/governance_engine.py"
    )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ontology_threshold_and_axiom_satisfaction_boundaries():
    ontology = governance.REOntology()
    assert ontology.classify({"is_patch", "targets_import_section"})[0] == (
        "ImportTablePatch",
        1.0,
    )
    assert ontology.classify({"is_comment"}) == [("CompliantOperation", 1.0)]
    assert ontology.classify({"is_patch"}, threshold=1.1) == []


def test_base_rule_and_rule_specific_negative_paths():
    with pytest.raises(NotImplementedError):
        governance.RERule("X", "base", governance.Severity.INFO, "description").evaluate(
            governance.OperationType.PATCH, None, "", {}, {}
        )

    rename = governance.NoMisleadingRenameRule()
    violations = rename.evaluate(
        governance.OperationType.RENAME,
        0x1000,
        "safe_main",
        {"api_calls": "memcpy", "arg_count": 4},
        {},
    )
    assert {item["rule_id"] for item in violations} == {"R003", "R003_main"}

    stack = governance.NoUnsafeStackFrameChangeRule()
    violations = stack.evaluate(
        governance.OperationType.TYPE_CHANGE,
        0x1000,
        "frame",
        {},
        {"targets_stack": True, "invalidates_locals": True},
    )
    assert violations[0]["rule_id"] == "R004_locals"

    execution = governance.NoUnknownCodeExecutionRule()
    assert execution.evaluate(
        governance.OperationType.EXECUTION, None, "", {}, {"unknown_origin": False}
    ) == []

    library = governance.NoRenameLibraryFunctionsRule()
    violations = library.evaluate(
        governance.OperationType.RENAME,
        0x401000,
        "replacement",
        {},
        {"is_library_function": True},
    )
    assert violations[0]["rule_id"] == "R006"


def test_engine_custom_rule_stats_and_no_rule_redaction_path():
    engine = governance.GovernanceEngine()

    class BrokenRule(governance.RERule):
        def evaluate(self, *args, **kwargs):
            raise RuntimeError("custom rule failed")

    engine.add_rule(
        BrokenRule("RX", "Broken custom rule", governance.Severity.HIGH, "test")
    )
    result = engine.evaluate_operation("rename", proposed_value="ordinary_name")
    assert result["verdict"] == "approved"
    assert result["approved"] is True
    assert engine.get_stats()["total_evaluations"] == 1

    warned = engine.evaluate_operation(
        "rename",
        proposed_value="safe_copy",
        context={"api_calls": "memcpy"},
    )
    assert warned["verdict"] == "warned"
    assert warned["approved"] is True

    engine.rules = []
    plain = engine.evaluate_operation("comment", proposed_value="plain")
    assert plain["verdict"] == "approved"
    engine.reset_stats()
    assert engine.get_stats() == {
        "total_evaluations": 0,
        "approved": 0,
        "blocked": 0,
        "redacted": 0,
        "warned": 0,
        "total_violations": 0,
    }


def test_engine_property_inference_and_unknown_operation_envelope():
    engine = governance.GovernanceEngine()
    properties = engine._infer_properties(
        None,
        "10.0.0.1 user@example.com password=hunter2 "
        + "a" * 32
        + " example.com",
        {
            "is_import_addr": True,
            "section_type": ".text",
            "targets_stack": True,
            "changes_frame_size": True,
            "invalidates_locals": True,
            "breaks_calling_convention": True,
            "unknown_origin": True,
            "writes_to_disk": True,
            "opens_socket": True,
            "calls_encryption": True,
            "modifies_system_state": True,
            "contradicts_api": True,
            "incorrect_prototype": True,
            "false_security_claim": True,
            "modifies_control_flow": True,
            "bypasses_security_check": True,
        },
    )
    assert {
        "targets_import_section",
        "targets_executable_section",
        "targets_stack",
        "changes_frame_size",
        "invalidates_locals",
        "breaks_calling_convention",
        "unknown_origin",
        "writes_to_disk",
        "opens_socket",
        "calls_encryption",
        "modifies_system_state",
        "contradicts_api_evidence",
        "implies_incorrect_prototype",
        "suggests_false_security",
        "modifies_code_flow",
        "bypasses_security_check",
        "contains_ip",
        "contains_email",
        "contains_credential",
        "contains_hash_secret",
        "contains_domain",
    } <= properties

    unknown = engine.evaluate_operation("not-a-real-operation", proposed_value="x")
    assert unknown["approved"] is False
    assert unknown["violations"][0]["rule_id"] == "R000"

    no_classification = governance.GovernanceEngine(ontology_threshold=2).evaluate_operation(
        "comment", proposed_value="plain"
    )
    assert no_classification["ontology_class"] == "CompliantOperation"
    assert no_classification["axiom_score"] == 0.0


def test_module_singleton_wrappers_and_no_pii_rule_fallback(monkeypatch):
    original = governance._governance_instance
    try:
        governance._governance_instance = governance.GovernanceEngine()
        assert governance.get_governance() is governance._governance_instance
        assert len(governance.list_rules()) == 6
        assert "[IP_REDACTED]" in governance.redact_pii("10.0.0.1")

        governance._governance_instance.rules = []
        assert governance.redact_pii("unchanged") == "unchanged"
        result = governance.evaluate_operation("comment", proposed_value="plain")
        assert result["verdict"] == "approved"
    finally:
        governance._governance_instance = original


def test_standalone_mcp_fallback_actions_and_error_paths(monkeypatch):
    standalone = _load_standalone("_standalone_governance_coverage")
    services = types.ModuleType("ida_pro_mcp.services")

    def coerce_int(_value):
        raise ValueError("bad address")

    services.coerce_int = coerce_int
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)

    missing = standalone.governance_engine(action="check")
    assert missing["code"] == "INVALID_ARGS"
    checked = standalone.governance_engine(
        action="check",
        operation_type="comment",
        addr="not-an-address",
        proposed_value="plain",
    )
    assert checked["ok"] is True
    redacted = standalone.governance_engine(
        action="redact", proposed_value="C2 at 192.168.1.1"
    )
    assert redacted["replacements_made"] is True
    assert standalone.governance_engine(action="list_rules")["rules"]
    assert standalone.governance_engine(action="stats")["ok"] is True
    assert standalone.governance_engine(action="unknown")["code"] == "ACTION_NOT_FOUND"
    assert standalone.make_error(code="X", message="Y")["code"] == "X"

    monkeypatch.setattr(standalone, "get_governance", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    failure = standalone.governance_engine(action="stats")
    assert failure["code"] == "IDA_ERROR"
