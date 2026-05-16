import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.schemas import TOOL_ACTIONS, TOOL_ARG_SCHEMAS, TOOL_DESCRIPTIONS


def test_workflow_description_mentions_firmware_triage_snapshot():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "triage_snapshot" in desc


def test_workflow_description_mentions_recon_sweep():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "recon_sweep" in desc


def test_workflow_actions_include_recon_sweep():
    assert "recon_sweep" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_catalog():
    assert "catalog" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_plan():
    assert "plan" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_explain():
    assert "explain" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_estimate():
    assert "estimate" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_compose():
    assert "compose" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_prioritize():
    assert "prioritize" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_execute_plan():
    assert "execute_plan" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_actions_include_audit_plan():
    assert "audit_plan" in TOOL_ACTIONS.get("workflow", [])


def test_workflow_description_mentions_dry_run():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "dry_run" in desc


def test_workflow_description_mentions_include_exclude_filters():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "include/exclude" in desc


def test_workflow_description_mentions_catalog():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "catalog" in desc


def test_workflow_description_mentions_plan():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "plan" in desc


def test_workflow_description_mentions_explain():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "explain" in desc


def test_workflow_description_mentions_estimate():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "estimate" in desc


def test_workflow_description_mentions_compose():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "compose" in desc


def test_workflow_description_mentions_prioritize():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "prioritize" in desc


def test_workflow_description_mentions_execute_plan():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "execute_plan" in desc


def test_workflow_description_mentions_audit_plan():
    desc = TOOL_DESCRIPTIONS.get("workflow", "")
    assert "audit_plan" in desc


def test_workflow_arg_schema_includes_plan_controls():
    schema = TOOL_ARG_SCHEMAS.get("workflow", {})
    assert "planned_calls" in schema
    assert "priority_mode" in schema
    assert "continue_on_error" in schema
    assert "max_steps" in schema
    assert "workflow_actions" in schema
    assert "workflow_action" in schema
    assert "dry_run" in schema
    assert "include_tools" in schema
    assert "exclude_tools" in schema


def test_firmware_view_description_mentions_triage_snapshot():
    desc = TOOL_DESCRIPTIONS.get("firmware_view", "")
    assert "triage_snapshot" in desc
