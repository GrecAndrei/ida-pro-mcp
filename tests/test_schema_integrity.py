"""Pin: schema integrity for the post-processing pipeline.

Verifies:
- GLOBAL_POST_PROCESS_CONTROLS exists and is well-formed
- Old WRAPPER_ACTIONS / GLOBAL_WRAPPER_ACTION_CONTROLS are gone
- Action enums don't contain wrapper action names (grep/pick/head/tail/next/stats)
- PP params are injected into every tool schema that has actions
- _action_enum_with_grep no longer exists
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None

importlib.import_module("ida_pro_mcp.host")


@pytest.fixture(scope="module")
def schemas():
    return importlib.import_module("ida_pro_mcp.host.schemas")


# ---------------------------------------------------------------------------
# Old wrapper system is gone
# ---------------------------------------------------------------------------

class TestOldWrapperSystemRemoved:
    def test_no_wrapper_actions_constant(self, schemas):
        assert not hasattr(schemas, "WRAPPER_ACTIONS"), "WRAPPER_ACTIONS should be removed"

    def test_no_global_wrapper_action_controls(self, schemas):
        assert not hasattr(schemas, "GLOBAL_WRAPPER_ACTION_CONTROLS"), \
            "GLOBAL_WRAPPER_ACTION_CONTROLS should be removed"

    def test_no_action_enum_with_grep(self, schemas):
        assert not hasattr(schemas, "_action_enum_with_grep"), \
            "_action_enum_with_grep should be removed"


# ---------------------------------------------------------------------------
# New PP controls exist and are well-formed
# ---------------------------------------------------------------------------

class TestPostProcessControls:
    def test_exists(self, schemas):
        assert hasattr(schemas, "GLOBAL_POST_PROCESS_CONTROLS")

    def test_has_expected_keys(self, schemas):
        pp = schemas.GLOBAL_POST_PROCESS_CONTROLS
        expected = {"grep", "grep_regex", "grep_invert", "grep_case",
                    "head", "tail", "offset", "limit", "pick", "field", "next_token"}
        assert set(pp.keys()) == expected

    def test_all_have_type(self, schemas):
        for key, schema in schemas.GLOBAL_POST_PROCESS_CONTROLS.items():
            assert "type" in schema, f"{key} missing 'type'"
            assert "description" in schema, f"{key} missing 'description'"

    def test_grep_is_string(self, schemas):
        assert schemas.GLOBAL_POST_PROCESS_CONTROLS["grep"]["type"] == "string"

    def test_head_tail_are_integers(self, schemas):
        assert schemas.GLOBAL_POST_PROCESS_CONTROLS["head"]["type"] == "integer"
        assert schemas.GLOBAL_POST_PROCESS_CONTROLS["tail"]["type"] == "integer"

    def test_next_token_is_string(self, schemas):
        assert schemas.GLOBAL_POST_PROCESS_CONTROLS["next_token"]["type"] == "string"


# ---------------------------------------------------------------------------
# Action enums are clean
# ---------------------------------------------------------------------------

class TestActionEnumsClean:
    # These are the old wrapper action names that should NOT appear in any
    # tool's action enum. "stats" is excluded because blackboard has a
    # legitimate native "stats" action.
    WRAPPER_NAMES = {"grep", "pick", "head", "tail", "next"}

    # Tools that have native actions named like wrapper names (false positives).
    KNOWN_NATIVE = {
        ("blackboard", "stats"),
    }

    def test_no_wrapper_actions_in_any_tool_enum(self, schemas):
        """No tool's action enum should contain the old wrapper action names."""
        for tool_name, actions in schemas.TOOL_ACTIONS.items():
            overlap = self.WRAPPER_NAMES & set(actions)
            assert not overlap, f"{tool_name} has wrapper actions in enum: {overlap}"

    def test_search_enum_has_analyze(self, schemas):
        assert "analyze" in schemas.TOOL_ACTIONS["search"]

    def test_search_enum_has_no_wrappers(self, schemas):
        actions = set(schemas.TOOL_ACTIONS["search"])
        assert not (actions & self.WRAPPER_NAMES)


# ---------------------------------------------------------------------------
# PP params injected into schemas
# ---------------------------------------------------------------------------

class TestPPParamsInjected:
    def test_full_schema_has_pp_params(self, schemas):
        """build_input_schema should include PP params for tools with actions."""
        schema = schemas.build_input_schema("search")
        props = schema["properties"]
        for key in schemas.GLOBAL_POST_PROCESS_CONTROLS:
            assert key in props, f"search schema missing PP param '{key}'"

    def test_lean_schema_has_pp_params(self, schemas):
        schema = schemas.build_input_schema_lean("search")
        props = schema["properties"]
        assert "grep" in props
        assert "head" in props
        assert "limit" in props
        assert "next_token" in props

    def test_data_schema_has_pp_params(self, schemas):
        schema = schemas.build_input_schema("data")
        props = schema["properties"]
        assert "grep" in props
        assert "head" in props

    def test_batch_schema_no_pp_params(self, schemas):
        """batch is special — no action enum, no PP params."""
        schema = schemas.build_input_schema("batch")
        props = schema["properties"]
        assert "grep" not in props

    def test_session_schema_no_action_no_pp(self, schemas):
        """session has action but the ultra schema is minimal."""
        schema = schemas.build_input_schema_ultra("session")
        props = schema["properties"]
        # Ultra schema should NOT have PP params — just action + idb
        assert "grep" not in props

    def test_search_action_enum_not_polluted(self, schemas):
        """The search action enum in the schema should not contain wrapper names."""
        schema = schemas.build_input_schema("search")
        enum = schema["properties"]["action"]["enum"]
        for wrapper in self.WrapperActions():
            assert wrapper not in enum, f"'{wrapper}' found in search action enum"

    def WrapperActions(self):
        return {"grep", "pick", "head", "tail", "next", "stats"}
