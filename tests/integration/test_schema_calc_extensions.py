import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.services import TOOL_ACTIONS, TOOL_ARG_SCHEMAS, TOOL_DESCRIPTIONS


def test_calc_actions_include_bitops():
    assert "bitops" in TOOL_ACTIONS.get("calc", [])


def test_calc_arg_schema_includes_bit_op():
    schema = TOOL_ARG_SCHEMAS.get("calc", {})
    assert "bit_op" in schema


def test_calc_description_mentions_bitops():
    desc = TOOL_DESCRIPTIONS.get("calc", "")
    assert "bitops" in desc

