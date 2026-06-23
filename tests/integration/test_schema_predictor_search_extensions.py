import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.services import TOOL_ACTIONS, TOOL_DESCRIPTIONS


def test_predictor_actions_include_recommend_bundle():
    assert "recommend_bundle" in TOOL_ACTIONS.get("predictor", [])


def test_predictor_description_mentions_recommend_bundle():
    desc = TOOL_DESCRIPTIONS.get("predictor", "")
    assert "recommend_bundle" in desc


def test_search_actions_include_smart_bundle():
    assert "smart_bundle" in TOOL_ACTIONS.get("search", [])


def test_search_description_mentions_smart_bundle():
    desc = TOOL_DESCRIPTIONS.get("search", "")
    assert "smart_bundle" in desc

