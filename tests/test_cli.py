import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp.cli import _normalize_tool_result


def test_normalize_tool_result_single_json_text_block():
    response = {
        "result": {
            "content": [{"type": "text", "text": '{"ok": true, "value": 7}'}],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {"ok": True, "value": 7}


def test_normalize_tool_result_preserves_multiple_content_blocks():
    response = {
        "result": {
            "content": [
                {"type": "text", "text": '{"ok": true, "value": 7}'},
                {"type": "text", "text": "follow-up note"},
            ],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {
        "content": [
            {"ok": True, "value": 7},
            {"text": "follow-up note", "isError": False},
        ],
        "isError": False,
    }


def test_normalize_tool_result_keeps_non_text_items():
    response = {
        "result": {
            "content": [
                {"type": "image", "url": "file:///tmp/plot.png"},
                {"type": "text", "text": "done"},
            ],
            "isError": False,
        }
    }

    assert _normalize_tool_result(response) == {
        "content": [
            {"type": "image", "url": "file:///tmp/plot.png"},
            {"text": "done", "isError": False},
        ],
        "isError": False,
    }
