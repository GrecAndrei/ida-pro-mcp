"""Pure unit tests for search response normalization helpers."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"


def _load_core_helpers():
    """Load pure helpers from search/core.py without IDA."""
    path = SRC / "ida_pro_mcp" / "ida_mcp" / "tools" / "search" / "core.py"
    text = path.read_text(encoding="utf-8")
    # Extract normalize_search_result + make_item + looks_like_identifier + clip_text + build_response
    # by executing a self-contained subset.
    ns: dict = {"re": re, "Optional": None, "LINE_MAX": 240}

    # clip_text
    m = re.search(
        r"def clip_text\(.*?\n(?:    .*\n)*?    return compact\[: max_len - 3\] \+ \"\.\.\.\"\n",
        text,
    )
    assert m, "clip_text not found"
    exec(m.group(0), ns)

    # build_response through looks_like_identifier block
    start = text.index("def build_response(")
    end = text.index("def demangle_safe(")
    exec(text[start:end], ns)

    # looks_like_address stub used by looks_like_identifier
    def looks_like_address(s: str) -> bool:
        s = (s or "").strip().lower()
        if s.startswith("0x"):
            try:
                int(s, 16)
                return True
            except ValueError:
                return False
        return False

    ns["looks_like_address"] = looks_like_address
    return ns


def test_build_response_has_results_and_matches():
    h = _load_core_helpers()
    r = h["build_response"](["a", "b"], 0, 10, 2, False, query="x")
    assert r["ok"] is True
    assert r["results"] == "a\nb"
    assert r["matches"] == "a\nb"
    assert r["count"] == 2
    assert r["query"] == "x"


def test_normalize_promotes_address_to_addr():
    h = _load_core_helpers()
    raw = {
        "ok": True,
        "matches": "0x1  foo",
        "items": [{"address": "0x401000", "name": "foo", "type": "names"}],
    }
    out = h["normalize_search_result"](raw, action="find", query="foo")
    assert out["action"] == "find"
    assert out["query"] == "foo"
    assert out["results"] == "0x1  foo"
    assert out["items"][0]["addr"] == "0x401000"
    assert out["items"][0]["address"] == "0x401000"


def test_normalize_passthrough_errors():
    h = _load_core_helpers()
    err = {"error": True, "code": "X", "message": "nope"}
    assert h["normalize_search_result"](err, action="find") is err or h["normalize_search_result"](err)["error"]


def test_looks_like_identifier():
    h = _load_core_helpers()
    assert h["looks_like_identifier"]("CreateFileW") is True
    assert h["looks_like_identifier"]("0x401000") is True
    assert h["looks_like_identifier"]("function that decrypts strings") is False
    assert h["looks_like_identifier"]("48 89 e5") is False


def test_make_item_hexes_int_addr():
    h = _load_core_helpers()
    item = h["make_item"](addr=0x401000, name="main", type="func", score=1.23456)
    assert item["addr"] == "0x401000"
    assert item["name"] == "main"
    assert item["score"] == 1.2346
