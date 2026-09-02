from __future__ import annotations

import pytest

from ida_pro_mcp.host.server.server_session import (
    _sess_coerce_none,
    _sess_coerce_note,
    _sess_coerce_query,
    _sess_coerce_rename,
    _sess_coerce_tag,
    _sess_coerce_untag,
    _substitute_params,
)


def test_session_coercion_guards() -> None:
    # None coercion
    kw, err = _sess_coerce_none({})
    assert kw == {}
    assert err is None

    # Rename: missing name returns error
    kw, err = _sess_coerce_rename({})
    assert err is not None
    assert "name required" in err["message"]

    # Rename: valid name
    kw, err = _sess_coerce_rename({"name": "new_session_name"})
    assert err is None
    assert kw == {"new_name": "new_session_name"}

    # Tag: missing tag returns error
    kw, err = _sess_coerce_tag({})
    assert err is not None
    assert "tag required" in err["message"]

    # Tag: valid tag
    kw, err = _sess_coerce_tag({"tag": "important"})
    assert err is None
    assert kw == {"tag": "important"}

    # Untag: missing tag returns error
    kw, err = _sess_coerce_untag({})
    assert err is not None
    assert "tag required" in err["message"]

    # Note: missing note returns error
    kw, err = _sess_coerce_note({})
    assert err is not None
    assert "note required" in err["message"]

    # Note: valid note
    kw, err = _sess_coerce_note({"note": "Session analysis notes"})
    assert err is None
    assert kw == {"note": "Session analysis notes"}

    # Query: missing query returns error
    kw, err = _sess_coerce_query({})
    assert err is not None
    assert "query required" in err["message"]

    # Query: valid query
    kw, err = _sess_coerce_query({"query": "SELECT 1"})
    assert err is None
    assert kw == {"query": "SELECT 1"}


def test_substitute_params() -> None:
    params = {"$addr": "0x401000", "name": "main_func"}
    data = {
        "target": "$addr",
        "title": "Analysis of $name at $addr",
        "nested_list": ["$name", "static_val", {"k": "$addr"}],
    }

    substituted = _substitute_params(data, params)
    assert substituted["target"] == "0x401000"
    assert substituted["title"] == "Analysis of main_func at 0x401000"
    assert substituted["nested_list"] == ["main_func", "static_val", {"k": "0x401000"}]
