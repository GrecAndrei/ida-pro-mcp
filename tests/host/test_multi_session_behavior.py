"""Behavioral coverage for cross-session group operations."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server_multi_session import (
    ServerMultiSessionMixin,
    SessionGroup,
)


class _SessionManager:
    def __init__(self, session_ids):
        self._session_ids = {sid.upper() for sid in session_ids}

    def session_exists(self, sid):
        return str(sid).upper() in self._session_ids


class _Server(ServerMultiSessionMixin):
    def __init__(self, tmp_path: Path, responses=None):
        self.cache_dir = str(tmp_path)
        self.session_mgr = _SessionManager({"AAAA0001", "BBBB0002", "CCCC0003"})
        self._responses = responses or {}
        self.calls = []
        self._init_multi_session()

    def call_tool(self, tool, session_id, **tool_args):
        self.calls.append((tool, session_id, tool_args))
        value = self._responses.get((tool, session_id))
        if callable(value):
            return value(tool_args)
        if value is None:
            return {"ok": True}
        return value


def _create(server, **kwargs):
    args = {"group_id": "g1", "session_ids": ["aaaa0001", "bbbb0002"]}
    args.update(kwargs)
    return server._ms_group_create(args)


def test_session_group_snapshot_is_deep_and_round_trips():
    group = SessionGroup("g1", "demo")
    group.session_ids = ["AAAA0001", "BBBB0002"]
    group.links = {"puts": {"provider_sid": "AAAA0001", "export_ea": "0x10", "importer_sids": ["BBBB0002"]}}
    group.metadata = {"tags": ["cross-binary"]}

    snapshot = group.to_dict()
    snapshot["links"]["puts"]["importer_sids"].append("CCCC0003")
    snapshot["metadata"]["tags"].append("mutated")
    assert group.links["puts"]["importer_sids"] == ["BBBB0002"]
    assert group.metadata == {"tags": ["cross-binary"]}

    restored = SessionGroup.from_dict({
        **group.to_dict(),
        "unknown": "ignored",
        "links": {"puts": group.links["puts"], "bad": "not-a-link"},
    })
    assert restored.to_dict()["group_id"] == "g1"
    assert restored.to_dict()["links"] == group.links


def test_group_create_validates_shape_membership_and_duplicates(tmp_path):
    server = _Server(tmp_path)
    assert server._ms_group_create({"session_ids": "AAAA0001"})["error"] is True
    assert server._ms_group_create({"session_ids": ["AAAA0001"]})["error"] is True
    assert server._ms_group_create({"session_ids": ["AAAA0001", ""]})["error"] is True
    assert server._ms_group_create({"session_ids": ["AAAA0001", "aaaa0001"]})["error"] is True
    assert server._ms_group_create({"session_ids": ["AAAA0001", 2]})["error"] is True
    missing = server._ms_group_create({"session_ids": ["AAAA0001", "FFFF9999"]})
    assert missing["error"] is True
    assert "not found" in missing["message"]

    created = _create(server, name="linked", metadata={"owner": "test"})
    assert created["ok"] is True
    assert created["group"]["name"] == "linked"
    assert created["group"]["session_ids"] == ["AAAA0001", "BBBB0002"]
    assert created["group"]["metadata"] == {"owner": "test"}

    duplicate = _create(server)
    assert duplicate["error"] is True
    assert "already exists" in duplicate["message"]


def test_group_rehydration_ignores_malformed_root(tmp_path):
    (tmp_path / "groups.json").write_text("null", encoding="utf-8")

    server = _Server(tmp_path)

    listed = server._handle_multi_session("group_list", {})
    assert listed == {"ok": True, "groups": [], "count": 0}


def test_group_rehydration_normalizes_malformed_link_rows(tmp_path):
    (tmp_path / "groups.json").write_text(
        json.dumps(
            [
                {
                    "group_id": "g1",
                    "session_ids": ["aaaa0001", "AAAA0001", 7, "bbbb0002"],
                    "links": {
                        " puts ": {
                            "provider_sid": "aaaa0001",
                            "export_ea": " 0x10 ",
                            "importer_sids": ["bbbb0002", "BBBB0002", 3],
                        },
                        "missing-provider": {
                            "export_ea": "0x20",
                            "importer_sids": [],
                        },
                        "string-importers": {
                            "provider_sid": "aaaa0001",
                            "export_ea": "0x30",
                            "importer_sids": "bbbb0002",
                        },
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    server = _Server(tmp_path)
    group = server._get_group("g1")

    assert group is not None
    assert group.session_ids == ["AAAA0001", "BBBB0002"]
    assert group.links == {
        "puts": {
            "provider_sid": "AAAA0001",
            "export_ea": "0x10",
            "importer_sids": ["BBBB0002"],
        }
    }


def test_group_list_status_and_unknown_action_have_stable_shapes(tmp_path):
    server = _Server(tmp_path)
    _create(server)
    listed = server._handle_multi_session("group_list", {})
    assert listed["ok"] is True
    assert listed["count"] == 1
    assert listed["groups"][0]["group_id"] == "g1"

    status = server._handle_multi_session("status", {})
    assert status == {"ok": True, "groups": [{
        "group_id": "g1",
        "name": "g1",
        "session_count": 2,
        "link_count": 0,
        "provider_count": 0,
        "importer_count": 0,
    }], "total_groups": 1}

    unknown = server._handle_multi_session("nope", {})
    assert unknown["error"] is True
    assert "group_list" in unknown["hint"]


def test_group_link_builds_import_provider_table_and_reports_rpc_errors(tmp_path):
    responses = {
        ("symbols", "AAAA0001"): {"exports": [{"name": "puts", "ea": "0x4010"}, {"name": "self", "ea": "0x4020"}]},
        ("symbols", "BBBB0002"): {"exports": [{"name": "other", "ea": "0x5010"}]},
        ("imports_deep", "AAAA0001"): {"imports": [{"name": "other"}, {"name": "puts"}]},
        ("imports_deep", "BBBB0002"): {"imports": [{"name": "puts"}, {"name": "puts"}, {"name": "self"}]},
    }
    server = _Server(tmp_path, responses)
    _create(server)

    linked = server._ms_group_link({"group_id": "g1"})
    assert linked == {
        "ok": True,
        "group_id": "g1",
        "links_built": 3,
        "total_links": 3,
        "exports_available": 3,
        "export_errors": None,
        "import_errors": None,
    }
    assert server._session_groups["g1"].links == {
        "other": {"provider_sid": "BBBB0002", "export_ea": "0x5010", "importer_sids": ["AAAA0001"]},
        "puts": {"provider_sid": "AAAA0001", "export_ea": "0x4010", "importer_sids": ["BBBB0002"]},
        "self": {"provider_sid": "AAAA0001", "export_ea": "0x4020", "importer_sids": ["BBBB0002"]},
    }
    persisted = json.loads((tmp_path / "groups.json").read_text())
    assert persisted[0]["link_count"] == 3


def test_group_link_keeps_error_rows_out_of_links(tmp_path):
    responses = {
        ("symbols", "AAAA0001"): {"error": True, "message": "runtime unavailable"},
        ("symbols", "BBBB0002"): {"exports": [{"name": "puts", "ea": "0x1"}]},
        ("imports_deep", "AAAA0001"): {"error": True, "message": "imports unavailable"},
        ("imports_deep", "BBBB0002"): {"imports": [{"name": "puts"}]},
    }
    server = _Server(tmp_path, responses)
    _create(server)

    linked = server._ms_group_link({"group_id": "g1"})

    assert linked["ok"] is True
    assert linked["links_built"] == 0
    assert linked["exports_available"] == 1
    assert linked["export_errors"] == [{"session_id": "AAAA0001", "error": "runtime unavailable"}]
    assert linked["import_errors"] == [{"session_id": "AAAA0001", "error": "imports unavailable"}]


def test_session_group_from_dict_and_disk_loading_fail_closed(tmp_path, monkeypatch):
    assert SessionGroup.from_dict(None).group_id == ""
    assert SessionGroup.from_dict({"group_id": "g", "session_ids": "bad", "links": []}).session_ids == []

    (tmp_path / "groups.json").write_text("{not json", encoding="utf-8")
    server = _Server(tmp_path)
    assert server._handle_multi_session("group_list", {}) == {
        "ok": True,
        "groups": [],
        "count": 0,
    }

    server._session_groups["g1"] = SessionGroup("g1")
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server_multi_session.json.dump",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read-only cache")),
    )
    server._persist_groups()
    assert not list(tmp_path.glob("groups.json.*.tmp"))


def test_multi_session_group_link_accepts_catalog_aliases_and_skips_bad_rows(tmp_path):
    responses = {
        ("symbols", "AAAA0001"): {
            "entries": [
                {"name": " puts ", "address": "0x4010"},
                "not-a-row",
                {"name": "", "ea": "0x4020"},
            ]
        },
        ("symbols", "BBBB0002"): {
            "symbols": [{"name": "read", "addr": "0x5010"}]
        },
        ("imports_deep", "AAAA0001"): {
            "entries": [{"name": "read"}, "bad", {"name": ""}, {"name": "puts"}]
        },
        ("imports_deep", "BBBB0002"): {
            "symbols": [{"name": " puts "}, {"name": "missing"}]
        },
    }
    server = _Server(tmp_path, responses)
    _create(server)

    result = server._ms_group_link({"group_id": "g1"})
    assert result["ok"] is True
    assert result["links_built"] == 2
    assert server._session_groups["g1"].links == {
        "read": {"provider_sid": "BBBB0002", "export_ea": "0x5010", "importer_sids": ["AAAA0001"]},
        "puts": {"provider_sid": "AAAA0001", "export_ea": "0x4010", "importer_sids": ["BBBB0002"]},
    }


def test_multi_session_cross_resolution_decompile_xrefs_and_detail_status(tmp_path):
    server = _Server(tmp_path)
    _create(server)
    group = server._session_groups["g1"]
    group.links = {
        "puts": {
            "provider_sid": "AAAA0001",
            "export_ea": "0x4010",
            "importer_sids": ["BBBB0002"],
        }
    }

    missing = server._ms_cross_resolve({"group_id": "g1"})
    assert missing["error"] is True
    resolved = server._ms_cross_resolve({"group_id": "g1", "symbol": " PUTS "})
    assert resolved["ok"] is True and resolved["symbol"] == "puts"
    resolved = server._ms_cross_resolve({"group_id": "g1", "symbol": "PUTS"})
    assert resolved["ok"] is True and resolved["symbol"] == "puts"
    assert server._ms_cross_resolve({"group_id": "g1", "symbol": "nope"})["error"] is True

    direct = server._ms_cross_decompile({"session_id": "BBBB0002", "address": "0x99"})
    assert direct["_cross_session"] == {
        "source_session_id": "BBBB0002",
        "resolved_from_symbol": None,
        "addr": "0x99",
    }
    by_symbol = server._ms_cross_decompile({"symbol": "PUTS"})
    assert by_symbol["_cross_session"]["source_session_id"] == "AAAA0001"
    assert by_symbol["_cross_session"]["addr"] == "0x4010"
    assert server._ms_cross_decompile({})["error"] is True
    assert server._ms_cross_decompile({"session_id": "AAAA0001"})["error"] is True
    assert server._ms_cross_decompile({"symbol": "unknown"})["error"] is True

    server._responses[("search", "BBBB0002")] = {
        "matches": [
            {"addr": "0x10", "name": "call_puts"},
            {"ea": "0x20", "text": "puts"},
            "bad-row",
        ]
    }
    shallow = server._ms_cross_xrefs({"group_id": "g1", "symbol": "puts"})
    assert shallow["ok"] is True and shallow["xrefs"] is None
    deep = server._ms_cross_xrefs({"group_id": "g1", "symbol": "PUTS", "deep": True})
    assert deep["ok"] is True
    assert deep["xrefs"] == [
        {"session_id": "BBBB0002", "addr": "0x10", "context": "call_puts"},
        {"session_id": "BBBB0002", "addr": "0x20", "context": "puts"},
    ]
    assert server._ms_cross_xrefs({"group_id": "g1"})["error"] is True
    assert server._ms_cross_xrefs({"group_id": "g1", "symbol": "none"})["error"] is True

    detail = server._ms_status({"group_id": "g1"})
    assert detail["ok"] is True
    assert detail["providers"] == {"AAAA0001": 1}
    assert detail["importers"] == {"BBBB0002": 1}
    assert detail["sample_links"][0]["symbol"] == "puts"
    assert server._ms_status({"group_id": "missing"})["error"] is True


def test_multi_session_group_helpers_tolerate_uninitialized_state(tmp_path):
    bare = ServerMultiSessionMixin()
    bare.cache_dir = ""
    bare._persist_groups()
    bare._drop_sid_from_groups("AAAA0001")
    assert bare._groups_path() is None

    server = _Server(tmp_path)
    group, error = server._require_group({})
    assert group is None and error["error"] is True
    assert server._ms_group_remove({})["error"] is True
    assert server._ms_group_remove({"group_id": "missing"})["error"] is True
    _create(server)
    removed = server._ms_group_remove({"group_id": "g1"})
    assert removed["ok"] is True and removed["removed"]["group_id"] == "g1"


def test_cross_resolve_is_case_insensitive_and_reports_missing_group_or_symbol(tmp_path):
    server = _Server(tmp_path)
    _create(server)
    server._session_groups["g1"].links = {
        "MessageBoxA": {"provider_sid": "AAAA0001", "export_ea": "0x123", "importer_sids": ["BBBB0002"]}
    }

    resolved = server._ms_cross_resolve({"group_id": "g1", "symbol": "messageboxa"})
    assert resolved["symbol"] == "MessageBoxA"
    assert resolved["provider_sid"] == "AAAA0001"
    assert resolved["importer_sids"] == ["BBBB0002"]

    missing_symbol = server._ms_cross_resolve({"group_id": "g1", "symbol": "absent"})
    assert missing_symbol["error"] is True
    missing_group = server._ms_cross_resolve({"group_id": "missing", "symbol": "x"})
    assert missing_group["error"] is True
    missing_arg = server._ms_cross_resolve({"group_id": "g1"})
    assert missing_arg["error"] is True


def test_cross_decompile_resolves_symbol_or_direct_target_and_marks_result(tmp_path):
    server = _Server(tmp_path, {("code", "AAAA0001"): {"ok": True, "pseudocode": "return 1;"}})
    _create(server)
    server._session_groups["g1"].links = {
        "target": {"provider_sid": "AAAA0001", "export_ea": "0x123", "importer_sids": []}
    }

    from_symbol = server._ms_cross_decompile({"group_id": "g1", "symbol": "TARGET"})
    assert from_symbol["ok"] is True
    assert from_symbol["_cross_session"] == {
        "source_session_id": "AAAA0001",
        "resolved_from_symbol": "TARGET",
        "addr": "0x123",
    }
    assert server.calls[-1] == ("code", "AAAA0001", {"action": "decompile", "addr": "0x123"})

    direct = server._ms_cross_decompile({"session_id": "BBBB0002", "address": "0x456"})
    assert direct["_cross_session"]["source_session_id"] == "BBBB0002"
    assert direct["_cross_session"]["addr"] == "0x456"
    assert server._ms_cross_decompile({"symbol": "unknown"})["error"] is True
    assert server._ms_cross_decompile({"session_id": "AAAA0001"})["error"] is True


def test_cross_diff_compares_two_sessions_and_preserves_numeric_changes(tmp_path):
    server = _Server(tmp_path, responses={
        ("code", "AAAA0001"): {
            "ok": True,
            "addr": "0x401000",
            "name": "sub_401000",
            "prototype": "int sub_401000(void)",
            "code": "int sub_401000() {\n  return sub_401100(16);\n}",
        },
        ("code", "BBBB0002"): {
            "ok": True,
            "addr": "0x501000",
            "name": "sub_501000",
            "prototype": "int sub_501000(void)",
            "code": "int sub_501000() {\n  return sub_501100(32);\n}",
        },
    })

    result = server._ms_cross_diff({
        "left_session": "aaaa0001",
        "left_address": "0x401000",
        "right_session": "bbbb0002",
        "right_address": "0x501000",
    })

    assert result["ok"] is True
    assert result["changed"] is True
    assert result["normalized"] is True
    assert "return sub_ADDR(16);" in result["diff"]
    assert "return sub_ADDR(32);" in result["diff"]
    assert "401100" not in result["diff"] and "501100" not in result["diff"]
    assert result["left"]["session_id"] == "AAAA0001"
    assert result["right"]["session_id"] == "BBBB0002"
    assert [call[1] for call in server.calls] == ["AAAA0001", "BBBB0002"]


def test_cross_diff_bounds_output_and_reports_decompile_failures(tmp_path):
    long_left = "\n".join(f"left_{i}" for i in range(20))
    long_right = "\n".join(f"right_{i}" for i in range(20))
    server = _Server(tmp_path, responses={
        ("code", "AAAA0001"): {"ok": True, "code": long_left},
        ("code", "BBBB0002"): {"ok": True, "code": long_right},
    })
    result = server._ms_cross_diff({
        "left_session": "AAAA0001", "left_address": "0x1",
        "right_session": "BBBB0002", "right_address": "0x2",
        "max_diff_lines": 4,
    })
    assert result["diff_truncated"] is True
    assert result["returned_diff_lines"] == 4

    server._responses[("code", "BBBB0002")] = {
        "error": True, "code": "DECOMPILER_FAILED", "message": "no decompiler"
    }
    failed = server._ms_cross_diff({
        "left_session": "AAAA0001", "left_address": "0x1",
        "right_session": "BBBB0002", "right_address": "0x2",
    })
    assert failed["error"] is True
    assert failed["code"] == MCPError.DECOMPILER_FAILED

    assert server._ms_cross_diff({})["error"] is True
    assert server._ms_cross_diff({
        "left_session": "AAAA0001", "right_session": "BBBB0002"
    })["error"] is True


def test_cross_xrefs_can_query_importers_and_handles_search_errors(tmp_path):
    responses = {
        ("search", "BBBB0002"): {"results": [{"ea": "0x20", "text": "call puts"}, {"addr": "0x30", "name": "puts@plt"}]},
    }
    server = _Server(tmp_path, responses)
    _create(server)
    server._session_groups["g1"].links = {
        "puts": {"provider_sid": "AAAA0001", "export_ea": "0x10", "importer_sids": ["BBBB0002"]}
    }

    shallow = server._ms_cross_xrefs({"group_id": "g1", "symbol": "puts"})
    assert shallow["xrefs"] is None
    assert shallow["importer_count"] == 1
    deep = server._ms_cross_xrefs({"group_id": "g1", "symbol": "puts", "deep": True})
    assert deep["xrefs"] == [
        {"session_id": "BBBB0002", "addr": "0x20", "context": "call puts"},
        {"session_id": "BBBB0002", "addr": "0x30", "context": "puts@plt"},
    ]

    server._responses[("search", "BBBB0002")] = {"error": True, "message": "search failed"}
    failed_deep = server._ms_cross_xrefs({"group_id": "g1", "symbol": "puts", "deep": True})
    assert failed_deep["xrefs"] == []


def test_drop_sid_removes_membership_provider_links_and_importer_references(tmp_path):
    server = _Server(tmp_path)
    _create(server)
    server._session_groups["g1"].links = {
        "provided": {"provider_sid": "BBBB0002", "export_ea": "0x1", "importer_sids": ["AAAA0001"]},
        "kept": {"provider_sid": "AAAA0001", "export_ea": "0x2", "importer_sids": ["BBBB0002", "CCCC0003"]},
    }

    server._drop_sid_from_groups("BBBB0002")

    group = server._session_groups["g1"]
    assert group.session_ids == ["AAAA0001"]
    assert "provided" not in group.links
    assert group.links["kept"]["importer_sids"] == ["CCCC0003"]


def test_group_remove_persists_removal_and_requires_existing_group(tmp_path):
    server = _Server(tmp_path)
    _create(server)
    removed = server._ms_group_remove({"group_id": "g1"})
    assert removed["ok"] is True
    assert removed["removed"]["group_id"] == "g1"
    assert json.loads((tmp_path / "groups.json").read_text()) == []
    assert server._ms_group_remove({"group_id": "g1"})["error"] is True
    assert server._ms_group_remove({})["error"] is True


def test_multi_session_deep_edges_99(tmp_path, monkeypatch):
    # 80: SessionGroup.from_dict with invalid export_ea
    bad_links = {
        "group_id": "g_bad",
        "name": "bad",
        "session_ids": ["AAAA0001"],
        "links": {
            "sym1": {"provider_sid": "AAAA0001", "export_ea": "", "importer_sids": ["BBBB0002"]},
            "sym2": {"provider_sid": "AAAA0001", "export_ea": "0x1000", "importer_sids": [123, "BBBB0002"]},
        },
    }
    sg = SessionGroup.from_dict(bad_links)
    assert "sym1" not in sg.links
    assert "sym2" in sg.links
    assert sg.links["sym2"]["importer_sids"] == ["BBBB0002"]

    server = _Server(tmp_path)

    # 158, 163: dict with groups list and non-list
    groups_file = tmp_path / "groups.json"
    groups_file.write_text(json.dumps({"groups": "not_a_list"}))
    server._load_groups_from_disk()

    # 168, 171-172, 174: rehydrate with non-dict, exception, empty group_id
    orig_from_dict = SessionGroup.from_dict

    def _corrupt_from_dict(entry):
        if entry.get("group_id") == "corrupt":
            raise ValueError("simulated corrupt entry")
        return orig_from_dict(entry)

    monkeypatch.setattr(SessionGroup, "from_dict", _corrupt_from_dict)
    groups_file.write_text(
        json.dumps({
            "groups": [
                "not_a_dict",
                {"group_id": "corrupt"},
                {"group_id": ""},
                {"group_id": "valid_g", "name": "val", "session_ids": []},
            ]
        })
    )
    server._load_groups_from_disk()
    monkeypatch.setattr(SessionGroup, "from_dict", orig_from_dict)
    assert "valid_g" in server._session_groups

    # 248: _drop_sid_from_groups when lock is None
    server._session_groups_lock = None
    server._drop_sid_from_groups("AAAA0001")
    server._session_groups_lock = threading.Lock()

    # 378: _ms_group_link with missing group
    err = server._ms_group_link({"group_id": "nonexistent"})
    assert err["error"] is True

    # 459: group removed while linking
    _create(server, group_id="g_race")
    orig_call_tool = server.call_tool

    def remove_during_calls(*a, **kw):
        with server._session_groups_lock:
            server._session_groups.pop("g_race", None)
        return {"exports": [], "imports": []}

    monkeypatch.setattr(server, "call_tool", remove_during_calls)
    res_gone = server._ms_group_link({"group_id": "g_race"})
    assert res_gone["code"] == MCPError.NOT_FOUND

    # 465: membership changed while linking
    _create(server, group_id="g_race2")

    def mutate_during_calls(*a, **kw):
        with server._session_groups_lock:
            server._session_groups["g_race2"].session_ids = ["AAAA0001"]
        return {"exports": [], "imports": []}

    monkeypatch.setattr(server, "call_tool", mutate_during_calls)
    res_mut = server._ms_group_link({"group_id": "g_race2"})
    assert res_mut["code"] == MCPError.CONFLICT
    monkeypatch.setattr(server, "call_tool", orig_call_tool)

    # 564, 575: _ms_cross_decompile group not found & symbol not found
    d1 = server._ms_cross_decompile({"group_id": "nonexistent", "symbol": "sym"})
    assert d1["error"] is True
    _create(server, group_id="g_decompile")
    d2 = server._ms_cross_decompile({"group_id": "g_decompile", "symbol": "unlinked_sym"})
    assert d2["error"] is True

    # 611: _ms_cross_xrefs group missing
    x1 = server._ms_cross_xrefs({"group_id": "nonexistent", "symbol": "sym"})
    assert x1["error"] is True

    # 675-677: _ms_status without group_id but with links
    server._session_groups["g_decompile"].links = {
        "puts": {"provider_sid": "AAAA0001", "importer_sids": ["BBBB0002"]},
    }
    g_res = server._ms_status({})
    assert g_res["ok"] is True
    assert any(g["provider_count"] >= 1 for g in g_res["groups"])
