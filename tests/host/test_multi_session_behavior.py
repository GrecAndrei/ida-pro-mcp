"""Behavioral coverage for cross-session group operations."""

from __future__ import annotations

import json
from pathlib import Path

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
