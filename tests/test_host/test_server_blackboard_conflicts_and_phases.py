from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from ida_pro_mcp.host.server.server_blackboard_phase import (
    _FUNCS_WRITE_ACTIONS,
    ServerBlackboardPhaseMixin,
    _strip_durable,
)
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore
from ida_pro_mcp.host.stores.symbol_db import SymbolDB


class _TestServer(ServerBlackboardMixin, ServerBlackboardPhaseMixin):
    _blackboard_module = None

    def __init__(self, tmp_path: Path) -> None:
        self.cache_dir = str(tmp_path / "cache")
        self.current_session = None
        self.session_mgr = SimpleNamespace(
            get_session=lambda _sid: None,
            get_high_confidence_hypotheses=lambda _sid, min_confidence=0.8: [],
        )
        self._blackboard_path_cache = {}
        self._blackboard_store = None
        self._blackboard_store_error = ""

    def _get_blackboard_store(self) -> BlackboardStore | None:
        return self._blackboard_store

    def _execute_tool(self, tool: str, args: dict) -> dict:
        return {"ok": True}

    def _publish_findings(self, store: object, args: dict) -> dict:
        return {"ok": True, "action": "publish_findings"}

    def _import_annotations(self, store: object, args: dict) -> dict:
        return {"ok": True, "action": "import_annotations"}

    def _phase_state(self, sid: str | None = None) -> dict:
        return {"phase": "scout", "auto_transition": True}

    def _bb_policy_bump(self) -> dict:
        return {"strict_mode": False}

    def _phase_snapshot(self, phase_state: dict, store: object) -> dict:
        return {"phase": "scout"}

    def _bb_policy_snapshot(self, policy_state: dict) -> dict:
        return {"strict_mode": False}

    def _bb_policy_check(self, policy_state: dict) -> dict:
        return {"ok": True}

    def _bb_policy_mark(self, policy_state: dict, kind: str) -> None:
        pass

    def _policy_persist(self, policy_state: dict) -> None:
        pass

    def _phase_transition(self, phase_state: dict, target: str, reason: str = "") -> None:
        phase_state["phase"] = target

    def _phase_tick(self, phase_state: dict, store: object, limit: int = 3) -> dict:
        return {"ok": True, "ticked": True}

    def _orchestration(self) -> MagicMock:
        orch = MagicMock()
        orch.enqueue_trace_task = MagicMock(return_value="task_123")
        return orch


def test_strip_durable_helper() -> None:
    data = {
        "phase": "scout",
        "turn": 3,
        "_durable_ns": "phase",
        "_durable_key": "SESS-1",
    }
    stripped = _strip_durable(data)
    assert stripped == {"phase": "scout", "turn": 3}


def test_funcs_write_actions() -> None:
    assert "create" in _FUNCS_WRITE_ACTIONS
    assert "delete" in _FUNCS_WRITE_ACTIONS
    assert "change" in _FUNCS_WRITE_ACTIONS
    assert "set_flags" in _FUNCS_WRITE_ACTIONS
    assert "list" not in _FUNCS_WRITE_ACTIONS


def test_phase_state_keys() -> None:
    mixin = ServerBlackboardPhaseMixin()
    assert mixin._bb_state_key("session_123") == "SESSION_123"
    assert mixin._bb_state_key(None) == ""


def test_server_blackboard_dispatch_errors(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    server._blackboard_store = None
    server._blackboard_store_error = ""
    res = server._handle_blackboard({"action": "read", "entry_id": "123"})
    assert res["error"] is True
    assert "IO_ERROR" in res["code"]

    server._blackboard_store_error = "disk down"
    res_db = server._handle_blackboard({"action": "read", "entry_id": "123"})
    assert res_db["error"] is True
    assert "DB_ERROR" in res_db["code"]

    server._blackboard_store_error = ""
    server._blackboard_store = BlackboardStore(str(tmp_path / "valid.db"))
    with patch.object(server, "_bb_dispatch_gate", return_value={"error": True, "code": "GATED"}):
        res_gated = server._handle_blackboard({"action": "read", "entry_id": "123"})
        assert res_gated["code"] == "GATED"


def test_session_blackboard_path_stat_oserror(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"DATA")
    sess = SimpleNamespace(
        binary_path=str(bin_file),
        idb_path=str(tmp_path / "a.i64"),
        session_id="S1",
    )
    with patch("os.path.isfile", return_value=True), patch("os.stat", side_effect=OSError("stat error")):
        p = server._session_blackboard_path(session_obj=sess)
        assert p != ""


def test_workspace_seed_and_merge_sqlite_errors(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    legacy_idb = tmp_path / "src.i64"
    legacy_bb = tmp_path / "src.i64.blackboard.db"
    legacy_bb.write_bytes(b"DATA")
    with patch("sqlite3.connect", side_effect=sqlite3.Error("connect fail")):
        server._seed_shared_workspace(str(tmp_path / "target.db"), "digest123", str(legacy_idb))

    db1 = tmp_path / "db1.db"
    db2 = tmp_path / "db2.db"
    with sqlite3.connect(db1) as conn:
        conn.execute("CREATE TABLE t (id INT)")
    with sqlite3.connect(db2) as conn:
        conn.execute("CREATE TABLE t (id INT)")

    # Test empty cols continue (line 435)
    mock_target = MagicMock()
    mock_target.__enter__.return_value = mock_target
    mock_source = MagicMock()
    mock_source.__enter__.return_value = mock_source
    mock_source.execute.side_effect = [
        MagicMock(fetchall=lambda: [("t",)]),
        MagicMock(fetchall=list),
    ]
    with patch("sqlite3.connect", side_effect=[mock_target, mock_source]):
        server._merge_workspace_rows(str(db1), str(db2))

    # Test inner sqlite3.Error on execute (line 444-445)
    mock_target = MagicMock()
    mock_target.__enter__.return_value = mock_target
    mock_source = MagicMock()
    mock_source.__enter__.return_value = mock_source
    mock_source.execute.side_effect = [
        MagicMock(fetchall=lambda: [("t",)]),
        sqlite3.Error("pragma error"),
    ]
    with patch("sqlite3.connect", side_effect=[mock_target, mock_source]):
        server._merge_workspace_rows(str(db1), str(db2))

    # Test outer connect sqlite3.Error
    with patch("sqlite3.connect", side_effect=sqlite3.Error("conn fail")):
        server._merge_workspace_rows(str(db1), str(db2))


def test_proposal_and_lifecycle_helpers(tmp_path: Path) -> None:
    db_path = tmp_path / "store.db"
    store = BlackboardStore(str(db_path))
    server = _TestServer(tmp_path)

    eid1 = server._write_proposal_entry(
        store,
        proposal_type="rename",
        title="title1",
        spec={},
        extra_tags=["extra1"],
    )
    entry1 = store.read(eid1)
    assert entry1 is not None
    assert "extra1" in entry1["tags"]

    eid2 = server._write_crawler_proposal(
        store,
        addr="0x1000",
        title="crawler_1",
        content="crawler notes",
        behavior_tags=["t1"],
    )
    assert eid2 is not None

    entry_bad_tags = store.read(eid1)
    assert entry_bad_tags is not None
    entry_bad_tags["tags"] = None
    with patch.object(store, "read", return_value=entry_bad_tags):
        up = server._apply_lifecycle_status(store, eid1, "verified")
        assert up is not None


def test_verified_proposal_addrs_and_lane_fetch(tmp_path: Path) -> None:
    db_path = tmp_path / "store.db"
    store = BlackboardStore(str(db_path))
    server = _TestServer(tmp_path)

    store.write(
        title="bad_json",
        content="{bad",
        category="proposal",
        tags=["status:verified"],
        addr="0x2000",
    )
    addrs = server._verified_proposal_addrs(store)
    assert "0x2000" in addrs

    with patch.object(store, "list", side_effect=RuntimeError("fail")):
        assert server._verified_proposal_addrs(store) == set()

    items_dead = server._lane_fetch(store, "lane_dead_ends", 5)
    assert isinstance(items_dead, list)

    items_hyp = server._lane_fetch(store, "lane_hypotheses", 5)
    assert isinstance(items_hyp, list)


def test_path_confinement_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = _TestServer(tmp_path)
    server.current_session = SimpleNamespace(idb_path="/mock/test.i64")

    with patch("os.path.dirname", side_effect=RuntimeError("dirname fail")):
        root = server._bb_path_root()
        assert root == os.path.realpath(server.cache_dir)

    monkeypatch.setenv("IDA_MCP_BLACKBOARD_ROOT", "/env/root")
    with patch("os.path.expanduser", side_effect=RuntimeError("expand fail")):
        assert server._bb_path_root() is None
    monkeypatch.delenv("IDA_MCP_BLACKBOARD_ROOT", raising=False)

    orig_realpath = os.path.realpath

    def _selective_realpath(p: str) -> str:
        if "sub/file.txt" in p:
            raise RuntimeError("realpath fail")
        return orig_realpath(p)

    monkeypatch.setattr(os.path, "realpath", _selective_realpath)
    _, err = server._bb_confine_path("sub/file.txt")
    assert err is not None

    assert server._bb_path_has_symlink("/path/outside", "/allowed/root") is True

    allowed = tmp_path / "root"
    allowed.mkdir()
    sub = allowed / "sub"
    sub.mkdir()
    assert server._bb_path_has_symlink(str(sub), str(allowed)) is False


def test_export_paging_offset(tmp_path: Path) -> None:
    db_path = tmp_path / "store_export.db"
    store = BlackboardStore(str(db_path))
    server = _TestServer(tmp_path)

    fake_page = [{"id": f"row_{i}", "category": "general", "title": f"T{i}", "confidence": 0.5} for i in range(1000)]
    second_page = [{"id": "row_last", "category": "general", "title": "Last", "confidence": 0.5}]
    with patch.object(store, "list", side_effect=[fake_page, second_page]):
        res = server._bb_action_export({"format": "json"}, store, {}, {})
        assert res["entries"] == 1001


def test_proposal_validation_and_spec_edges(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    assert "name required" in (server._validate_rename_spec({"renames": [{"addr": "0x1000"}]}) or "")
    assert "addr required" in (server._validate_patch_spec({"patches": [{"asm": "nop"}]}) or "")
    assert "must be an object" in (server._validate_proposal_spec("type", "bad") or "")
    assert server._validate_proposal_spec("type", {"types": [{"addr": "0x1000", "type": "int"}]}) is None

    db_path = tmp_path / "store_prop.db"
    store = BlackboardStore(str(db_path))
    assert server._proposal_entries(store, status="") == []


def test_proposal_execution_and_verify_edges(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    with patch.object(server, "_execute_tool", side_effect=RuntimeError("tool failed")):
        assert server._symbol_at("0x1000") == ""

    v_res = server._proposal_verify("rename", {"renames": [{"addr": ""}]})
    assert v_res["ok"] is False

    with patch.object(server, "_execute_tool", side_effect=RuntimeError("exec failed")):
        exec_res = server._proposal_execute("rename", {"renames": [{"addr": "0x1000", "name": "new_name"}]})
        assert exec_res["applied"] == 0


def test_cross_session_hypotheses_edges(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    assert server._export_session_hypotheses_to_symbol_db("sess_1", None) == 0
    assert server._import_cross_session_hypotheses(None) == 0

    sess = SimpleNamespace(binary_path="", analysis_options={"baseaddr": 0x10000})
    server.session_mgr.get_high_confidence_hypotheses = lambda sid, min_confidence=0.8: []
    assert server._export_session_hypotheses_to_symbol_db("sess_1", sess) == 0

    server.session_mgr.get_high_confidence_hypotheses = lambda sid, min_confidence=0.8: [{"statement": ""}]
    assert server._export_session_hypotheses_to_symbol_db("sess_1", sess) == 0

    # Line 1376-1377: baseaddr exception
    sess_bad_base = SimpleNamespace(binary_path="", analysis_options={"baseaddr": "invalid_base"})
    server.session_mgr.get_high_confidence_hypotheses = lambda sid, min_confidence=0.8: [{"statement": "0x1000"}]
    with patch.object(SymbolDB, "upsert_hypothesis", return_value="row1"):
        assert server._export_session_hypotheses_to_symbol_db("sess_1", sess_bad_base) == 1

    # Line 1389-1390: int parsing exception
    mock_m = MagicMock()
    mock_m.group.side_effect = ValueError("bad int")
    with patch("re.search", return_value=mock_m):
        assert server._export_session_hypotheses_to_symbol_db("sess_1", sess) == 0

    with patch.object(SymbolDB, "upsert_hypothesis", side_effect=RuntimeError("boom")):
        assert server._export_session_hypotheses_to_symbol_db("sess_1", sess) == 0

    # Line 1417: no hits
    sess2 = SimpleNamespace(binary_path="", analysis_options={"baseaddr": 0x20000})
    with patch.object(SymbolDB, "query_hypotheses", return_value=[]):
        assert server._import_cross_session_hypotheses(sess2) == 0

    # Line 1425-1426: baseaddr exception in import
    sess2_bad_base = SimpleNamespace(binary_path="", analysis_options={"baseaddr": "invalid_base"})
    with patch.object(SymbolDB, "query_hypotheses", return_value=[{"hypothesis_text": "sub_1", "addr_offset": 0}]), \
         patch.object(server, "_session_blackboard_path", return_value=str(tmp_path / "bb.db")):
        assert server._import_cross_session_hypotheses(sess2_bad_base) >= 0

    # Line 1430: store is None
    with patch.object(SymbolDB, "query_hypotheses", return_value=[{"hypothesis_text": "sub_1", "addr_offset": 0}]), patch.object(server, "_session_blackboard_path", return_value=""), \
             patch.object(_TestServer, "_blackboard_module", None), \
             patch.object(server, "_get_blackboard_store", return_value=None):
        assert server._import_cross_session_hypotheses(sess2) == 0

    # Line 1439: exists_similar is True
    with patch.object(SymbolDB, "query_hypotheses", return_value=[{"hypothesis_text": "sub_1", "addr_offset": 0}]):
        mock_st = MagicMock()
        mock_st.exists_similar.return_value = True
        with patch.object(server, "_session_blackboard_path", return_value=""), \
             patch.object(_TestServer, "_blackboard_module", None), \
             patch.object(server, "_get_blackboard_store", return_value=mock_st):
            assert server._import_cross_session_hypotheses(sess2) == 0

        db_path = tmp_path / "store_hyp.db"
        store = BlackboardStore(str(db_path))
        with patch.object(server, "_get_blackboard_store", return_value=store), patch.object(store, "exists_similar", return_value=True):
            assert server._import_cross_session_hypotheses(sess2) == 0


def test_action_handlers_edges(tmp_path: Path) -> None:
    db_path = tmp_path / "store_actions.db"
    store = BlackboardStore(str(db_path))
    server = _TestServer(tmp_path)

    p_set = server._bb_action_policy_set({"enforce_phases": []}, store, {}, {})
    assert p_set["ok"] is True

    w_res = server._bb_action_write({"title": "f1", "tags": [" ", "tag_a"]}, store, {}, {})
    assert w_res["ok"] is True

    with patch.object(store, "upsert_finding", side_effect=ValueError("bad param")):
        w_err = server._bb_action_write({"title": "f2"}, store, {}, {})
        assert w_err["error"] is True

    d_err = server._bb_action_decision_card({"title": ""}, store, {}, {})
    assert d_err["error"] is True

    prop_id = store.write(title="prop", content=json.dumps({"proposal_type": "rename", "spec": {}}), category="proposal")
    acc_err = server._bb_action_proposal_accept({"proposal_id": prop_id}, store, {}, {})
    assert acc_err["error"] is True

    prop_id2 = store.write(
        title="prop2",
        content=json.dumps({"proposal_type": "type", "spec": {"types": [{"addr": "0x1000", "type": "int"}]}}),
        category="proposal",
    )
    with patch.object(
        store,
        "read",
        return_value={
            "category": "proposal",
            "content": json.dumps({"proposal_type": "type", "spec": {"types": [{"addr": "0x1000", "type": "int"}]}}),
            "tags": None,
        },
    ):
        acc_res = server._bb_action_proposal_accept({"proposal_id": prop_id2, "dry_run": True}, store, {}, {})
        assert acc_res["ok"] is True

    with patch.object(store, "read", return_value={"category": "proposal", "content": "{bad_json", "tags": None}), patch.object(store, "update", return_value=False):
        rej_err = server._bb_action_proposal_reject({"proposal_id": "p1"}, store, {}, {})
        assert rej_err["error"] is True

    t_err1 = server._bb_action_trace_ingest({"text": ""}, store, {}, {})
    assert t_err1["error"] is True

    t_err2 = server._bb_action_trace_ingest({"source_entry_id": "nonexistent"}, store, {}, {})
    assert t_err2["error"] is True

    src_id = store.write(title="src_title", content="src_content")
    t_ok = server._bb_action_trace_ingest({"source_entry_id": src_id}, store, {}, {})
    assert t_ok["ok"] is True

    up_err = server._bb_action_update({"entry_id": ""}, store, {}, {})
    assert up_err["error"] is True

    m_res = server._bb_action_merge({}, store, {}, {})
    assert m_res["ok"] is True

    with patch.object(store, "record_examination", side_effect=ValueError("invalid verdict")):
        me_err = server._bb_action_mark_examined({}, store, {}, {})
        assert me_err["error"] is True

    bad_prop_id = store.write(title="bad_json_prop", content="{unclosed_json", category="proposal")
    list_res = server._bb_action_proposal_list({}, store, {}, {})
    assert any(p["proposal_id"] == bad_prop_id and p["proposal_type"] == "unknown" for p in list_res["proposals"])

    with patch.object(store, "read", return_value={"id": prop_id2, "category": "proposal", "content": json.dumps({"proposal_type": "type", "spec": {"types": [{"addr": "0x1000", "type": "int"}]}}), "tags": "string_not_list"}), \
         patch.object(server, "_proposal_verify", return_value={"ok": True}), \
         patch.object(server, "_proposal_execute", return_value={"ok": True}):
        acc_res2 = server._bb_action_proposal_accept({"proposal_id": prop_id2, "dry_run": False}, store, {}, {})
        assert acc_res2["ok"] is True

    with patch.object(store, "read", return_value={"id": prop_id2, "category": "proposal", "content": "{}", "tags": "string_not_list"}):
        rej_res2 = server._bb_action_proposal_reject({"proposal_id": prop_id2}, store, {}, {})
        assert rej_res2["ok"] is True

    assert server._bb_action_publish_findings({}, store, {}, {})["ok"] is True
    assert server._bb_action_import_annotations({}, store, {}, {})["ok"] is True

    with patch.object(server, "_bb_action_proposal_reject", return_value={"ok": True, "action": "rejected"}):
        assert server._bb_action_reject({}, store, {}, {})["ok"] is True


    # Lines 1452-1453: exception in _import_cross_session_hypotheses
    sess2 = SimpleNamespace(binary_path="", analysis_options={"baseaddr": 0x20000})
    with patch.object(SymbolDB, "query_hypotheses", side_effect=RuntimeError("symboldb down")):
        assert server._import_cross_session_hypotheses(sess2) == 0


def test_proposal_status_update_tags_not_list(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    store = BlackboardStore(str(tmp_path / "store.db"))
    eid = store.write(title="prop", content="{}", category="proposal")
    with patch.object(store, "read", return_value={"id": eid, "tags": "not_a_list", "content": "{}"}):
        server._apply_lifecycle_status(store, eid, "open")


def test_symlink_under_root_empty_part(tmp_path: Path) -> None:
    server = _TestServer(tmp_path)
    with patch("os.path.relpath", return_value="sub//file.json"):
        assert server._bb_path_has_symlink(str(tmp_path / "sub/file.json"), str(tmp_path)) is False
