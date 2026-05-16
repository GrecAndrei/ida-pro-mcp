"""
Unit tests for:
- ProposalStore (CRUD, accept/reject, scoped accept)
- AnalysisEngine (lifecycle, stage logic, notifications)
- ida://state resource
- ida://proposals resource
- accept_proposal / reject_proposal server actions
"""
import os
import sys
import json
import math
import struct
import tempfile
import threading
import time
import types
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── load analysis_engine without IDA ─────────────────────────────────────────

def _load_engine_mod():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "host", "analysis_engine.py")
    spec = importlib.util.spec_from_file_location("_ae_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_ae = _load_engine_mod()
ProposalStore = _ae.ProposalStore
AnalysisEngine = _ae.AnalysisEngine


def _ps():
    return ProposalStore(db_path=tempfile.mktemp(suffix=".db"))


# ── load blackboard without IDA ───────────────────────────────────────────────

def _load_bb_mod():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "ida_mcp", "tools", "blackboard.py")
    spec = importlib.util.spec_from_file_location("_bb_ae_test", path)
    mod = importlib.util.module_from_spec(spec)
    # Inject IDA stubs into the module's own namespace so imports inside
    # blackboard.py resolve without touching sys.modules
    _stub_names = ["idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
                   "ida_segment", "ida_name", "ida_typeinf", "ida_nalt",
                   "ida_hexrays", "ida_frame", "ida_struct", "ida_lines"]
    _saved = {}
    for m in _stub_names:
        _saved[m] = sys.modules.get(m)
        if m not in sys.modules:
            stub = types.ModuleType(m)
            sys.modules[m] = stub
    if not hasattr(sys.modules["idaapi"], "BADADDR"):
        sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
    try:
        spec.loader.exec_module(mod)
    finally:
        # Restore sys.modules to pre-test state
        for m, orig in _saved.items():
            if orig is None:
                sys.modules.pop(m, None)
            else:
                sys.modules[m] = orig
    return mod

_bb = _load_bb_mod()


def _pack(v):
    return struct.pack(f"{len(v)}f", *v)


# ═══════════════════════════════════════════════════════════════════════════════
# ProposalStore
# ═══════════════════════════════════════════════════════════════════════════════

def test_proposal_add_and_list():
    ps = _ps()
    pid = ps.add("rename_batch", "Rename 5 crypto funcs", "summary",
                 [{"id": "a", "addr": "0x401000", "suggested_name": "aes_init"}],
                 confidence=0.8)
    assert pid
    pending = ps.list_pending()
    assert len(pending) == 1
    assert pending[0]["proposal_type"] == "rename_batch"
    assert pending[0]["confidence"] == 0.8


def test_proposal_accept_all():
    ps = _ps()
    pid = ps.add("rename_batch", "Rename", "s",
                 [{"id": "a", "addr": "0x401000", "suggested_name": "foo"},
                  {"id": "b", "addr": "0x402000", "suggested_name": "bar"}])
    result = ps.accept(pid, scope="all")
    assert result is not None
    assert len(result["accepted_items"]) == 2
    assert ps.count_pending() == 0


def test_proposal_accept_selected():
    ps = _ps()
    pid = ps.add("rename_batch", "Rename", "s",
                 [{"id": "a", "addr": "0x401000", "suggested_name": "foo"},
                  {"id": "b", "addr": "0x402000", "suggested_name": "bar"}])
    result = ps.accept(pid, scope="selected", selected_ids=["a"])
    assert len(result["accepted_items"]) == 1
    assert result["accepted_items"][0]["id"] == "a"


def test_proposal_reject():
    ps = _ps()
    pid = ps.add("hypothesis", "Vuln at 0x401000", "s", [])
    ok = ps.reject(pid)
    assert ok
    assert ps.count_pending() == 0
    assert ps.list_pending() == []


def test_proposal_accept_nonexistent():
    ps = _ps()
    assert ps.accept("nonexistent") is None


def test_proposal_reject_nonexistent():
    ps = _ps()
    assert not ps.reject("nonexistent")


def test_proposal_count_pending():
    ps = _ps()
    assert ps.count_pending() == 0
    ps.add("rename_batch", "A", "s", [])
    ps.add("hypothesis", "B", "s", [])
    assert ps.count_pending() == 2
    pid = ps.list_pending()[0]["id"]
    ps.reject(pid)
    assert ps.count_pending() == 1


def test_proposal_sorted_by_confidence():
    ps = _ps()
    ps.add("rename_batch", "Low", "s", [], confidence=0.3)
    ps.add("rename_batch", "High", "s", [], confidence=0.9)
    pending = ps.list_pending()
    assert pending[0]["confidence"] >= pending[1]["confidence"]


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisEngine lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

def _make_engine(rpc_fn=None, notify_fn=None):
    bb = tempfile.mktemp(suffix=".bb.db")
    props = tempfile.mktemp(suffix=".props.db")
    return AnalysisEngine(
        session_id="test1234",
        rpc_fn=rpc_fn or (lambda t, a: {}),
        notify_fn=notify_fn or (lambda n: None),
        bb_path=bb,
        proposals_path=props,
    )


def test_engine_start_stop():
    eng = _make_engine()
    assert not eng.is_running()
    eng.start()
    assert eng.is_running()
    eng.stop()
    time.sleep(0.2)
    # Thread may still be alive briefly but stop event is set
    assert eng._stop.is_set()


def test_engine_status():
    eng = _make_engine()
    s = eng.status()
    assert "running" in s
    assert "pending_proposals" in s
    assert "classified_functions" in s


def test_engine_double_start_safe():
    eng = _make_engine()
    eng.start()
    t1 = eng._thread
    eng.start()  # should not create a second thread
    assert eng._thread is t1
    eng.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisEngine — contradiction monitor
# ═══════════════════════════════════════════════════════════════════════════════

def test_contradiction_monitor_detects_conflict():
    """Two entries with high cosine similarity but different categories → contradiction."""
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    # Use BlackboardStore to create the full schema, then inject vectors
    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid1 = store.write("AES key schedule", category="crypto_symmetric",
                       addr="0x401000", confidence=0.8, embed=False)
    eid2 = store.write("AES key schedule variant", category="network_http",
                       addr="0x402000", confidence=0.7, embed=False)

    import sqlite3
    v = [1.0, 0.0, 0.0, 0.0]
    blob = _pack(v)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid1))
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid2))
        conn.commit()

    eng._stage_contradiction_monitor()

    warnings = [n for n in notifications
                if n.get("params", {}).get("data", {}).get("type") == "contradiction"]
    assert len(warnings) >= 1
    assert warnings[0]["params"]["data"]["similarity"] >= 0.8


def test_contradiction_monitor_no_false_positive_same_category():
    """Same category entries should NOT trigger contradiction."""
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid1 = store.write("AES init", category="crypto_symmetric",
                       addr="0x401000", confidence=0.8, embed=False)
    eid2 = store.write("AES encrypt", category="crypto_symmetric",
                       addr="0x402000", confidence=0.8, embed=False)

    import sqlite3
    v = [1.0, 0.0, 0.0, 0.0]
    blob = _pack(v)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid1))
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid2))
        conn.commit()

    eng._stage_contradiction_monitor()
    warnings = [n for n in notifications
                if n.get("params", {}).get("data", {}).get("type") == "contradiction"]
    assert len(warnings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisEngine — cross-session matcher
# ═══════════════════════════════════════════════════════════════════════════════

def test_cross_session_matcher_finds_match():
    """Engine finds a matching function in another session's embedding DB."""
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    import sqlite3, tempfile as _tf
    tmpdir = _tf.mkdtemp()
    other_db = os.path.join(tmpdir, "other_session.embeddings.db")
    v = [1.0, 0.0, 0.0, 0.0]
    blob = _pack(v)
    with sqlite3.connect(other_db) as conn:
        conn.execute("CREATE TABLE embeddings (addr TEXT, name TEXT, vector BLOB)")
        conn.execute("INSERT INTO embeddings VALUES (?,?,?)",
                     ("0x401000", "aes_key_schedule", blob))
        conn.commit()

    eng._embeddings_dir = tmpdir

    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid = store.write("sub_401000", category="general",
                      addr="0x401000", confidence=0.5, embed=False)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid))
        conn.commit()

    eng._stage_cross_session_matcher()

    matches = [n for n in notifications
               if n.get("params", {}).get("data", {}).get("type") == "cross_session_match"]
    assert len(matches) >= 1
    assert matches[0]["params"]["data"]["matched_name"] == "aes_key_schedule"
    assert matches[0]["params"]["data"]["similarity"] >= 0.85
    assert eng.proposals.count_pending() >= 1
    pending = eng.proposals.list_pending()
    assert any(p["proposal_type"] == "cross_session" for p in pending)


def test_cross_session_matcher_no_match_below_threshold():
    """Low-similarity functions should not generate proposals."""
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    import sqlite3, tempfile as _tf
    tmpdir = _tf.mkdtemp()
    other_db = os.path.join(tmpdir, "other_session.embeddings.db")
    v_other = [0.0, 1.0, 0.0, 0.0]  # orthogonal to v_current
    v_current = [1.0, 0.0, 0.0, 0.0]
    with sqlite3.connect(other_db) as conn:
        conn.execute("CREATE TABLE embeddings (addr TEXT, name TEXT, vector BLOB)")
        conn.execute("INSERT INTO embeddings VALUES (?,?,?)",
                     ("0x401000", "some_func", _pack(v_other)))
        conn.commit()

    eng._embeddings_dir = tmpdir

    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid = store.write("sub_401000", category="general",
                      addr="0x401000", confidence=0.5, embed=False)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (_pack(v_current), eid))
        conn.commit()

    eng._stage_cross_session_matcher()
    assert eng.proposals.count_pending() == 0


# ═══════════════════════════════════════════════════════════════════════════════
# AnalysisEngine — taint tracer
# ═══════════════════════════════════════════════════════════════════════════════

def test_taint_tracer_detects_sink():
    """Taint tracer finds a dangerous sink reachable from a recv import."""
    notifications = []
    calls = []

    def rpc(tool, args):
        calls.append((tool, args))
        if tool == "data" and args.get("action") == "imports":
            return {"imports": [{"name": "recv", "ea": 0x401000}]}
        if tool == "code" and args.get("action") == "callers":
            return {"callers": [{"name": "memcpy", "addr": 0x402000}]}
        return {}

    eng = _make_engine(rpc_fn=rpc, notify_fn=lambda n: notifications.append(n))

    # Create minimal blackboard table
    import sqlite3
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blackboard (
                id TEXT PRIMARY KEY, title TEXT, content TEXT,
                category TEXT, addr TEXT, addr_end TEXT, tags TEXT,
                confidence REAL, created_at REAL, updated_at REAL,
                q_value REAL, source TEXT, vector BLOB,
                resolved INTEGER DEFAULT 0, contradicted INTEGER DEFAULT 0,
                contradiction_reason TEXT, ioc_type TEXT, ioc_value TEXT,
                depends_on TEXT, blocks_addr TEXT, register TEXT, reg_type TEXT,
                bridges TEXT, schema TEXT, quantized BLOB, q_signs BLOB,
                norm REAL, call_idx INTEGER
            )
        """)
        conn.commit()

    eng._stage_taint_tracer()

    sink_notifs = [n for n in notifications
                   if n.get("params", {}).get("data", {}).get("type") == "taint_sink"]
    assert len(sink_notifs) >= 1
    assert sink_notifs[0]["params"]["data"]["sink"] == "memcpy"
    assert eng.proposals.count_pending() >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# ida://state resource
# ═══════════════════════════════════════════════════════════════════════════════

def _load_resources_mod():
    path = os.path.join(os.path.dirname(__file__), "..", "src",
                        "ida_pro_mcp", "host", "resources.py")
    spec = importlib.util.spec_from_file_location("_res_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_res = _load_resources_mod()
ResourceResolver = _res.ResourceResolver


def _make_resolver(engine=None, bb_path=""):
    calls = {}
    def exec_fn(name, kwargs):
        calls[name] = kwargs
        if name == "idb":
            return {"filename": "test.exe", "processor": "ARM", "bits": 32, "file_size": 65536}
        if name == "data" and kwargs.get("action") == "functions":
            return {"functions": [
                {"name": "sub_401000", "start_ea": 0x401000},
                {"name": "main", "start_ea": 0x402000},
                {"name": "sub_403000", "start_ea": 0x403000},
            ]}
        return {}
    return ResourceResolver(exec_fn, engine=engine, bb_path=bb_path), calls


def test_state_resource_basic_structure():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://state")
    assert result is not None
    data = json.loads(result["text"])
    assert "binary" in data
    assert "coverage" in data
    assert "_note" in data


def test_state_resource_firmware_note_mentions_triage_snapshot():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    note = data.get("binary", {}).get("firmware_note", "")
    assert "triage_snapshot" in note


def test_state_resource_firmware_next_actions_include_triage_snapshot():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    actions = data.get("_next_actions", [])
    assert any("triage_snapshot" in a for a in actions)


def test_state_resource_note_mentions_firmware_triage_snapshot():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    note = data.get("_note", "")
    assert "triage_snapshot" in note


def test_state_resource_coverage():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    cov = data["coverage"]
    assert cov["total_functions"] == 3
    assert cov["named_functions"] == 1  # only "main" is named
    assert cov["unnamed_functions"] == 2
    assert cov["pct_named"] == pytest.approx(33.3, abs=0.2)


def test_state_resource_with_engine():
    eng = _make_engine()
    eng._proposals.add("rename_batch", "Rename 3 funcs", "s", [], confidence=0.8)
    resolver, _ = _make_resolver(engine=eng)
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    assert "engine" in data
    assert data["engine"]["pending_proposals"] == 1
    assert "note" in data["engine"]


def test_state_resource_with_blackboard():
    store = _bb.BlackboardStore(db_path=tempfile.mktemp(suffix=".db"))
    store.write("AES key schedule", category="hypothesis", addr="0x401000", confidence=0.9)
    store.write("C2 IP", category="ioc", ioc_type="ip_port", ioc_value="1.2.3.4:80")

    resolver, _ = _make_resolver(bb_path=store.db_path)
    result = resolver.read("ida://state")
    data = json.loads(result["text"])
    bb = data.get("blackboard", {})
    assert bb.get("stats", {}).get("total_entries", 0) >= 2
    assert len(bb.get("top_hypotheses", [])) >= 1
    assert len(bb.get("iocs", [])) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# ida://proposals resource
# ═══════════════════════════════════════════════════════════════════════════════

def test_proposals_resource_no_engine():
    resolver, _ = _make_resolver()
    result = resolver.read("ida://proposals")
    data = json.loads(result["text"])
    assert data["proposals"] == []
    assert "note" in data


def test_proposals_resource_with_engine():
    eng = _make_engine()
    eng._proposals.add("rename_batch", "Rename 5 crypto funcs", "summary",
                       [{"id": "a", "addr": "0x401000", "suggested_name": "aes_init"}],
                       confidence=0.8)
    eng._proposals.add("cross_session", "Import from v1", "summary",
                       [{"id": "b", "addr": "0x402000", "suggested_name": "sha256_init"}],
                       confidence=0.9)
    resolver, _ = _make_resolver(engine=eng)
    result = resolver.read("ida://proposals")
    data = json.loads(result["text"])
    assert data["count"] == 2
    types_found = {p["proposal_type"] for p in data["proposals"]}
    assert "rename_batch" in types_found
    assert "cross_session" in types_found
    assert "note" in data


def test_proposals_resource_empty_after_reject():
    eng = _make_engine()
    pid = eng._proposals.add("hypothesis", "Vuln", "s", [])
    eng._proposals.reject(pid)
    resolver, _ = _make_resolver(engine=eng)
    result = resolver.read("ida://proposals")
    data = json.loads(result["text"])
    assert data["count"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# notifications/resources/updated
# ═══════════════════════════════════════════════════════════════════════════════

def test_engine_pushes_resource_updated_on_contradiction():
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid1 = store.write("AES init", category="crypto_symmetric",
                       addr="0x401000", confidence=0.8, embed=False)
    eid2 = store.write("AES init variant", category="network_http",
                       addr="0x402000", confidence=0.7, embed=False)

    import sqlite3
    v = [1.0, 0.0, 0.0, 0.0]
    blob = _pack(v)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid1))
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid2))
        conn.commit()

    eng._stage_contradiction_monitor()

    resource_updates = [
        n for n in notifications
        if n.get("method") == "notifications/resources/updated"
    ]
    uris = {n["params"]["uri"] for n in resource_updates}
    assert "ida://state" in uris


def test_engine_pushes_resource_updated_on_cross_session():
    notifications = []
    eng = _make_engine(notify_fn=lambda n: notifications.append(n))

    import sqlite3, tempfile as _tf
    tmpdir = _tf.mkdtemp()
    other_db = os.path.join(tmpdir, "other_session.embeddings.db")
    v = [1.0, 0.0, 0.0, 0.0]
    blob = _pack(v)
    with sqlite3.connect(other_db) as conn:
        conn.execute("CREATE TABLE embeddings (addr TEXT, name TEXT, vector BLOB)")
        conn.execute("INSERT INTO embeddings VALUES (?,?,?)",
                     ("0x401000", "known_func", blob))
        conn.commit()

    eng._embeddings_dir = tmpdir

    store = _bb.BlackboardStore(db_path=eng._bb_path)
    eid = store.write("sub_401000", category="general",
                      addr="0x401000", confidence=0.5, embed=False)
    with sqlite3.connect(eng._bb_path) as conn:
        conn.execute("UPDATE blackboard SET vector=? WHERE id=?", (blob, eid))
        conn.commit()

    eng._stage_cross_session_matcher()

    resource_updates = [
        n for n in notifications
        if n.get("method") == "notifications/resources/updated"
    ]
    uris = {n["params"]["uri"] for n in resource_updates}
    assert "ida://proposals" in uris
    assert "ida://state" in uris


# ═══════════════════════════════════════════════════════════════════════════════
# _cosine / _unpack helpers
# ═══════════════════════════════════════════════════════════════════════════════

def test_cosine_identical():
    v = [1.0, 0.0, 0.0, 0.0]
    assert abs(_ae._cosine(v, v) - 1.0) < 1e-6


def test_cosine_orthogonal():
    a = [1.0, 0.0]
    b = [0.0, 1.0]
    assert abs(_ae._cosine(a, b)) < 1e-6


def test_cosine_zero_vector():
    assert _ae._cosine([0.0, 0.0], [1.0, 0.0]) == 0.0


def test_pack_unpack_roundtrip():
    v = [0.1, 0.5, 0.9, 0.3]
    blob = _ae._pack(v)
    v2 = _ae._unpack(blob)
    for a, b in zip(v, v2):
        assert abs(a - b) < 1e-5


import pytest  # needed for approx

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
