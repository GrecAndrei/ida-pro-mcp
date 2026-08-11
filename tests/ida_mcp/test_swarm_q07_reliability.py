"""Work-order q07 regression tests: error envelope + bridge reliability.

Covers the q07 reliability contract end to end:

- ``ida_mcp/error_handling``: ``handle_error`` dispatches timeouts to the
  dedicated ``*_TIMEOUT`` codes (with ``recoverable=True``), decompiler /
  emulation failures to their codes, and everything else to ``UNKNOWN``;
  ``make_error`` always emits ``category`` + ``recoverable``; the canonical
  address parser's bare-hex policy is exercised against an opaque RISC-V raw
  blob (a small mapped image window) where a bare token resolves as hex when
  it maps and is refused with a "use 0x prefix" hint when it does not.

- ``server_script.py`` (IDA-side RPC bridge): a non-mapping ``args`` payload
  is INVALID_ARGS (not an internal crash); a TypeError raised by a tool is
  classified INVALID_ARGS with a clear message (never "Internal server
  error"); a RuntimeError stays UNKNOWN_ERROR (p17 pin preserved); during
  startup analysis tool calls are gated with ANALYSIS_INCOMPLETE
  (``recoverable=True``) while ping reports ``analyzing: true``; bridge
  error envelopes (UNAUTHORIZED / INVALID_REQUEST / REQUEST_TOO_LARGE) carry
  the same category/recoverable shape as tool errors.

- ``zeromcp/mcp.py``: a non-serializable tool result becomes an isError
  envelope instead of taking the server down.

- ``host/server/server_semantic.py``: a rebuild persists cached row vectors
  into the vector BLOB column (never recomputing them), and a malformed
  gadget payload surfaces as a per-action error instead of silent zero rows.

- ``host/server/audit.py``: args hashing is failure-proof (the record is
  still written for args the old ``sort_keys`` hash would have rejected), and
  a burst of records is coalesced into a bounded set of flushes.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import threading
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IDA_MCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp"


# ===========================================================================
# Loading helpers (standalone, no ida_* required)
# ===========================================================================

def _load_module(name: str, relpath: str):
    """Load a source module standalone (no package __init__) and return it."""
    path = Path(relpath)
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _register_ida_mcp_stub_packages():
    """Register ``ida_pro_mcp`` / ``ida_pro_mcp.ida_mcp`` stub packages so
    ``from ida_pro_mcp.ida_mcp.error_handling import ...`` resolves to the
    standalone-loaded module instead of the real (IDA-dependent) package."""
    pkg = sys.modules.get("ida_pro_mcp") or types.ModuleType("ida_pro_mcp")
    pkg.__path__ = [str(REPO / "src" / "ida_pro_mcp")]
    sys.modules["ida_pro_mcp"] = pkg
    sub = sys.modules.get("ida_pro_mcp.ida_mcp") or types.ModuleType("ida_pro_mcp.ida_mcp")
    sub.__path__ = [str(IDA_MCP)]
    sys.modules["ida_pro_mcp.ida_mcp"] = sub


def _load_error_handling():
    _register_ida_mcp_stub_packages()
    eh = _load_module("q07_error_handling_ut", str(IDA_MCP / "error_handling.py"))
    # Let server_script's guarded import find the real factory.
    sys.modules["ida_pro_mcp.ida_mcp.error_handling"] = eh
    return eh


def _load_server_script():
    """Load server_script.py with fake IDA modules so it imports outside IDA.

    server_script imports ``ida_segment``/``idautils``/``idc`` at module scope
    and calls ``sys.exit(1)`` when they are missing (the same gate p17's
    fixture stubs out). The autouse ``_isolate_sys_modules`` fixture restores
    sys.modules after each test, so the stubs need no manual cleanup.
    """
    eh = _load_error_handling()
    for name in ("ida_segment", "idautils", "idc"):
        sys.modules.setdefault(name, types.ModuleType(name))
    mod = _load_module(
        "q07_server_script_ut", str(REPO / "src" / "ida_pro_mcp" / "server_script.py")
    )
    mod._eh = eh  # expose for tests
    return mod


# ===========================================================================
# error_handling: handle_error dispatch + envelope shape
# ===========================================================================

def test_handle_error_timeout_dispatches_to_dedicated_codes():
    eh = _load_error_handling()

    # handle_error calls traceback.format_exc() which needs a real traceback;
    # drive it through a call so the trace is genuine.
    def invoke(exc):
        try:
            raise exc
        except Exception:
            return eh.handle_error(sys.exc_info()[1], context=None)

    err = invoke(TimeoutError("hung"))
    assert err["code"] == eh.MCPError.RPC_TIMEOUT
    assert err["recoverable"] is True
    assert err["category"] == "runtime"

    err_d = invoke(TimeoutError("decompile hung"))
    assert err_d["code"] == eh.MCPError.DECOMPILER_TIMEOUT

    err_s = invoke(TimeoutError("search over 64MB blob hung"))
    assert err_s["code"] == eh.MCPError.SEARCH_TIMEOUT


def test_handle_error_decompiler_and_emulation_non_timeout_codes():
    eh = _load_error_handling()

    def invoke(exc):
        try:
            raise exc
        except Exception:
            return eh.handle_error(sys.exc_info()[1], context=None)

    err = invoke(RuntimeError("decompilation of function at 0x1000 failed"))
    assert err["code"] == eh.MCPError.DECOMPILER_FAILED

    err2 = invoke(RuntimeError("emulation step faulted at 0x2000"))
    assert err2["code"] == eh.MCPError.EMULATION_ERROR

    err3 = invoke(ValueError("boom"))
    assert err3["code"] == eh.MCPError.UNKNOWN
    assert err3["recoverable"] is False


def test_make_error_always_emits_category_and_recoverable():
    eh = _load_error_handling()
    err = eh.make_error(eh.MCPError.INVALID_ARGS, "x")
    assert set(err) >= {"error", "code", "category", "message", "recoverable"}
    assert err["recoverable"] is False
    # Bridge codes get caller-attributable categories.
    assert eh.make_error(eh.MCPError.UNAUTHORIZED, "x")["category"] == "user"
    assert eh.make_error(eh.MCPError.INVALID_REQUEST, "x")["category"] == "user"
    assert eh.make_error(eh.MCPError.REQUEST_TOO_LARGE, "x")["category"] == "user"


# ===========================================================================
# error_handling: canonical address parser on an opaque RISC-V raw blob
# ===========================================================================

def test_riscv_raw_blob_bare_hex_policy(monkeypatch):
    """An opaque RISC-V raw blob maps only [0x800, 0x1000): an all-digit bare
    token resolves as hex when it maps inside, and an unmapped bare token is
    refused with a 'use 0x prefix' hint instead of being silently misread as
    decimal."""
    eh = _load_error_handling()
    monkeypatch.setattr(eh, "_image_min_ea", lambda: 0x800)
    monkeypatch.setattr(eh, "_image_max_ea", lambda: 0x1000)

    # RISC-V vector-handler table entry at 0x900, written habitually without
    # a prefix by firmware analysts.
    addr, err = eh.parse_address_canonical("900")
    assert err is None
    assert addr == 0x900

    # An address that maps inside still resolves through parse_address_safe.
    addr2, err2 = eh.parse_address_safe("999")
    assert err2 is None and addr2 == 0x999

    # A bare token outside the image is ambiguous -> refused with a hint.
    addr3, err3 = eh.parse_address_canonical("401000")
    assert addr3 is None
    assert err3["code"] == eh.MCPError.ADDRESS_INVALID
    assert "0x prefix" in err3.get("hint", "")

    # A bare token containing hex letters is ambiguous with symbol names and
    # is refused (all-digit tokens are the only auto-hex case).
    addr5, err5 = eh.parse_address_canonical("9c0")
    assert addr5 is None
    assert err5["code"] == eh.MCPError.ADDRESS_INVALID

    # Explicit 0x always wins regardless of the image window.
    addr4, err4 = eh.parse_address_canonical("0x401000")
    assert err4 is None and addr4 == 0x401000


# ===========================================================================
# server_script (bridge): args validation, TypeError classification, gate
# ===========================================================================

def _prepare_bridge(mod):
    mod._SESSION_TOKEN = "secret"
    mod._BOUND_PORT = 13337
    return mod


def test_bridge_non_mapping_args_is_invalid_args():
    mod = _prepare_bridge(_load_server_script())
    res = mod.process_single(
        {"tool": "analysis", "args": ["0x401000"], "session_token": "secret"}
    )
    assert res["error"] is True
    assert res["code"] == "INVALID_ARGS"
    assert "args" in res.get("hint", "")
    # The envelope carries the shared category/recoverable shape.
    assert "category" in res
    assert "recoverable" in res


def test_bridge_typeerror_from_tool_is_invalid_args_not_internal():
    mod = _prepare_bridge(_load_server_script())

    def _boom(**args):
        raise TypeError("int() argument must be a string")

    mod.TOOLS = {"analysis": _boom}
    res = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert res["error"] is True
    assert res["code"] == "INVALID_ARGS"
    assert "Internal server error" not in res.get("hint", "")


def test_bridge_runtimeerror_stays_unknown_error():
    mod = _prepare_bridge(_load_server_script())

    def _boom(**args):
        raise RuntimeError("decompiler exploded")

    mod.TOOLS = {"analysis": _boom}
    res = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert res["code"] == "UNKNOWN_ERROR"
    assert "request arguments" in res.get("hint", "")


def test_bridge_startup_gate_analysis_incomplete_and_ping():
    mod = _prepare_bridge(_load_server_script())
    calls = []

    def _tool(**args):
        calls.append(args)
        return {"ok": True}

    mod.TOOLS = {"analysis": _tool}

    # Open the gate window (simulating a bridge mid-startup).
    mod._STARTUP_DONE.clear()
    try:
        res = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
        assert res["error"] is True
        assert res["code"] == "ANALYSIS_INCOMPLETE"
        assert res["recoverable"] is True
        assert calls == [], "tool must not run while startup analysis is in flight"

        ping = mod.process_single({"type": "ping"})
        assert ping.get("pong") is True
        assert ping.get("analyzing") is True
    finally:
        mod._STARTUP_DONE.set()

    ping = mod.process_single({"type": "ping"})
    assert ping.get("analyzing") is False
    res2 = mod.process_single({"tool": "analysis", "args": {}, "session_token": "secret"})
    assert res2["ok"] is True
    assert calls == [{}]


def test_bridge_error_envelopes_carry_shared_shape():
    mod = _prepare_bridge(_load_server_script())
    for code in ("UNAUTHORIZED", "INVALID_REQUEST", "REQUEST_TOO_LARGE", "INTERNAL"):
        err = mod._build_error("bridge", f"msg for {code}", code=code)
        assert set(err) >= {"error", "code", "category", "message", "recoverable"}
        json.dumps(err)  # serializable on the wire
    assert mod._build_error("bridge", "x", code="UNAUTHORIZED")["category"] == "user"
    assert mod._build_error("bridge", "x", code="INVALID_REQUEST")["category"] == "user"
    assert mod._build_error("bridge", "x", code="REQUEST_TOO_LARGE")["category"] == "user"


def test_bridge_riscv_raw_blob_end_to_end(monkeypatch):
    """A fake RISC-V gadget tool consumes the canonical parser; the bridge
    delivers the caller's bare-hex token to the right EA, and an ambiguous
    unmapped token surfaces as an actionable ADDRESS_INVALID."""
    mod = _prepare_bridge(_load_server_script())
    eh = mod._eh
    monkeypatch.setattr(eh, "_image_min_ea", lambda: 0x800)
    monkeypatch.setattr(eh, "_image_max_ea", lambda: 0x1000)

    seen = {}

    def riscv_gadget(address, **kwargs):
        addr, err = eh.parse_address_canonical(address)
        if err:
            return err
        seen["ea"] = addr
        return {"ok": True, "gadget": f"gadget@0x{addr:x}"}

    mod.TOOLS = {"gadgets": riscv_gadget}

    res = mod.process_single(
        {"tool": "gadgets", "args": {"address": "900"}, "session_token": "secret"}
    )
    assert res["ok"] is True
    assert seen["ea"] == 0x900

    res2 = mod.process_single(
        {"tool": "gadgets", "args": {"address": "401000"}, "session_token": "secret"}
    )
    assert res2["error"] is True
    assert res2["code"] == "ADDRESS_INVALID"
    assert "0x prefix" in res2.get("hint", "")


# ===========================================================================
# zeromcp: non-serializable tool result -> isError envelope
# ===========================================================================

def _load_zeromcp():
    pkg = types.ModuleType("q07_zeromcp")
    pkg.__path__ = [str(IDA_MCP / "zeromcp")]
    sys.modules["q07_zeromcp"] = pkg
    jr = _load_module("q07_zeromcp.jsonrpc", str(IDA_MCP / "zeromcp" / "jsonrpc.py"))
    mcp = _load_module("q07_zeromcp.mcp", str(IDA_MCP / "zeromcp" / "mcp.py"))
    return jr, mcp


def test_zeromcp_non_serializable_tool_result_is_iserror():
    jr, mcp = _load_zeromcp()
    server = mcp.McpServer("q07")

    def bad_tool(**kw):
        return {"ok": True, "data": {1, 2, 3}}

    server.tool(bad_tool)  # registered as "bad_tool"
    out = server._mcp_tools_call("bad_tool", {})
    assert out["isError"] is True
    assert out["structuredContent"]["error"]["code"] == "INTERNAL"
    json.dumps(out)


# ===========================================================================
# host/server_semantic: vector persistence + per-action errors
# ===========================================================================

def _import_semantic():
    from ida_pro_mcp.host.server.server_semantic import (
        _GADGET_VEC_CACHE,
        ServerSemanticMixin,
        _pack_vector,
        _unpack_vector,
    )
    return ServerSemanticMixin, _GADGET_VEC_CACHE, _pack_vector, _unpack_vector


def _make_semantic_server(mixin_cls, tmp, session):
    """Build a fake host server that inherits the semantic mixin, so the mixin
    methods (db path, connect, rebuild, ...) bind to the same ``self``."""
    class _FakeServer(mixin_cls, _FakeSemanticServer):
        pass

    return _FakeServer(tmp, session)


class _FakeSession:
    def __init__(self, sid, idb_path, binary_path):
        self.session_id = sid
        self.idb_path = idb_path
        self.binary_path = binary_path


class _FakeSessionMgr:
    def __init__(self, tmp):
        self.tmp = Path(tmp)

    def get_session_artifact_dir(self, sid, create=True):
        d = self.tmp / str(sid)
        if create:
            d.mkdir(parents=True, exist_ok=True)
        return str(d)


class _FakeSemanticServer:
    def __init__(self, tmp, session):
        self.session_mgr = _FakeSessionMgr(tmp)
        self.current_session = session
        self._session = session
        self._semantic_index_lock = threading.RLock()
        self.call_tool = None

    def _ensure_client_owns_session(self, session):
        return None

    def _resolve_session_from_idb_ref(self, idb_ref):
        return self._session


GADGET_PAYLOAD = {
    "ok": True,
    "gadgets": [
        {"addr": "0x8009c0", "insns": 3, "gadget": "addi sp, sp, -16 ; ret"},
        {"addr": "0x8009d0", "insns": 2, "gadget": "lw a0, 0(sp) ; ret"},
    ],
}


def test_semantic_rebuild_persists_cached_vectors_only(tmp_path):
    Mixin, cache, pack, unpack = _import_semantic()
    cache.clear()
    try:
        # Pre-seed one row's embedding; the other row must NOT be computed.
        cache["addi sp, sp, -16 ; ret"] = [0.1, 0.2, 0.3]
        session = _FakeSession("s1", "/fake/s1.i64", "/fake/blob.bin")
        server = _make_semantic_server(Mixin, str(tmp_path), session)
        server.call_tool = lambda tool, idb_path, **kwargs: GADGET_PAYLOAD

        rebuilt = Mixin._semantic_index_rebuild(server, session, ["rop"], 3000, 6)
        assert rebuilt["ok"] is True
        assert rebuilt["rows_indexed"] == 2
        assert rebuilt["errors"] == []

        db = Path(rebuilt["db_path"])
        conn = sqlite3.connect(str(db))
        try:
            rows = conn.execute(
                "SELECT gadget, vector FROM gadgets WHERE source_action='rop' ORDER BY addr"
            ).fetchall()
        finally:
            conn.close()
        assert len(rows) == 2
        vec_by_gadget = dict(rows)
        # Vectors are stored as float32, so compare at 6-decimal tolerance.
        assert [round(x, 6) for x in unpack(vec_by_gadget["addi sp, sp, -16 ; ret"])] == [0.1, 0.2, 0.3]
        assert vec_by_gadget["lw a0, 0(sp) ; ret"] is None
    finally:
        cache.clear()


def test_semantic_rebuild_malformed_payload_is_per_action_error(tmp_path):
    Mixin, cache, pack, unpack = _import_semantic()
    cache.clear()
    try:
        session = _FakeSession("s2", "/fake/s2.i64", "/fake/blob.bin")
        server = _make_semantic_server(Mixin, str(tmp_path), session)

        # A tool that returns a bare string (not a dict with a gadgets list).
        server.call_tool = lambda tool, idb_path, **kwargs: "nope"
        rebuilt = Mixin._semantic_index_rebuild(server, session, ["rop"], 3000, 6)
        # No rows, an error -> the rebuild surfaces the per-action failure.
        assert rebuilt.get("error") is True
        assert any(e.get("action") == "rop" for e in rebuilt.get("details", {}).get("errors", []))

        # Mixed: one good action, one broken action.
        def call_tool(tool, idb_path, action=None, **kwargs):
            if action == "rop":
                return GADGET_PAYLOAD
            return {"ok": True}  # missing 'gadgets' list -> unusable shape

        server2 = _make_semantic_server(Mixin, str(tmp_path), _FakeSession("s3", "/fake/s3.i64", "/fake/blob.bin"))
        server2.call_tool = call_tool
        rebuilt2 = Mixin._semantic_index_rebuild(server2, session, ["rop", "jop"], 3000, 6)
        assert rebuilt2["ok"] is True
        assert rebuilt2["rows_indexed"] == 2
        assert any(e.get("action") == "jop" for e in rebuilt2["errors"])
    finally:
        cache.clear()


def test_semantic_vector_pack_roundtrip():
    Mixin, cache, pack, unpack = _import_semantic()
    vec = [0.5, -0.25, 1.0, 3.14159]
    # Vectors persist as float32 BLOBs (compact storage), so values that are
    # not exactly representable in single precision round-trip with rounding.
    assert [round(v, 6) for v in unpack(pack(vec))] == [round(v, 6) for v in vec]
    assert pack([]) is None
    assert unpack(b"\x00\x00\x00\x00") == [0.0]
    assert unpack(b"garbage-not-float-bytes") is None
    assert unpack(None) is None


# ===========================================================================
# host/server/audit: failure-proof hashing + coalesced flush cadence
# ===========================================================================

def _load_audit():
    from ida_pro_mcp.host.server.audit import AuditLogger, _canonical_args_hash, _shallow
    return AuditLogger, _shallow, _canonical_args_hash


def test_audit_args_hash_survives_mixed_key_types(tmp_path):
    AuditLogger, _shallow, _canonical_args_hash = _load_audit()
    logger = AuditLogger(str(tmp_path), max_mb=1)
    # Mixed int/str keys raise TypeError under sort_keys on the raw dict —
    # the exact failure that used to drop the whole audit record.
    args = {"topic": "x", 1: "one", 2: [3, 4, 5]}
    logger.log(
        tool="search",
        action="list",
        args=args,
        result={"ok": True},
        latency_ms=1.0,
        session_id="S1",
    )
    logger.close()
    written = list(tmp_path.rglob("*.jsonl"))
    assert written
    record = json.loads(written[0].read_text())
    h = record["args_hash"]
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


def test_audit_shallow_hash_is_bounded_for_huge_args(tmp_path):
    AuditLogger, _shallow, _canonical_args_hash = _load_audit()
    logger = AuditLogger(str(tmp_path), max_mb=1)
    big = {"items": list(range(100_000))}
    logger.log(
        tool="search",
        action="list",
        args=big,
        result={"ok": True},
        latency_ms=1.0,
        session_id="S1",
    )
    logger.close()
    written = list(tmp_path.rglob("*.jsonl"))
    record = json.loads(written[0].read_text())
    assert len(record["args_hash"]) == 16
    # The preview must be bounded (shallow truncation), not 100k items.
    assert "args_preview" not in record or len(record["args_preview"]) <= 500


def test_audit_flush_cadence_coalesces_burst(tmp_path):
    AuditLogger, _shallow, _canonical_args_hash = _load_audit()
    logger = AuditLogger(str(tmp_path), max_mb=1)
    for i in range(20):
        logger.log(
            tool="search",
            action="list",
            args={"q": str(i)},
            result={"ok": True},
            latency_ms=0.5,
            session_id="S1",
        )
    logger.close()
    written = list(tmp_path.rglob("*.jsonl"))
    lines = [ln for ln in written[0].read_text().splitlines() if ln.strip()]
    assert len(lines) == 20
