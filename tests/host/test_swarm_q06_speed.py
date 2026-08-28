"""Regression tests for work order q06 — per-request dispatch/batch/cache speed.

Coverage (each maps to a q06 directive):
- D6/D7  cache.py: canonicalized keys collapse hex/decimal spellings of the
          same address; a narrow address-family write invalidates only the
          written page plus whole-walk entries, keeping unrelated pages live;
          a no-address write falls back to the full physical clear (the
          ``invalidate_all()`` contract is preserved).
- D9     rate_limit.py: cheap host-only bookkeeping is exempt from the token
          buckets while writes/exec stay hard-limited.
- D3     postprocess.py: prefers the tool's pre-slice ``total`` for ``_total``
          so a server-side sliced page keeps correct pagination bookkeeping.
- D1     server_dispatch.py: policy config is parsed once per (mtime_ns, size)
          change, not on every call.
- D5     server_workflow_batch.py: a pure-read batch on one live session is
          served by ONE list-shaped RPC with per-item session tokens; writes,
          mixed sessions, host-only tools, and no-session cases fall back to
          the per-call loop.
- D10    host/batch_manager.py: persistence rewrites are debounced to <=1/sec
          and the persisted path is cached (no per-save ``os.makedirs``).

An opaque RISC-V raw-blob scenario is used where relevant: a headerless .bin
firmware session whose addresses are low blob offsets (e.g. 0x1000) is read
through a batch — the exact "wrong arch / offset / base" failure surface q06
is meant to keep fast.
"""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
import threading
from pathlib import Path

import ida_pro_mcp.host.batch_manager as bm_mod
from ida_pro_mcp.host.batch_manager import BatchManager
from ida_pro_mcp.host.server.rate_limit import is_rate_limit_exempt
from ida_pro_mcp.host.server.server import IDAMCPServer

REPO = Path(__file__).resolve().parents[2]
CACHE_PATH = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "cache.py"


def _load_cache():
    """Load cache.py standalone (no ida_* imports, so no stubs required)."""
    spec = importlib.util.spec_from_file_location("q06_cache_ut", str(CACHE_PATH))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# D6 / D7 — cache canonicalization + narrow write invalidation
# ---------------------------------------------------------------------------


def test_cache_canonicalizes_hex_decimal_and_narrow_invalidate():
    """Hex vs decimal spellings of the same RISC-V blob offset hit one cache
    entry; a write on the same 4 KiB page removes that read and whole-walks but
    leaves unrelated pages live; a no-address write physically clears."""
    cache = _load_cache()
    c = cache.ToolResultCache(max_entries=32, ttl_seconds=300)

    # Raw RISC-V blob: reset vector area at 0x1000, UART at 0x2000.
    c.put("data", {"action": "read_bytes", "addr": "0x1000"}, {"ok": True, "v": 1})
    c.put("data", {"action": "read_bytes", "addr": "0x2000"}, {"ok": True, "v": 2})
    c.put("data", {"action": "functions"}, {"ok": True, "v": 3})  # whole-walk
    assert c.stats()["entries"] == 3

    # Decimal spelling of 0x1000 (=4096) must hit the same key, not a new one.
    c.put("data", {"action": "read_bytes", "addr": "4096"}, {"ok": True, "v": 4})
    assert c.stats()["entries"] == 3
    assert c.get("data", {"action": "read_bytes", "addr": "0x1000"}) == {
        "ok": True,
        "v": 4,
    }

    # A rename at 0x1014 shares the 0x1000 page -> drop that read and the
    # whole-walk; the 0x2000 page is unrelated and survives.
    c.invalidate_for_write({"action": "rename", "addr": "0x1014"})
    assert c.get("data", {"action": "read_bytes", "addr": "0x1000"}) is None
    assert c.get("data", {"action": "functions"}) is None
    assert c.get("data", {"action": "read_bytes", "addr": "0x2000"}) is not None

    # A write with no address falls back to the full physical clear — the
    # documented invalidate_all() contract, preserved on the narrow path.
    c.put("data", {"action": "read_bytes", "addr": "0x2000"}, {"ok": True})
    c.invalidate_for_write({"action": "save_idb"})
    assert c.stats()["entries"] == 0


def test_cache_invalidate_all_still_physically_clears():
    """Explicit invalidate_all() keeps its physical-clear contract."""
    cache = _load_cache()
    c = cache.ToolResultCache(max_entries=32, ttl_seconds=300)
    c.put("data", {"action": "functions"}, {"ok": True})
    c.put("calc", {"action": "eval", "expr": "1+1"}, {"ok": True})
    c.invalidate_all()
    assert c.stats()["entries"] == 0
    assert c.stats()["write_generation"] == 1


# ---------------------------------------------------------------------------
# D9 — cheap host-only rate-limit exemption
# ---------------------------------------------------------------------------


def test_rate_limit_exempt_cheap_host_only():
    assert is_rate_limit_exempt("session", "status") is True
    assert is_rate_limit_exempt("session", "list") is True
    assert is_rate_limit_exempt("session", "create") is False
    assert is_rate_limit_exempt("session", "close") is False
    assert is_rate_limit_exempt("background", "status") is True
    assert is_rate_limit_exempt("background", "list") is True
    assert is_rate_limit_exempt("background", "submit") is False
    assert is_rate_limit_exempt("blackboard", "read") is True
    assert is_rate_limit_exempt("blackboard", "search") is True
    assert is_rate_limit_exempt("blackboard", "delete") is False
    assert is_rate_limit_exempt("bookmarks", "") is True
    assert is_rate_limit_exempt("truncation", "continue") is True
    # Real RPC / write work stays hard-limited.
    assert is_rate_limit_exempt("modify", "rename") is False
    assert is_rate_limit_exempt("data", "functions") is False
    assert is_rate_limit_exempt("misc", "python") is False


# ---------------------------------------------------------------------------
# D3 — post-processing bookkeeping for server-side sliced pages
# ---------------------------------------------------------------------------


def test_postprocess_prefers_tool_total_for_server_side_pages():
    from ida_pro_mcp.host.server.postprocess import apply_post_processing

    # The tool already sliced server-side (data returned a page + pre-slice
    # total); the host re-applies PP with the forwarded offset neutralized
    # (offset=0), so `_total` must come from the tool's pre-slice count.
    payload = {
        "ok": True,
        "functions": "\n".join(f"f{i}" for i in range(5)),
        "total": 500,
        "offset": 100,
        "count": 5,
    }
    out = apply_post_processing(payload, {"offset": 0, "limit": 5})
    assert out["_post_processed"] is True
    assert out["_total"] == 500  # full pre-slice count, not len(page)
    assert out["_count"] == 5
    assert len(out["functions"]) == 5

    # Host-side slicing without a tool total keeps len(items) as the total.
    out2 = apply_post_processing({"ok": True, "items": list(range(50))}, {"head": 10})
    assert out2["_count"] == 10
    assert out2["_total"] == 50


# ---------------------------------------------------------------------------
# D1 — policy config parsed once per (mtime_ns, size) change
# ---------------------------------------------------------------------------


def test_policy_config_cached_by_mtime_size(tmp_path, monkeypatch):
    from ida_pro_mcp.host.server import server_dispatch

    # This test exercises the config-FILE read path specifically; the CI
    # workflow sets IDA_MCP_POLICY_MODE=permissive for the whole run, which
    # would shadow the file and short-circuit _policy_baseline_mode before it
    # ever stats/opens policy.json. Deleting it makes the test deterministic
    # regardless of ambient env.
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)

    server_dispatch._POLICY_CONFIG_CACHE.clear()
    policy = tmp_path / "policy.json"
    policy.write_text('{"mode": "enforce"}')
    monkeypatch.setattr(os.path, "expanduser", lambda _p: str(policy))

    real_open = builtins.open
    opens = {"n": 0}

    def counting_open(path, *a, **k):
        if str(path).endswith("policy.json"):
            # Count config READS only: the test itself writes the file via
            # Path.write_text (a 'w' open) and must not skew the read count.
            mode = str(k.get("mode") or (a[0] if a else "r"))
            if not any(ch in mode for ch in "wax+"):
                opens["n"] += 1
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", counting_open)

    server = IDAMCPServer()
    opens["n"] = 0  # ignore any config reads during server construction
    try:
        assert server._policy_baseline_mode() == "enforce"
        assert server._policy_baseline_mode() == "enforce"
        assert opens["n"] == 1  # second call served from the (mtime,size) cache

        # Changing the file changes its size -> a new key -> one re-read.
        policy.write_text('{"mode": "assist"}')
        assert server._policy_baseline_mode() == "assist"
        assert opens["n"] == 2
    finally:
        server_dispatch._POLICY_CONFIG_CACHE.clear()


# ---------------------------------------------------------------------------
# D5 — single list-shaped RPC for pure-read batches
# ---------------------------------------------------------------------------


class _FakeProc:
    # pid=None lets the server's atexit runtime-cleanup treat the fake as
    # already-gone instead of trying to signal it.
    pid = None

    def poll(self):
        return None


class _FakeSession:
    def __init__(self, sid, idb_path):
        self.session_id = sid
        self.idb_path = idb_path
        self.policy_mode = None


def _server_with_live_runtime(sessions):
    server = IDAMCPServer()
    for ses in sessions:
        server.session_runtimes[ses.session_id] = {
            "process": _FakeProc(),
            "port": 18000 + len(server.session_runtimes),
            "auth_token": "TOK_" + ses.session_id,
            "rpc_lock": threading.Lock(),
        }
    server.current_session = sessions[0]
    return server


def test_fast_path_serves_pure_read_batch_with_one_rpc(tmp_path, monkeypatch):
    # Opaque RISC-V raw blob: headerless firmware.bin loaded at a low base.
    ses = _FakeSession("SID_RISCV", str(tmp_path / "firmware.bin"))
    server = _server_with_live_runtime([ses])

    captured = {}

    def fake_send(request, port, *a, **k):
        captured["payload"] = request
        captured["port"] = port
        return [
            {
                "ok": True,
                "functions": "\n".join(f"f{i}" for i in range(3)),
                "total": 3,
                "offset": 0,
                "count": 3,
            },
            {
                "ok": True,
                "strings": "\n".join(f"s{i}" for i in range(2)),
                "total": 2,
                "offset": 0,
                "count": 2,
            },
        ]

    monkeypatch.setattr(server, "_send_rpc_with_retry", fake_send)
    monkeypatch.setattr(server, "_cache_next_page", lambda *_a, **_k: _a[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "data", "arguments": {"action": "functions"}},
                {"name": "data", "arguments": {"action": "strings"}},
            ],
        }
    )
    assert result["ok"] is True
    assert result["count"] == 2
    assert result["summary"]["errors"] == 0
    # One list-shaped RPC to the session's runtime, not two round-trips.
    assert captured["port"] == 18000
    assert isinstance(captured["payload"], list)
    assert len(captured["payload"]) == 2
    for item in captured["payload"]:
        # Each list item carries its own session token (server_script
        # process_single validates it per request).
        assert item["session_token"] == "TOK_SID_RISCV"
    assert captured["payload"][0]["tool"] == "data"
    assert captured["payload"][0]["args"]["action"] == "functions"
    # Per-item results survive the per-result tail pipeline.
    assert result["results"][0]["result"]["total"] == 3


def test_fast_path_refunds_rate_reservations_before_fallback(tmp_path, monkeypatch):
    ses = _FakeSession("SID", str(tmp_path / "blob.bin"))
    server = _server_with_live_runtime([ses])

    class _RateLimiter:
        def __init__(self):
            self.checked = []
            self.refunded = []

        def check(self, tool):
            self.checked.append(tool)
            return True, ""

        def refund(self, tool):
            self.refunded.append(tool)

    limiter = _RateLimiter()
    server.rate_limiter = limiter
    monkeypatch.setattr(
        server,
        "_send_rpc_with_retry",
        lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionRefusedError("offline")),
    )

    assert server._try_batch_fast_path(
        [
            {"name": "data", "arguments": {"action": "functions"}},
            {"name": "data", "arguments": {"action": "strings"}},
        ],
        False,
    ) is None
    assert limiter.checked == ["data", "data"]
    assert limiter.refunded == ["data", "data"]


def test_fast_path_falls_back_for_write_calls(tmp_path, monkeypatch):
    ses = _FakeSession("SID", str(tmp_path / "blob.bin"))
    server = _server_with_live_runtime([ses])
    sent = []
    monkeypatch.setattr(
        server,
        "_send_rpc_with_retry",
        lambda *a, **k: (sent.append(a[0]), {"ok": True})[1],
    )
    calls = []
    monkeypatch.setattr(
        server,
        "_execute_tool",
        lambda tool, args: calls.append((tool, args)) or {"ok": True, "tool": tool},
    )
    monkeypatch.setattr(server, "_cache_next_page", lambda *_a, **_k: _a[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "data", "arguments": {"action": "functions"}},
                {"name": "modify", "arguments": {"action": "rename", "addr": "0x1000", "value": "x"}},
            ],
        }
    )
    # modify/rename is a WRITE (policy risk write_idb) -> fast path declines ->
    # both calls go through the per-call loop (_execute_tool), no list RPC.
    assert sent == []
    assert [t for t, _ in calls] == ["data", "modify"]
    assert result["count"] == 2
    assert result["summary"]["errors"] == 0


def test_fast_path_falls_back_without_live_runtime(monkeypatch):
    server = IDAMCPServer()  # current_session is None -> no runtime
    monkeypatch.setattr(
        server, "_execute_tool", lambda tool, args: {"ok": True, "tool": tool}
    )
    monkeypatch.setattr(server, "_cache_next_page", lambda *_a, **_k: _a[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "data", "arguments": {"action": "functions"}},
                {"name": "data", "arguments": {"action": "strings"}},
            ],
        }
    )
    assert result["ok"] is True
    assert result["count"] == 2


def test_fast_path_falls_back_for_mixed_sessions(tmp_path, monkeypatch):
    sa = _FakeSession("SID_A", str(tmp_path / "a.bin"))
    sb = _FakeSession("SID_B", str(tmp_path / "b.bin"))
    server = _server_with_live_runtime([sa, sb])
    sent = []
    monkeypatch.setattr(
        server,
        "_send_rpc_with_retry",
        lambda *a, **k: (sent.append(a[0]), {"ok": True})[1],
    )
    calls = []
    monkeypatch.setattr(
        server,
        "_execute_tool",
        lambda tool, args: calls.append((tool, args)) or {"ok": True, "tool": tool},
    )
    monkeypatch.setattr(server, "_cache_next_page", lambda *_a, **_k: _a[2])
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    result = server._handle_batch(
        {
            "calls": [
                {"name": "data", "arguments": {"action": "functions"}},
                {"name": "data", "arguments": {"action": "strings", "idb": "SID_B"}},
            ],
        }
    )
    # A single RPC cannot span two runtimes -> fall back to the per-call loop.
    assert sent == []
    assert len(calls) == 2
    assert result["count"] == 2


# ---------------------------------------------------------------------------
# D3 — pure PP page-slice forwarded to natively-paging tools
# ---------------------------------------------------------------------------


def test_d3_slice_forwarded_when_limit_aliases_to_native_count(monkeypatch):
    """data(action=functions, offset=100, limit=50) must forward offset+count
    to the tool (returning [100,150)) instead of double-skipping host-side.

    arg normalization aliases the caller's PP `limit` to the native `count`
    (the data/funcs schema uses `count`) before PP extraction, so the page
    size lands in args while pp keeps only `offset`. The forwarding block
    must treat that native count as the page size or the tool returns items
    [0,50) and the host re-applies offset=100 -> an empty page.
    """
    ses = _FakeSession("SID", "/tmp/fw.bin")
    server = _server_with_live_runtime([ses])
    captured = {}

    def fake_call_tool(tool, ip, **kwargs):
        captured["args"] = dict(kwargs)
        off = int(kwargs.get("offset", 0) or 0)
        cnt = int(kwargs.get("count", 0) or 0)
        if cnt <= 0:  # real data tool default: whole list
            funcs = [f"f{i}" for i in range(500)]
            return {"ok": True, "functions": "\n".join(funcs), "total": 500, "offset": 0, "count": 500}
        funcs = [f"f{i}" for i in range(off, off + cnt)]
        return {"ok": True, "functions": "\n".join(funcs), "total": 500, "offset": off, "count": cnt}

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    res = server._execute_tool(
        "data", {"action": "functions", "offset": 100, "limit": 50, "idb": "SID"}
    )
    # Tool-side forward happened: offset+count both reach the tool.
    assert captured["args"].get("offset") == 100
    assert captured["args"].get("count") == 50
    # Page is [100,150), not an empty double-skip.
    assert res["_post_processed"] is True
    assert res["_count"] == 50
    assert res["_total"] == 500
    assert res["functions"][0] == "f100"
    assert res["next_token"]

    # Continuation replays WITHOUT the forwarded cursor (full refetch +
    # host-side slice) so the tool's own cursor never double-advances.
    captured.clear()
    nxt = server._execute_tool(
        "data", {"action": "functions", "next_token": res["next_token"], "idb": "SID"}
    )
    assert captured["args"].get("offset") is None
    assert captured["args"].get("count") is None
    assert nxt["_count"] == 50
    assert nxt["functions"][0] == "f150"


def test_d3_slice_not_forwarded_when_grep_needs_full_list(monkeypatch):
    """A slice combined with grep must NOT be forwarded: grep has to see every
    item, so the tool keeps returning the full list and the host filters."""
    ses = _FakeSession("SID", "/tmp/fw.bin")
    server = _server_with_live_runtime([ses])
    captured = {}

    def fake_call_tool(tool, ip, **kwargs):
        captured["args"] = dict(kwargs)
        funcs = [f"f{i}" for i in range(500)]
        return {"ok": True, "functions": "\n".join(funcs), "total": 500}

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    res = server._execute_tool(
        "data",
        {"action": "functions", "offset": 100, "limit": 50, "grep": "f9", "idb": "SID"},
    )
    # The forwarding block must NOT inject a tool-side offset when grep is
    # present (grep needs the full list host-side). Note `count` still rides
    # through as the aliased native param — that is the tool's own native
    # pagination, independent of D3 forwarding.
    assert captured["args"].get("offset") is None
    assert res["_post_processed"] is True
    assert res["_count"] is not None


def test_code_disasm_limit_reaches_ida_not_stolen_by_pp(monkeypatch):
    """ida_disassemble(limit=N) is a native instruction cap, not host PP."""
    ses = _FakeSession("SID", "/tmp/fw.bin")
    server = _server_with_live_runtime([ses])
    captured = {}

    def fake_call_tool(tool, ip, **kwargs):
        captured["args"] = dict(kwargs)
        n = int(kwargs.get("limit") or kwargs.get("max_items") or 11)
        return {
            "ok": True,
            "addr": "0x401000",
            "name": "main",
            "disasm": "\n".join(f"0x{0x401000 + i:x}  nop" for i in range(n)),
            "count": n,
        }

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    monkeypatch.setattr(server, "_record_activity", lambda *_a, **_k: None)

    res = server._execute_tool(
        "code",
        {"action": "disasm", "addrs": "0x401000", "limit": 4, "idb": "SID"},
    )
    assert captured["args"].get("limit") == 4
    assert captured["args"].get("max_items") == 4
    assert res.get("count") == 4


# ---------------------------------------------------------------------------
# D10 — batch_manager persistence debounce + cached persist path
# ---------------------------------------------------------------------------


def test_batch_manager_persist_debounces_and_caches_path(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path))
    writes = {"n": 0}
    mkdirs = {"n": 0}
    real_replace = os.replace
    real_makedirs = os.makedirs

    def counting_replace(src, dst):
        if str(dst).endswith(".json"):
            writes["n"] += 1
        return real_replace(src, dst)

    def counting_makedirs(*a, **k):
        mkdirs["n"] += 1
        return real_makedirs(*a, **k)

    monkeypatch.setattr(os, "replace", counting_replace)
    monkeypatch.setattr(os, "makedirs", counting_makedirs)

    # Deterministic clock so the debounce window is never crossed by CI jitter.
    clock = {"now": 1000.0}
    monkeypatch.setattr(bm_mod.time, "time", lambda: clock["now"])

    mgr = BatchManager(max_workers=2)
    # makedirs runs exactly once (in __init__ -> _load_persisted -> _persist_path).
    assert mkdirs["n"] == 1
    try:
        t1 = mgr.submit("tool_call", {"x": 1}, run_fn=lambda task: {"ok": True})
        mgr.wait(t1, timeout=5)
        # First terminal task writes immediately (no prior write in this window).
        assert writes["n"] == 1

        clock["now"] += 0.2  # second completion lands inside the 1s window
        t2 = mgr.submit("tool_call", {"x": 2}, run_fn=lambda task: {"ok": True})
        mgr.wait(t2, timeout=5)
        # Second completion is coalesced (dirty flag only) — no extra disk write.
        assert writes["n"] == 1
        # The cached persist path means no further os.makedirs on the hot path.
        assert mkdirs["n"] == 1

        # Shutdown flushes the still-dirty state and both tasks are persisted.
        mgr.shutdown()
        assert writes["n"] == 2
        data = json.loads(Path(mgr._persist_path()).read_text())
        assert len(data) == 2
    finally:
        mgr.shutdown()
