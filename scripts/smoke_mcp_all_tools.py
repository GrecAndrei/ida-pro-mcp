#!/usr/bin/env python3
"""
Smoke-test EVERY ida-pro-mcp tool against real IDA Pro, over the real MCP
JSON-RPC stdio protocol (not a shim).

Spawns a fresh host server (`python -m ida_pro_mcp.host.server`), does the
MCP initialize handshake, creates a real IDA session from a real binary, then
calls one curated read-only/light action per tool and classifies the result:

  OK       -> {ok: true}                      (plumbing works, real data)
  CLEAN    -> {error: true, code != UNKNOWN}  (plumbing works, structured err)
  CRASH    -> {error: true, code == UNKNOWN_ERROR} (the bug class we hunt)
  TIMEOUT  -> no response within the per-call budget
  OTHER    -> unexpected payload shape

A CLEAN error (INVALID_ARGS / SESSION_REQUIRED / GOVERNANCE_BLOCKED / NOT_FOUND)
counts as PASS for plumbing: the call reached the tool and came back as a
structured error, not a crash/traceback. Only CRASH/TIMEOUT are failures.

Usage:
  python scripts/smoke_mcp_all_tools.py
  python scripts/smoke_mcp_all_tools.py --binary /path/to/foo.exe
  python scripts/smoke_mcp_all_tools.py --timeout 150
"""
from __future__ import annotations

import contextlib
import json
import os
import select
import subprocess
import sys
import time
from typing import Any

VENV_PY = "/home/alex/.local/share/ida-pro-mcp/.venv/bin/python"
HOST_MODULE = "ida_pro_mcp.host.server"
DEFAULT_BINARY = "/home/alex/ida-pro-mcp/tests/data/test_binary.exe"
DEFAULT_TIMEOUT = 120

# Replicate the env Claude Code uses to launch the host, plus test-friendly
# disables. IDA_MCP_RESPONSE_ENRICH intentionally unset (default off) so
# responses stay lean (and consistent with the enrichment-gating fix).
BASE_ENV = {
    "IDADIR": "/home/alex/ida-pro-9.3",
    "IDA_MCP_EMBED_MODEL": "/home/alex/Downloads/bge-code-v1-q8_0.gguf",
    "IDA_MCP_EMBED_SERVER_BIN": "/home/alex/.local/share/ida-pro-mcp/bin/llama-server",
    "IDA_MCP_DISABLE_STUCK_DETECTION": "1",
    "IDA_MCP_DISABLE_RATE_LIMIT": "1",
    "IDA_MCP_RESPONSE_MODE": "compact",
    "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS": "1",
    "IDA_MCP_TOOLS_LIST_MODE": "full",
    "IDA_MCP_COMPACT_MAX_ITEMS": "12",
    "IDA_MCP_COMPACT_MAX_STRING": "200",
    "IDA_MCP_COMPACT_CHAR_BUDGET": "8000",
}

# Placeholders substituted at runtime:
#   __ADDR__  first function start_ea   __ADDR2__ second   __IDB__ session idb path
# Curated to be read-only / light / fast. _risk_ack=true bypasses the policy
# REQUIRE_ACK gate (server_dispatch.py:952) so we exercise the real in-IDA path,
# not the ack-reject path. Chosen actions are non-destructive, so acking is safe.
CURATED: dict[str, tuple[str, dict]] = {
    "abi":            ("detect",        {"addr": "__ADDR__"}),
    "agent":          ("search_all",    {"query": "zzzznomatchxyz", "max_items": 1}),
    "analysis":       ("get_options",   {}),
    "annotation":     ("summary",       {}),
    "batch":          ("__none__",      {"calls": []}),
    "binary_info":    ("headers",       {}),
    "blackboard":     ("stats",         {}),
    "bookmarks":      ("list",          {}),
    "bridge_search":  ("search",        {"query": "main", "top_k": 3}),
    "bulk":           ("export_annotations", {}),
    "calc":           ("eval",          {"expr": "0x140001000 + 0x10"}),
    "classify":       ("binary",        {}),
    "code":           ("decompile",     {"addr": "__ADDR__"}),
    "compare":        ("find_clones",   {"idb": "__IDB__"}),
    "coverage":       ("report",        {}),
    "crypto_id":      ("identify",      {}),
    "ctree":          ("get",           {"addr": "__ADDR__"}),
    "data":           ("functions",     {"count": 2, "include_prototype": False}),
    "data_ops":       ("make_string",   {"addr": "__ADDR__", "size": 1}),
    "debug":          ("status",        {}),
    "deobfuscate":    ("detect",        {}),
    "entropy":        ("summary",       {}),
    "export":         ("listing",       {"limit": 5}),
    "filter":         ("filter",        {"data": {"functions": ["a", "b"]}, "query": "."}),
    "firmware_view":  ("triage_snapshot", {}),
    "funcs":          ("info",          {"addr": "__ADDR__"}),
    "gadgets":        ("mitigations",   {}),
    "governance":     ("list_rules",    {}),
    "graph":          ("hub_functions", {}),
    "history":        ("list",          {}),
    "hooks":          ("suggest",       {"addr": "__ADDR__"}),
    "idb":            ("summary",       {}),
    "imports_deep":   ("thunks",        {}),
    "intelligence":   ("intelligence_status", {}),
    "knowledge":      ("chip_families", {}),
    "llm_helpers":    ("bootstrap",     {}),
    "lumina":         ("status",        {}),
    "memory":         ("read",          {"addr": "__ADDR__", "size": 16}),
    "microcode":      ("get",           {"addr": "__ADDR__"}),
    "misc":           ("plugin_list",  {}),
    "modify":         ("comment",       {"addr": "__ADDR__", "comment": "smoke"}),
    "nav":            ("interesting",   {}),
    "packer":         ("detect",        {}),
    "patterns":       ("list_sigs",     {}),
    "predictor":      ("suggest_next_tool", {}),
    "project":        ("list_recent",   {}),
    "protocol":       ("detect",        {}),
    "query":          ("data",          {"count": 2}),
    "search":         ("find",          {"query": "main", "limit": 3}),
    "segments":       ("list",          {}),
    "session":        ("list",          {}),
    "stack_analysis": ("summary",       {"addr": "__ADDR__"}),
    "string_ops":     ("find_urls",     {}),
    "summarize":      ("binary",        {}),
    "symbols":        ("status",        {}),
    "taint":          ("sources",       {}),
    "threat_hunt":    ("findings",       {}),
    "trace_analysis": ("get",           {}),
    "truncation":     ("continue",      {"token": "deadbeef"}),
    "types":          ("list",          {}),
    "wiki":           ("list_topics",   {}),
    "workflow":       ("catalog",       {}),
    "yara_hunt":      ("list_rules",    {}),
}

# Tools whose only meaningful actions are lifecycle/meta and would corrupt the
# run if actually executed (close/delete/kill/restore/patch). We still call them
# but with a deliberately-benign action so they return a clean error, never run.
META_FORCE_CLEAN: dict[str, tuple[str, dict]] = {
    # session: "list" is in CURATED already (read-only).
    "history": ("list", {}),  # already read; keep
}

SKIP_TOOLS: set[str] = set()  # nothing skipped by default


class MCPClient:
    def __init__(self, timeout: float):
        self.proc: subprocess.Popen | None = None
        self._id = 0
        self.timeout = timeout

    def start(self) -> None:
        env = dict(os.environ)
        env.update(BASE_ENV)
        self.proc = subprocess.Popen(
            [VENV_PY, "-u", "-m", HOST_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd="/home/alex/ida-pro-mcp",
            bufsize=0,
        )
        self._id = 0

    def stop(self) -> None:
        if self.proc:
            with contextlib.suppress(Exception):
                self.proc.stdin.close()
            with contextlib.suppress(Exception):
                self.proc.stdout.close()
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                with contextlib.suppress(Exception):
                    self.proc.kill()
            self.proc = None

    def _readline_timeout(self, timeout: float) -> bytes | None:
        assert self.proc is not None and self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            try:
                r, _, _ = select.select([fd], [], [], remaining)
            except (OSError, ValueError):
                return None
            if not r:
                return None  # timeout
            chunk = self.proc.stdout.readline()
            if not chunk:
                return b""  # EOF
            return chunk

    def call(self, method: str, params: dict | None = None) -> dict | None:
        """Send one JSON-RPC request, return the matching response (id-matched,
        skipping interleaved notifications / late/mismatched lines)."""
        assert self.proc is not None and self.proc.stdin is not None
        self._id += 1
        rid = self._id
        req: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            req["params"] = params
        line = json.dumps(req, separators=(",", ":")) + "\n"
        try:
            self.proc.stdin.write(line.encode("utf-8"))
            self.proc.stdin.flush()
        except Exception:
            return {"_rpc_error": {"message": "stdin write failed"}}
        # Read lines until we find our id. Skip notifications (no id) and any
        # late response from a previously-timed-out call (mismatched id).
        while True:
            raw = self._readline_timeout(self.timeout)
            if raw is None:
                return {"_timeout": True}
            if raw == b"":
                return {"_eof": True}
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                continue  # non-JSON banner/log line
            if not isinstance(obj, dict):
                continue
            if obj.get("id") == rid:
                return obj
            # mismatched id (late response or notification) -> ignore, keep reading

    def initialize(self) -> bool:
        r = self.call("initialize", {"capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}})
        return bool(r and "result" in r)

    def tools_list(self) -> list[dict]:
        r = self.call("tools/list", {})
        if not r or "result" not in r:
            return []
        return r["result"].get("tools", []) or []

    def tool_call(self, name: str, args: dict) -> tuple[dict | None, str]:
        r = self.call("tools/call", {"name": name, "arguments": args})
        if not r:
            return None, "no response"
        if "_timeout" in r:
            return None, "timeout"
        if "_eof" in r:
            return None, "eof"
        if "_rpc_error" in r:
            return {"_rpc_error": r["_rpc_error"]}, "rpc_error"
        if "error" in r:
            return {"_rpc_error": r["error"]}, "rpc_error"
        res = r.get("result", {})
        content = res.get("content") or []
        text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
        try:
            payload = json.loads(text) if text else {}
        except Exception:
            payload = {"_raw": text[:500]}
        return payload, ""


def first_addr_from_functions(payload: dict, n: int = 2) -> list[str]:
    addrs: list[str] = []
    val = payload.get("functions")
    if isinstance(val, str):
        for ln in val.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            tok = ln.split()[0]
            if tok.lower().startswith("0x"):
                addrs.append(tok)
                if len(addrs) >= n:
                    break
    return addrs


def classify(payload: dict | None, err: str) -> tuple[str, str]:
    if err == "timeout":
        return "TIMEOUT", "(no response in budget)"
    if err == "eof":
        return "CRASH", "(host stdout EOF / process died)"
    if err == "rpc_error":
        return "CRASH", f"rpc: {json.dumps(payload.get('_rpc_error'))[:160]}"
    if err == "no response":
        return "TIMEOUT", "(no response)"
    if payload is None:
        return "OTHER", "None payload"
    if "_raw" in payload:
        return "OTHER", f"non-JSON: {str(payload['_raw'])[:120]}"
    if payload.get("ok") is True:
        return "OK", ""
    # A bool `ok` (True or False) without an `error: True` envelope is a
    # success-shape reporting state (e.g. blackboard.policy_check returns
    # ok=False + reasons when the policy state is stale). The tool worked;
    # this is not a crash or a plumbing error.
    if isinstance(payload.get("ok"), bool) and payload.get("error") is not True:
        return "OK", f"ok={payload['ok']} keys={list(payload.keys())[:5]}"
    if payload.get("error") is True:
        code = str(payload.get("code") or payload.get("name") or "?")
        msg = str(payload.get("message") or payload.get("hint") or "")
        if code in ("UNKNOWN_ERROR", "UNKNOWN", "INTERNAL"):
            # try to surface a traceback if the host attached one
            det = payload.get("details") or {}
            tb = ""
            if isinstance(det, dict):
                tb = str(det.get("traceback") or "")
            note = msg[:120]
            if tb:
                # last meaningful line of the traceback
                last = [l for l in tb.splitlines() if l.strip()][-1:]
                note = (last[0][:120] if last else note)
            return "CRASH", f"{code}: {note}"
        return "CLEAN", f"{code}: {msg[:100]}"
    return "OTHER", f"keys={list(payload.keys())[:6]}"


def substitute(args: dict, addr: str, addr2: str, idb: str) -> dict:
    out = {}
    for k, v in args.items():
        if isinstance(v, str):
            v = v.replace("__ADDR__", addr).replace("__ADDR2__", addr2).replace("__IDB__", idb)
        out[k] = v
    out["_risk_ack"] = True
    return out


def fallback_args(schema: dict, addr: str) -> dict:
    """Schema-driven minimal args for tools not in CURATED."""
    props = (schema or {}).get("properties", {}) or {}
    args: dict[str, Any] = {}
    action_prop = props.get("action", {})
    enum = action_prop.get("enum") if isinstance(action_prop, dict) else None
    if enum:
        safe = ["status", "list", "summary", "stats", "meta", "overview",
                "info", "report", "detect", "health", "list_topics", "frontier",
                "find", "search", "catalog", "binary", "functions"]
        chosen = next((a for a in safe if a in enum), enum[0])
        args["action"] = chosen
    for name, prop in props.items():
        if name in ("action", "_risk_ack"):
            continue
        typ = prop.get("type") if isinstance(prop, dict) else None
        if name in ("addr", "addrs", "ea", "start", "start_ea", "target", "addr1"):
            args[name] = addr
        elif name in ("query", "q", "text", "expr", "pattern", "uri", "name"):
            args[name] = "main"
        elif name in ("count", "limit", "max_items", "top_k", "n"):
            args[name] = 3
        elif name in ("size", "length"):
            args[name] = 16
        elif name in ("offset", "start_i"):
            args[name] = 0
        elif typ == "boolean":
            args[name] = False
        elif typ == "integer":
            args[name] = 1
        elif typ == "array":
            args[name] = []
        elif typ == "object":
            args[name] = {}
    args["_risk_ack"] = True
    return args


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--only", help="comma-separated tool names to run")
    args_cli = ap.parse_args()

    if not os.path.isfile(VENV_PY):
        print(f"FATAL: venv python not found: {VENV_PY}", file=sys.stderr)
        return 2
    if not os.path.isfile(args_cli.binary):
        print(f"FATAL: binary not found: {args_cli.binary}", file=sys.stderr)
        return 2
    if not os.path.isfile(os.path.join(BASE_ENV["IDADIR"], "idat")):
        print(f"FATAL: idat not found in IDADIR={BASE_ENV['IDADIR']}", file=sys.stderr)
        return 2

    only = set(args_cli.only.split(",")) if args_cli.only else None
    cli = MCPClient(timeout=args_cli.timeout)
    rows: list[tuple[str, str, str, str]] = []
    counts = {"OK": 0, "CLEAN": 0, "CRASH": 0, "TIMEOUT": 0, "OTHER": 0}

    def restart() -> bool:
        cli.stop()
        cli.start()
        if not cli.initialize():
            return False
        # create session
        payload, err = cli.tool_call("session", {
            "action": "create",
            "binary_path": args_cli.binary,
            "processor": "metapc", "bitness": 64, "endian": "little",
            "_risk_ack": True,
        })
        return not (err or not payload or payload.get("ok") is not True)

    try:
        cli.start()
        if not cli.initialize():
            print("FATAL: initialize handshake failed", file=sys.stderr)
            return 3

        # session + addrs
        if not restart():
            print("FATAL: could not create session / spawn IDA", file=sys.stderr)
            return 4
        sess = cli.call("tools/call", {"name": "session", "arguments": {"action": "status", "_risk_ack": True}})
        sid = ""
        if sess and "result" in sess:
            try:
                p = json.loads(sess["result"]["content"][0]["text"])
                sid = p.get("session_id") or (p.get("session") or {}).get("session_id", "")
            except Exception:
                pass
        # idb path for compare
        idb_path = ""
        sp = cli.call("tools/call", {"name": "idb", "arguments": {"action": "meta", "_risk_ack": True}})
        if sp and "result" in sp:
            try:
                p = json.loads(sp["result"]["content"][0]["text"])
                idb_path = p.get("idb_path") or p.get("path") or ""
            except Exception:
                pass

        # fetch two addrs
        ap2, _ = cli.tool_call("data", {"action": "functions", "count": 2, "include_prototype": False, "_risk_ack": True})
        addrs = first_addr_from_functions(ap2 or {}, 2) if ap2 else []
        if len(addrs) < 2:
            # fallback: entrypoints
            ep, _ = cli.tool_call("idb", {"action": "entrypoints", "_risk_ack": True})
            eps = []
            if isinstance(ep, dict):
                eps = ep.get("entrypoints") or []
            for e in eps[:2]:
                if isinstance(e, dict):
                    a = e.get("ea") or e.get("address")
                    if a:
                        addrs.append(a if str(a).startswith("0x") else hex(int(a, 16)) if isinstance(a, str) else hex(a))
        addr = addrs[0] if addrs else "0x140001000"
        addr2 = addrs[1] if len(addrs) > 1 else addr
        print("=== ida-pro-mcp smoke test ===")
        print(f"binary : {args_cli.binary}")
        print(f"session: {sid or '(unknown)'}  addr: {addr} / {addr2}  idb: {idb_path or '-'}")
        print()

        tools = cli.tools_list()
        if not tools:
            print("FATAL: tools/list returned no tools", file=sys.stderr)
            return 5
        names = [t.get("name", "") for t in tools]
        print(f"tools/list: {len(names)} tools")
        print()
        print(f"{'STATUS':7} {'TOOL':18} {'ACTION':18} RESULT")
        print(f"{'-'*7} {'-'*18} {'-'*18} {'-'*50}")

        for t in tools:
            name = t.get("name", "")
            if not name or name in SKIP_TOOLS:
                continue
            if only and name not in only:
                continue
            schema = t.get("inputSchema") or {}

            if name in CURATED:
                action, kw = CURATED[name]
                call_args = substitute(kw, addr, addr2, idb_path)
                if action != "__none__":
                    call_args["action"] = action
                action_lbl = action if action != "__none__" else "(none)"
            else:
                call_args = fallback_args(schema, addr)
                action_lbl = str(call_args.get("action", "-"))

            payload, err = cli.tool_call(name, call_args)
            status, note = classify(payload, err)
            counts[status] = counts.get(status, 0) + 1
            rows.append((status, name, action_lbl, note))
            tag = status
            print(f"{tag:7} {name:18} {action_lbl:18} {note}")
            sys.stdout.flush()

            # recover from a wedged host (timeout / EOF)
            if status in ("TIMEOUT", "CRASH") and err in ("timeout", "eof"):
                ok = restart()
                if not ok:
                    print("  (host restart failed; aborting remaining tools)", file=sys.stderr)
                    break

    finally:
        cli.stop()

    print()
    print("=== SUMMARY ===")
    total = sum(counts.values())
    for k in ("OK", "CLEAN", "CRASH", "TIMEOUT", "OTHER"):
        print(f"  {k:7}: {counts.get(k,0):3}")
    print(f"  {'TOTAL':7}: {total:3}")
    failures = [r for r in rows if r[0] in ("CRASH", "TIMEOUT", "OTHER")]
    if failures:
        print()
        print("=== ATTENTION (CRASH / TIMEOUT / OTHER) ===")
        for st, nm, ac, nt in failures:
            print(f"  {st:7} {nm}.{ac}  -> {nt}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
