#!/usr/bin/env python3
"""
AIC8800D80 firmware RE eval harness.

Runs DeepSeek V4 Pro, DeepSeek V4 Flash, and Qwen3.6 Plus in parallel
against the ida-pro-mcp server on a real firmware binary.
Each model gets its own isolated MCP/IDA session and a fixed tool budget.

Usage:
    python eval_harness.py --binary /path/to/firmware.bin [--max-turns 30]

API key: read from OPENCODE_API_KEY env var, or ~/.claude/.secretkey.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import textwrap
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openai import OpenAI


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ENDPOINT = "https://opencode.ai/zen/go/v1/chat/completions"
BASE_URL  = "https://opencode.ai/zen/go/v1"

MODELS = [
    {
        "id":          "deepseek-v4-pro",
        "label":       "DeepSeek V4 Pro",
        "extra":       {"reasoning_effort": "high"},
        "tool_budget": 60,
        "max_turns":   35,
    },
    {
        "id":          "deepseek-v4-flash",
        "label":       "DeepSeek V4 Flash",
        "extra":       {"reasoning_effort": "max"},
        "tool_budget": 40,
        "max_turns":   30,
    },
    {
        "id":          "qwen3.6-plus",
        "label":       "Qwen3.6 Plus",
        "extra":       {"extra_body": {"enable_thinking": True, "thinking_budget": 8192}},
        "tool_budget": 40,
        "max_turns":   30,
    },
]

MAX_TURNS       = 30    # default cap (overridden per model above)
TOOL_BUDGET     = 40    # default cap (overridden per model above)
CONTEXT_WARN_K  = 80_000  # warn when prompt tokens approach this
CONTEXT_TRIM_K  = 120_000 # aggressively summarise older turns above this

MCP_CMD = [
    sys.executable, "-u",
    str(Path(__file__).parent.parent.parent / "ida_mcp_stdio.py"),
]
MCP_ENV_BASE = {
    **os.environ,
    "IDADIR": os.environ.get("IDADIR", "/home/grec-alexander/ida-pro-9.2"),
    "IDA_MCP_RESPONSE_MODE":    "compact",
    "IDA_MCP_QOL_MODE":         "balanced",
    "IDA_MCP_BATCH_COMPACT":    "1",
    "IDA_MCP_COMPACT_MAX_ITEMS": "48",
    "IDA_MCP_COMPACT_MAX_STRING": "1400",
    "IDA_MCP_COMPACT_CHAR_BUDGET": "30000",
    "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS": "1",
}

def _make_mcp_env(label: str) -> dict:
    """Each model gets its own isolated cache dir so IDB files never collide."""
    slug = label.lower().replace(" ", "_").replace("/", "_")
    cache_dir = str(Path(__file__).parent / "results" / f"cache_{slug}_{int(time.time())}")
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    return {**MCP_ENV_BASE, "IDA_MCP_CACHE_DIR": cache_dir}

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert reverse engineer using IDA Pro via the ida-pro-mcp tool suite.
    You have been given a raw firmware binary for an AIC8800D80 WiFi chip.
    Your job is to perform a thorough analysis using ALL relevant MCP tools available to you.

    MANDATORY SEQUENCE to start every session:
    1. session(action="create", binary_path="<path>")  — always first
    2. idb(action="overview")                          — get architecture + firmware context
    3. Follow the _next_calls and _nudge hints in every response

    ANALYSIS BREADTH — you are expected to use tools from ALL of these categories:
    - Session management: session, idb
    - Firmware triage: firmware_view (triage_snapshot, detect_load_address, detect_vector_table, detect_mmio)
    - Workflow: workflow (triage_fast)
    - Code analysis: funcs, code, patterns
    - Data structures: data, types
    - Cross-references: graph, search
    - Annotations: annotation, bookmarks
    - Blackboard: blackboard (for tracking hypotheses)
    - Symbols and imports: symbols, data(action="imports"), data(action="strings")
    - Binary info: binary_info

    Do NOT stop after a single triage. Dig deep — decompile interesting functions,
    find strings, trace MMIO accesses, identify the RTOS, map out the call graph.
    Work systematically. When a tool response includes _next_calls or recommendations,
    follow them.

    When you have exhausted your analysis or hit the tool budget, produce a
    comprehensive FINAL REPORT covering:
    - Architecture and load address
    - Identified firmware components (RTOS, WiFi stack layers, BT if present)
    - Entry points and key functions found
    - MMIO peripheral map
    - Interesting strings, version info, build metadata
    - Hypotheses about firmware purpose and structure
    - Suggested next steps for deeper RE
""")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class Score:
    label: str
    pts: int = 0
    events: list[str] = field(default_factory=list)
    penalties: int = 0

    # checkpoints (each awarded at most once)
    _awarded: set[str] = field(default_factory=set)

    RUBRIC = {
        "session_create_first":     (5,  "Called session(create) as first tool call"),
        "arch_correct":             (10, "Correctly identified ARM/32/LE architecture"),
        "triage_snapshot":          (8,  "Called firmware_view(triage_snapshot)"),
        "detect_vector_table":      (5,  "Called firmware_view(detect_vector_table)"),
        "detect_mmio":              (5,  "Called firmware_view(detect_mmio)"),
        "detect_load_address":      (4,  "Called firmware_view(detect_load_address)"),
        "used_funcs":               (4,  "Called funcs tool"),
        "used_code_decompile":      (5,  "Decompiled at least one function"),
        "used_data_strings":        (4,  "Called data(action=strings)"),
        "used_data_imports":        (3,  "Called data(action=imports)"),
        "used_graph":               (5,  "Called xref/graph tool"),
        "used_xref_analysis":       (3,  "Called xref analysis tool"),
        "used_search":              (3,  "Called search tool"),
        "used_patterns":            (3,  "Called patterns tool"),
        "used_blackboard":          (3,  "Used blackboard to track findings"),
        "used_workflow":            (3,  "Called workflow tool"),
        "used_binary_info":         (2,  "Called binary_info tool"),
        "followed_next_calls":      (5,  "Followed _next_calls hint at least 3 times"),
        "final_report":             (8,  "Produced a coherent final report"),
        "identified_rtos":          (5,  "Identified or hypothesized the RTOS"),
        "identified_version":       (4,  "Found version/build string"),
        "found_rivierawaves_stack": (10, "Found RivieraWaves/LMAC/KE stack artifacts"),
        "wrote_annotation":         (5,  "Wrote annotation or comment"),
    }

    def award(self, key: str, note: str = ""):
        if key in self._awarded:
            return
        if key not in self.RUBRIC:
            return
        pts, desc = self.RUBRIC[key]
        self._awarded.add(key)
        self.pts += pts
        self.events.append(f"+{pts:2d}  {desc}" + (f" [{note}]" if note else ""))

    def penalize(self, reason: str, pts: int = 3):
        self.penalties += pts
        self.events.append(f"-{pts:2d}  PENALTY: {reason}")

    @property
    def total(self) -> int:
        return max(0, self.pts - self.penalties)

    @property
    def max_pts(self) -> int:
        return sum(v for v, _ in self.RUBRIC.values())


# ---------------------------------------------------------------------------
# MCP client (newline-delimited JSON, matching existing mcp_real_client.py)
# ---------------------------------------------------------------------------

class MCPClient:
    def __init__(self, cmd: list[str], env: dict):
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, env=env,
        )
        self._id = 0
        self._lock = threading.Lock()

    def _send_recv(self, method: str, params: dict | None = None) -> dict:
        with self._lock:
            self._id += 1
            req = {"jsonrpc": "2.0", "id": self._id, "method": method}
            if params:
                req["params"] = params
            line_out = json.dumps(req) + "\n"
            self.proc.stdin.write(line_out)
            self.proc.stdin.flush()
            line_in = self.proc.stdout.readline()
            if not line_in:
                stderr = self.proc.stderr.read(2000) if self.proc.stderr else ""
                raise RuntimeError(f"MCP server closed (stderr: {stderr[:500]})")
            return json.loads(line_in)

    def initialize(self) -> dict:
        r = self._send_recv("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "eval-harness", "version": "1.0"},
        })
        # send initialized notification (no response expected, but write it)
        notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n"
        self.proc.stdin.write(notif)
        self.proc.stdin.flush()
        return r

    def list_tools(self) -> list[dict]:
        r = self._send_recv("tools/list", {})
        return r.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        r = self._send_recv("tools/call", {"name": name, "arguments": arguments})
        return r.get("result", r.get("error", {}))

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Context management helpers
# ---------------------------------------------------------------------------

def _estimate_tokens(messages: list[dict]) -> int:
    """Rough token estimate: 1 token ≈ 4 chars."""
    total = sum(len(json.dumps(m)) for m in messages)
    return total // 4


def _trim_context(messages: list[dict], keep_system: bool = True) -> list[dict]:
    """
    When context gets large, summarise the middle of the conversation.
    Keeps: system prompt, first 2 user/assistant turns, last 6 turns.
    Replaces the middle with a single summarise marker.
    """
    if len(messages) <= 10:
        return messages

    system = [m for m in messages if m["role"] == "system"]
    non_system = [m for m in messages if m["role"] != "system"]

    if len(non_system) <= 8:
        return messages

    head = non_system[:2]
    tail = non_system[-6:]
    skipped = len(non_system) - len(head) - len(tail)
    summary_msg = {
        "role": "assistant",
        "content": f"[{skipped} earlier turns summarised to save context. "
                   "Key findings so far are reflected in blackboard and my analysis above.]",
    }
    return system + head + [summary_msg] + tail


# ---------------------------------------------------------------------------
# Scoring helpers (applied to live tool calls and responses)
# ---------------------------------------------------------------------------

def _score_tool_call(tool_name: str, args: dict, score: Score,
                     call_count: int, prev_calls: list[str], next_call_hints: list[str]):
    full = f"{tool_name}:{json.dumps(args or {}, sort_keys=True)}"

    if call_count == 1 and tool_name == "session" and args.get("action") == "create":
        score.award("session_create_first")

    if tool_name == "firmware_view":
        a = args.get("action", "")
        if a == "triage_snapshot":
            score.award("triage_snapshot")
        elif a == "detect_vector_table":
            score.award("detect_vector_table")
        elif a == "detect_mmio":
            score.award("detect_mmio")
        elif a == "detect_load_address":
            score.award("detect_load_address")

    if tool_name == "funcs":
        score.award("used_funcs")
    if tool_name == "code" and args.get("action") in ("decompile", "smart_decompile", "disassemble"):
        score.award("used_code_decompile")
    if tool_name == "data":
        a = args.get("action", "")
        if a == "strings":
            score.award("used_data_strings")
        if a == "imports":
            score.award("used_data_imports")
    if tool_name == "graph":
        score.award("used_graph")
        if args.get("action") == "xref_graph":
            score.award("used_xref_analysis")
    if tool_name == "xref_analysis":
        score.award("used_xref_analysis")
    if tool_name == "search":
        score.award("used_search")
    if tool_name == "patterns":
        score.award("used_patterns")
    if tool_name == "blackboard":
        score.award("used_blackboard")
    if tool_name == "workflow":
        score.award("used_workflow")
    if tool_name == "binary_info":
        score.award("used_binary_info")
    if tool_name in ("annotation", "comment_mgr"):
        score.award("wrote_annotation")
    if tool_name == "modify" and args.get("action") == "comment":
        score.award("wrote_annotation")

    # Penalty: repeated identical call
    if prev_calls.count(full) >= 2 and score.penalties < 20:
        delta = min(2, 20 - score.penalties)
        if delta > 0:
            score.penalize(f"repeated identical call: {full}", pts=delta)


def _score_tool_result(tool_name: str, args: dict, result_text: str, score: Score):
    low = result_text.lower()

    # Architecture correct?
    if tool_name in ("idb", "session", "analysis") and (
        ("arm" in low or "cortex" in low) and ("32" in low or "thumb" in low)
    ):
        score.award("arch_correct", "ARM/32 detected in response")

    # RTOS hints
    for rtos in ("freertos", "threadx", "rtx", "ucos", "rtos", "task_create", "osthread"):
        if rtos in low:
            score.award("identified_rtos", f"hint: {rtos}")
            break

    # Version / build string
    for pat in ("version", "build", "v1.", "v2.", "v3.", "sdk", "release", "fw_ver"):
        if pat in low:
            score.award("identified_version", f"hint: {pat}")
            break
    for pat in ("rivierawaves", "lmac", "ke_task", "ke_msg", "ke_evt", "rwip"):
        if pat in low:
            score.award("found_rivierawaves_stack", f"hint: {pat}")
            break


def _score_followed_hints(messages: list[dict], score: Score):
    """Count how many times a _next_calls hint was followed in the next turn."""
    followed = 0
    for i, msg in enumerate(messages):
        if msg.get("role") != "tool":
            continue
        content = msg.get("content", "")
        if "_next_calls" not in content and "next_actions" not in content:
            continue
        # look at the next assistant message's tool calls
        for j in range(i + 1, min(i + 3, len(messages))):
            nxt = messages[j]
            if nxt.get("role") == "assistant" and nxt.get("tool_calls"):
                followed += 1
                break
    if followed >= 3:
        score.award("followed_next_calls", f"{followed} times")


def _score_final_response(text: str, score: Score):
    low = text.lower()
    report_markers = ["architecture", "entry point", "mmio", "peripheral",
                      "string", "rtos", "hypothesis", "load address",
                      "vector table", "function", "summary", "findings"]
    hits = sum(1 for m in report_markers if m in low)
    if hits >= 5:
        score.award("final_report", f"{hits} report sections detected")


# ---------------------------------------------------------------------------
# Single-model agent loop
# ---------------------------------------------------------------------------

def _load_api_key() -> str:
    key = os.environ.get("OPENCODE_API_KEY", "")
    if not key:
        for p in [
            Path(__file__).parent.parent.parent / ".claude" / "secretkey.txt",
            Path.home() / ".claude" / ".secretkey.txt",
            Path.home() / ".secretkey.txt",
        ]:
            if p.exists():
                key = p.read_text().strip().split("\n")[0].strip()
                break
    if not key:
        raise RuntimeError(
            "No API key found. Set OPENCODE_API_KEY or create ~/.claude/.secretkey.txt"
        )
    return key


def run_model(model_cfg: dict, binary_path: str, max_turns: int, api_key: str) -> dict:
    label = model_cfg["label"]
    model_id = model_cfg["id"]
    extra = model_cfg.get("extra", {})
    # Per-model overrides take precedence over global defaults.
    max_turns  = model_cfg.get("max_turns",   max_turns)
    tool_budget = model_cfg.get("tool_budget", TOOL_BUDGET)

    print(f"\n{'='*60}")
    print(f"  {label}  —  starting")
    print(f"{'='*60}")

    score = Score(label=label)
    t_start = time.time()
    tool_call_count = 0
    prev_calls: list[str] = []
    next_call_hints: list[str] = []
    all_tool_results: list[str] = []

    # --- start MCP server with isolated cache dir per model ---
    mcp = MCPClient(MCP_CMD, _make_mcp_env(label))
    try:
        mcp.initialize()
        mcp_tools = mcp.list_tools()
    except Exception as e:
        print(f"  [{label}] MCP init failed: {e}")
        mcp.close()
        return {"label": label, "error": str(e), "score": score}

    print(f"  [{label}] MCP ready — {len(mcp_tools)} tools available")

    # --- build OpenAI tool definitions from MCP manifest ---
    openai_tools = []
    for t in mcp_tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", "")[:1000],
                "parameters": t.get("inputSchema", {"type": "object", "properties": {}}),
            },
        })

    # --- OpenAI client ---
    client = OpenAI(api_key=api_key, base_url=BASE_URL)

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Analyze this AIC8800D80 WiFi chip firmware binary thoroughly: {binary_path}\n\n"
                "Use as many tools as needed. Start with session(create), then idb(overview), "
                "then follow the firmware analysis workflow. Explore broadly — code, data, "
                "strings, MMIO, entry points, RTOS artifacts. Produce a comprehensive report."
            ),
        },
    ]

    turns = 0
    last_text = ""

    while turns < max_turns and tool_call_count < tool_budget:
        turns += 1

        # context management
        est_tokens = _estimate_tokens(messages)
        if est_tokens > CONTEXT_TRIM_K:
            print(f"  [{label}] trimming context (~{est_tokens//1000}k tokens)")
            messages = _trim_context(messages)

        # build call kwargs
        call_kwargs: dict[str, Any] = dict(
            model=model_id,
            messages=messages,
            tools=openai_tools,
            tool_choice="auto",
            max_tokens=4096,
        )

        # apply reasoning/thinking params
        extra_body = extra.get("extra_body", {})
        if "reasoning_effort" in extra:
            call_kwargs["reasoning_effort"] = extra["reasoning_effort"]
        if extra_body:
            call_kwargs["extra_body"] = extra_body

        try:
            resp = client.chat.completions.create(**call_kwargs)
        except Exception as e:
            print(f"  [{label}] API error turn {turns}: {e}")
            break

        msg = resp.choices[0].message
        finish = resp.choices[0].finish_reason

        # extract reasoning_content if present (DeepSeek / Qwen thinking)
        reasoning = getattr(msg, "reasoning_content", None)
        if reasoning:
            print(f"  [{label}] <think> {reasoning[:120].replace(chr(10),' ')}…")

        # assistant text
        if msg.content:
            last_text = msg.content
            print(f"  [{label}] turn {turns}: {msg.content[:200].replace(chr(10),' ')}")

        # done?
        if not msg.tool_calls:
            print(f"  [{label}] finished (finish={finish})")
            break

        # build assistant turn dict (preserve reasoning_content for multi-turn)
        asst_dict: dict[str, Any] = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ],
        }
        if reasoning:
            asst_dict["reasoning_content"] = reasoning
        messages.append(asst_dict)

        # execute each tool call
        tool_result_msgs = []
        for tc in msg.tool_calls:
            tool_call_count += 1
            tname = tc.function.name
            try:
                targs = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                targs = {}

            print(f"  [{label}]   tool[{tool_call_count}] {tname}({targs.get('action','')}) …")
            _score_tool_call(tname, targs, score, tool_call_count, prev_calls, next_call_hints)
            prev_calls.append(f"{tname}:{json.dumps(targs, sort_keys=True)}")

            try:
                result = mcp.call_tool(tname, targs)
            except Exception as e:
                result = {"ok": False, "error": str(e)}

            result_str = json.dumps(result)[:4000]  # cap per-result size
            all_tool_results.append(result_str)

            # extract next_call hints for scoring
            if isinstance(result, dict):
                hints = result.get("_next_calls") or result.get("next_actions") or []
                if isinstance(hints, list):
                    next_call_hints.extend(hints)

            _score_tool_result(tname, targs, result_str, score)

            tool_result_msgs.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str,
            })

            if tool_call_count >= tool_budget:
                print(f"  [{label}] tool budget exhausted ({tool_budget})")
                break

        messages.extend(tool_result_msgs)

    # --- final scoring pass ---
    _score_followed_hints(messages, score)
    _score_final_response(last_text + " ".join(all_tool_results), score)

    elapsed = time.time() - t_start
    usage_tokens = _estimate_tokens(messages)

    print(f"\n  [{label}] DONE — {tool_call_count} tool calls, {turns} turns, {elapsed:.0f}s")
    print(f"  [{label}] Score: {score.total}/{score.max_pts}")

    mcp.close()
    return {
        "label": label,
        "model_id": model_id,
        "score": score,
        "tool_calls": tool_call_count,
        "turns": turns,
        "elapsed_s": round(elapsed, 1),
        "approx_tokens": usage_tokens,
        "messages": messages,
    }


# ---------------------------------------------------------------------------
# Parallel runner + report
# ---------------------------------------------------------------------------

def run_all(binary_path: str, max_turns: int):
    api_key = _load_api_key()
    print(f"Binary: {binary_path}")
    print(f"Models: {', '.join(m['label'] for m in MODELS)}")
    budgets = ", ".join(f"{m['label']}: {m.get('tool_budget', TOOL_BUDGET)} tools / {m.get('max_turns', max_turns)} turns" for m in MODELS)
    print(f"Budgets: {budgets}")

    results = []
    threads = []
    lock = threading.Lock()

    def _run(cfg):
        r = run_model(cfg, binary_path, max_turns, api_key)
        with lock:
            results.append(r)

    for cfg in MODELS:
        t = threading.Thread(target=_run, args=(cfg,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    _print_report(results)
    _save_report(results, binary_path)


def _print_report(results: list[dict]):
    print("\n\n" + "="*70)
    print("  FINAL SCORECARD")
    print("="*70)

    results.sort(key=lambda r: r.get("score", Score("")).total, reverse=True)

    for r in results:
        label = r["label"]
        if "error" in r:
            print(f"\n{label}: ERROR — {r['error']}")
            continue
        s = r["score"]
        print(f"\n{'─'*50}")
        print(f"  {label}")
        print(f"  Score:       {s.total:3d} / {s.max_pts}  (raw {s.pts}, penalties -{s.penalties})")
        print(f"  Tool calls:  {r['tool_calls']}")
        print(f"  Turns:       {r['turns']}")
        print(f"  Time:        {r['elapsed_s']}s")
        print(f"  ~Tokens:     {r['approx_tokens']:,}")
        print(f"\n  Checkpoints:")
        for ev in s.events:
            print(f"    {ev}")

    print("\n" + "="*70)
    # winner
    winners = [r for r in results if "error" not in r]
    if winners:
        best = winners[0]
        print(f"  WINNER: {best['label']}  ({best['score'].total}/{best['score'].max_pts})")
    print("="*70)


def _save_report(results: list[dict], binary_path: str):
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    bin_name = Path(binary_path).stem
    out_path = out_dir / f"eval_{bin_name}_{ts}.json"

    serialisable = []
    for r in results:
        rec = {k: v for k, v in r.items() if k != "messages"}
        if "score" in rec:
            sc = rec["score"]
            rec["score"] = {
                "label": sc.label,
                "total": sc.total,
                "raw_pts": sc.pts,
                "penalties": sc.penalties,
                "max_pts": sc.max_pts,
                "events": sc.events,
                "awarded": list(sc._awarded),
            }
        serialisable.append(rec)

    out_path.write_text(json.dumps(serialisable, indent=2))
    print(f"\n  Results saved to: {out_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LLM firmware RE eval harness")
    ap.add_argument(
        "--binary",
        default="/home/grec-alexander/Downloads/aic8800d80/fmacfw_8800d80_h_u02.bin",
        help="Path to raw firmware binary",
    )
    ap.add_argument("--max-turns", type=int, default=MAX_TURNS)
    args = ap.parse_args()

    if not Path(args.binary).exists():
        sys.exit(f"Binary not found: {args.binary}")

    run_all(args.binary, args.max_turns)
