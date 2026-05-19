#!/usr/bin/env python3
"""
AIC8800D80 firmware RE eval harness — v2.

Key features:
  - Outcome-based rubric (~300 pts) shown to models in system prompt
  - report_progress synthetic tool: earns bonus pts (not in total), logged to dated JSON
  - Rich per-turn telemetry: tokens, latency, success/fail/empty, thinking tokens
  - Progress logs: results/progress_<model>_<binary>_<ts>.json

API key: read from OPENCODE_API_KEY env var, or ~/.claude/.secretkey.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import time
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openai import OpenAI


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = "https://opencode.ai/zen/go/v1"

AZURE_BASE_URL = "https://alexpopescu-resource.services.ai.azure.com/openai/v1"
OPENCODE_AUTH_PATH = Path.home() / ".local" / "share" / "opencode" / "auth.json"

MODELS = [
    {
        "id":          "deepseek-v4-flash",
        "label":       "DeepSeek V4 Flash",
        "extra":       {"reasoning_effort": "max"},
        "tool_budget": 100,
        "max_turns":   70,
    },
    {
        "id":          "gpt-5.4-mini",
        "label":       "GPT-5.4 Mini",
        "extra":       {"reasoning_effort": "high"},
        "base_url":    AZURE_BASE_URL,
        "api_key_source": "azure",
        "use_max_completion_tokens": True,
        "tool_budget": 100,
        "max_turns":   70,
    },
]

MAX_TURNS      = 70
TOOL_BUDGET    = 100
CONTEXT_TRIM_K = 120_000

MCP_CMD = [
    sys.executable, "-u",
    str(Path(__file__).parent.parent.parent / "ida_mcp_stdio.py"),
]
MCP_ENV_BASE = {
    **os.environ,
    "IDADIR": os.environ.get("IDADIR", "/home/REDACTED/ida-pro-9.2"),
    "IDA_MCP_RESPONSE_MODE":         "compact",
    "IDA_MCP_QOL_MODE":              "balanced",
    "IDA_MCP_BATCH_COMPACT":         "1",
    "IDA_MCP_COMPACT_MAX_ITEMS":     "48",
    "IDA_MCP_COMPACT_MAX_STRING":    "1400",
    "IDA_MCP_COMPACT_CHAR_BUDGET":   "30000",
    "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS": "1",
}

def _make_mcp_env(label: str) -> dict:
    slug = label.lower().replace(" ", "_").replace("/", "_")
    cache_dir = str(Path(__file__).parent / "results" / f"cache_{slug}_{int(time.time())}")
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    return {**MCP_ENV_BASE, "IDA_MCP_CACHE_DIR": cache_dir}


# ---------------------------------------------------------------------------
# Rubric — outcome-based
# ---------------------------------------------------------------------------

RUBRIC = {
    # Session start (5 pts)
    "session_create_first":         (5,  "Called session(create) as first tool call"),
    # Architecture & loading (50 pts)
    "arch_correct":                 (20, "Correctly identified ARM Cortex-M architecture"),
    "load_address_correct":         (15, "Correctly identified load address as 0x120000"),
    "vector_table_found":           (10, "Found and parsed the Cortex-M vector table"),
    "reset_handler_found":          (5,  "Located the Reset_Handler entry point"),
    # RTOS & stack identification (60 pts)
    "identified_rtos":              (20, "Correctly identified RTOS by name"),
    "found_rivierawaves_stack":     (30, "Found RivieraWaves/LMAC/KE stack artifacts"),
    "found_sdio_usb_transport":     (10, "Found SDIO or USB transport layer evidence"),
    # Code analysis (60 pts)
    "traced_reset_to_main":         (20, "Traced Reset_Handler → main/init call chain"),
    "named_functions_5":            (10, "Identified and named ≥5 meaningful functions"),
    "decompiled_function":          (10, "Successfully decompiled at least one function"),
    "created_handler_functions_3":  (8,  "Created ≥3 vector-handler functions via funcs(action='create')"),
    "found_mmio_3":                 (15, "Mapped ≥3 MMIO peripheral addresses"),
    "interrupt_table_complete":     (5,  "Interrupt handler table has ≥20 entries"),
    # Data & strings (45 pts)
    "found_version_string":         (15, "Found firmware version or build string"),
    "found_wifi_stack_layers":      (15, "Identified FMAC/LMAC/PHY layer separation"),
    "found_bt_coexistence":         (15, "Found Bluetooth coexistence evidence"),
    # Synthesis (65 pts)
    "firmware_purpose_hypothesis":  (20, "Produced accurate firmware purpose hypothesis"),
    "actionable_next_steps":        (15, "Listed specific actionable RE next steps"),
    "used_blackboard_3":            (10, "Used blackboard to persist ≥3 distinct findings"),
    "followed_next_calls":          (12, "Followed _next_calls hints ≥3 times"),
    "final_report":                 (8,  "Produced coherent final report with ≥8 sections"),
    # Efficiency bonus (up to 20 pts — computed at end)
    "efficiency_bonus":             (20, "Efficiency: high findings-per-tool-call ratio"),
}
# Total max: 5+50+60+60+45+65+20 = 305

BONUS_PTS_PER_REPORT_HIGH   = 5   # confidence: confirmed | high
BONUS_PTS_PER_REPORT_MEDIUM = 3   # confidence: medium
BONUS_MAX                   = 50  # cap on total bonus


def _rubric_summary() -> str:
    lines = [
        "SCORING RUBRIC (max ~300 pts — this rubric is visible to you intentionally):",
        "  Session start:       session(create) first → 5 pts",
        "  Architecture (50):  ARM Cortex-M ID → 20 | load 0x120000 → 15 | vector table → 10 | Reset_Handler → 5",
        "  RTOS & stack (60):  RTOS name → 20 | RivieraWaves/LMAC/KE artifacts → 30 | SDIO/USB transport → 10",
        "  Code analysis (68): Reset→main chain → 20 | ≥5 named funcs → 10 | decompile → 10 | create ≥3 handlers → 8 | ≥3 MMIO → 15 | IRQ table → 5",
        "  Data/strings (45):  version string → 15 | FMAC/LMAC/PHY → 15 | BT coex → 15",
        "  Synthesis (65):     purpose hypothesis → 20 | next steps → 15 | blackboard ≥3 → 10 | follow hints ≥3× → 12 | final report → 8",
        "  Efficiency bonus:   up to 20 pts based on checkpoints-earned / tool-calls ratio",
        "  BONUS (not in total): report_progress earns 3–5 pts per substantive finding (max 50).",
    ]
    return "\n".join(lines)


SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert reverse engineer using IDA Pro via the ida-pro-mcp tool suite.
    You have been given a raw firmware binary for an AIC8800D80 WiFi chip.
    Your goal: perform the most thorough analysis possible and maximise your score.

    MANDATORY SEQUENCE:
    1. session(action="create", binary_path="<path>")  — always first
    2. Poll session(action="status") until analysis_complete=true — DO NOT call analysis(wait), it crashes IDA
    3. idb(action="overview")                          — architecture + firmware context
    4. firmware_view(action="triage_snapshot") + firmware_view(action="detect_vector_table")
    5. Follow every _next_calls and _nudge hint in responses

    RAW BINARY RULE: IDA does NOT auto-create functions on raw ARM binaries.
    After session create you will see 0 functions. This is normal.
    You MUST manually create them:
      a) firmware_view(action="bootstrap", chip_family="AIC8800D80", load_base=0x120000)
         — creates vector-table functions synchronously (no wait needed)
      b) Then call funcs(action="create", address=<Reset_Handler_addr>) for the reset handler
      c) Then code(action="disasm"/"decompile") will work on those addresses

    WHAT TO FIND (high-value targets):
    - ARM Cortex-M architecture, load address (hint: not 0x0), vector table at start
    - RTOS: FreeRTOS, ThreadX, AliOS/Rhino — find task creation, scheduler strings
    - RivieraWaves WiFi stack: ke_task, ke_msg, ke_evt, rwip, lmac, fmac strings
    - SDIO/USB transport layer strings and functions
    - MMIO peripheral base addresses (WiFi MAC, BT, timers, GPIO)
    - Version/build strings with actual numbers
    - Bluetooth coexistence: bt_coex, bt_allow, bt not allow, wifiidle+bt strings
    - FMAC/LMAC/PHY layer separation in code structure
    - Reset_Handler → main call chain via decompilation
    - At least 3 concrete handler functions lifted from IVT entries (Reset/NMI/HardFault etc.)

    Use report_progress(category, finding, confidence, evidence) to log important
    discoveries as you make them. Each call earns bonus points and externalises
    your reasoning. Do NOT batch everything into the final report — call it as you go.

""") + _rubric_summary() + textwrap.dedent("""

    Do NOT stop early. Use your full tool budget. When done, write a comprehensive
    FINAL REPORT covering: architecture, load address, RTOS, WiFi stack layers,
    entry points, MMIO map, version strings, BT coexistence, transport, purpose
    hypothesis, and specific next RE steps.

    HARD CHALLENGE OBJECTIVES:
    - Avoid call loops: do not repeat the exact same tool call >2 times unless arguments changed materially.
    - If funcs(create) fails, immediately pivot: firmware_view(auto_retype/bootstrap) then retry create on handlers.
    - Keep evidence concrete: include addresses, names, and exact strings in findings.
""")


# ---------------------------------------------------------------------------
# Synthetic report_progress tool (intercepted by harness, not forwarded to MCP)
# ---------------------------------------------------------------------------

REPORT_PROGRESS_TOOL = {
    "type": "function",
    "function": {
        "name": "report_progress",
        "description": (
            "Log an important finding or hypothesis you have just established. "
            "Call this as you discover things — do not wait for the final report. "
            "Earns bonus points per substantive entry."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["architecture", "rtos", "code", "mmio", "strings",
                             "hypothesis", "transport", "bt", "summary", "other"],
                },
                "finding": {
                    "type": "string",
                    "description": "The specific finding — include addresses, values, names.",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["confirmed", "high", "medium", "low"],
                },
                "evidence": {
                    "type": "string",
                    "description": "Brief evidence (tool name + key data that supports this).",
                },
            },
            "required": ["category", "finding", "confidence"],
        },
    },
}


# ---------------------------------------------------------------------------
# Stats dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TurnStats:
    turn: int
    elapsed_s: float
    latency_ms: float
    input_tokens: int
    output_tokens: int
    thinking_tokens: int
    tool_names: list[str] = field(default_factory=list)
    tool_success: int = 0
    tool_empty: int = 0
    tool_error: int = 0
    progress_reports: list[dict] = field(default_factory=list)


@dataclass
class RunStats:
    model_id: str
    label: str
    binary: str
    eval_start: str

    turns: list[TurnStats] = field(default_factory=list)
    progress_reports: list[dict] = field(default_factory=list)
    bonus_pts: int = 0

    @property
    def total_input_tokens(self) -> int:
        return sum(t.input_tokens for t in self.turns)

    @property
    def total_output_tokens(self) -> int:
        return sum(t.output_tokens for t in self.turns)

    @property
    def total_thinking_tokens(self) -> int:
        return sum(t.thinking_tokens for t in self.turns)

    @property
    def avg_latency_ms(self) -> float:
        if not self.turns:
            return 0.0
        return sum(t.latency_ms for t in self.turns) / len(self.turns)

    @property
    def p95_latency_ms(self) -> float:
        if not self.turns:
            return 0.0
        lats = sorted(t.latency_ms for t in self.turns)
        idx = max(0, int(len(lats) * 0.95) - 1)
        return lats[idx]

    @property
    def tool_success_rate(self) -> float:
        total = sum(t.tool_success + t.tool_empty + t.tool_error for t in self.turns)
        if total == 0:
            return 0.0
        return sum(t.tool_success for t in self.turns) / total

    @property
    def tool_empty_rate(self) -> float:
        total = sum(t.tool_success + t.tool_empty + t.tool_error for t in self.turns)
        if total == 0:
            return 0.0
        return sum(t.tool_empty for t in self.turns) / total

    @property
    def unique_tools_used(self) -> set[str]:
        names: set[str] = set()
        for t in self.turns:
            names.update(t.tool_names)
        return names

    @property
    def stall_count(self) -> int:
        """Turns where every tool call returned empty."""
        count = 0
        for t in self.turns:
            total = t.tool_success + t.tool_empty + t.tool_error
            if total > 0 and t.tool_empty == total:
                count += 1
        return count

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "label": self.label,
            "binary": self.binary,
            "eval_start": self.eval_start,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_thinking_tokens": self.total_thinking_tokens,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "p95_latency_ms": round(self.p95_latency_ms, 1),
            "tool_success_rate": round(self.tool_success_rate, 3),
            "tool_empty_rate": round(self.tool_empty_rate, 3),
            "unique_tools_used": sorted(self.unique_tools_used),
            "unique_tool_count": len(self.unique_tools_used),
            "stall_count": self.stall_count,
            "bonus_pts": self.bonus_pts,
            "progress_reports": self.progress_reports,
            "turns": [
                {
                    "turn": t.turn,
                    "elapsed_s": round(t.elapsed_s, 1),
                    "latency_ms": round(t.latency_ms, 1),
                    "input_tokens": t.input_tokens,
                    "output_tokens": t.output_tokens,
                    "thinking_tokens": t.thinking_tokens,
                    "tools": t.tool_names,
                    "success": t.tool_success,
                    "empty": t.tool_empty,
                    "error": t.tool_error,
                }
                for t in self.turns
            ],
        }


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

@dataclass
class Score:
    label: str
    pts: int = 0
    penalties: int = 0
    events: list[str] = field(default_factory=list)
    _awarded: set[str] = field(default_factory=set)

    # running counters for multi-call checkpoints
    mmio_found: set[str] = field(default_factory=set)
    blackboard_writes: int = 0
    named_func_count: int = 0
    fmac_seen: bool = False
    lmac_phy_seen: bool = False
    created_handlers: set[str] = field(default_factory=set)

    def award(self, key: str, note: str = "") -> None:
        if key in self._awarded or key not in RUBRIC:
            return
        pts, desc = RUBRIC[key]
        self._awarded.add(key)
        self.pts += pts
        self.events.append(f"+{pts:2d}  {desc}" + (f" [{note}]" if note else ""))

    def award_tiered(self, key: str, pts: int, note: str = "") -> None:
        if key in self._awarded or key not in RUBRIC:
            return
        max_pts = RUBRIC[key][0]
        actual = min(pts, max_pts)
        if actual <= 0:
            return
        desc = RUBRIC[key][1]
        self._awarded.add(key)
        self.pts += actual
        self.events.append(f"+{actual:2d}  {desc}" + (f" [{note}]" if note else ""))

    def penalize(self, reason: str, pts: int = 3) -> None:
        self.penalties += pts
        self.events.append(f"-{pts:2d}  PENALTY: {reason}")

    @property
    def total(self) -> int:
        return max(0, self.pts - self.penalties)

    @property
    def max_pts(self) -> int:
        return sum(v for v, _ in RUBRIC.values())


# ---------------------------------------------------------------------------
# MCP client
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
            req: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
            if params:
                req["params"] = params
            self.proc.stdin.write(json.dumps(req) + "\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
            if not line:
                stderr = self.proc.stderr.read(2000) if self.proc.stderr else ""
                raise RuntimeError(f"MCP server closed (stderr: {stderr[:500]})")
            return json.loads(line)

    def initialize(self) -> dict:
        r = self._send_recv("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "eval-harness", "version": "2.0"},
        })
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n"
        )
        self.proc.stdin.flush()
        return r

    def list_tools(self) -> list[dict]:
        r = self._send_recv("tools/list", {})
        return r.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        r = self._send_recv("tools/call", {"name": name, "arguments": arguments})
        return r.get("result", r.get("error", {}))

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------

def _estimate_tokens(messages: list[dict]) -> int:
    return sum(len(json.dumps(m)) for m in messages) // 4


def _trim_context(messages: list[dict]) -> list[dict]:
    if len(messages) <= 10:
        return messages
    system = [m for m in messages if m["role"] == "system"]
    rest = [m for m in messages if m["role"] != "system"]
    if len(rest) <= 8:
        return messages
    head, tail = rest[:2], rest[-6:]
    skipped = len(rest) - len(head) - len(tail)
    return system + head + [{
        "role": "assistant",
        "content": f"[{skipped} earlier turns summarised. Key findings persisted to blackboard.]",
    }] + tail


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _score_tool_call(tool: str, args: dict, score: Score,
                     call_count: int, prev_calls: list[str]) -> None:
    if call_count == 1 and tool == "session" and args.get("action") == "create":
        score.award("session_create_first")

    if tool == "blackboard" and args.get("action") == "write":
        score.blackboard_writes += 1
        if score.blackboard_writes >= 3:
            score.award("used_blackboard_3")

    if tool in ("funcs",) and args.get("action") in ("create", "rename"):
        name = str(args.get("name") or args.get("new_name") or "")
        if name and not name.startswith("sub_") and not name.startswith("loc_"):
            score.named_func_count += 1
            if score.named_func_count >= 5:
                score.award("named_functions_5", f"{score.named_func_count} named")

    full = f"{tool}:{json.dumps(args or {}, sort_keys=True)}"
    if prev_calls.count(full) >= 2 and score.penalties < 20:
        delta = min(2, 20 - score.penalties)
        if delta > 0:
            score.penalize(f"repeated identical call: {tool}({args.get('action','')})", pts=delta)


def _score_tool_result(tool: str, args: dict, result_str: str, score: Score) -> None:
    low = result_str.lower()
    action = str(args.get("action", "")).lower()

    # Architecture
    if "arm" in low and ("cortex" in low or "32" in low or "thumb" in low):
        if tool in ("session", "idb", "analysis", "firmware_view"):
            score.award("arch_correct", "ARM/Cortex-M in response")

    # Load address — match 0x120000 but NOT 0x1200000
    if re.search(r'\b0x120000\b(?!0)', result_str, re.IGNORECASE):
        if tool in ("session", "idb", "firmware_view", "analysis"):
            score.award("load_address_correct", "0x120000 confirmed")

    # Vector table
    if tool == "firmware_view" and action == "detect_vector_table":
        if "vectors" in low and ('"handler"' in low or "reset" in low):
            score.award("vector_table_found", "vectors list returned")
            count_m = re.search(r'"vectors_detected"\s*:\s*(\d+)', result_str)
            if count_m and int(count_m.group(1)) >= 20:
                score.award("interrupt_table_complete", f"{count_m.group(1)} entries")

    # Reset_Handler
    if "reset_handler" in low or "0x1201a8" in low:
        score.award("reset_handler_found", "Reset_Handler located")

    # RTOS
    for rtos in ("freertos", "threadx", "rtx", "ucos", "aliosthing", "rhino", "krhino",
                 "xtaskcreate", "vTaskCreate", "tx_thread_create", "osthreadcreate"):
        if rtos.lower() in low:
            score.award("identified_rtos", f"hint: {rtos}")
            break

    # RivieraWaves / KE stack
    ke_hits = sum(1 for p in ("ke_task", "ke_msg", "ke_evt", "ke_timer", "rwip",
                               "lmactx", "lmacrx", "rivierawaves", "rw_main") if p in low)
    if ke_hits >= 1:
        score.award("found_rivierawaves_stack", f"{ke_hits} KE/RW artifacts")

    # SDIO / USB transport
    for pat in ("sdio_func", "sdio_claim", "usb_transport", "sdio_readb", "sdio_writeb"):
        if pat in low:
            score.award("found_sdio_usb_transport", f"hint: {pat}")
            break

    # Decompilation
    if tool == "code" and action in ("decompile", "smart_decompile"):
        if len(result_str) > 200 and ("int " in result_str or "void " in result_str or "return" in result_str):
            score.award("decompiled_function", "decompile returned code")

    # Handler lifting via funcs(create)
    if tool == "funcs" and action == "create":
        if '"ok": true' in low:
            addr_m = re.search(r'"addr"\s*:\s*"(0x[0-9a-f]+)"', low)
            if addr_m:
                score.created_handlers.add(addr_m.group(1))
            if len(score.created_handlers) >= 3:
                score.award("created_handler_functions_3", f"{len(score.created_handlers)} handlers")

    # Traced reset → main
    if tool == "code" and action in ("decompile", "smart_decompile", "disasm"):
        if ("main" in low or "system_init" in low or "_start" in low) and \
           ("reset" in low or "0x1201" in low):
            score.award("traced_reset_to_main", "main/init in reset disasm")

    # MMIO peripheral addresses
    if tool == "firmware_view" and action == "detect_mmio":
        addrs = re.findall(r'0x4[0-9a-f]{7}', result_str, re.IGNORECASE)
        for a in addrs:
            score.mmio_found.add(a.lower())
        if len(score.mmio_found) >= 3:
            score.award("found_mmio_3", f"{len(score.mmio_found)} MMIO addresses")

    # Version / build string with actual value
    if re.search(r'(version|build|fw_ver|sdk_ver)\s*[:\s=]+\s*[\d\.\-_v]+', low):
        score.award("found_version_string", "version value found")
    elif re.search(r'v\d+\.\d+\.\d+', low):
        score.award("found_version_string", "semver found")

    # WiFi stack layers: need both FMAC and LMAC/PHY
    if "fmac" in low:
        score.fmac_seen = True
    if "lmac" in low or "phy_" in low or "rf_" in low:
        score.lmac_phy_seen = True
    if score.fmac_seen and score.lmac_phy_seen:
        score.award("found_wifi_stack_layers", "FMAC + LMAC/PHY seen")

    # BT coexistence
    for pat in ("bt_coex", "bt_allow", "bt not allow", "wifiidle,bt", "bt_idle",
                "coexistence", "bt_activity"):
        if pat in low:
            score.award("found_bt_coexistence", f"hint: {pat}")
            break


def _score_followed_hints(messages: list[dict], score: Score) -> None:
    followed = 0
    for i, msg in enumerate(messages):
        if msg.get("role") != "tool":
            continue
        content = msg.get("content", "")
        if "_next_calls" not in content and "next_actions" not in content:
            continue
        for j in range(i + 1, min(i + 3, len(messages))):
            nxt = messages[j]
            if nxt.get("role") == "assistant" and nxt.get("tool_calls"):
                followed += 1
                break
    if followed >= 3:
        score.award("followed_next_calls", f"{followed} times")


def _score_final_response(text: str, score: Score) -> None:
    low = text.lower()
    markers = ["architecture", "entry point", "mmio", "rtos", "hypothesis",
               "load address", "vector", "function", "summary", "findings",
               "next step", "peripheral", "wifi stack"]
    hits = sum(1 for m in markers if m in low)
    if hits >= 8:
        score.award("final_report", f"{hits} sections")

    # Synthesis checkpoints from final report text
    if "purpose" in low or "role" in low:
        if "wifi" in low and ("firmware" in low or "mac" in low):
            score.award("firmware_purpose_hypothesis", "purpose in final report")
    if "next step" in low or "recommend" in low or "further analysis" in low:
        score.award("actionable_next_steps", "next steps in final report")


def _compute_efficiency_bonus(score: Score, tool_call_count: int) -> None:
    if tool_call_count == 0:
        return
    n = len(score._awarded) - (1 if "efficiency_bonus" in score._awarded else 0)
    ratio = n / tool_call_count
    if ratio >= 0.15:
        score.award_tiered("efficiency_bonus", 20, f"ratio={ratio:.2f}")
    elif ratio >= 0.12:
        score.award_tiered("efficiency_bonus", 15, f"ratio={ratio:.2f}")
    elif ratio >= 0.09:
        score.award_tiered("efficiency_bonus", 10, f"ratio={ratio:.2f}")
    elif ratio >= 0.06:
        score.award_tiered("efficiency_bonus", 5, f"ratio={ratio:.2f}")


# ---------------------------------------------------------------------------
# report_progress interception
# ---------------------------------------------------------------------------

def _handle_report_progress(args: dict, run_stats: RunStats, turn: int,
                              elapsed_s: float) -> tuple[str, dict]:
    finding   = str(args.get("finding", "")).strip()
    confidence = str(args.get("confidence", "low"))
    category   = str(args.get("category", "other"))
    evidence   = str(args.get("evidence", "")).strip()

    bonus = 0
    if len(finding) > 40 and run_stats.bonus_pts < BONUS_MAX:
        if confidence in ("confirmed", "high"):
            bonus = min(BONUS_PTS_PER_REPORT_HIGH, BONUS_MAX - run_stats.bonus_pts)
        elif confidence == "medium":
            bonus = min(BONUS_PTS_PER_REPORT_MEDIUM, BONUS_MAX - run_stats.bonus_pts)
        run_stats.bonus_pts += bonus

    entry = {
        "turn": turn,
        "elapsed_s": round(elapsed_s, 1),
        "category": category,
        "finding": finding,
        "confidence": confidence,
        "evidence": evidence,
        "bonus_pts": bonus,
    }
    run_stats.progress_reports.append(entry)

    result = {
        "ok": True,
        "logged": True,
        "bonus_pts_earned": bonus,
        "total_bonus_pts": run_stats.bonus_pts,
        "note": "Finding logged. Keep exploring!",
    }
    return json.dumps(result), entry


# ---------------------------------------------------------------------------
# API key
# ---------------------------------------------------------------------------

def _load_api_key(source: str = "opencode") -> str:
    """Load API key from OpenCode auth store or legacy env/secret files."""
    provider_name = "azure" if source == "azure" else "opencode-go"

    # Check env vars first
    if source == "azure":
        key = os.environ.get("AZURE_API_KEY", "")
    else:
        key = os.environ.get("OPENCODE_API_KEY", "")
    if key:
        return key

    # OpenCode's auth store keeps provider credentials in a single JSON file.
    try:
        if OPENCODE_AUTH_PATH.exists():
            auth = json.loads(OPENCODE_AUTH_PATH.read_text())
            provider = auth.get(provider_name, {})
            key = str(provider.get("key", "") or "").strip()
            if key:
                return key
    except Exception:
        pass

    for p in [
        Path(__file__).parent.parent.parent / ".claude" / "secretkey.txt",
        Path.home() / ".claude" / ".secretkey.txt",
        Path.home() / ".secretkey.txt",
        Path("/home/REDACTED/Downloads/ida-pro-mcp/.claude/secretkey.txt"),
    ]:
        if p.exists():
            lines = [l.strip() for l in p.read_text().strip().splitlines() if l.strip()]
            if len(lines) > 0:
                key = lines[1] if source == "azure" and len(lines) > 1 else lines[0]
                break
    if not key:
        raise RuntimeError(
            f"No API key found for source='{source}'. "
            f"Expected {provider_name} in {OPENCODE_AUTH_PATH} or set OPENCODE_API_KEY / AZURE_API_KEY."
        )
    return key


# ---------------------------------------------------------------------------
# Single-model agent loop
# ---------------------------------------------------------------------------

def run_model(model_cfg: dict, binary_path: str, max_turns: int, api_key: str, azure_key: str = "") -> dict:
    label       = model_cfg["label"]
    model_id    = model_cfg["id"]
    extra       = model_cfg.get("extra", {})
    max_turns   = model_cfg.get("max_turns", max_turns)
    tool_budget = model_cfg.get("tool_budget", TOOL_BUDGET)
    model_base_url = model_cfg.get("base_url", BASE_URL)
    key_source  = model_cfg.get("api_key_source", "opencode")
    model_api_key  = azure_key if key_source == "azure" else api_key

    print(f"\n{'='*60}\n  {label}  —  starting\n{'='*60}")

    score = Score(label=label)
    run_stats = RunStats(
        model_id=model_id,
        label=label,
        binary=binary_path,
        eval_start=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )
    t_start = time.time()
    tool_call_count = 0
    prev_calls: list[str] = []

    mcp = MCPClient(MCP_CMD, _make_mcp_env(label))
    try:
        mcp.initialize()
        mcp_tools = mcp.list_tools()
    except Exception as e:
        print(f"  [{label}] MCP init failed: {e}")
        mcp.close()
        return {"label": label, "error": str(e), "score": score, "run_stats": run_stats}

    print(f"  [{label}] MCP ready — {len(mcp_tools)} tools available")

    openai_tools = [REPORT_PROGRESS_TOOL] + [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", "")[:1000],
                "parameters": t.get("inputSchema", {"type": "object", "properties": {}}),
            },
        }
        for t in mcp_tools
    ]

    client = OpenAI(api_key=model_api_key, base_url=model_base_url)

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Analyze this AIC8800D80 WiFi firmware binary as deeply as possible: {binary_path}\n\n"
                "Follow the mandatory sequence, then dig into every high-value target in the rubric. "
                "Use report_progress as you find things. Exhaust your tool budget before writing the final report."
            ),
        },
    ]

    turns = 0
    last_text = ""

    while turns < max_turns and tool_call_count < tool_budget:
        turns += 1
        t_turn = time.time()

        if _estimate_tokens(messages) > CONTEXT_TRIM_K:
            print(f"  [{label}] trimming context")
            messages = _trim_context(messages)

        tokens_key = "max_completion_tokens" if model_cfg.get("use_max_completion_tokens") else "max_tokens"
        call_kwargs: dict[str, Any] = dict(
            model=model_id,
            messages=messages,
            tools=openai_tools,
            tool_choice="auto",
            **{tokens_key: 4096},
        )
        extra_body = extra.get("extra_body", {})
        if "reasoning_effort" in extra:
            call_kwargs["reasoning_effort"] = extra["reasoning_effort"]
        if extra_body:
            call_kwargs["extra_body"] = extra_body

        try:
            resp = client.chat.completions.create(**call_kwargs)
        except Exception as e:
            print(f"  [{label}] API error turn {turns}: {type(e).__name__}: {e!r}")
            tb = traceback.format_exc(limit=4)
            print("".join(f"    {line}\n" for line in tb.rstrip().splitlines()))
            break

        latency_ms = (time.time() - t_turn) * 1000
        msg = resp.choices[0].message

        # Extract token counts
        usage = getattr(resp, "usage", None)
        input_tok  = getattr(usage, "prompt_tokens", 0) or 0
        output_tok = getattr(usage, "completion_tokens", 0) or 0
        details    = getattr(usage, "completion_tokens_details", None)
        think_tok  = getattr(details, "reasoning_tokens", 0) or 0

        # Reasoning preview
        reasoning = getattr(msg, "reasoning_content", None)
        if reasoning:
            print(f"  [{label}] <think> {reasoning[:120].replace(chr(10),' ')}…")

        if msg.content:
            last_text = msg.content
            print(f"  [{label}] turn {turns}: {msg.content[:180].replace(chr(10),' ')}")

        if not msg.tool_calls:
            print(f"  [{label}] finished (finish={resp.choices[0].finish_reason})")
            break

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

        turn_stats = TurnStats(
            turn=turns,
            elapsed_s=time.time() - t_start,
            latency_ms=latency_ms,
            input_tokens=input_tok,
            output_tokens=output_tok,
            thinking_tokens=think_tok,
        )

        tool_result_msgs: list[dict] = []
        for tc in msg.tool_calls:
            tname = tc.function.name
            try:
                targs = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                targs = {}

            # --- intercept report_progress (free — doesn't consume budget) ---
            if tname == "report_progress":
                result_str, entry = _handle_report_progress(
                    targs, run_stats, turns, time.time() - t_start
                )
                turn_stats.progress_reports.append(entry)
                print(f"  [{label}]   report_progress({targs.get('category','')}) "
                      f"+{entry['bonus_pts']}bp — {str(targs.get('finding',''))[:80]}")
                # Also score synthesis checkpoints from report_progress content
                cat = str(targs.get("category", ""))
                if cat == "hypothesis":
                    score.award("firmware_purpose_hypothesis", "via report_progress")
                if cat in ("summary", "other") and "next step" in str(targs.get("finding","")).lower():
                    score.award("actionable_next_steps", "via report_progress")
                tool_result_msgs.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })
                continue

            # --- regular MCP tool ---
            tool_call_count += 1
            turn_stats.tool_names.append(tname)

            print(f"  [{label}]   tool[{tool_call_count}] {tname}({targs.get('action','')}) …")
            _score_tool_call(tname, targs, score, tool_call_count, prev_calls)
            prev_calls.append(f"{tname}:{json.dumps(targs, sort_keys=True)}")

            try:
                result = mcp.call_tool(tname, targs)
            except Exception as e:
                result = {"ok": False, "error": str(e)}

            result_str = json.dumps(result)[:5000]

            # Classify result quality
            if isinstance(result, dict) and result.get("error"):
                turn_stats.tool_error += 1
            else:
                _is_meaningful = (
                    isinstance(result, dict) and
                    any(k in result for k in (
                        "items", "results", "vectors", "functions", "strings",
                        "code", "decompiled", "addr", "segments", "entries",
                    ))
                ) or len(result_str) > 100
                if _is_meaningful:
                    turn_stats.tool_success += 1
                else:
                    turn_stats.tool_empty += 1

            _score_tool_result(tname, targs, result_str, score)

            tool_result_msgs.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str,
            })

            if tool_call_count >= tool_budget:
                print(f"  [{label}] tool budget exhausted ({tool_budget})")
                break

        run_stats.turns.append(turn_stats)
        messages.extend(tool_result_msgs)

    # --- final passes ---
    _score_followed_hints(messages, score)
    combined = last_text + " ".join(
        m.get("content", "") for m in messages if m.get("role") == "tool"
    )
    _score_final_response(combined, score)
    _compute_efficiency_bonus(score, tool_call_count)

    elapsed = time.time() - t_start
    print(f"\n  [{label}] DONE — {tool_call_count} tools, {turns} turns, {elapsed:.0f}s")
    print(f"  [{label}] Score: {score.total}/{score.max_pts}  bonus: {run_stats.bonus_pts}")

    mcp.close()
    return {
        "label": label,
        "model_id": model_id,
        "score": score,
        "run_stats": run_stats,
        "tool_calls": tool_call_count,
        "turns": turns,
        "elapsed_s": round(elapsed, 1),
        "messages": messages,
    }


# ---------------------------------------------------------------------------
# Parallel runner + report
# ---------------------------------------------------------------------------

def run_all(binary_path: str, max_turns: int, model_filter: list[str] | None = None) -> None:
    api_key   = _load_api_key("opencode")
    try:
        azure_key = _load_api_key("azure")
    except RuntimeError:
        azure_key = ""

    active_models = [m for m in MODELS if not model_filter or m["label"] in model_filter]

    print(f"Binary: {binary_path}")
    print(f"Models: {', '.join(m['label'] for m in active_models)}")
    budgets = ", ".join(
        f"{m['label']}: {m.get('tool_budget', TOOL_BUDGET)} tools / {m.get('max_turns', max_turns)} turns"
        for m in active_models
    )
    print(f"Budgets: {budgets}")

    results: list[dict] = []
    lock = threading.Lock()

    def _run(cfg: dict) -> None:
        r = run_model(cfg, binary_path, max_turns, api_key, azure_key)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=_run, args=(cfg,), daemon=True) for cfg in active_models]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    _print_report(results)
    _save_report(results, binary_path)
    _save_progress_logs(results, binary_path)


def _print_report(results: list[dict]) -> None:
    print("\n\n" + "=" * 70)
    print("  FINAL SCORECARD")
    print("=" * 70)

    results.sort(key=lambda r: r.get("score", Score("")).total, reverse=True)

    for r in results:
        label = r["label"]
        if "error" in r:
            print(f"\n{label}: ERROR — {r['error']}")
            continue
        s: Score = r["score"]
        rs: RunStats = r["run_stats"]
        print(f"\n{'─'*60}")
        print(f"  {label}")
        print(f"  Score:        {s.total:3d} / {s.max_pts}  (raw {s.pts}, penalties -{s.penalties})")
        print(f"  Bonus pts:    {rs.bonus_pts}  (not in total, {len(rs.progress_reports)} reports filed)")
        print(f"  Tool calls:   {r['tool_calls']}  |  Turns: {r['turns']}  |  Time: {r['elapsed_s']}s")
        print(f"\n  Token usage:")
        print(f"    Input:      {rs.total_input_tokens:,}")
        print(f"    Output:     {rs.total_output_tokens:,}")
        print(f"    Thinking:   {rs.total_thinking_tokens:,}")
        print(f"    Total:      {rs.total_input_tokens + rs.total_output_tokens + rs.total_thinking_tokens:,}")
        print(f"\n  Latency:      avg {rs.avg_latency_ms:.0f}ms  |  p95 {rs.p95_latency_ms:.0f}ms")
        print(f"  Tool quality: {rs.tool_success_rate:.0%} success  |  {rs.tool_empty_rate:.0%} empty  |  stalls: {rs.stall_count}")
        print(f"  Unique tools: {len(rs.unique_tools_used)}  ({', '.join(sorted(rs.unique_tools_used)[:8])}{'…' if len(rs.unique_tools_used) > 8 else ''})")
        print(f"\n  Checkpoints:")
        for ev in s.events:
            print(f"    {ev}")

    print("\n" + "=" * 70)
    winners = [r for r in results if "error" not in r]
    if winners:
        best = winners[0]
        print(f"  WINNER: {best['label']}  ({best['score'].total}/{best['score'].max_pts})")
    print("=" * 70)


def _save_report(results: list[dict], binary_path: str) -> None:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"eval_{Path(binary_path).stem}_{ts}.json"

    serialisable = []
    for r in results:
        rec = {k: v for k, v in r.items() if k not in ("messages",)}
        if "score" in rec:
            sc: Score = rec["score"]
            rec["score"] = {
                "label": sc.label,
                "total": sc.total,
                "raw_pts": sc.pts,
                "penalties": sc.penalties,
                "max_pts": sc.max_pts,
                "events": sc.events,
                "awarded": sorted(sc._awarded),
            }
        if "run_stats" in rec:
            rec["run_stats"] = rec["run_stats"].to_dict()
        serialisable.append(rec)

    out_path.write_text(json.dumps(serialisable, indent=2))
    print(f"\n  Results saved to: {out_path}")


def _save_progress_logs(results: list[dict], binary_path: str) -> None:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    bin_stem = Path(binary_path).stem

    for r in results:
        if "error" in r or "run_stats" not in r:
            continue
        rs: RunStats = r["run_stats"]
        sc: Score = r["score"]
        slug = rs.label.lower().replace(" ", "_")
        path = out_dir / f"progress_{slug}_{bin_stem}_{ts}.json"
        payload = {
            "model": rs.label,
            "model_id": rs.model_id,
            "binary": binary_path,
            "eval_start": rs.eval_start,
            "score": sc.total,
            "max_pts": sc.max_pts,
            "bonus_pts": rs.bonus_pts,
            "progress_reports": rs.progress_reports,
            "telemetry": {
                "total_input_tokens": rs.total_input_tokens,
                "total_output_tokens": rs.total_output_tokens,
                "total_thinking_tokens": rs.total_thinking_tokens,
                "avg_latency_ms": round(rs.avg_latency_ms, 1),
                "p95_latency_ms": round(rs.p95_latency_ms, 1),
                "tool_success_rate": round(rs.tool_success_rate, 3),
                "tool_empty_rate": round(rs.tool_empty_rate, 3),
                "unique_tool_count": len(rs.unique_tools_used),
                "stall_count": rs.stall_count,
            },
        }
        path.write_text(json.dumps(payload, indent=2))
        print(f"  Progress log: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LLM firmware RE eval harness v2")
    ap.add_argument(
        "--binary",
        default="/home/REDACTED/Downloads/aic8800d80/fmacfw_8800d80_h_u02.bin",
    )
    ap.add_argument("--max-turns", type=int, default=MAX_TURNS)
    ap.add_argument("--models", nargs="+", help="Run only these model labels (e.g. 'GPT-5.4 Mini')")
    args = ap.parse_args()

    if not Path(args.binary).exists():
        sys.exit(f"Binary not found: {args.binary}")

    run_all(args.binary, args.max_turns, model_filter=args.models)
