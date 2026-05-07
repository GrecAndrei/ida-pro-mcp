#!/usr/bin/env python3
"""
Cartographer-μ Cognitive Layer: Non-Mathematical Intelligence.

This module adds structural, narrative, and behavioral intelligence
that goes beyond scoring formulas. It thinks about:

  - What story is the analyst building? (NarrativeThread)
  - What patterns emerge across entries? (PatternSynthesizer)
  - What is the analyst actually trying to DO? (TaskInference)
  - When the LLM fails, who misled it? (ErrorAttribution)
  - What actions did the analyst take? (AnalystActionModel)
  - What is the analyst MISSING? (VoidTracker)
  - What dead ends did we hit? (ShadowBlackboard)
  - What would SURPRISE the analyst? (CuriosityEngine)
  - What happened WHEN? (EpisodicMemory)
  - What level of detail is needed? (MultiResolutionComposer)

Zero calculus. Zero gradient descent. Just structural reasoning.
"""
from __future__ import annotations

import os
import re
import json
import time
import sqlite3
import math
import threading
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


# =============================================================================
# 1. NarrativeThread: The Analysis Story
# =============================================================================

class NarrativeThread:
    """
    Reverse engineering is storytelling. The analyst starts at an entry point,
    follows calls, discovers behaviors, and builds a coherent narrative.

    NarrativeThread tracks the story so far and identifies GAPS that need filling.
    """

    CHAPTER_TYPES = ["entry", "pivot", "discovery", "correlation", "conclusion"]

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "narrative.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._chapters: List[Dict[str, Any]] = []  # in-memory for current session

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chapters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    ts REAL,
                    chapter_type TEXT,
                    title TEXT,
                    bridges TEXT,
                    predecessor INTEGER
                )
            """)
            conn.commit()

    def add_chapter(
        self,
        chapter_type: str,
        title: str,
        bridges: List[str],
        session_id: Optional[str] = None,
    ) -> int:
        """Add a chapter to the narrative. Returns chapter ID."""
        pred = self._chapters[-1]["id"] if self._chapters else None
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO chapters (session_id, ts, chapter_type, title, bridges, predecessor) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), chapter_type, title, json.dumps(bridges), pred),
            )
            cid = cur.lastrowid
            conn.commit()
        self._chapters.append({
            "id": cid, "type": chapter_type, "title": title,
            "bridges": set(bridges), "ts": time.time(),
        })
        # Keep only last 50 chapters in memory
        if len(self._chapters) > 50:
            self._chapters = self._chapters[-50:]
        return cid

    def get_gaps(self) -> List[Dict[str, Any]]:
        """
        Find narrative gaps: places where the story has a hole.

        Examples:
          - "We found a crypto function but don't know what it encrypts"
          - "We found a C2 URL but don't know when it's called"
          - "We found a loader but don't know what it loads"
        """
        gaps = []
        if len(self._chapters) < 2:
            return gaps

        # Look for pairs that SHOULD connect but don't
        for i in range(len(self._chapters) - 1):
            curr = self._chapters[i]
            nxt = self._chapters[i + 1]

            # Gap: crypto found but no data flow TO it
            if curr["type"] == "discovery" and "crypt" in curr["title"].lower():
                if not any("crypt" in c["title"].lower() for c in self._chapters[i+1:i+4]):
                    gaps.append({
                        "type": "missing_flow",
                        "description": f"Found crypto at {curr['title']} but no data source identified",
                        "bridges": list(curr["bridges"]),
                        "priority": "high",
                    })

            # Gap: network endpoint found but no caller
            if curr["type"] == "discovery" and any(b in ("http", "socket", "connect") for b in curr["title"].lower()):
                if not any("call" in c["title"].lower() for c in self._chapters[i+1:i+4]):
                    gaps.append({
                        "type": "missing_caller",
                        "description": f"Found network endpoint but caller chain incomplete",
                        "bridges": list(curr["bridges"]),
                        "priority": "high",
                    })

            # Gap: two discoveries with no correlation
            if curr["type"] == "discovery" and nxt["type"] == "discovery":
                shared = curr["bridges"] & nxt["bridges"]
                if not shared:
                    gaps.append({
                        "type": "missing_correlation",
                        "description": f"Unrelated discoveries: {curr['title']} and {nxt['title']}",
                        "bridges": list(curr["bridges"] | nxt["bridges"]),
                        "priority": "medium",
                    })

        return gaps

    def get_story_summary(self, max_chapters: int = 10) -> str:
        """Return a human-readable story of the analysis so far."""
        recent = self._chapters[-max_chapters:]
        lines = []
        for ch in recent:
            lines.append(f"[{ch['type']}] {ch['title']}")
        return "\n".join(lines)


# =============================================================================
# 2. PatternSynthesizer: Emergent Intelligence
# =============================================================================

class PatternSynthesizer:
    """
    Don't just score individual entries. Detect PATTERNS across multiple entries.

    If 3 entries all mention 'VirtualAlloc' at different addresses,
    synthesize: "Memory allocation cluster detected" — this is more useful
    than any individual entry.
    """

    def __init__(self):
        self._pattern_cache: Dict[str, Dict[str, Any]] = {}

    def synthesize(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a set of entries and synthesize higher-order patterns.
        Returns synthetic findings that are MORE useful than individual entries.
        """
        if len(entries) < 2:
            return []

        patterns = []

        # Pattern 1: API Cluster
        api_counts = Counter()
        api_addrs = defaultdict(list)
        for e in entries:
            bridges = e.get("bridges", [])
            if isinstance(bridges, str):
                try:
                    bridges = json.loads(bridges)
                except Exception:
                    bridges = []
            for b in bridges:
                if not b.startswith("0x") and not b.startswith("~"):
                    api_counts[b] += 1
                    api_addrs[b].append(e.get("addr", ""))

        for api, count in api_counts.items():
            if count >= 3:
                addrs = [a for a in api_addrs[api] if a]
                patterns.append({
                    "type": "api_cluster",
                    "title": f"{api} cluster: {count} occurrences",
                    "description": f"{api} appears {count} times across {len(set(addrs))} addresses",
                    "bridges": [api] + addrs[:5],
                    "priority": "high" if count >= 5 else "medium",
                })

        # Pattern 2: Address Proximity Cluster
        addrs = []
        for e in entries:
            addr = e.get("addr", "")
            if addr and addr.startswith("0x"):
                try:
                    addrs.append(int(addr, 16))
                except Exception:
                    pass
        if len(addrs) >= 3:
            addrs.sort()
            gaps = [addrs[i+1] - addrs[i] for i in range(len(addrs)-1)]
            if gaps:
                avg_gap = sum(gaps) / len(gaps)
                tight_clusters = []
                cluster_start = addrs[0]
                for i, gap in enumerate(gaps):
                    if gap > avg_gap * 3:  # Big gap = new cluster
                        if addrs[i] - cluster_start < 0x10000:  # Within 64KB
                            tight_clusters.append((cluster_start, addrs[i]))
                        cluster_start = addrs[i+1]
                if addrs[-1] - cluster_start < 0x10000:
                    tight_clusters.append((cluster_start, addrs[-1]))

                for start, end in tight_clusters:
                    patterns.append({
                        "type": "address_cluster",
                        "title": f"Code cluster: 0x{start:x} - 0x{end:x}",
                        "description": f"Multiple findings within {(end-start)//1024}KB region",
                        "bridges": [f"0x{start:x}", f"0x{end:x}"],
                        "priority": "high",
                    })

        # Pattern 3: Phase Jump
        phases = [e.get("schema", {}).get("phase_hint", "triage") if isinstance(e.get("schema"), dict) else "triage" for e in entries]
        phase_changes = sum(1 for i in range(len(phases)-1) if phases[i] != phases[i+1])
        if phase_changes >= 3:
            patterns.append({
                "type": "phase_chaos",
                "title": "Analysis phase unstable",
                "description": f"Frequent phase changes ({phase_changes}) — analyst may be stuck or multi-tasking",
                "bridges": [],
                "priority": "medium",
            })

        # Pattern 4: Repeated Same Finding
        title_counts = Counter(str(e.get("title", "")) for e in entries)
        for title, count in title_counts.items():
            if count >= 3 and title:
                patterns.append({
                    "type": "redundancy",
                    "title": f"Repeated finding: {title[:40]}",
                    "description": f"This finding appeared {count} times — analyst may be circling",
                    "bridges": [],
                    "priority": "low",
                })

        return patterns


# =============================================================================
# 3. TaskInference: What Is The Analyst Trying To Do?
# =============================================================================

class TaskInference:
    """
    Infer the analyst's current task from their tool sequence.
    Different tasks need different types of context.
    """

    TASK_PATTERNS = {
        "naming": {
            "sequence": [("data", "functions"), ("code", "decompile"), ("funcs", "rename")],
            "description": "Analyst is naming/renaming functions",
            "context_need": "function_signatures",
        },
        "hunting": {
            "sequence": [("search", "bytes"), ("code", "disasm"), ("search", "bytes")],
            "description": "Analyst is hunting for specific patterns",
            "context_need": "anomalies",
        },
        "tracing": {
            "sequence": [("code", "decompile"), ("graph", "callgraph"), ("code", "decompile")],
            "description": "Analyst is tracing execution flow",
            "context_need": "callers_callees",
        },
        "patching": {
            "sequence": [("code", "decompile"), ("modify", "patch_asm")],
            "description": "Analyst is preparing to patch",
            "context_need": "alternatives",
        },
        "vuln_hunt": {
            "sequence": [("search", "vulnerable"), ("code", "decompile"), ("string_ops", "find_c2")],
            "description": "Analyst is hunting vulnerabilities",
            "context_need": "sinks",
        },
        "exploring": {
            "sequence": [],  # default
            "description": "Analyst is exploring broadly",
            "context_need": "overview",
        },
    }

    def __init__(self):
        self._history: List[Tuple[str, str]] = []  # (tool, action)

    def record(self, tool: str, action: str):
        self._history.append((tool, action))
        if len(self._history) > 20:
            self._history = self._history[-20:]

    def infer(self) -> Dict[str, Any]:
        """Infer current task from recent tool sequence."""
        if len(self._history) < 2:
            return self.TASK_PATTERNS["exploring"]

        recent = self._history[-6:]

        for task_name, task_info in self.TASK_PATTERNS.items():
            if task_name == "exploring":
                continue
            seq = task_info["sequence"]
            if not seq:
                continue
            # Check if recent history contains this sequence (in order, not necessarily consecutive)
            idx = 0
            for t, a in recent:
                if idx < len(seq) and (t, a) == seq[idx]:
                    idx += 1
            if idx >= len(seq):
                return {**task_info, "task_name": task_name, "confidence": idx / len(recent)}

        # Partial match: check if ANY pattern matches partially
        best_task = "exploring"
        best_score = 0
        for task_name, task_info in self.TASK_PATTERNS.items():
            if task_name == "exploring":
                continue
            seq = task_info["sequence"]
            if not seq:
                continue
            idx = 0
            for t, a in recent:
                if idx < len(seq) and (t, a) == seq[idx]:
                    idx += 1
            score = idx / len(seq) if seq else 0
            if score > best_score:
                best_score = score
                best_task = task_name

        if best_score >= 0.5:
            return {**self.TASK_PATTERNS[best_task], "task_name": best_task, "confidence": best_score}

        return {**self.TASK_PATTERNS["exploring"], "task_name": "exploring", "confidence": 0.0}


# =============================================================================
# 4. ErrorAttribution: Who Mislead The LLM?
# =============================================================================

class ErrorAttribution:
    """
    When the LLM makes a mistake, trace it back to injected context.

    This is the MOST valuable learning signal. If the LLM hallucinates
    "0x140002000 is the decryption routine" because we injected an entry
    about 0x140001000 that mentioned crypto, we need to LOWER the Q-value
    of entries that cause confusion, not just entries that are ignored.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "error_attribution.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    session_id TEXT,
                    error_type TEXT,
                    error_message TEXT,
                    injected_bridges TEXT,
                    suspected_bridge TEXT
                )
            """)
            conn.commit()

    def analyze(
        self,
        error_message: str,
        injected_entries: List[Dict[str, Any]],
        session_id: Optional[str] = None,
    ) -> List[Tuple[str, float]]:
        """
        Given an error and what was injected, return [(bridge, blame_score), ...]
        """
        # Extract addresses from error message
        error_addrs = set(re.findall(r"0x[0-9a-fA-F]{8,16}", str(error_message)))
        error_addrs = {a.lower() for a in error_addrs}

        blames = []
        for entry in injected_entries:
            entry_bridges = entry.get("bridges", [])
            if isinstance(entry_bridges, str):
                try:
                    entry_bridges = json.loads(entry_bridges)
                except Exception:
                    entry_bridges = []

            for bridge in entry_bridges:
                blame = 0.0
                bridge_norm = bridge.lower() if bridge.startswith("0x") else bridge

                # Direct match: error mentions a bridge we injected
                if bridge_norm in error_addrs:
                    blame = 1.0
                # Proximity: error address is close to injected address
                elif bridge.startswith("0x") and error_addrs:
                    try:
                        bridge_val = int(bridge, 16)
                        for ea in error_addrs:
                            ea_val = int(ea, 16)
                            if abs(bridge_val - ea_val) < 0x1000:
                                blame = 0.7
                                break
                    except Exception:
                        pass
                # Keyword confusion: error mentions API name we injected
                elif bridge.lower() in str(error_message).lower():
                    blame = 0.5

                if blame > 0:
                    blames.append((bridge, blame))

        # Persist
        with sqlite3.connect(self.db_path) as conn:
            for bridge, blame in blames:
                conn.execute(
                    "INSERT INTO errors (ts, session_id, error_type, error_message, injected_bridges, suspected_bridge) VALUES (?, ?, ?, ?, ?, ?)",
                    (time.time(), session_id, "hallucination", str(error_message)[:200],
                     json.dumps([e.get("id", "") for e in injected_entries]), bridge),
                )
            conn.commit()

        return blames


# =============================================================================
# 5. AnalystActionModel: What Did They Actually DO?
# =============================================================================

class AnalystActionModel:
    """
    Track what ACTIONS the analyst takes, not just what tools they call.

    A tool call is noise. An ACTION is signal:
      - "renamed function" = analyst understood it
      - "added comment" = analyst found something worth noting
      - "patched byte" = analyst fixed/changed behavior
      - "created bookmark" = analyst wants to come back
      - "wrote to blackboard" = analyst wants to remember

    These are MUCH stronger signals than "they called code.decompile".
    """

    ACTION_WEIGHTS = {
        "rename": 1.0,          # Highest: analyst assigned meaning
        "comment": 0.8,         # High: analyst recorded insight
        "bookmark": 0.7,        # High: analyst wants to return
        "blackboard_write": 0.6,# Medium: analyst offloaded memory
        "patch": 0.9,           # Very high: analyst changed behavior
        "type_set": 0.7,        # High: analyst understood structure
        "follow_up_same": 0.3,  # Low: analyst needed more info
        "ignore": -0.5,         # Negative: injection was useless
        "error": -0.8,          # Very negative: injection mislead
    }

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "analyst_actions.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._last_tool_call: Optional[Tuple[str, str]] = None

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    session_id TEXT,
                    action_type TEXT,
                    tool TEXT,
                    details TEXT,
                    bridges TEXT,
                    reward REAL
                )
            """)
            conn.commit()

    def infer_action(
        self,
        prev_tool: str,
        prev_action: str,
        prev_result: Any,
        next_tool: str,
        next_action: str,
        next_args: Any,
    ) -> Optional[str]:
        """
        Infer what the analyst DID based on tool sequence and results.
        """
        # Rename: funcs.rename after code.decompile
        if prev_tool == "code" and prev_action in ("decompile", "disasm"):
            if next_tool == "funcs" and next_action in ("rename", "set_name"):
                return "rename"

        # Comment: modify.comment after code.decompile
        if prev_tool == "code" and prev_action in ("decompile", "disasm"):
            if next_tool == "modify" and next_action == "comment":
                return "comment"

        # Patch: modify.patch_asm after code.decompile
        if prev_tool == "code" and prev_action in ("decompile", "disasm"):
            if next_tool == "modify" and next_action == "patch_asm":
                return "patch"

        # Bookmark: bookmarks.add
        if next_tool == "bookmarks" and next_action == "add":
            return "bookmark"

        # Blackboard write
        if next_tool == "blackboard" and next_action == "write":
            return "blackboard_write"

        # Type set: types.set_prototype or funcs.set_type
        if next_tool in ("types", "funcs") and next_action in ("set_prototype", "set_type"):
            return "type_set"

        # Follow-up on same address
        if isinstance(next_args, dict) and isinstance(prev_result, dict):
            prev_addr = str(prev_result.get("addr", ""))
            next_addr = str(next_args.get("addr", ""))
            if prev_addr and prev_addr == next_addr:
                return "follow_up_same"

        # Ignore: no tool call for >30s or completely unrelated next call
        # (detected by caller based on timing)

        return None

    def record_action(
        self,
        action_type: str,
        tool: str = "",
        details: str = "",
        bridges: List[str] = None,
        session_id: Optional[str] = None,
    ) -> float:
        """Record an inferred action and return its reward."""
        reward = self.ACTION_WEIGHTS.get(action_type, 0.0)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO actions (ts, session_id, action_type, tool, details, bridges, reward) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), session_id, action_type, tool, details,
                 json.dumps(bridges or []), reward),
            )
            conn.commit()
        return reward

    def get_action_stats(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get summary of analyst actions."""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            if session_id:
                cur.execute(
                    "SELECT action_type, COUNT(*), AVG(reward) FROM actions WHERE session_id = ? GROUP BY action_type",
                    (session_id,),
                )
            else:
                cur.execute(
                    "SELECT action_type, COUNT(*), AVG(reward) FROM actions GROUP BY action_type",
                )
            rows = cur.fetchall()
            return {
                row[0]: {"count": row[1], "avg_reward": round(row[2], 3)}
                for row in rows
            }


# =============================================================================
# 6. VoidTracker: The Power of Negative Space
# =============================================================================

class VoidTracker:
    """
    Conventional RAG asks: "what's relevant?"
    VoidTracker asks: "what's MISSING?"

    The analyst often needs to know what they HAVEN'T looked at yet:
      - "You haven't examined the import table"
      - "No one has checked the .rdata section for strings"
      - "The entry point hasn't been decompiled"

    This is counter-intuitive but incredibly useful. It's like a museum guide
    saying "don't miss the basement" instead of describing the paintings.
    """

    VOID_CATEGORIES = {
        "import_table": {
            "keywords": ["imports", "iat", "GetProcAddress", "LoadLibrary"],
            "description": "Import table / IAT analysis",
        },
        "export_table": {
            "keywords": ["exports", "export_analysis"],
            "description": "Export table analysis",
        },
        "strings": {
            "keywords": ["strings", "string", "ascii", "unicode"],
            "description": "String analysis",
        },
        "entry_point": {
            "keywords": ["entry", "entrypoint", "start", "main"],
            "description": "Entry point analysis",
        },
        "crypto": {
            "keywords": ["crypt", "aes", "rsa", "xor", "hash"],
            "description": "Cryptographic material",
        },
        "network": {
            "keywords": ["http", "socket", "connect", "recv", "send", "url"],
            "description": "Network indicators",
        },
        "resources": {
            "keywords": ["resource", "rsrc", "pe_resource"],
            "description": "PE resources",
        },
    }

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "void_tracker.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._session_coverage: Dict[str, Set[str]] = defaultdict(set)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS coverage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    ts REAL,
                    category TEXT,
                    bridges TEXT
                )
            """)
            conn.commit()

    def record_coverage(self, entry: Dict[str, Any], session_id: Optional[str] = None):
        """Record that an area has been analyzed."""
        title = str(entry.get("title", "")).lower()
        text = str(entry.get("content", "")).lower()
        combined = title + " " + text

        for category, info in self.VOID_CATEGORIES.items():
            if any(kw in combined for kw in info["keywords"]):
                self._session_coverage[session_id or "default"].add(category)
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO coverage (session_id, ts, category, bridges) VALUES (?, ?, ?, ?)",
                        (session_id or "default", time.time(), category,
                         json.dumps(entry.get("bridges", []))),
                    )
                    conn.commit()
                break

    def get_voids(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return what's NOT been analyzed yet.
        This is the unconventional part — we inject ABSENCE, not presence.
        """
        covered = self._session_coverage.get(session_id or "default", set())
        voids = []
        for category, info in self.VOID_CATEGORIES.items():
            if category not in covered:
                voids.append({
                    "type": "void",
                    "category": category,
                    "description": f"No coverage of {info['description']} yet",
                    "suggested_action": f"Consider analyzing {info['description']}",
                    "priority": "medium",
                })
        return voids

    def get_void_report(self, session_id: Optional[str] = None) -> str:
        """Human-readable void report."""
        voids = self.get_voids(session_id)
        if not voids:
            return "Coverage appears comprehensive."
        lines = ["UNEXPLORED TERRITORY:"]
        for v in voids[:5]:
            lines.append(f"  • {v['description']}")
        return "\n".join(lines)


# =============================================================================
# 7. ShadowBlackboard: Learning from Failure
# =============================================================================

class ShadowBlackboard:
    """
    A parallel blackboard for DEAD ENDS, FAILED HYPOTHESES, and WRONG TURNS.

    Conventional systems only store successes. But in RE, you learn more from
    "this wasn't the C2 function" than "this was the C2 function." The shadow
    prevents the analyst and LLM from repeating the same wrong assumptions.

    This is deeply unconventional: we deliberately inject NEGATIVE knowledge.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "shadow_blackboard.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._session_shadows: List[Dict[str, Any]] = []

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS shadows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    ts REAL,
                    hypothesis TEXT,
                    why_wrong TEXT,
                    bridges TEXT,
                    lesson TEXT
                )
            """)
            conn.commit()

    def add_shadow(
        self,
        hypothesis: str,
        why_wrong: str,
        bridges: List[str],
        lesson: str = "",
        session_id: Optional[str] = None,
    ):
        """
        Record a failed hypothesis.

        Example:
          hypothesis: "0x140001000 is the C2 initialization"
          why_wrong: "It only connects to localhost, no C2 indicators"
          lesson: "Localhost connections in loader context are usually debug, not C2"
        """
        shadow = {
            "ts": time.time(),
            "hypothesis": hypothesis,
            "why_wrong": why_wrong,
            "bridges": bridges,
            "lesson": lesson,
        }
        self._session_shadows.append(shadow)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO shadows (session_id, ts, hypothesis, why_wrong, bridges, lesson) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), hypothesis, why_wrong,
                 json.dumps(bridges), lesson),
            )
            conn.commit()

    def get_warnings(self, query_bridges: List[str]) -> List[Dict[str, Any]]:
        """
        Given current query bridges, return relevant warnings from the shadow.
        This prevents repeating mistakes.
        """
        warnings = []
        query_set = set(query_bridges)
        for shadow in self._session_shadows:
            shadow_bridges = set(shadow.get("bridges", []))
            if query_set & shadow_bridges:  # Overlap
                warnings.append({
                    "type": "shadow_warning",
                    "hypothesis": shadow["hypothesis"],
                    "why_wrong": shadow["why_wrong"],
                    "lesson": shadow["lesson"],
                    "priority": "high",
                })
        return warnings

    def get_lessons(self) -> List[str]:
        """Extract all learned lessons."""
        return list(set(s.get("lesson", "") for s in self._session_shadows if s.get("lesson")))


# =============================================================================
# 8. CuriosityEngine: Surprise-Based Ranking
# =============================================================================

class CuriosityEngine:
    """
    Most RAG systems optimize for relevance: "does this match the query?"
    CuriosityEngine optimizes for SURPRISE: "would this be unexpected?"

    An entry is valuable not because it's similar to what we're doing,
    but because it CONNECTS two seemingly unrelated things.

    Example:
      - "VirtualAlloc at 0x140001000" → boring (expected)
      - "VirtualAlloc at 0x140001000 called from JPEG parser at 0x140020000"
        → SURPRISING (high curiosity)

    This is the difference between a search engine and a detective.
    """

    def __init__(self):
        self._co_occurrence: Dict[Tuple[str, str], int] = defaultdict(int)
        self._total_seen = 0

    def observe(self, entries: List[Dict[str, Any]]):
        """Learn co-occurrence patterns from entries."""
        for entry in entries:
            bridges = entry.get("bridges", [])
            if isinstance(bridges, str):
                try:
                    bridges = json.loads(bridges)
                except Exception:
                    bridges = []
            # Record all pairs
            for i, b1 in enumerate(bridges):
                for b2 in bridges[i+1:]:
                    pair = tuple(sorted([b1, b2]))
                    self._co_occurrence[pair] += 1
            self._total_seen += 1

    def surprise_score(self, entry: Dict[str, Any]) -> float:
        """
        Return how SURPRISING this entry is.
        High score = bridges that don't usually co-occur.
        """
        bridges = entry.get("bridges", [])
        if isinstance(bridges, str):
            try:
                bridges = json.loads(bridges)
            except Exception:
                bridges = []

        if len(bridges) < 2:
            return 0.0  # Single bridges can't be surprising

        # Compute average co-occurrence of all bridge pairs
        total_prob = 0.0
        count = 0
        for i, b1 in enumerate(bridges):
            for b2 in bridges[i+1:]:
                pair = tuple(sorted([b1, b2]))
                cooccur = self._co_occurrence.get(pair, 0)
                # Probability this pair co-occurs
                prob = cooccur / max(self._total_seen, 1)
                total_prob += prob
                count += 1

        avg_prob = total_prob / max(count, 1)
        # Surprise = inverse of probability
        # Low co-occurrence = high surprise
        surprise = 1.0 - avg_prob
        return surprise

    def get_surprising_entries(
        self,
        entries: List[Dict[str, Any]],
        topk: int = 3,
    ) -> List[Dict[str, Any]]:
        """Return the most surprising entries."""
        scored = []
        for entry in entries:
            score = self.surprise_score(entry)
            if score > 0.5:  # Only truly surprising things
                scored.append((score, entry))
        scored.sort(reverse=True, key=lambda x: x[0])
        return [
            {**entry, "surprise_score": round(score, 2)}
            for score, entry in scored[:topk]
        ]


# =============================================================================
# 9. EpisodicMemory: Time-Anchored Causal Events
# =============================================================================

class EpisodicMemory:
    """
    Semantic memory: "0x140001000 is crypto"
    Episodic memory: "At 14:32, after injecting context about 0x140001000,
                      the analyst renamed it to 'decrypt_buffer' and then
                      discovered 3 related functions in the next 10 minutes"

    Episodic memory captures CAUSALITY and TIMING. It's crucial for:
      - "What happened right before this discovery?"
      - "Did context injection X lead to breakthrough Y?"
      - "How long does it usually take to analyze crypto functions?"
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "episodic_memory.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._recent_episodes: List[Dict[str, Any]] = []

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    ts REAL,
                    event_type TEXT,
                    description TEXT,
                    bridges TEXT,
                    duration_ms INTEGER,
                    outcome TEXT
                )
            """)
            conn.commit()

    def record_episode(
        self,
        event_type: str,
        description: str,
        bridges: List[str],
        duration_ms: int = 0,
        outcome: str = "",
        session_id: Optional[str] = None,
    ):
        """
        Record a time-anchored event.

        event_type: "injection", "breakthrough", "dead_end", "pivot", "stuck"
        """
        episode = {
            "ts": time.time(),
            "event_type": event_type,
            "description": description,
            "bridges": bridges,
            "duration_ms": duration_ms,
            "outcome": outcome,
        }
        self._recent_episodes.append(episode)
        if len(self._recent_episodes) > 100:
            self._recent_episodes = self._recent_episodes[-100:]

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO episodes (session_id, ts, event_type, description, bridges, duration_ms, outcome) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), event_type, description,
                 json.dumps(bridges), duration_ms, outcome),
            )
            conn.commit()

    def get_causal_chain(
        self,
        bridge: str,
        window_seconds: float = 300,
    ) -> List[Dict[str, Any]]:
        """
        Get the causal chain around a bridge.
        "What happened before and after we learned about X?"
        """
        now = time.time()
        chain = []
        for ep in self._recent_episodes:
            if bridge in ep.get("bridges", []):
                if abs(now - ep["ts"]) < window_seconds:
                    chain.append(ep)
        # Sort by time
        chain.sort(key=lambda x: x["ts"])
        return chain

    def get_temporal_patterns(self) -> List[Dict[str, Any]]:
        """
        Detect temporal patterns:
          - "After injection X, breakthrough usually follows within 60s"
          - "Stuck periods last ~5 minutes on average"
        """
        patterns = []
        # Look for injection -> breakthrough pairs
        for i, ep in enumerate(self._recent_episodes):
            if ep["event_type"] == "injection":
                for j in range(i+1, min(i+10, len(self._recent_episodes))):
                    next_ep = self._recent_episodes[j]
                    if next_ep["event_type"] == "breakthrough":
                        gap = next_ep["ts"] - ep["ts"]
                        shared = set(ep.get("bridges", [])) & set(next_ep.get("bridges", []))
                        if shared:
                            patterns.append({
                                "type": "injection_leads_to_breakthrough",
                                "description": f"Context injection led to breakthrough {gap:.0f}s later",
                                "shared_bridges": list(shared),
                                "time_gap": gap,
                            })
                        break  # Only first breakthrough
        return patterns


# =============================================================================
# 10. MultiResolutionComposer: Hierarchical Context
# =============================================================================

class MultiResolutionComposer:
    """
    Provide context at multiple zoom levels simultaneously.

    Galaxy:   "This binary has 5 distinct behavioral clusters"
    System:   "The crypto cluster interacts with the network cluster via X"
    Planet:   "Function at 0x140001000 allocates memory and calls Y"
    Surface:  "Instruction at 0x14000105F moves 0x40 into rdx"

    The LLM can choose which resolution to focus on. This is how human
    analysts work — they zoom in and out constantly.
    """

    def compose(
        self,
        entries: List[Dict[str, Any]],
        current_addr: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compose multi-resolution context.
        """
        # Galaxy: high-level clusters
        apis = Counter()
        categories = Counter()
        for e in entries:
            bridges = e.get("bridges", [])
            if isinstance(bridges, str):
                try:
                    bridges = json.loads(bridges)
                except Exception:
                    bridges = []
            for b in bridges:
                if not b.startswith("0x") and not b.startswith("~"):
                    apis[b] += 1
            cat = e.get("category", "finding")
            categories[cat] += 1

        galaxy = {
            "level": "galaxy",
            "summary": f"{len(entries)} findings across {len(apis)} APIs and {len(categories)} categories",
            "top_apis": apis.most_common(5),
            "category_distribution": dict(categories),
        }

        # Solar system: interactions between top clusters
        interactions = []
        if len(entries) >= 2:
            # Find entries that share bridges (interactions)
            for i, e1 in enumerate(entries[:10]):
                for e2 in entries[i+1:11]:
                    b1 = set(e1.get("bridges", []))
                    b2 = set(e2.get("bridges", []))
                    shared = b1 & b2
                    if shared and len(shared) < len(b1 | b2):
                        interactions.append({
                            "between": [e1.get("title", "")[:30], e2.get("title", "")[:30]],
                            "shared_bridges": list(shared),
                        })

        solar_system = {
            "level": "solar_system",
            "interactions": interactions[:5],
        }

        # Planet: entries near current address
        planet_entries = []
        if current_addr and current_addr.startswith("0x"):
            try:
                curr_val = int(current_addr, 16)
                for e in entries:
                    addr = e.get("addr", "")
                    if addr and addr.startswith("0x"):
                        try:
                            val = int(addr, 16)
                            if abs(val - curr_val) < 0x10000:  # Within 64KB
                                planet_entries.append({
                                    "id": e.get("id", ""),
                                    "title": str(e.get("title", ""))[:60],
                                    "addr": addr,
                                    "distance": hex(abs(val - curr_val)),
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        planet = {
            "level": "planet",
            "nearby_findings": planet_entries[:5],
        }

        # Surface: current query details (provided by caller)
        surface = {
            "level": "surface",
            "note": "Detailed instruction-level context provided by current tool call",
        }

        return {
            "galaxy": galaxy,
            "solar_system": solar_system,
            "planet": planet,
            "surface": surface,
        }


# =============================================================================
# 11. CognitiveOrchestrator: Unified Interface
# =============================================================================

class CognitiveOrchestrator:
    """
    Combine ALL cognitive layers to produce context that is:
      - Relevant (bridge match)
      - Timely (temporal)
      - Pattern-aware (synthesized clusters)
      - Task-appropriate (inferred intent)
      - Narrative-coherent (fills story gaps)
      - Error-aware (avoids misleading context)
      - Coverage-aware (knows what's missing)
      - Failure-aware (learns from shadows)
      - Surprise-aware (injects the unexpected)
      - Causal (episodic memory)
      - Multi-resolution (hierarchical)
    """

    def __init__(self):
        self.narrative = NarrativeThread()
        self.patterns = PatternSynthesizer()
        self.tasks = TaskInference()
        self.errors = ErrorAttribution()
        self.actions = AnalystActionModel()
        self.void = VoidTracker()
        self.shadow = ShadowBlackboard()
        self.curiosity = CuriosityEngine()
        self.episodic = EpisodicMemory()
        self.multires = MultiResolutionComposer()

    def enrich_context(
        self,
        current_tool: str,
        current_action: str,
        payload: Any,
        working_memory: List[Dict[str, Any]],
        blackboard_entries: List[Dict[str, Any]],
        query_bridges: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Enrich working_memory with full cognitive stack.
        """
        # Record task
        self.tasks.record(current_tool, current_action)
        task = self.tasks.infer()

        # Add narrative chapter
        self.narrative.add_chapter(
            chapter_type="discovery" if current_tool in {"code", "data", "search"} else "pivot",
            title=f"{current_tool}.{current_action}",
            bridges=query_bridges or [],
        )

        # Record coverage
        for entry in working_memory:
            self.void.record_coverage(entry)

        # Learn from entries
        self.curiosity.observe(working_memory + blackboard_entries[:20])

        # Synthesize patterns
        synthesized = self.patterns.synthesize(working_memory + blackboard_entries[:20])

        # Get narrative gaps
        gaps = self.narrative.get_gaps()

        # Get voids (what's missing)
        voids = self.void.get_voids()

        # Get shadows (what went wrong)
        shadows = self.shadow.get_warnings(query_bridges or []) if query_bridges else []

        # Get surprising entries
        surprising = self.curiosity.get_surprising_entries(blackboard_entries[:50])

        # Get temporal patterns
        temporal = self.episodic.get_temporal_patterns()

        # Get multi-resolution context
        current_addr = None
        if isinstance(payload, dict):
            current_addr = str(payload.get("addr", ""))
        multires = self.multires.compose(blackboard_entries[:30], current_addr)

        return {
            "working_memory": working_memory,
            "synthesized_patterns": synthesized[:3],
            "narrative_gaps": gaps[:2],
            "inferred_task": {
                "name": task.get("task_name", "exploring"),
                "description": task.get("description", ""),
                "confidence": task.get("confidence", 0.0),
                "context_need": task.get("context_need", "overview"),
            },
            "analyst_action_summary": self.actions.get_action_stats(),
            "voids": voids[:3],  # What you haven't looked at
            "shadow_warnings": shadows[:2],  # Don't repeat these mistakes
            "surprising_findings": surprising,  # The unexpected
            "temporal_patterns": temporal[:2],  # What usually happens next
            "multi_resolution": multires,  # Galaxy / system / planet / surface
        }
