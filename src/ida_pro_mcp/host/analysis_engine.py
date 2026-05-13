"""
Analysis Engine — background pipeline that runs continuously per session.

Four stages share a single priority queue (next_target from blackboard):
  1. Classifier sweep  — BehaviorClassifier on unnamed functions → blackboard entries
  2. Contradiction monitor — cosine scan on every new write → flag conflicts
  3. Taint tracer      — IOC entries → forward data-flow → vuln entries
  4. Cross-session matcher — new embeddings → scan other sessions → match proposals

The engine is reactive: stages 2–4 are triggered by blackboard writes, not polling.
Stage 1 polls the function list on a slow timer.

Usage (from server.py):
    engine = AnalysisEngine(session_id, server_port, rpc_fn, notify_fn, bb_path)
    engine.start()
    engine.stop()
"""
from __future__ import annotations

import json
import math
import os
import struct
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional


# ── helpers ──────────────────────────────────────────────────────────────────

def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def _unpack(blob: bytes) -> List[float]:
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def _pack(v: List[float]) -> bytes:
    return struct.pack(f"{len(v)}f", *v)


# ── Proposal store ────────────────────────────────────────────────────────────

class ProposalStore:
    """
    Thread-safe in-memory + SQLite-backed proposal queue.

    Proposal types:
      rename_batch    — suggest renaming N functions
      annotation_batch — suggest adding comments to N functions
      hypothesis      — engine believes X about address Y
      cross_session   — N functions match a previous session
      vuln            — taint trace found a dangerous sink
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        import sqlite3
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY,
                    proposal_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT,
                    items TEXT,          -- JSON list of {addr, name, reason, ...}
                    confidence REAL DEFAULT 0.5,
                    created_at REAL,
                    status TEXT DEFAULT 'pending',  -- pending/accepted/rejected
                    accepted_ids TEXT,   -- JSON list of accepted item ids
                    session_id TEXT
                )
            """)
            conn.commit()

    def add(self, proposal_type: str, title: str, summary: str,
            items: List[Dict], confidence: float = 0.5,
            session_id: str = "") -> str:
        pid = uuid.uuid4().hex[:12]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?,?)",
                (pid, proposal_type, title, summary,
                 json.dumps(items), confidence, time.time(),
                 "pending", "[]", session_id)
            )
            conn.commit()
        return pid

    def list_pending(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id,proposal_type,title,summary,items,confidence,created_at,session_id "
                "FROM proposals WHERE status='pending' ORDER BY confidence DESC"
            ).fetchall()
        return [
            {"id": r[0], "proposal_type": r[1], "title": r[2], "summary": r[3],
             "items": json.loads(r[4] or "[]"), "confidence": r[5],
             "created_at": r[6], "session_id": r[7]}
            for r in rows
        ]

    def accept(self, proposal_id: str, scope: str = "all",
               selected_ids: Optional[List[str]] = None) -> Optional[Dict]:
        """Accept a proposal. Returns the proposal dict with accepted items."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id,proposal_type,title,items FROM proposals WHERE id=? AND status='pending'",
                (proposal_id,)
            ).fetchone()
            if not row:
                return None
            items = json.loads(row[3] or "[]")
            if scope == "selected" and selected_ids:
                accepted = [it for it in items if it.get("id") in selected_ids]
            else:
                accepted = items
            conn.execute(
                "UPDATE proposals SET status='accepted', accepted_ids=? WHERE id=?",
                (json.dumps([it.get("id") for it in accepted]), proposal_id)
            )
            conn.commit()
        return {"id": row[0], "proposal_type": row[1], "title": row[2],
                "accepted_items": accepted}

    def reject(self, proposal_id: str, bb_path: str = "") -> bool:
        """Reject a proposal and write a dead_end entry to the blackboard."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id,proposal_type,title,items FROM proposals WHERE id=? AND status='pending'",
                (proposal_id,)
            ).fetchone()
            if not row:
                return False
            conn.execute(
                "UPDATE proposals SET status='rejected' WHERE id=?",
                (proposal_id,)
            )
            conn.commit()

        # Rejection feedback: write dead_end entries so engine doesn't re-propose
        if bb_path:
            try:
                items = json.loads(row[3] or "[]")
                import sqlite3 as _sq3
                with _sq3.connect(bb_path, timeout=5) as bconn:
                    bconn.execute("PRAGMA journal_mode=WAL")
                    for item in items[:10]:
                        addr = item.get("addr", "")
                        if not addr:
                            continue
                        # Check if dead_end already exists for this addr
                        existing = bconn.execute(
                            "SELECT id FROM blackboard WHERE addr=? AND category='dead_end'",
                            (addr,)
                        ).fetchone()
                        if existing:
                            continue
                        bconn.execute(
                            "INSERT OR IGNORE INTO blackboard "
                            "(id, category, title, content, addr, confidence, "
                            "created_at, updated_at, q_value, source, source_type, "
                            "resolved, tags, evidence) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                uuid.uuid4().hex[:8], "dead_end",
                                f"Rejected: {row[2][:60]}",
                                f"Proposal '{row[1]}' was rejected by LLM",
                                addr, 0.1,
                                time.time(), time.time(), 0.1,
                                "engine.rejected", "engine_rejected",
                                1,  # resolved=1 so it's excluded from next_target
                                json.dumps(["rejected", row[1]]),
                                json.dumps([{"type": "rejection", "value": proposal_id,
                                             "weight": 0.0, "ts": time.time()}]),
                            )
                        )
                    bconn.commit()
            except Exception:
                pass
        return True

    def count_pending(self) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM proposals WHERE status='pending'"
            ).fetchone()[0]


# ── Analysis Engine ───────────────────────────────────────────────────────────

class AnalysisEngine:
    """
    Background analysis engine for a single session.

    rpc_fn(tool, args) → dict   — calls IDA tool via TCP RPC
    notify_fn(notification)     — sends MCP notification to client
    bb_path                     — path to blackboard SQLite file
    proposals_path              — path to proposals SQLite file
    embeddings_dir              — directory containing *.embeddings.db files
    """

    # Sinks that indicate a dangerous data-flow endpoint
    DANGEROUS_SINKS = {
        "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "vsprintf",
        "gets", "scanf", "system", "exec", "execve", "popen",
        "WinExec", "ShellExecute", "CreateProcess",
    }

    # Sources that indicate user-controlled input
    TAINT_SOURCES = {
        "recv", "recvfrom", "read", "fread", "fgets", "gets",
        "scanf", "sscanf", "getenv", "RegQueryValueEx",
        "ReadFile", "WSARecv",
    }

    def __init__(
        self,
        session_id: str,
        rpc_fn: Callable[[str, Dict], Dict],
        notify_fn: Callable[[Dict], None],
        bb_path: str,
        proposals_path: str,
        embeddings_dir: str = "",
    ):
        self.session_id = session_id
        self._rpc = rpc_fn
        self._notify = notify_fn
        self._bb_path = bb_path
        self._proposals_path = proposals_path
        self._embeddings_dir = embeddings_dir or os.path.dirname(bb_path)

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proposals = ProposalStore(proposals_path)

        # Track what we've already processed to avoid re-work
        self._classified: set = set()
        self._checked_contradictions: set = set()
        self._tainted: set = set()
        self._cross_checked: set = set()

        # KG / narrative / gap state
        self._kg = None          # KnowledgeGraph, lazy-init
        self._binary_type = ""   # detected once
        self._gaps_seeded = False
        self._last_narrative_ts = 0.0
        self._narrative_interval = 120.0  # regenerate every 2 min

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True,
            name=f"analysis-engine-{self.session_id[:8]}"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    # ── main loop ─────────────────────────────────────────────────────────────

    def _loop(self):
        """Interleave all stages. Each iteration does one unit of work."""
        sweep_interval = 60
        entropy_interval = 120
        tag_interval = 300
        kg_interval = 90       # KG analysis every 90s
        last_sweep = 0.0
        last_entropy = 0.0
        last_tag = 0.0
        last_kg = 0.0

        while not self._stop.is_set():
            try:
                now = time.time()

                # Reactive stages
                self._stage_contradiction_monitor()
                self._stage_cross_session_matcher()
                self._stage_taint_tracer()
                self._stage_crawler_feed()

                # Periodic stages
                if now - last_sweep >= sweep_interval:
                    self._stage_classifier_sweep()
                    last_sweep = time.time()

                if now - last_entropy >= entropy_interval:
                    self._stage_entropy_scan()
                    last_entropy = time.time()

                if now - last_tag >= tag_interval:
                    self._stage_auto_tag_propagate()
                    last_tag = time.time()

                if now - last_kg >= kg_interval:
                    self._stage_knowledge_graph()
                    last_kg = time.time()

            except Exception:
                pass

            self._stop.wait(timeout=15)

    # ── Stage 1: Classifier sweep ─────────────────────────────────────────────

    def _stage_classifier_sweep(self):
        """Classify all unnamed functions, batch-propose renames."""
        try:
            result = self._rpc("data", {"action": "functions", "count": 500})
            funcs = result.get("functions", []) if isinstance(result, dict) else []
        except Exception:
            return

        unnamed = [
            f for f in funcs
            if f.get("name", "").startswith("sub_") or f.get("name", "").startswith("j_")
        ]
        if not unnamed:
            return

        classifier = self._get_classifier()
        if not classifier:
            return

        batch: List[Dict] = []
        for fn in unnamed:
            addr = fn.get("start_ea") or fn.get("addr")
            if not addr or addr in self._classified:
                continue
            try:
                dec = self._rpc("code", {"action": "decompile", "addr": hex(addr)})
                pseudo = dec.get("pseudocode", "") if isinstance(dec, dict) else ""
                if not pseudo:
                    continue
                tags = classifier.classify(pseudo)
                if not tags:
                    continue
                top_tag = tags[0]
                confidence = 0.55 + 0.1 * len(tags)  # more tags = more confident
                suggested_name = f"{top_tag}_{hex(addr)[2:]}"
                batch.append({
                    "id": uuid.uuid4().hex[:8],
                    "addr": hex(addr),
                    "current_name": fn.get("name", ""),
                    "suggested_name": suggested_name,
                    "behavior_tags": tags,
                    "confidence": round(min(confidence, 0.95), 3),
                    "reason": f"BehaviorClassifier: {', '.join(tags)}",
                })
                self._classified.add(addr)
            except Exception:
                self._classified.add(addr)  # don't retry failures
                continue

        if not batch:
            return

        # Group by dominant tag for cleaner proposals
        by_tag: Dict[str, List] = {}
        for item in batch:
            tag = item["behavior_tags"][0]
            by_tag.setdefault(tag, []).append(item)

        for tag, items in by_tag.items():
            if len(items) < 2:
                continue  # single-function proposals are noise
            avg_conf = sum(i["confidence"] for i in items) / len(items)
            pid = self._proposals.add(
                proposal_type="rename_batch",
                title=f"Rename {len(items)} {tag} functions",
                summary=(
                    f"BehaviorClassifier identified {len(items)} unnamed functions "
                    f"with behavior '{tag}'. Suggested names based on tag + address."
                ),
                items=items,
                confidence=round(avg_conf, 3),
                session_id=self.session_id,
            )
            self._push_proposal_notification(pid, "rename_batch",
                f"Found {len(items)} unnamed {tag} functions — rename batch ready",
                avg_conf)

        # Also write a blackboard region entry if we found a cluster
        self._write_cluster_regions(by_tag)

    def _write_cluster_regions(self, by_tag: Dict[str, List]):
        """If a tag cluster spans a contiguous address range, write a region entry."""
        store = self._bb_store()
        if not store:
            return
        for tag, items in by_tag.items():
            if len(items) < 3:
                continue
            addrs = []
            for it in items:
                try:
                    addrs.append(int(it["addr"], 16))
                except Exception:
                    pass
            if not addrs:
                continue
            lo, hi = min(addrs), max(addrs)
            span = hi - lo
            if span > 0x100000:  # > 1MB — not a cluster
                continue
            existing = store.list(category="region", addr=hex(lo))
            if existing:
                continue
            store.write(
                f"{tag} cluster ({len(items)} functions)",
                category="region",
                addr=hex(lo), addr_end=hex(hi),
                tags=[tag, "engine", "cluster"],
                confidence=0.7,
                source="engine",
            )
            self._push_resource_updated("ida://blackboard/regions")
            self._push_resource_updated("ida://state")

    # ── Stage 2: Contradiction monitor ────────────────────────────────────────

    def _stage_contradiction_monitor(self):
        """Scan new blackboard entries for contradictions with existing ones."""
        store = self._bb_store()
        if not store:
            return

        # Get all entries with vectors that we haven't checked yet
        try:
            import sqlite3
            with sqlite3.connect(self._bb_path, timeout=5) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                rows = conn.execute(
                    "SELECT id, title, content, category, addr, vector, confidence "
                    "FROM blackboard WHERE vector IS NOT NULL AND contradicted=0 AND resolved=0"
                ).fetchall()
        except Exception:
            return

        unchecked = [r for r in rows if r[0] not in self._checked_contradictions]
        if not unchecked:
            return

        # Build lookup of all vectors
        all_vecs = {r[0]: (r, _unpack(r[5])) for r in rows if r[5]}

        for row in unchecked:
            eid, title, content, category, addr, blob, conf = row
            self._checked_contradictions.add(eid)
            if not blob:
                continue
            vec = _unpack(blob)

            for other_id, (other_row, other_vec) in all_vecs.items():
                if other_id == eid:
                    continue
                sim = _cosine(vec, other_vec)
                if sim < 0.80:
                    continue
                # High similarity but different category or conflicting title
                other_cat = other_row[3]
                other_title = other_row[1]
                if category == other_cat:
                    continue  # same category — not a contradiction
                # Different categories with high semantic similarity = potential conflict
                reason = (
                    f"Entry '{title}' (cat={category}) is semantically similar "
                    f"(sim={sim:.2f}) to '{other_title}' (cat={other_cat}) "
                    f"but has a different classification."
                )
                # Write a hypothesis about the contradiction
                store.write(
                    f"Contradiction: {title[:40]} vs {other_title[:40]}",
                    category="hypothesis",
                    addr=addr or other_row[4],
                    content=reason,
                    tags=["contradiction", "engine", category, other_cat],
                    confidence=round(sim * 0.8, 3),
                    source="engine",
                )
                self._push_resource_updated("ida://state")
                self._notify({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "warning",
                        "data": {
                            "type": "contradiction",
                            "message": f"Contradiction detected: {title[:50]} vs {other_title[:50]}",
                            "similarity": round(sim, 3),
                            "addr": addr,
                            "reason": reason,
                        },
                    },
                })
                break  # one contradiction per entry is enough

    # ── Stage 3: Taint tracer ─────────────────────────────────────────────────

    def _stage_taint_tracer(self):
        """Follow IOC/source entries forward through xrefs to find dangerous sinks."""
        store = self._bb_store()
        if not store:
            return

        # Find IOC entries that are taint sources (network recv, file read, etc.)
        iocs = store.list(category="ioc", include_resolved=False)
        sources = [
            e for e in iocs
            if e.get("addr") and e["id"] not in self._tainted
            and any(s in (e.get("ioc_value") or e.get("title") or "").lower()
                    for s in self.TAINT_SOURCES)
        ]

        # Also check for imports that are taint sources
        try:
            imports_result = self._rpc("data", {"action": "imports", "count": 200})
            imports = imports_result.get("imports", []) if isinstance(imports_result, dict) else []
            for imp in imports:
                name = imp.get("name", "")
                if name in self.TAINT_SOURCES:
                    addr = imp.get("ea") or imp.get("addr")
                    if addr:
                        # Synthesize a source entry
                        sources.append({
                            "id": f"import_{name}",
                            "addr": hex(addr) if isinstance(addr, int) else addr,
                            "title": f"Import: {name}",
                            "ioc_value": name,
                        })
        except Exception:
            pass

        for source in sources[:5]:  # process at most 5 per cycle
            self._tainted.add(source["id"])
            self._trace_taint_from(source, store)

    def _trace_taint_from(self, source: Dict, store):
        """BFS from source address through xrefs, looking for dangerous sinks."""
        start_addr = source.get("addr", "")
        if not start_addr:
            return

        visited: set = set()
        queue = [start_addr]
        depth = 0
        max_depth = 4

        while queue and depth < max_depth:
            next_queue = []
            for addr in queue[:10]:  # cap breadth
                if addr in visited:
                    continue
                visited.add(addr)
                try:
                    # Get callers of this address (who calls this source?)
                    xrefs = self._rpc("code", {"action": "callers", "addr": addr})
                    callers = xrefs.get("callers", []) if isinstance(xrefs, dict) else []
                    for caller in callers[:5]:
                        caller_addr = caller.get("addr") or caller.get("ea")
                        if not caller_addr:
                            continue
                        caller_name = caller.get("name", "")
                        # Check if this caller is a dangerous sink
                        if any(sink in caller_name for sink in self.DANGEROUS_SINKS):
                            self._report_taint_sink(source, caller, store, depth + 1)
                        else:
                            next_queue.append(
                                hex(caller_addr) if isinstance(caller_addr, int) else caller_addr
                            )
                except Exception:
                    pass
            queue = next_queue
            depth += 1

    def _report_taint_sink(self, source: Dict, sink: Dict, store, depth: int):
        """Write a vuln entry and push a notification for a taint path."""
        sink_name = sink.get("name", "unknown")
        sink_addr = sink.get("addr") or sink.get("ea", "?")
        source_title = source.get("title", source.get("ioc_value", "?"))
        confidence = max(0.5, 0.9 - depth * 0.1)

        title = f"Taint: {source_title} → {sink_name}"
        content = (
            f"Data from '{source_title}' (addr={source.get('addr')}) "
            f"reaches dangerous sink '{sink_name}' at {hex(sink_addr) if isinstance(sink_addr, int) else sink_addr} "
            f"in {depth} hop(s). Potential buffer overflow or command injection."
        )

        # Don't duplicate
        existing = store.list(category="vuln", addr=source.get("addr"))
        if any(sink_name in e.get("title", "") for e in existing):
            return

        eid = store.write(
            title, category="vuln",
            addr=source.get("addr"),
            content=content,
            tags=["taint", "engine", sink_name],
            confidence=confidence,
            source="engine",
        )

        # Add to proposals
        pid = self._proposals.add(
            proposal_type="hypothesis",
            title=title,
            summary=content,
            items=[{"id": eid, "addr": source.get("addr"),
                    "sink": sink_name, "depth": depth}],
            confidence=confidence,
            session_id=self.session_id,
        )

        self._push_resource_updated("ida://state")
        self._push_resource_updated("ida://proposals")
        self._notify({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": "warning",
                "data": {
                    "type": "taint_sink",
                    "message": title,
                    "source": source.get("addr"),
                    "sink": sink_name,
                    "sink_addr": hex(sink_addr) if isinstance(sink_addr, int) else str(sink_addr),
                    "depth": depth,
                    "confidence": confidence,
                    "proposal_id": pid,
                },
            },
        })

    # ── Stage 4: Cross-session matcher ────────────────────────────────────────

    def _stage_cross_session_matcher(self):
        """Compare new embeddings against all other session embedding indexes."""
        try:
            import sqlite3
            with sqlite3.connect(self._bb_path, timeout=5) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                new_entries = conn.execute(
                    "SELECT id, title, addr, vector FROM blackboard "
                    "WHERE vector IS NOT NULL AND source != 'cross_session'"
                ).fetchall()
        except Exception:
            return

        unchecked = [r for r in new_entries if r[0] not in self._cross_checked]
        if not unchecked:
            return

        # Find other session embedding DBs
        other_dbs = self._find_other_embedding_dbs()
        if not other_dbs:
            for r in unchecked:
                self._cross_checked.add(r[0])
            return

        store = self._bb_store()
        if not store:
            return

        for row in unchecked[:10]:  # cap per cycle
            eid, title, addr, blob = row
            self._cross_checked.add(eid)
            if not blob:
                continue
            vec = _unpack(blob)
            self._match_against_other_sessions(eid, title, addr, vec, other_dbs, store)

    def _find_other_embedding_dbs(self) -> List[str]:
        """Find *.embeddings.db files from other sessions."""
        results = []
        try:
            for fname in os.listdir(self._embeddings_dir):
                if fname.endswith(".embeddings.db"):
                    full = os.path.join(self._embeddings_dir, fname)
                    # Skip the current session's db
                    if self.session_id[:8].lower() in fname.lower():
                        continue
                    results.append(full)
        except Exception:
            pass
        return results

    def _match_against_other_sessions(
        self, eid: str, title: str, addr: str,
        vec: List[float], other_dbs: List[str], store
    ):
        """Scan other session embedding DBs for similar functions."""
        import sqlite3
        best_sim = 0.85  # threshold
        best_match = None
        best_db = None

        for db_path in other_dbs:
            try:
                with sqlite3.connect(db_path, timeout=3) as conn:
                    rows = conn.execute(
                        "SELECT addr, name, vector FROM embeddings WHERE vector IS NOT NULL"
                    ).fetchall()
                for r in rows:
                    if not r[2]:
                        continue
                    other_vec = _unpack(r[2])
                    sim = _cosine(vec, other_vec)
                    if sim > best_sim:
                        best_sim = sim
                        best_match = {"addr": r[0], "name": r[1], "sim": sim}
                        best_db = os.path.basename(db_path)
            except Exception:
                continue

        if not best_match:
            return

        match_name = best_match["name"] or f"sub_{best_match['addr']}"
        content = (
            f"Function at {addr} ('{title}') matches '{match_name}' "
            f"from session '{best_db}' with similarity {best_match['sim']:.3f}."
        )

        # Don't duplicate
        existing = store.list(category="cross_session", addr=addr)
        if existing:
            return

        store.write(
            f"Cross-session match: {match_name}",
            category="cross_session",
            addr=addr,
            content=content,
            tags=["cross_session", "engine", match_name],
            confidence=round(best_match["sim"], 3),
            source="cross_session",
        )

        pid = self._proposals.add(
            proposal_type="cross_session",
            title=f"Import name '{match_name}' from previous session?",
            summary=content,
            items=[{
                "id": uuid.uuid4().hex[:8],
                "addr": addr,
                "suggested_name": match_name,
                "source_session": best_db,
                "similarity": best_match["sim"],
            }],
            confidence=round(best_match["sim"], 3),
            session_id=self.session_id,
        )

        self._push_resource_updated("ida://proposals")
        self._push_resource_updated("ida://state")
        self._notify({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": "info",
                "data": {
                    "type": "cross_session_match",
                    "message": f"Function at {addr} matches '{match_name}' from {best_db} (sim={best_match['sim']:.3f})",
                    "addr": addr,
                    "matched_name": match_name,
                    "source_session": best_db,
                    "similarity": best_match["sim"],
                    "proposal_id": pid,
                },
            },
        })

    # ── Stage 5: Crawler feed ─────────────────────────────────────────────────

    def _stage_crawler_feed(self):
        """
        Pull pending crawler proposals into the engine's blackboard as
        low-confidence entries so next_target can rank them.

        The crawler proposes via _BackgroundCrawler._pending. We consume
        high-confidence ones automatically (confidence > 0.75) and write
        them as 'hypothesis' entries. Lower-confidence ones stay as proposals
        for the LLM to review.
        """
        try:
            import importlib.util, os as _os
            path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "ida_mcp", "tools", "blackboard.py"
            )
            spec = importlib.util.spec_from_file_location("_engine_bb_cf", _os.path.abspath(path))
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                  "idawrite": lambda f: f, "IDAError": Exception})
            spec.loader.exec_module(mod)
            crawler = mod._BackgroundCrawler.instance()
        except Exception:
            return

        pending = list(crawler._pending.values())
        auto_accepted = []
        for p in pending:
            conf = p.get("confidence", 0.5)
            if conf < 0.75:
                continue  # leave for LLM review
            pid = p.get("proposal_id", "")
            addr = p.get("addr", "")
            if not addr:
                continue
            # Check if already in blackboard
            store = self._bb_store()
            if store and store.list(addr=addr, category="hypothesis"):
                crawler._pending.pop(pid, None)
                continue
            # Auto-accept high-confidence proposals
            eid = crawler.accept(pid)
            if eid and store:
                store.update(eid, source_type="crawler",
                             evidence=[{"type": "crawler", "value": p.get("title", ""),
                                        "weight": conf, "ts": time.time()}])
                auto_accepted.append(addr)

        if auto_accepted:
            self._push_resource_updated("ida://state")
            self._push_resource_updated("ida://blackboard/next_target")

    # ── Stage 6: Entropy scan ─────────────────────────────────────────────────

    def _stage_entropy_scan(self):
        """
        Compute byte entropy for each segment. High-entropy regions (>6.5)
        are likely crypto, packed, or compressed — write as region entries.
        """
        try:
            segs_result = self._rpc("idb", {"action": "segments"})
            segs = segs_result.get("segments", []) if isinstance(segs_result, dict) else []
        except Exception:
            return

        store = self._bb_store()
        if not store:
            return

        for seg in segs[:20]:  # cap to avoid slow scans
            name = seg.get("name") or seg.get("segment_name", "")
            start = seg.get("start_ea") or seg.get("start")
            end = seg.get("end_ea") or seg.get("end")
            if not (start and end):
                continue
            size = (end - start) if isinstance(end, int) and isinstance(start, int) else 0
            if size <= 0 or size > 0x100000:  # skip > 1MB
                continue

            try:
                mem_result = self._rpc("memory", {"action": "read",
                                                   "addr": hex(start) if isinstance(start, int) else start,
                                                   "size": min(size, 4096)})
                raw = mem_result.get("bytes") or mem_result.get("data", "")
                if not raw:
                    continue
                # Decode hex string if needed
                if isinstance(raw, str):
                    try:
                        raw = bytes.fromhex(raw.replace(" ", ""))
                    except Exception:
                        continue
                entropy = self._byte_entropy(raw)
            except Exception:
                continue

            if entropy < 6.5:
                continue

            addr_hex = hex(start) if isinstance(start, int) else str(start)
            addr_end_hex = hex(end) if isinstance(end, int) else str(end)

            # Don't duplicate
            existing = store.list(category="region", addr=addr_hex)
            if existing:
                # Update entropy value
                store.update(existing[0]["id"], entropy=entropy)
                continue

            eid = store.write(
                f"High-entropy region: {name} (entropy={entropy:.2f})",
                category="region",
                addr=addr_hex, addr_end=addr_end_hex,
                tags=["entropy", "engine", "crypto_candidate"],
                confidence=min(0.95, (entropy - 6.5) / 1.5 * 0.5 + 0.5),
                source="engine", source_type="engine_entropy",
                entropy=entropy,
                evidence=[{"type": "entropy", "value": f"{entropy:.3f}",
                           "weight": min(1.0, (entropy - 6.5) / 1.5),
                           "ts": time.time()}],
            )
            self._push_resource_updated("ida://state")
            self._notify({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": "info",
                    "data": {
                        "type": "high_entropy_region",
                        "message": f"High-entropy region found: {name} at {addr_hex} (entropy={entropy:.2f})",
                        "addr": addr_hex,
                        "entropy": entropy,
                        "segment": name,
                    },
                },
            })

    def _byte_entropy(self, data: bytes) -> float:
        """Shannon entropy of a byte sequence, 0–8."""
        import math
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        entropy = 0.0
        for c in counts:
            if c:
                p = c / n
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    # ── Stage 7: Auto-tag propagation ─────────────────────────────────────────

    def _stage_auto_tag_propagate(self):
        """Propagate tags from high-confidence entries to same-address entries."""
        store = self._bb_store()
        if not store:
            return
        updated = store.auto_tag_propagate()
        if updated > 0:
            self._push_resource_updated("ida://state")

    # ── Stage 8: Knowledge graph ──────────────────────────────────────────────

    def _stage_knowledge_graph(self):
        """
        Run all KG analysis sub-stages:
          a) Detect binary type + seed gaps (once)
          b) System discovery from call graph clusters
          c) Struct inference from offset access patterns
          d) State machine detection
          e) Peripheral detection from MMIO accesses
          f) Attack surface mapping
          g) Try to fill open gaps
          h) Regenerate narrative if due
        """
        kg = self._get_kg()
        store = self._bb_store()
        if not kg or not store:
            return

        # a) Seed gaps once
        if not self._gaps_seeded:
            try:
                from .gap_engine import GapEngine
                ge = GapEngine(kg)
                if not self._binary_type:
                    self._binary_type = ge.detect_binary_type(store)
                ge.seed_gaps(self._binary_type)
                self._gaps_seeded = True
            except Exception:
                pass

        # b) System discovery
        self._kg_discover_systems(kg, store)

        # c) Struct inference
        self._kg_infer_structs(kg, store)

        # d) State machine detection
        self._kg_detect_state_machines(kg, store)

        # e) Peripheral detection
        self._kg_detect_peripherals(kg, store)

        # f) Attack surface
        self._kg_map_attack_surface(kg, store)

        # g) Fill gaps
        try:
            from .gap_engine import GapEngine
            GapEngine(kg).try_fill_gaps(store)
        except Exception:
            pass

        # h) Narrative
        now = time.time()
        if now - self._last_narrative_ts >= self._narrative_interval:
            self._regenerate_narrative(kg, store)
            self._last_narrative_ts = now

        self._push_resource_updated("ida://state")

    def _kg_discover_systems(self, kg, store):
        """
        Discover systems by clustering blackboard entries with the same tags.

        A system is a group of ≥3 functions sharing a dominant behavior tag
        (e.g. 'crypto_symmetric', 'network_http') that are connected by xrefs.
        """
        entries = store.list(limit=500, include_resolved=False)
        # Group by dominant tag
        tag_groups: Dict[str, List[str]] = {}
        for e in entries:
            addr = e.get("addr", "")
            if not addr:
                continue
            tags = [t for t in e.get("tags", [])
                    if t not in ("manual", "engine", "crawler", "rejected",
                                 "entropy", "cluster", "xref", "seed")]
            if not tags:
                continue
            dominant = tags[0]
            tag_groups.setdefault(dominant, []).append(addr)

        existing_systems = {s["name"] for s in kg.list_systems()}

        for tag, addrs in tag_groups.items():
            if len(addrs) < 3:
                continue
            sys_name = f"{tag} subsystem"
            if sys_name in existing_systems:
                # Update members
                for s in kg.list_systems():
                    if s["name"] == sys_name:
                        new_members = list(set(s["members"]) | set(addrs))
                        if len(new_members) != len(s["members"]):
                            kg.update_system(s["id"], members=new_members,
                                             coverage_pct=min(100.0, len(new_members) * 10))
                        break
                continue

            # New system
            sid = kg.add_system(
                name=sys_name,
                members=addrs,
                description=f"Functions classified as {tag}",
                tags=[tag],
                confidence=0.6,
            )
            self._notify({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": "info",
                    "data": {
                        "type": "system_discovered",
                        "message": f"System discovered: {sys_name} ({len(addrs)} functions)",
                        "system_id": sid,
                        "members": addrs[:5],
                    },
                },
            })
            existing_systems.add(sys_name)

    def _kg_infer_structs(self, kg, store):
        """
        Infer data structures from data_flow entries.

        If multiple data_flow entries at different addresses reference the same
        register with different offsets, they likely access the same struct.
        """
        df_entries = store.list(category="data_flow", limit=200, include_resolved=True)
        if len(df_entries) < 3:
            return

        # Group by register name
        reg_groups: Dict[str, List[Dict]] = {}
        for e in df_entries:
            reg = e.get("register", "")
            if reg:
                reg_groups.setdefault(reg, []).append(e)

        for reg, entries in reg_groups.items():
            if len(entries) < 3:
                continue
            # Extract offsets from reg_type field (e.g. "wifi_frame_t+0x14")
            offsets = []
            for e in entries:
                rt = e.get("reg_type", "")
                import re as _re
                m = _re.search(r'\+0x([0-9a-f]+)', rt, _re.I)
                if m:
                    offsets.append(int(m.group(1), 16))

            if len(offsets) < 2:
                continue

            # Check if this matches an existing struct
            existing = kg.find_struct_by_offset_pattern(offsets, threshold=0.5)
            if existing:
                # Record new access sites
                for e in entries:
                    if e.get("addr"):
                        kg.record_struct_access(existing["id"], e["addr"],
                                                "read", offsets[0] if offsets else 0)
                continue

            # Infer new struct
            members = [{"offset": o, "size": 4, "type": "unknown",
                        "name": f"field_{o:03x}", "evidence": "data_flow"}
                       for o in sorted(set(offsets))]
            struct_name = f"struct_{reg}_t"
            existing_names = {s["name"] for s in kg.list_structs()}
            if struct_name not in existing_names:
                kg.add_struct(
                    name=struct_name,
                    members=members,
                    size_bytes=max(offsets) + 4 if offsets else 0,
                    confidence=0.5,
                )

    def _kg_detect_state_machines(self, kg, store):
        """
        Detect state machines from blackboard entries tagged 'state_machine'
        or from data_flow entries that write to a global.
        """
        # Look for entries that mention state variables
        entries = store.list(limit=200, include_resolved=False)
        state_vars: Dict[str, List[Dict]] = {}
        for e in entries:
            tags = e.get("tags", [])
            if "state_machine" in tags or "state_var" in tags:
                addr = e.get("addr", "")
                if addr:
                    state_vars.setdefault(addr, []).append(e)

        existing_vars = {sm.get("state_var") for sm in kg.list_state_machines()}

        for var_addr, entries_list in state_vars.items():
            if var_addr in existing_vars:
                continue
            # Infer state machine name from tags
            all_tags = []
            for e in entries_list:
                all_tags.extend(e.get("tags", []))
            name_tags = [t for t in all_tags
                         if t not in ("state_machine", "state_var", "engine", "manual")]
            sm_name = f"{name_tags[0]} state machine" if name_tags else f"state machine @ {var_addr}"

            kg.add_state_machine(
                name=sm_name,
                state_var=var_addr,
                confidence=0.55,
            )

    def _kg_detect_peripherals(self, kg, store):
        """
        Detect peripherals from high-entropy region entries and IOC entries
        that reference MMIO-like addresses (aligned, high addresses).
        """
        regions = store.list(category="region", include_resolved=True, limit=100)
        for r in regions:
            addr = r.get("addr", "")
            if not addr:
                continue
            try:
                addr_int = int(addr, 16)
            except Exception:
                continue
            # MMIO heuristic: address > 0x40000000 and 4KB-aligned
            if addr_int < 0x40000000:
                continue
            if addr_int % 0x1000 != 0:
                continue
            # Infer peripheral type from tags/title
            title = r.get("title", "").lower()
            tags = r.get("tags", [])
            ptype = "unknown"
            if any(w in title for w in ("uart", "serial", "usart")):
                ptype = "uart"
            elif any(w in title for w in ("spi", "qspi")):
                ptype = "spi"
            elif any(w in title for w in ("dma",)):
                ptype = "dma"
            elif any(w in title for w in ("aes", "crypto", "cipher")):
                ptype = "crypto"
            elif any(w in title for w in ("timer", "pwm", "rtc")):
                ptype = "timer"
            elif any(w in title for w in ("gpio", "pin")):
                ptype = "gpio"
            elif "entropy" in tags:
                ptype = "crypto"  # high-entropy MMIO region → likely crypto accelerator

            kg.add_peripheral(
                base_addr=addr,
                name=r.get("title", f"peripheral @ {addr}"),
                periph_type=ptype,
                confidence=0.5,
            )

    def _kg_map_attack_surface(self, kg, store):
        """
        Map attack surface from IOC entries and vuln entries.
        """
        iocs = store.list(category="ioc", include_resolved=False, limit=50)
        existing_eps = {a["entry_point"] for a in kg.list_attack_surface()}

        for ioc in iocs:
            addr = ioc.get("addr", "")
            if not addr or addr in existing_eps:
                continue
            ioc_type = ioc.get("ioc_type", "")
            # Determine reachability
            if ioc_type in ("ip_port", "url", "domain"):
                reachable = "air_unauthenticated"
                input_type = "network_packet"
            elif ioc_type in ("crypto_key", "crypto_iv"):
                reachable = "air_authenticated"
                input_type = "encrypted_data"
            else:
                reachable = "unknown"
                input_type = "unknown"

            kg.add_attack_surface(
                entry_point=addr,
                name=ioc.get("title", ""),
                reachable_from=reachable,
                input_type=input_type,
                confidence=ioc.get("confidence", 0.5),
            )
            existing_eps.add(addr)

        # Vuln entries → update attack surface with known_vulns
        vulns = store.list(category="vuln", include_resolved=False, limit=20)
        for vuln in vulns:
            addr = vuln.get("addr", "")
            if not addr:
                continue
            for as_entry in kg.list_attack_surface():
                if as_entry["entry_point"] == addr:
                    known = as_entry.get("known_vulns", [])
                    if vuln["id"] not in known:
                        known.append(vuln["id"])
                        kg.update_attack_surface(as_entry["id"],
                                                  known_vulns=known,
                                                  fuzz_priority=min(0.99, as_entry.get("fuzz_priority", 0.5) + 0.2))

    def _regenerate_narrative(self, kg, store):
        """Generate narrative and write it to blackboard as a 'narrative' entry."""
        try:
            from .narrative_engine import NarrativeEngine
            ne = NarrativeEngine(kg, store)
            # Get binary meta from a recent idb call if possible
            try:
                meta = self._rpc("idb", {"action": "meta"})
            except Exception:
                meta = {}
            text = ne.generate(binary_meta=meta)
            if not text.strip():
                return

            # Write/update the narrative entry in blackboard
            existing = store.list(category="narrative", limit=1, include_resolved=True)
            if existing:
                store.update(existing[0]["id"], content=text, title="Analysis Narrative")
            else:
                store.write(
                    "Analysis Narrative",
                    content=text,
                    category="narrative",
                    confidence=1.0,
                    source="engine",
                    source_type="engine_narrative",
                    embed=False,
                )
            self._push_resource_updated("ida://state")
        except Exception:
            pass

    def _get_kg(self):
        """Lazy-init KnowledgeGraph."""
        if self._kg is None:
            try:
                from .knowledge_graph import KnowledgeGraph
                self._kg = KnowledgeGraph(self._bb_path)
            except Exception:
                pass
        return self._kg

    # ── helpers ───────────────────────────────────────────────────────────────

    def _bb_store(self):
        try:
            import importlib.util
            path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "ida_mcp", "tools", "blackboard.py"
            )
            spec = importlib.util.spec_from_file_location("_engine_bb", path)
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                  "idawrite": lambda f: f, "IDAError": Exception})
            spec.loader.exec_module(mod)
            return mod.BlackboardStore(db_path=self._bb_path)
        except Exception:
            return None

    def _get_classifier(self):
        try:
            from .intelligence import BehaviorClassifier
            return BehaviorClassifier()
        except Exception:
            return None

    def _push_resource_updated(self, uri: str):
        self._notify({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": uri},
        })

    def _push_proposal_notification(self, pid: str, ptype: str, message: str, confidence: float):
        self._notify({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": "info",
                "data": {
                    "type": "proposal_ready",
                    "proposal_type": ptype,
                    "proposal_id": pid,
                    "message": message,
                    "confidence": confidence,
                    "action": "Read ida://proposals to review and accept/reject",
                },
            },
        })

    # ── public API for server ─────────────────────────────────────────────────

    @property
    def proposals(self) -> ProposalStore:
        return self._proposals

    def status(self) -> Dict:
        return {
            "running": self.is_running(),
            "session_id": self.session_id,
            "classified_functions": len(self._classified),
            "checked_contradictions": len(self._checked_contradictions),
            "tainted_sources": len(self._tainted),
            "cross_checked": len(self._cross_checked),
            "pending_proposals": self._proposals.count_pending(),
            "stages": ["classifier_sweep", "contradiction_monitor", "taint_tracer",
                       "cross_session_matcher", "crawler_feed", "entropy_scan",
                       "auto_tag_propagate"],
        }
