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

import importlib.util
import os
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import closing, suppress
from pathlib import Path

from ..intelligence.helpers import (
    cosine_similarity as _cosine,
)
from ..intelligence.helpers import (
    quantile as _q,
)
from ..intelligence.helpers import (
    unpack_floats as _unpack,
)

try:
    from .analysis_engine_kg import AnalysisEngineKnowledgeGraphMixin
except ImportError:
    _kg_path = Path(__file__).with_name("analysis_engine_kg.py")
    _kg_spec = importlib.util.spec_from_file_location("analysis_engine_kg", _kg_path)
    if _kg_spec is None or _kg_spec.loader is None:
        raise
    _kg_mod = importlib.util.module_from_spec(_kg_spec)
    _kg_spec.loader.exec_module(_kg_mod)
    AnalysisEngineKnowledgeGraphMixin = _kg_mod.AnalysisEngineKnowledgeGraphMixin

# ── helpers ──────────────────────────────────────────────────────────────────


# ── Proposal store ────────────────────────────────────────────────────────────
try:
    from ..stores.analysis_proposal_store import ProposalStore
except ImportError:
    _proposal_store_path = Path(__file__).resolve().parent.parent / "stores" / "analysis_proposal_store.py"
    _proposal_store_spec = importlib.util.spec_from_file_location(
        "analysis_proposal_store", _proposal_store_path
    )
    if _proposal_store_spec is None or _proposal_store_spec.loader is None:
        raise
    _proposal_store_mod = importlib.util.module_from_spec(_proposal_store_spec)
    _proposal_store_spec.loader.exec_module(_proposal_store_mod)
    ProposalStore = _proposal_store_mod.ProposalStore

class AnalysisEngine(AnalysisEngineKnowledgeGraphMixin):
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
        rpc_fn: Callable[[str, dict], dict],
        notify_fn: Callable[[dict], None],
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
        self._thread: threading.Thread | None = None
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

        # Frontier engine state
        self._fe = None          # FrontierEngine, lazy-init
        self._fe_built = False   # clusters built at least once

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

    def stop(self, join_timeout: float = 2.0):
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=max(0.0, float(join_timeout or 0.0)))
        if t and not t.is_alive():
            self._thread = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    # ── main loop ─────────────────────────────────────────────────────────────

    def _loop(self):
        """Interleave all stages. Each iteration does one unit of work."""
        sweep_interval = 60
        entropy_interval = 120
        tag_interval = 300
        kg_interval = 90       # KG analysis every 90s
        frontier_interval = 180  # frontier rebuild every 3 min
        last_sweep = 0.0
        last_entropy = 0.0
        last_tag = 0.0
        last_kg = 0.0
        last_frontier = 0.0

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

                if now - last_frontier >= frontier_interval:
                    self._stage_frontier()
                    last_frontier = time.time()

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

        batch: list[dict] = []
        for fn in unnamed:
            addr = fn.get("start_ea") or fn.get("addr")
            if not addr or addr in self._classified:
                continue
            try:
                dec = self._rpc("code", {"action": "decompile", "addr": hex(addr)})
                pseudo = dec.get("pseudocode", "") if isinstance(dec, dict) else ""
                if not pseudo:
                    continue
                classified = classifier.classify(pseudo)
                if not classified:
                    continue
                tags = [
                    str(row.get("behavior") or row.get("label") or "").strip()
                    if isinstance(row, dict)
                    else str(row).strip()
                    for row in classified
                ]
                tags = [tag for tag in tags if tag]
                if not tags:
                    continue
                top_tag = tags[0]
                top_conf = 0.0
                if isinstance(classified[0], dict):
                    try:
                        top_conf = float(classified[0].get("confidence") or 0.0)
                    except Exception:
                        top_conf = 0.0
                confidence = max(top_conf, 0.55 + 0.1 * len(tags))  # more tags = more confident
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
        by_tag: dict[str, list] = {}
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

    def _write_cluster_regions(self, by_tag: dict[str, list]):
        """If a tag cluster spans a contiguous address range, write a region entry."""
        store = self._bb_store()
        if not store:
            return
        for tag, items in by_tag.items():
            if len(items) < 3:
                continue
            addrs = []
            for it in items:
                with suppress(Exception):
                    addrs.append(int(it["addr"], 16))
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
            with closing(sqlite3.connect(self._bb_path, timeout=5)) as conn:
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
            sim_candidates: list[tuple[float, str, tuple, list[float]]] = []

            for other_id, (other_row, other_vec) in all_vecs.items():
                if other_id == eid:
                    continue
                sim = _cosine(vec, other_vec)
                sim_candidates.append((sim, other_id, other_row, other_vec))
            if not sim_candidates:
                continue
            sim_vals = sorted(float(x[0]) for x in sim_candidates)
            q50 = sim_vals[len(sim_vals) // 2]
            q75 = sim_vals[min(len(sim_vals) - 1, int(round((len(sim_vals) - 1) * 0.75)))]
            sim_gate = min(0.995, q75 + max(0.0, q75 - q50))
            for sim, other_id, other_row, other_vec in sorted(sim_candidates, key=lambda x: x[0], reverse=True):
                if sim < sim_gate:
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
                    confidence=round(sim * 0.9, 3),
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

    def _trace_taint_from(self, source: dict, store):
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
                        import re as _re
                        _clean = _re.split(r"[@.]", caller_name.lstrip("_"))[0]
                        if _clean in self.DANGEROUS_SINKS:
                            self._report_taint_sink(source, caller, store, depth + 1)
                        else:
                            next_queue.append(
                                hex(caller_addr) if isinstance(caller_addr, int) else caller_addr
                            )
                except Exception:
                    pass
            queue = next_queue
            depth += 1

    def _report_taint_sink(self, source: dict, sink: dict, store, depth: int):
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
        self._push_resource_updated("ida://taint")
        sink_addr_str = hex(sink_addr) if isinstance(sink_addr, int) else str(sink_addr)
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
                    "sink_addr": sink_addr_str,
                    "depth": depth,
                    "confidence": confidence,
                    "proposal_id": pid,
                    # Specific tool calls the LLM should execute
                    "required_actions": [
                        f"llm_helpers(action='dangerous_pattern_explainer', addr='{sink_addr_str}')",
                        f"taint(action='trace', addr='{source.get('addr', '')}', source='{source.get('ioc_value', 'recv')}')",
                        f"blackboard(action='write', addr='{sink_addr_str}', category='vuln', title='{title[:60]}', confidence={confidence:.2f})",
                    ],
                    "note": f"CALL llm_helpers(action='dangerous_pattern_explainer', addr='{sink_addr_str}') for full exploitation analysis",
                },
            },
        })

    # ── Stage 4: Cross-session matcher ────────────────────────────────────────

    def _stage_cross_session_matcher(self):
        """Compare new embeddings against all other session embedding indexes."""
        try:
            import sqlite3
            with closing(sqlite3.connect(self._bb_path, timeout=5)) as conn:
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

    def _find_other_embedding_dbs(self) -> list[str]:
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
        vec: list[float], other_dbs: list[str], store
    ):
        """Scan other session embedding DBs for similar functions."""
        import sqlite3

        best_sim = -1.0
        best_match = None
        best_db = None
        all_sims: list[float] = []

        for db_path in other_dbs:
            try:
                with closing(sqlite3.connect(db_path, timeout=3)) as conn:
                    rows = conn.execute(
                        "SELECT addr, name, vector FROM embeddings WHERE vector IS NOT NULL"
                    ).fetchall()
                for r in rows:
                    if not r[2]:
                        continue
                    other_vec = _unpack(r[2])
                    sim = _cosine(vec, other_vec)
                    all_sims.append(sim)
                    if sim > best_sim:
                        best_sim = sim
                        best_match = {"addr": r[0], "name": r[1], "sim": sim}
                        best_db = os.path.basename(db_path)
            except Exception:
                continue

        if not best_match:
            return
        # Adaptive match confidence: require top similarity to exceed
        # session-observed similarity distribution, not a fixed cutoff.
        q50 = _q(all_sims, 0.50, default=0.0)
        q90 = _q(all_sims, 0.90, default=1.0)
        spread = max(1e-6, q90 - q50)
        adaptive_gate = min(0.98, q90 + (0.15 * spread))
        if best_match["sim"] < adaptive_gate:
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
            import importlib.util
            import os as _os
            # analysis_engine.py is in host/analysis/; blackboard.py is at the
            # package root (ida_pro_mcp/ida_mcp/tools/) — two levels up.
            path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "..", "ida_mcp", "tools", "blackboard.py"
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
        conf_vals = sorted(float(p.get("confidence", 0.5) or 0.5) for p in pending)
        if conf_vals:
            q50 = conf_vals[len(conf_vals) // 2]
            q75 = conf_vals[min(len(conf_vals) - 1, int(round((len(conf_vals) - 1) * 0.75)))]
            auto_accept_gate = min(0.99, q75 + max(0.0, q75 - q50))
        else:
            auto_accept_gate = 1.0
        for p in pending:
            conf = p.get("confidence", 0.5)
            if conf < auto_accept_gate:
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

            _entropy_gate = 6.5
            if entropy < _entropy_gate:
                continue

            addr_hex = hex(start) if isinstance(start, int) else str(start)
            addr_end_hex = hex(end) if isinstance(end, int) else str(end)

            # Don't duplicate
            existing = store.list(category="region", addr=addr_hex)
            if existing:
                # Update entropy value
                store.update(existing[0]["id"], entropy=entropy)
                continue

            store.write(
                f"High-entropy region: {name} (entropy={entropy:.2f})",
                category="region",
                addr=addr_hex, addr_end=addr_end_hex,
                tags=["entropy", "engine", "crypto_candidate"],
                confidence=min(0.98, max(0.5, 0.5 + max(0.0, entropy - _entropy_gate) / max(1.0, 8.0 - _entropy_gate))),
                source="engine", source_type="engine_entropy",
                entropy=entropy,
                evidence=[{"type": "entropy", "value": f"{entropy:.3f}",
                           "weight": min(1.0, max(0.0, entropy - _entropy_gate) / max(1.0, 8.0 - _entropy_gate)),
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

    def _get_fe(self):
        """Lazy-init FrontierEngine."""
        if self._fe is None:
            try:
                from .frontier import FrontierEngine
                # embeddings DB lives next to the IDB: <idb>.embeddings.db
                # We find it by scanning embeddings_dir for *.embeddings.db
                emb_db = ""
                if self._embeddings_dir and os.path.isdir(self._embeddings_dir):
                    for fname in os.listdir(self._embeddings_dir):
                        if fname.endswith(".embeddings.db"):
                            emb_db = os.path.join(self._embeddings_dir, fname)
                            break
                if not emb_db:
                    emb_db = self._bb_path.replace(".blackboard.db", ".embeddings.db")
                self._fe = FrontierEngine(emb_db, self._bb_path)
            except Exception:
                pass
        return self._fe

    # ── Stage 9: Frontier (cluster + propagate + score) ───────────────────────

    def _stage_frontier(self):
        """
        1. Rebuild embedding clusters (k-means over all indexed functions)
        2. Propagate LLM labels to cluster neighbors
        3. Score unvisited functions and seed blackboard with top frontier entries
        4. Detect embedding contradictions and push as proposals
        """
        try:
            fe = self._get_fe()
            if fe is None:
                return

            # Rebuild clusters
            n = fe.refresh()
            if n < 5:
                return  # not enough indexed functions yet
            self._fe_built = True

            # Propagate labels
            propagated = fe.propagate_labels()

            # Score frontier — get xref/entropy hints from blackboard
            xref_counts: dict = {}
            entropy_map: dict = {}
            try:
                import sqlite3 as _sq3
                with closing(_sq3.connect(self._bb_path, timeout=5)) as conn:
                    for row in conn.execute(
                        "SELECT addr, xref_count, entropy FROM blackboard "
                        "WHERE addr != '' AND addr IS NOT NULL"
                    ):
                        if row[0]:
                            xref_counts[row[0]] = int(row[1] or 0)
                            entropy_map[row[0]] = float(row[2] or 0.0)
            except Exception:
                pass

            frontier = fe.frontier(limit=30, xref_counts=xref_counts, entropy_map=entropy_map)

            # Seed top frontier entries into blackboard as hypothesis entries
            bb = self._bb_store()
            if bb and frontier:
                for entry in frontier[:10]:
                    addr = entry["addr"]
                    # Skip if already in blackboard
                    existing = bb.list(addr=addr, limit=1, include_resolved=False)
                    if existing:
                        continue
                    reason_parts = []
                    if entry["nearest_label_title"]:
                        reason_parts.append(f"near '{entry['nearest_label_title'][:40]}'")
                    if entry["xref_count"] > 5:
                        reason_parts.append(f"xrefs={entry['xref_count']}")
                    if entry["entropy"] > 6.0:
                        reason_parts.append(f"entropy={entry['entropy']:.1f}")
                    reason = ", ".join(reason_parts) or "frontier scoring"
                    bb.write(
                        title=f"[frontier] {entry['name']} — {reason}",
                        category="hypothesis",
                        addr=addr,
                        content=f"Frontier score={entry['score']:.3f}, cluster={entry['cluster']}, "
                                f"proximity={entry['proximity']:.3f}",
                        tags=["frontier", "auto"],
                        confidence=min(0.7, entry["score"] + 0.2),
                        source="frontier_engine",
                        source_type="engine_frontier",
                        embed=False,
                    )

            # Contradiction detection — push as proposals
            contradictions = fe.detect_contradictions()
            if contradictions:
                items = [
                    {
                        "id": f"contra_{c['addr_a']}_{c['addr_b']}",
                        "addr_a": c["addr_a"],
                        "addr_b": c["addr_b"],
                        "title_a": c["title_a"],
                        "title_b": c["title_b"],
                        "category_a": c["category_a"],
                        "category_b": c["category_b"],
                        "similarity": c["embedding_similarity"],
                        "note": c["note"],
                    }
                    for c in contradictions[:5]
                ]
                pid = self._proposals.add(
                    proposal_type="embedding_contradiction",
                    title=f"Embedding contradictions detected ({len(contradictions)} pairs)",
                    summary=(
                        f"{len(contradictions)} function pairs are in the same embedding cluster "
                        "but have different labels. Review and correct."
                    ),
                    items=items,
                    confidence=0.65,
                    session_id=self.session_id,
                )
                self._push_proposal_notification(
                    pid, "embedding_contradiction",
                    f"{len(contradictions)} label contradictions detected by embedding analysis",
                    0.65,
                )

            self._push_resource_updated("ida://blackboard/frontier")

            # Notify with top frontier target if coverage is low
            cov = fe.coverage()
            if cov["coverage_pct"] < 50 and frontier:
                top = frontier[0]
                self._notify({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "data": {
                            "type": "frontier_updated",
                            "coverage_pct": cov["coverage_pct"],
                            "analyzed": cov["analyzed"],
                            "unvisited": cov["unvisited"],
                            "top_target": top["addr"],
                            "top_target_name": top["name"],
                            "top_score": top["score"],
                            "propagated": len(propagated),
                            "required_actions": [
                                f"code(action='smart_decompile', addrs='{top['addr']}')",
                                "blackboard(action='frontier', limit=10)",
                            ],
                            "note": (
                                f"Coverage: {cov['coverage_pct']}% ({cov['unvisited']} unvisited). "
                                f"Top target: {top['name']} at {top['addr']} (score={top['score']:.3f}). "
                                f"CALL code(action='smart_decompile', addrs='{top['addr']}')"
                            ),
                        },
                    },
                })

        except Exception:
            pass

    # ── helpers ───────────────────────────────────────────────────────────────

    def _bb_store(self):
        try:
            import importlib.util
            # analysis_engine.py is in host/analysis/; blackboard.py is at the
            # package root (ida_pro_mcp/ida_mcp/tools/) — two levels up.
            path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "ida_mcp", "tools", "blackboard.py"
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
            from ..intelligence.core import BehaviorClassifier
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

    def status(self) -> dict:
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
