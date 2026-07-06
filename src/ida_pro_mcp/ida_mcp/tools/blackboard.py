"""
Blackboard: Persistent, self-maintaining analysis context for firmware RE.

Extended schema supports:
  - region       : annotated memory regions (addr_start, addr_end)
  - ioc          : IOCs (ip, port, key, magic, url) with ioc_type + value fields
  - dead_end     : resolved/skip markers so you don't revisit
  - dependency   : "must understand X before Y" task graph
  - data_flow    : register/variable state at a function boundary
  - contradiction: marks a prior entry as contradicted with reason
  - hypothesis   : auto-generated from BehaviorClassifier
  - cluster      : behavioral cluster summaries
  - rename_suggestion : propagated rename candidates
  - pointer/string/entropy/address/pointer_chain/deref : auto-captured

Background crawler (start_crawler / stop_crawler) follows xrefs from known
addresses, finds new ones, and proposes them via MCP notification.

Actions:
  write, read, list, search, update, delete, clear, stats, prune, merge
  contradict     - Mark an entry as contradicted
  next_target    - Return highest-priority unexplored address
  start_crawler  - Start background xref crawler
  stop_crawler   - Stop background xref crawler
  crawler_status - Show crawler state and pending proposals
  accept         - Accept a crawler proposal (writes to blackboard)
  reject         - Reject a crawler proposal
"""

from __future__ import annotations

import contextlib
import json
import threading
import uuid
from typing import Dict, List, Optional

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    def tool(f):
        return f  # type: ignore
if "idaread" not in globals():
    def idaread(f):
        return f  # type: ignore
if "idawrite" not in globals():
    def idawrite(f):
        return f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore

try:
    from ida_pro_mcp.services import BlackboardStore as _BaseBlackboardStore
except ImportError:
    try:
        from host.blackboard_store import BlackboardStore as _BaseBlackboardStore  # type: ignore
    except ImportError:
        raise


def _get_embedder():
    try:
        from ida_pro_mcp.services import BgeCodeEmbedder
        return BgeCodeEmbedder()
    except ImportError:
        try:
            from host.intelligence.core import BgeCodeEmbedder  # type: ignore
            return BgeCodeEmbedder()
        except ImportError:
            return None


class BlackboardStore(_BaseBlackboardStore):
    def _get_embedder(self):
        return _get_embedder()


# ─────────────────────────────────────────────────────────────────────────────
# Background Crawler
# ─────────────────────────────────────────────────────────────────────────────

class _BackgroundCrawler:
    """
    Follows xrefs from known blackboard addresses, discovers new functions,
    classifies them, and proposes them as blackboard entries.

    Proposals are queued in _pending. The LLM can accept/reject via
    blackboard(action="accept"|"reject", proposal_id=...).

    When a proposal is accepted, it's written to the blackboard.
    When running inside IDA, it also sends an MCP notification so the LLM
    sees a popup-style prompt.
    """

    _instance: Optional[_BackgroundCrawler] = None
    _instances_by_key: Dict[str, _BackgroundCrawler] = {}
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pending: Dict[str, Dict] = {}  # proposal_id -> proposal
        self._visited: set = set()
        self._work_queue: List[str] = []
        self._parents: Dict[str, str] = {}
        self._visited_count: int = 0
        self._notify_fn = None  # injected by server to send MCP notifications

    @classmethod
    def instance(cls, db_path: Optional[str] = None) -> _BackgroundCrawler:
        with cls._lock:
            key = str(db_path or "").strip().lower()
            if key:
                inst = cls._instances_by_key.get(key)
                if inst is None:
                    inst = cls(db_path)
                    cls._instances_by_key[key] = inst
                cls._instance = inst
                return inst
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    def start(self, notify_fn=None) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        if notify_fn:
            self._notify_fn = notify_fn
        self._thread = threading.Thread(
            target=self._crawl_loop, daemon=True, name="bb-crawler"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def pending_proposals(self) -> List[Dict]:
        return list(self._pending.values())

    def visited_count(self) -> int:
        return int(self._visited_count)

    def accept(self, proposal_id: str) -> Optional[str]:
        p = self._pending.pop(proposal_id, None)
        if not p:
            return None
        store = BlackboardStore(self._db_path)
        conf = float(p.get("confidence", 0.6) or 0.6)
        return store.write(
            title=p["title"],
            content=p.get("content", ""),
            category=p.get("category", "hypothesis"),
            addr=p.get("addr", ""),
            tags=p.get("tags", []),
            confidence=min(1.0, conf + 0.1),
            source="crawler.accepted",
        )

    def reject(self, proposal_id: str) -> bool:
        p = self._pending.pop(proposal_id, None)
        if not p:
            return False
        # Demote confidence for existing hypothesis entries at this address.
        try:
            store = BlackboardStore(self._db_path)
            addr = str(p.get("addr") or "").strip()
            if addr:
                rows = store.list(category="hypothesis", addr=addr, include_resolved=True, include_contradicted=True, limit=20)
                for e in rows:
                    eid = str(e.get("id") or e.get("entry_id") or "").strip()
                    old = float(e.get("confidence", 0.5) or 0.5)
                    if eid:
                        store.update(eid, confidence=max(0.0, old - 0.15))
        except Exception:
            pass
        return True

    def _crawl_loop(self) -> None:
        """Main crawler loop: frontier -> agent quick -> hypothesis proposal every 0.5s."""
        # Lazy-import to keep the module importable without IDA SDK (sync.py
        # calls idaapi.get_kernel_version() at the top level).
        try:
            from ida_pro_mcp.ida_mcp.sync import bypass_sync
        except ImportError:
            try:
                from ida_mcp.sync import bypass_sync  # type: ignore
            except ImportError:
                try:
                    from sync import bypass_sync  # type: ignore[import-not-found]
                except ImportError:
                    from contextlib import nullcontext
                    bypass_sync = nullcontext  # type: ignore[assignment]
        while not self._stop_event.wait(0.5):
            # Bypass the @idaread/@idawrite safety wrapper because the crawler
            # runs on a background thread that cannot use execute_sync. The
            # tools it calls (agent, blackboard) already handle their own locking.
            with bypass_sync(reason="background crawler"), contextlib.suppress(Exception):
                self._crawl_step()

    def _crawl_step(self) -> None:
        store = BlackboardStore(self._db_path)
        try:
            # Restore queue/visited snapshot when resuming.
            st = store.list(category="crawler_state", include_resolved=True, include_contradicted=True, limit=1)
            if st:
                import json as _json
                meta = _json.loads(str(st[0].get("content") or "{}"))
                if isinstance(meta, dict):
                    if not self._visited and isinstance(meta.get("visited"), list):
                        self._visited = {str(x) for x in meta.get("visited", [])}
                    if not self._work_queue and isinstance(meta.get("queue"), list):
                        self._work_queue = [str(x) for x in meta.get("queue", []) if str(x)]
                    if not self._parents and isinstance(meta.get("parents"), dict):
                        self._parents = {str(k): str(v) for k, v in meta.get("parents", {}).items()}
        except Exception:
            pass
        try:
            f_res = blackboard(action="frontier", db_path=self._db_path or "", limit=25)
            frontier = f_res.get("results", []) if isinstance(f_res, dict) else []
            if frontier and isinstance(frontier[0], dict) and "addr" not in frontier[0]:
                frontier = []
        except Exception:
            frontier = []
        if not frontier:
            try:
                frontier = store.next_target(limit=25)
            except Exception:
                frontier = []
        addr_str = ""
        discovery_path = []
        # Prefer in-session queue expansion first.
        while self._work_queue and not addr_str:
            cand = self._work_queue.pop(0)
            if cand and cand not in self._visited:
                addr_str = cand
        if not addr_str:
            next_target = None
            for t in frontier:
                addr = str(t.get("addr") or "").strip()
                if not addr or addr in self._visited:
                    continue
                next_target = t
                break
            if not next_target:
                return
            addr_str = str(next_target.get("addr") or "").strip()

        # Reconstruct caller -> callee chain.
        cur = addr_str
        hop = 0
        while cur and hop < 8:
            discovery_path.append(cur)
            cur = self._parents.get(cur, "")
            hop += 1
        discovery_path = list(reversed(discovery_path))

        self._visited.add(addr_str)
        self._visited_count += 1
        findings = []
        quick = {}
        try:
            try: from .agent import agent as _agent_tool  # type: ignore
            except ImportError: from agent import agent as _agent_tool  # type: ignore[import-not-found]
            quick = _agent_tool(action="quick", addr=addr_str)
            findings = quick.get("findings") if isinstance(quick, dict) else []
            if not isinstance(findings, list):
                findings = []
        except Exception:
            findings = []
        # Expand graph traversal from discovered callees.
        try:
            for c in (quick.get("callees") or []):
                c_addr = ""
                c_addr = str(c.get("addr") or c.get("ea") or "").strip() if isinstance(c, dict) else str(c).strip().split()[0]
                if not c_addr or c_addr in self._visited or c_addr in self._work_queue:
                    continue
                self._parents[c_addr] = addr_str
                self._work_queue.append(c_addr)
                if len(self._work_queue) >= 50:
                    break
            if len(self._work_queue) > 50:
                self._work_queue = self._work_queue[:50]
        except Exception:
            pass

        if not findings:
            try:
                import json as _json
                store.write(
                    title="crawler_state",
                    content=_json.dumps({
                        "visited": sorted(self._visited)[:400],
                        "queue": self._work_queue[:50],
                        "parents": self._parents,
                    }),
                    category="crawler_state",
                    tags=["crawler"],
                    confidence=1.0,
                    source="crawler.state",
                )
            except Exception:
                pass
            return
        summary = str(findings[0])[:220]
        pid = str(uuid.uuid4())[:8]
        proposal = {
            "proposal_id": pid,
            "addr": addr_str,
            "title": f"Crawler quick analysis @ {addr_str}",
            "content": summary,
            "category": "hypothesis",
            "tags": ["crawler", "quick"],
            "confidence": 0.65,
            "source_addr": addr_str,
            "behavior_tags": quick.get("labels", []) if isinstance(quick, dict) else [],
            "discovery_path": discovery_path,
        }
        self._pending[pid] = proposal
        try:
            store.write(
                title=proposal["title"],
                content=proposal["content"],
                category="hypothesis",
                addr=proposal["addr"],
                tags=proposal["tags"],
                confidence=float(proposal["confidence"]),
                source="crawler.auto",
                source_type="crawler",
            )
            import json as _json
            store.write(
                title="crawler_state",
                content=_json.dumps({
                    "visited": sorted(self._visited)[:400],
                    "queue": self._work_queue[:50],
                    "parents": self._parents,
                }),
                category="crawler_state",
                tags=["crawler"],
                confidence=1.0,
                source="crawler.state",
            )
        except Exception:
            pass

        # Send MCP notification for new proposals
        if self._notify_fn:
            with contextlib.suppress(Exception):
                self._notify_fn({
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {
                        "level": "info",
                        "logger": "blackboard.crawler",
                        "data": {
                            "message": "Crawler generated 1 quick-analysis proposal",
                            "proposals": [{"proposal_id": proposal["proposal_id"], "addr": proposal["addr"], "title": proposal["title"], "behavior_tags": proposal.get("behavior_tags", [])}],
                            "action": "Use blackboard(action='accept', proposal_id=...) or blackboard(action='reject', proposal_id=...) for each proposal.",
                        },
                    },
                })


# ─────────────────────────────────────────────────────────────────────────────
# Auto-capture helpers (called by memory.py and calc.py)
# ─────────────────────────────────────────────────────────────────────────────

def auto_capture_calc(result: Dict, db_path: Optional[str] = None) -> None:  # noqa: D401
    """Deprecated: the always-on auto-capture for `calc` was broken
    (skipped `eval`, lost the question for `resolve`, looked at the wrong
    key for `chain`).

    The replacement is opt-in: pass `persist=True` to `calc()` and the
    LLM's question + the result are written to the blackboard. See
    `calc._calc_persist_capture`. This function is kept as a no-op stub
    so any external import keeps working; new code should not use it.
    """
    return


# ─────────────────────────────────────────────────────────────────────────────
# MCP tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def blackboard(
    action: str = "list",
    entry_id: str = "",
    title: str = "",
    content: str = "",
    category: str = "general",
    addr: str = "",
    addr_end: str = "",
    tags: Optional[List[str]] = None,
    confidence: float = 0.5,
    tag: str = "",
    query: str = "",
    min_confidence: float = 0.0,
    limit: int = 100,
    offset: int = 0,
    db_path: str = "",
    max_entries: int = 1000,
    min_q_value: float = 0.0,
    older_than_days: int = 0,
    top_k: int = 10,
    threshold: float = 0.4,
    reason: str = "",
    proposal_id: str = "",
    ioc_type: str = "",
    ioc_value: str = "",
    depends_on: str = "",
    blocks_addr: str = "",
    register: str = "",
    reg_type: str = "",
    include_resolved: bool = False,
    include_contradicted: bool = False,
    # v3 fields
    evidence: Optional[List[Dict]] = None,
    source_type: str = "",
    entropy: float = 0.0,
    xref_count: int = 0,
    evidence_type: str = "",
    evidence_value: str = "",
    evidence_weight: float = 1.0,
    **kwargs,
) -> dict:
    """
    Persistent, self-maintaining analysis context for firmware RE.

    Extended categories: region, ioc, dead_end, dependency, data_flow,
    contradiction, hypothesis, cluster, rename_suggestion, pointer, string,
    entropy, address, pointer_chain, deref, session_diff.

    Actions:
      write          - Pin a finding. Returns entry_id.
      read           - Get entry by ID.
      list           - List entries (filter by category, addr, tag).
      search         - Semantic search (bge-code-v1 cosine or substring fallback).
      update         - Modify an entry.
      delete         - Remove an entry.
      clear          - Remove all (or by category).
      stats          - Counts, categories, IOCs, resolved/contradicted.
      prune          - Evict low-quality or old entries.
      merge          - Deduplicate similar entries.
      contradict     - Mark entry as contradicted with reason.
      resolve        - Mark entry as resolved/dead-end.
      next_target    - Return highest-priority unexplored addresses.
      start_crawler  - Start background xref crawler.
      stop_crawler   - Stop background xref crawler.
      crawler_status - Show crawler state and pending proposals.
      accept         - Accept a crawler proposal (writes to blackboard).
      reject         - Reject a crawler proposal.
      export_symbols - Export named functions into persistent symbol knowledge DB.
      import_symbols - Import high-confidence symbol matches from knowledge DB.

    Firmware RE examples:
      # Annotate a memory region
      blackboard(action="write", category="region", title="TCP/IP stack",
                 addr="0x80400000", addr_end="0x80410000", confidence=0.85)

      # Record an IOC
      blackboard(action="write", category="ioc", title="Hardcoded C2 IP",
                 ioc_type="ip_port", ioc_value="192.168.100.1:8080",
                 addr="0x80412340", confidence=0.99)

      # Mark a dead end
      blackboard(action="write", category="dead_end",
                 title="0x8041500 is memset wrapper — skip",
                 addr="0x8041500")
      blackboard(action="resolve", entry_id="abc123")

      # Record a dependency
      blackboard(action="write", category="dependency",
                 title="Must understand 0x8040100 before 0x8041200",
                 addr="0x8041200", depends_on="0x8040100")

      # Record data flow
      blackboard(action="write", category="data_flow",
                 title="r3 into 0x8041200 = packet buffer ptr",
                 addr="0x8041200", register="r3", reg_type="packet_buffer*")

      # Contradict a prior hypothesis
      blackboard(action="contradict", entry_id="abc123",
                 reason="Found it calls malloc — not a custom allocator")

      # Get next analysis target
      blackboard(action="next_target")

      # Start background crawler
      blackboard(action="start_crawler")
    """
    store = BlackboardStore(db_path=db_path or None)

    if action == "write":
        if not title:
            return make_error(MCPError.INVALID_ARGS, "title required")
        eid = store.write(
            title, content, category, addr, addr_end, tags, confidence,
            source="manual", ioc_type=ioc_type, ioc_value=ioc_value,
            depends_on=depends_on, blocks_addr=blocks_addr,
            register=register, reg_type=reg_type,
            evidence=evidence or [], source_type=source_type or "manual",
            entropy=entropy, xref_count=xref_count,
        )
        # Async label propagation: only when inside IDA (idc module available)
        # and confidence is high enough to be worth propagating
        if addr and confidence >= 0.6 and source_type not in ("propagated", "engine_frontier"):
            try:
                import threading as _thr

                import idc as _idc_check  # noqa: F401 — only start thread if IDA is available
                def _propagate():
                    try:
                        from ida_pro_mcp.services import FrontierEngine
                    except ImportError:
                        try:
                            from host.frontier import FrontierEngine  # type: ignore
                        except ImportError:
                            return
                    try:
                        idb_path = ""
                        try:
                            import idc as _idc
                            idb_path = _idc.get_idb_path() or ""
                        except Exception:
                            pass
                        if not idb_path:
                            return  # no IDB path — skip propagation
                        emb_db = idb_path + ".embeddings.db"
                        import os as _os
                        if not _os.path.exists(emb_db):
                            return  # no embeddings indexed yet — skip
                        fe = FrontierEngine(emb_db, store.db_path)
                        if fe.refresh() >= 3:
                            fe.propagate_labels()
                    except Exception:
                        pass
                _thr.Thread(target=_propagate, daemon=True, name="bb-propagate").start()
            except ImportError:
                pass  # not inside IDA — skip propagation
        return {"ok": True, "entry_id": eid}

    elif action == "read":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        entry = store.read(entry_id)
        return {"ok": True, "entry": entry} if entry else make_error(MCPError.NOT_FOUND, f"Entry \'{entry_id}\' not found", details={"entry_id": entry_id})

    elif action == "list":
        entries = store.list(
            category=category or None, addr=addr or None,
            tag=tag or None, min_confidence=min_confidence,
            limit=limit, offset=offset,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
            ioc_type=ioc_type or None,
        )
        return {"ok": True, "entries": entries, "count": len(entries)}

    elif action == "search":
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required")
        results = store.semantic_search(
            query=query, top_k=top_k, threshold=threshold,
            category=category or None,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
        )
        return {"ok": True, "results": results, "count": len(results)}

    elif action == "semantic_index":
        stats = store.semantic_index(category=category or None)
        return {"ok": True, **stats}

    elif action == "semantic_rebuild":
        force = bool(kwargs.get("force", False))
        result = store.semantic_rebuild(
            category=category or None,
            force=force,
            limit=int(limit or 5000),
        )
        return result

    elif action == "related_by_behavior":
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required")
        thr = threshold
        try:
            thr = float(threshold)
        except Exception:
            thr = 0.4
        hits = store.semantic_search(
            query=query,
            top_k=max(1, int(top_k or 10)),
            threshold=max(0.0, thr),
            category=category or None,
            include_resolved=include_resolved,
            include_contradicted=include_contradicted,
        )
        out = []
        for h in hits:
            tags = h.get("tags") or []
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except Exception:
                    tags = []
            out.append(
                {
                    "entry_id": h.get("id"),
                    "title": h.get("title"),
                    "addr": h.get("addr"),
                    "category": h.get("category"),
                    "confidence": h.get("confidence"),
                    "similarity": h.get("similarity"),
                    "tags": tags,
                }
            )
        return {
            "ok": True,
            "behavior": query,
            "results": out,
            "count": len(out),
        }

    elif action == "update":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        fields: Dict = {}
        if title: fields["title"] = title
        if content: fields["content"] = content
        if category and category != "general": fields["category"] = category
        if addr: fields["addr"] = addr
        if tags is not None: fields["tags"] = tags
        if confidence != 0.5: fields["confidence"] = confidence
        fields.update({k: v for k, v in kwargs.items()
                       if k in {"title","content","category","addr","confidence","q_value","resolved"}})
        if not fields:
            return make_error(MCPError.INVALID_ARGS, "No fields to update")
        ok = store.update(entry_id, **fields)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry \'{entry_id}\' not found", details={"entry_id": entry_id})

    elif action == "delete":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        ok = store.delete(entry_id)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry \'{entry_id}\' not found", details={"entry_id": entry_id})

    elif action == "clear":
        count = store.clear(category=category if category != "general" else None)
        return {"ok": True, "deleted": count}

    elif action == "stats":
        return {"ok": True, **store.stats()}

    elif action == "merge":
        result = store.auto_merge(addr=addr, category=category if category != "general" else "")
        return {"ok": True, **result}

    elif action == "prune":
        result = store.prune(max_entries=max_entries, min_q_value=min_q_value, older_than_days=older_than_days)
        return {"ok": True, **result}

    elif action == "contradict":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        if not reason:
            return make_error(MCPError.INVALID_ARGS, "reason required")
        ok = store.contradict(entry_id, reason)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry \'{entry_id}\' not found", details={"entry_id": entry_id})

    elif action == "resolve":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        ok = store.mark_resolved(entry_id)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry \'{entry_id}\' not found", details={"entry_id": entry_id})

    elif action == "next_target":
        targets = store.next_target(limit=limit or 5)
        # Optional semantic rerank: when query is provided, blend queue priority with embedding similarity.
        if query:
            sem_hits = store.semantic_search(
                query=query,
                top_k=max(limit or 5, 10),
                threshold=max(0.2, float(threshold or 0.4) - 0.1),
                include_resolved=False,
                include_contradicted=False,
            )
            sim_by_addr = {}
            for h in sem_hits:
                a = str(h.get("addr") or "").strip()
                if a:
                    sim_by_addr[a] = float(h.get("similarity") or 0.0)
            if sim_by_addr:
                for t in targets:
                    a = str(t.get("addr") or "").strip()
                    sim = sim_by_addr.get(a, 0.0)
                    base = float(t.get("priority_score") or 0.0)
                    t["semantic_similarity"] = round(sim, 4)
                    t["blended_priority"] = round((0.78 * base) + (0.22 * sim), 4)
                targets = sorted(
                    targets,
                    key=lambda x: (float(x.get("blended_priority") or 0.0), float(x.get("priority_score") or 0.0)),
                    reverse=True,
                )
        return {
            "ok": True,
            "targets": targets,
            "count": len(targets),
            "query": query or None,
            "note": (
                "Highest-priority unexplored addresses. With query set, ranking blends queue priority "
                "and embedding similarity."
            ),
        }

    elif action == "start_crawler":
        crawler = _BackgroundCrawler.instance(db_path=db_path or None)
        crawler.start()
        return {"ok": True, "running": crawler.is_running(),
                "note": "Crawler uses frontier targets and runs agent(action='quick') every 0.5s. Use crawler_status to see proposals."}

    elif action == "stop_crawler":
        crawler = _BackgroundCrawler.instance()
        crawler.stop()
        return {"ok": True, "running": False}

    elif action == "crawler_status":
        crawler = _BackgroundCrawler.instance()
        proposals = crawler.pending_proposals()
        return {
            "ok": True,
            "running": crawler.is_running(),
            "pending_proposals": len(proposals),
            "proposals_pending": len(proposals),
            "addresses_visited": crawler.visited_count(),
            "proposals": proposals[:10],
            "note": "Use blackboard(action='accept', proposal_id=...) or blackboard(action='reject', proposal_id=...) for each proposal.",
        }

    elif action == "accept":
        if not proposal_id:
            return make_error(MCPError.INVALID_ARGS, "proposal_id required")
        crawler = _BackgroundCrawler.instance()
        eid = crawler.accept(proposal_id)
        return {"ok": bool(eid), "entry_id": eid} if eid else make_error(MCPError.NOT_FOUND, f"Proposal \'{proposal_id}\' not found", details={"proposal_id": proposal_id})

    elif action == "reject":
        if not proposal_id:
            return make_error(MCPError.INVALID_ARGS, "proposal_id required")
        crawler = _BackgroundCrawler.instance()
        ok = crawler.reject(proposal_id)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Proposal \'{proposal_id}\' not found", details={"proposal_id": proposal_id})

    elif action == "add_evidence":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        if not evidence_type or not evidence_value:
            return make_error(MCPError.INVALID_ARGS, "evidence_type and evidence_value required")
        ok = store.add_evidence(entry_id, evidence_type, evidence_value, evidence_weight)
        return {"ok": ok}

    elif action == "calibrate":
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        new_conf = store.calibrate_confidence(entry_id)
        return {"ok": new_conf is not None, "confidence": new_conf}

    elif action == "campaign_summary":
        return {"ok": True, **store.campaign_summary()}

    elif action == "auto_tag_propagate":
        updated = store.auto_tag_propagate()
        return {"ok": True, "updated": updated}

    # ── Knowledge Graph write actions ─────────────────────────────────────────
    elif action in ("add_system", "add_struct", "add_gap", "fill_gap",
                    "add_state_machine", "add_peripheral", "add_attack_surface",
                    "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
                    "kg_state_machines", "kg_attack_surface", "kg_peripherals"):
        try:
            import importlib.util as _ilu
            import os as _os
            _kg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                     "..", "..", "host", "knowledge_graph.py")
            _spec = _ilu.spec_from_file_location("_bb_kg", _os.path.abspath(_kg_path))
            _kgmod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_kgmod)
            kg = _kgmod.KnowledgeGraph(db_path=store.db_path)
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"KnowledgeGraph unavailable: {e}", details={"exception_type": type(e).__name__})

        if action == "add_system":
            if not title:
                return make_error(MCPError.INVALID_ARGS, "title required (system name)")
            members = kwargs.get("members") or []
            entry_points = kwargs.get("entry_points") or []
            exit_points = kwargs.get("exit_points") or []
            sid = kg.add_system(title, members=members, description=content,
                                entry_points=entry_points, exit_points=exit_points,
                                tags=tags or [], confidence=confidence)
            return {"ok": True, "system_id": sid}

        elif action == "add_struct":
            if not title:
                return make_error(MCPError.INVALID_ARGS, "title required (struct name)")
            members_data = kwargs.get("members") or []
            size = int(kwargs.get("size_bytes") or 0)
            sid = kg.add_struct(title, members=members_data, size_bytes=size,
                                confidence=confidence)
            return {"ok": True, "struct_id": sid}

        elif action == "add_gap":
            if not title:
                return make_error(MCPError.INVALID_ARGS, "title required (expected capability)")
            hints = kwargs.get("hints") or []
            gap_type = kwargs.get("gap_type") or "capability"
            binary_type = kwargs.get("binary_type") or ""
            gid = kg.add_gap(title, why=content, hints=hints,
                             priority=confidence, gap_type=gap_type,
                             binary_type=binary_type)
            return {"ok": True, "gap_id": gid}

        elif action == "fill_gap":
            gap_id = kwargs.get("gap_id") or entry_id
            if not gap_id:
                return make_error(MCPError.INVALID_ARGS, "gap_id or entry_id required")
            filled_by = addr or kwargs.get("filled_by") or ""
            ok = kg.fill_gap(gap_id, filled_by)
            return {"ok": ok}

        elif action == "add_state_machine":
            if not title:
                return make_error(MCPError.INVALID_ARGS, "title required (state machine name)")
            state_var = addr or kwargs.get("state_var") or ""
            states = kwargs.get("states") or []
            sid = kg.add_state_machine(title, state_var=state_var, states=states,
                                       confidence=confidence)
            return {"ok": True, "state_machine_id": sid}

        elif action == "add_peripheral":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (MMIO base address)")
            periph_type = kwargs.get("periph_type") or "unknown"
            drivers = kwargs.get("drivers") or []
            pid = kg.add_peripheral(addr, name=title, periph_type=periph_type,
                                    drivers=drivers, confidence=confidence)
            return {"ok": True, "peripheral_id": pid}

        elif action == "add_attack_surface":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required (entry point address)")
            reachable_from = kwargs.get("reachable_from") or "unknown"
            input_type = kwargs.get("input_type") or "unknown"
            call_stack = kwargs.get("call_stack") or []
            aid = kg.add_attack_surface(addr, name=title,
                                        reachable_from=reachable_from,
                                        input_type=input_type,
                                        call_stack=call_stack,
                                        confidence=confidence)
            return {"ok": True, "attack_surface_id": aid}

        elif action == "kg_summary":
            return {"ok": True, **kg.summary()}
        elif action == "kg_systems":
            return {"ok": True, "systems": kg.list_systems()}
        elif action == "kg_gaps":
            resolved_flag = kwargs.get("resolved", False)
            return {"ok": True, "gaps": kg.list_gaps(resolved=bool(resolved_flag))}
        elif action == "kg_structs":
            return {"ok": True, "structs": kg.list_structs()}
        elif action == "kg_state_machines":
            return {"ok": True, "state_machines": kg.list_state_machines()}
        elif action == "kg_attack_surface":
            return {"ok": True, "attack_surface": kg.list_attack_surface()}
        elif action == "kg_peripherals":
            return {"ok": True, "peripherals": kg.list_peripherals()}

    elif action == "frontier":
        # Return ranked unvisited functions from FrontierEngine.
        # Requires embeddings to be indexed (code(action='decompile') or index_fast).
        try:
            from ida_pro_mcp.services import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 3:
            return {
                "ok": True, "frontier": [], "count": 0,
                "note": "Not enough indexed embeddings. Decompile some functions first.",
            }
        # Gather xref/entropy hints from blackboard
        xref_counts: dict = {}
        entropy_map: dict = {}
        try:
            import sqlite3 as _sq3
            with _sq3.connect(store.db_path, timeout=5) as conn:
                for row in conn.execute(
                    "SELECT addr, xref_count, entropy FROM blackboard "
                    "WHERE addr != '' AND addr IS NOT NULL"
                ):
                    if row[0]:
                        xref_counts[row[0]] = int(row[1] or 0)
                        entropy_map[row[0]] = float(row[2] or 0.0)
        except Exception:
            pass
        results = fe.frontier(limit=limit, xref_counts=xref_counts, entropy_map=entropy_map)
        lines = [
            f"{r['addr']}  {r['name']}  score={r['score']:.3f}  "
            f"cluster={r['cluster']}  proximity={r['proximity']:.3f}"
            + (f"  near='{r['nearest_label_title'][:30]}'" if r.get("nearest_label_title") else "")
            for r in results
        ]
        return {
            "ok": True,
            "frontier": "\n".join(lines),
            "items": results,
            "count": len(results),
            "indexed": n,
            "note": (
                "Ranked by: proximity to labeled functions (embedding cosine) + "
                "xref count + entropy + cluster coverage. "
                "Use code(action='smart_decompile') on top results."
            ),
        }

    elif action == "coverage":
        # Coverage map: analyzed/visited/unvisited counts + per-cluster breakdown.
        try:
            from ida_pro_mcp.services import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 1:
            return {
                "ok": True,
                "coverage_pct": 0.0,
                "total_indexed": 0,
                "analyzed": 0,
                "unvisited": 0,
                "note": "No embeddings indexed yet.",
            }
        return {"ok": True, **fe.coverage()}

    elif action == "propagate_labels":
        # Propagate LLM blackboard labels to embedding-similar neighbors.
        # Writes 'propagated' source_type entries for neighbors within cosine threshold.
        try:
            from ida_pro_mcp.services import FrontierEngine
        except ImportError:
            from host.frontier import FrontierEngine  # type: ignore
        idb_path = ""
        try:
            import idc as _idc
            idb_path = _idc.get_idb_path() or ""
        except Exception:
            pass
        emb_db = (idb_path + ".embeddings.db") if idb_path else ""
        fe = FrontierEngine(emb_db, store.db_path)
        n = fe.refresh()
        if n < 3:
            return {"ok": True, "propagated": 0, "note": "Not enough embeddings."}
        new_entries = fe.propagate_labels()
        return {
            "ok": True,
            "propagated": len(new_entries),
            "entries": new_entries[:20],
            "note": (
                f"Propagated {len(new_entries)} labels to embedding neighbors "
                f"(threshold={FrontierEngine.PROPAGATE_THRESHOLD}, "
                f"decay={FrontierEngine.PROPAGATE_DECAY}). "
                "Use blackboard(action='list', source_type='propagated') to review."
            ),
        }
    elif action == "export_symbols":
        try:
            from .knowledge import knowledge
        except Exception:
            from knowledge import knowledge  # type: ignore
        return knowledge(action="export_session", min_confidence=min_confidence, **kwargs)
    elif action == "import_symbols":
        try:
            from .knowledge import knowledge
        except Exception:
            from knowledge import knowledge  # type: ignore
        return knowledge(action="import_symbols", min_confidence=min_confidence, limit=limit, **kwargs)

    else:
        return make_error(MCPError.ACTION_NOT_FOUND, f"Unknown action: {action}")
