#!/usr/bin/env python3
"""Blackboard store and host-side orchestration helpers."""

import hashlib
import importlib.util
import json
import os
import re
from typing import Any, Optional

from .errors import MCPError, make_error
from .schemas import TOOL_ACTIONS
from .symbol_db import SymbolDB


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class ServerBlackboardMixin:
    def _get_blackboard_store(self):
        """
        Return a BlackboardStore scoped to the current session's IDB path.
        Creates a new store object per session so binaries don't share findings.
        Falls back to the cached global store when no session is active.
        """
        try:
            if type(self)._blackboard_module is None:
                import importlib.util
                bb_path = os.path.join(SCRIPT_DIR, "..", "ida_mcp", "tools", "blackboard.py")
                bb_path = os.path.abspath(bb_path)
                spec = importlib.util.spec_from_file_location("_host_blackboard", bb_path)
                mod = importlib.util.module_from_spec(spec)
                mod.__dict__["tool"] = lambda f: f
                mod.__dict__["idaread"] = lambda f: f
                mod.__dict__["idawrite"] = lambda f: f
                mod.__dict__["IDAError"] = Exception
                spec.loader.exec_module(mod)
                type(self)._blackboard_module = mod
            mod = type(self)._blackboard_module
            # Per-binary scoping: derive path from current session IDB
            idb = None
            if self.current_session and getattr(self.current_session, "idb_path", None):
                idb = self.current_session.idb_path + ".blackboard.db"
            return mod.BlackboardStore(db_path=idb)
        except Exception:
            # Last-resort fallback: global store
            if type(self)._blackboard_store is None:
                try:
                    type(self)._blackboard_store = type(self)._blackboard_module.BlackboardStore()
                except Exception:
                    return None
            return type(self)._blackboard_store

    def _binary_sha256(self, binary_path: str) -> str:
        try:
            if not binary_path or not os.path.exists(binary_path):
                return ""
            h = hashlib.sha256()
            with open(binary_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _export_session_hypotheses_to_symbol_db(self, sid: str, session_obj=None) -> int:
        try:
            sess = session_obj or self.session_mgr.get_session(sid)
            if not sess:
                return 0
            hyps = self.session_mgr.get_high_confidence_hypotheses(sid, min_confidence=0.8)
            if not hyps:
                return 0
            bin_hash = self._binary_sha256(str(getattr(sess, "binary_path", "") or ""))
            chip = str((getattr(sess, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            baseaddr = 0
            try:
                raw_base = (getattr(sess, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            sdb = SymbolDB()
            count = 0
            for h in hyps:
                text = str(h.get("statement") or h.get("title") or "").strip()
                if not text:
                    continue
                m = re.search(r"0x[0-9a-fA-F]+", text)
                if not m:
                    continue
                try:
                    addr = int(m.group(0), 16)
                except Exception:
                    continue
                addr_offset = addr - baseaddr if baseaddr and addr >= baseaddr else addr
                conf = float(h.get("confidence", 0.8) or 0.8)
                rid = sdb.upsert_hypothesis(
                    binary_hash=bin_hash,
                    chip_family=chip,
                    addr_offset=int(addr_offset),
                    hypothesis_text=text,
                    confidence=conf,
                    source_session=sid,
                    source_binary=str(getattr(sess, "binary_path", "") or ""),
                )
                if rid:
                    count += 1
            return int(count)
        except Exception:
            return 0

    def _import_cross_session_hypotheses(self, session_obj) -> int:
        try:
            if not session_obj:
                return 0
            bin_hash = self._binary_sha256(str(getattr(session_obj, "binary_path", "") or ""))
            chip = str((getattr(session_obj, "analysis_options", {}) or {}).get("chip_family") or "").strip()
            sdb = SymbolDB()
            hits = sdb.query_hypotheses(binary_hash=bin_hash, chip_family=chip, limit=200)
            if not hits:
                return 0
            baseaddr = 0
            try:
                raw_base = (getattr(session_obj, "analysis_options", {}) or {}).get("baseaddr")
                if isinstance(raw_base, str):
                    baseaddr = int(raw_base, 0)
                elif raw_base is not None:
                    baseaddr = int(raw_base)
            except Exception:
                baseaddr = 0
            bb_path = str(getattr(session_obj, "idb_path", "") or "") + ".blackboard.db"
            store = type(self)._blackboard_module.BlackboardStore(db_path=bb_path) if type(self)._blackboard_module else self._get_blackboard_store()
            if store is None:
                return 0
            imported = 0
            for row in hits:
                title = str(row.get("hypothesis_text") or "").strip()
                if not title:
                    continue
                off = int(row.get("addr_offset", 0) or 0)
                addr = hex((baseaddr + off) if baseaddr else off)
                if store.exists_similar(addr, "hypothesis", title):
                    continue
                store.write(
                    title=title,
                    content=f"Imported from prior session ({row.get('source_session', '')})",
                    category="hypothesis",
                    addr=addr,
                    tags=["cross_session", "symboldb"],
                    confidence=float(row.get("confidence", 0.8) or 0.8),
                    source="symbol_db.import",
                    source_type="cross_session",
                )
                imported += 1
            return int(imported)
        except Exception:
            return 0

    def _handle_blackboard(self, args: dict) -> dict:
        """Host-side blackboard handler so it works without IDA runtime."""
        store = self._get_blackboard_store()
        if store is None:
            return make_error(MCPError.IDA_ERROR, "BlackboardStore unavailable")
        action = str(args.get("action") or "list").strip().lower()
        if action == "write":
            title = str(args.get("name") or args.get("title") or "").strip()
            if not title:
                return make_error(MCPError.INVALID_ARGS, "name/title required for write")
            # Parse Cartographer-μ metadata if provided
            bridges_raw = str(args.get("bridges") or "")
            bridges = [b.strip() for b in bridges_raw.split(",") if b.strip()]
            schema_str = str(args.get("schema") or "")
            schema = {}
            if schema_str:
                try:
                    schema = json.loads(schema_str)
                except Exception:
                    pass
            vector = args.get("vector")
            quantized = args.get("quantized")
            q_signs = args.get("q_signs")
            norm = float(args.get("norm", 0.0))
            q_value = float(args.get("q_value", 0.5))
            call_idx = int(args.get("call_idx", 0))
            raw_tags = args.get("tags")
            if isinstance(raw_tags, list):
                tags = [str(t).strip() for t in raw_tags if str(t).strip()]
            elif isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            else:
                tags = []

            eid = store.write(
                title=title,
                content=str(args.get("notes") or args.get("content") or ""),
                category=str(args.get("category") or "general"),
                addr=str(args.get("addr") or ""),
                tags=tags,
                confidence=float(args.get("confidence", 0.5)),
                bridges=bridges,
                schema=schema,
                vector=vector,
                quantized=quantized,
                q_signs=q_signs,
                norm=norm,
                q_value=q_value,
                call_idx=call_idx,
            )
            return {"ok": True, "entry_id": eid, "action": "write"}
        if action == "list":
            entries = store.list(
                category=str(args.get("category") or "").strip() or None,
                addr=str(args.get("addr") or "").strip() or None,
                tag=str(args.get("tag") or "").strip() or None,
                min_confidence=float(args.get("min_confidence", 0.0)),
                limit=_bounded_int(args.get("limit", 100), 100, min_value=1, max_value=1000),
                offset=_bounded_int(args.get("offset", 0), 0, min_value=0),
            )
            return {"ok": True, "entries": entries, "count": len(entries)}
        if action == "search":
            query = str(args.get("query") or args.get("pattern") or "").strip()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query/pattern required for blackboard search")
            entries = store.semantic_search(
                query=query,
                top_k=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500),
                threshold=float(args.get("threshold", 0.4)),
                category=str(args.get("category") or "").strip() or None,
                include_resolved=bool(args.get("include_resolved", True)),
                include_contradicted=bool(args.get("include_contradicted", False)),
            )
            return {"ok": True, "query": query, "entries": entries, "count": len(entries)}
        if action == "read":
            entry = store.read(str(args.get("entry_id") or ""))
            if entry is None:
                return make_error(MCPError.INVALID_ARGS, "Entry not found")
            return {"ok": True, "entry": entry}
        if action == "update":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            updates = {
                k: v
                for k, v in (args or {}).items()
                if k
                not in {
                    "action",
                    "entry_id",
                }
            }
            if not updates:
                return make_error(MCPError.INVALID_ARGS, "No update fields provided")
            ok = store.update(entry_id, **updates)
            return {"ok": ok, "action": "update", "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found or no valid fields")
        if action == "delete":
            ok = store.delete(str(args.get("entry_id") or ""))
            return {"ok": ok, "action": "delete"}
        if action == "clear":
            count = store.clear(category=str(args.get("category") or "").strip() or None)
            return {"ok": True, "deleted": count}
        if action == "stats":
            return {"ok": True, **store.stats()}
        if action == "merge":
            result = store.auto_merge(
                addr=str(args.get("addr") or "").strip(),
                category=str(args.get("category") or "").strip(),
                similarity_threshold=float(args.get("similarity_threshold", 0.85)),
            )
            return {"ok": True, **result}
        if action == "prune":
            result = store.prune(
                max_entries=_bounded_int(args.get("max_entries", 1000), 1000, min_value=1, max_value=100000),
                min_q_value=float(args.get("min_q_value", 0.0)),
                older_than_days=int(args.get("older_than_days", 0)),
            )
            return {"ok": True, **result}
        if action == "contradict":
            eid = str(args.get("entry_id") or "").strip()
            reason = str(args.get("reason") or "").strip()
            if not eid or not reason:
                return make_error(MCPError.INVALID_ARGS, "entry_id and reason required")
            ok = store.contradict(eid, reason)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "resolve":
            eid = str(args.get("entry_id") or "").strip()
            if not eid:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            ok = store.mark_resolved(eid)
            return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")
        if action == "next_target":
            targets = store.next_target(limit=int(args.get("limit") or 5))
            return {"ok": True, "targets": targets, "count": len(targets),
                    "note": "Highest-priority unexplored addresses. Use code(action='decompile') on the top target."}
        if action == "frontier":
            try:
                from .frontier import FrontierEngine
                emb_db = os.path.join(self.cache_dir, "embeddings.sqlite3")
                fe = FrontierEngine(emb_db, getattr(store, "db_path", None))
                results = fe.frontier(limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200))
                return {"ok": True, "frontier": results, "count": len(results)}
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"frontier unavailable: {e}")
        if action == "add_evidence":
            entry_id = str(args.get("entry_id") or "").strip()
            evidence_type = str(args.get("evidence_type") or args.get("type") or "").strip()
            value = str(args.get("value") or "").strip()
            if not entry_id or not evidence_type or not value:
                return make_error(MCPError.INVALID_ARGS, "entry_id, evidence_type/type, and value required")
            ok = store.add_evidence(entry_id, evidence_type=evidence_type, value=value, weight=float(args.get("weight", 1.0)))
            return {"ok": ok, "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
        if action == "calibrate":
            entry_id = str(args.get("entry_id") or "").strip()
            if not entry_id:
                return make_error(MCPError.INVALID_ARGS, "entry_id required")
            new_conf = store.calibrate_confidence(entry_id)
            if new_conf is None:
                return make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
            return {"ok": True, "entry_id": entry_id, "confidence": new_conf}
        if action == "campaign_summary":
            return {"ok": True, "summary": store.campaign_summary()}
        if action == "auto_tag_propagate":
            updated = store.auto_tag_propagate()
            return {"ok": True, "updated": int(updated)}
        if action in ("start_crawler", "stop_crawler", "crawler_status", "accept", "reject"):
            # Delegate to the tool module which owns the crawler singleton
            mod = type(self)._blackboard_module
            if mod is None:
                return make_error(MCPError.IDA_ERROR, "BlackboardStore unavailable")
            crawler = mod._BackgroundCrawler.instance()
            if action == "start_crawler":
                crawler.start(notify_fn=self._send_notification)
                return {"ok": True, "running": crawler.is_running(),
                        "note": "Crawler uses frontier targets and runs agent(action='quick') every 0.5s."}
            elif action == "stop_crawler":
                crawler.stop()
                return {"ok": True, "running": False}
            elif action == "crawler_status":
                proposals = crawler.pending_proposals()
                return {"ok": True, "running": crawler.is_running(),
                        "pending_proposals": len(proposals), "proposals_pending": len(proposals),
                        "addresses_visited": crawler.visited_count(), "proposals": proposals[:10]}
            elif action == "accept":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                eid = crawler.accept(pid)
                return {"ok": bool(eid), "entry_id": eid} if eid else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
            elif action == "reject":
                pid = str(args.get("proposal_id") or "").strip()
                if not pid:
                    return make_error(MCPError.INVALID_ARGS, "proposal_id required")
                ok = crawler.reject(pid)
                return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found")
        if action == "attention_status":
            return {"ok": True, "note": "attention_kernel replaced by intelligence.py"}
        if action == "attention_policy_upsert":
            return {"ok": True, "action": "attention_policy_upsert",
                    "note": "attention_kernel replaced by intelligence.py"}
        if action in ("accept_proposal", "reject_proposal"):
            sid = self.current_session.session_id if self.current_session else ""
            engine = self._analysis_engines.get(sid)
            if not engine:
                return make_error(MCPError.NOT_FOUND, "No analysis engine running for current session")
            pid = str(args.get("proposal_id") or "").strip()
            if not pid:
                return make_error(MCPError.INVALID_PARAMS, "proposal_id required")
            if action == "accept_proposal":
                scope = str(args.get("scope") or "all").strip()
                selected_ids = args.get("selected_ids") or []
                result = engine.proposals.accept(pid, scope=scope, selected_ids=selected_ids)
                if result is None:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                # Apply accepted items based on proposal type
                applied = self._apply_proposal(result, engine)
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://state"},
                })
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid, "accepted_items": len(result.get("accepted_items", [])), "applied": applied}
            else:
                bb_path = os.path.join(self.cache_dir, f"{sid}.blackboard.db")
                ok = engine.proposals.reject(pid, bb_path=bb_path)
                if not ok:
                    return make_error(MCPError.NOT_FOUND, f"Proposal '{pid}' not found or already processed")
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": "ida://proposals"},
                })
                return {"ok": True, "proposal_id": pid}
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported blackboard action: '{action}'",
            hint="Valid actions: write, read, list, search, update, delete, clear, stats, merge, prune, contradict, resolve, next_target, start_crawler, stop_crawler, crawler_status, accept, reject, accept_proposal, reject_proposal, add_evidence, calibrate, campaign_summary, auto_tag_propagate",
        )

