#!/usr/bin/env python3
"""Blackboard host surface: dict-driven action dispatch over the store.

The host-side blackboard handler is the single authority for every
blackboard action (the in-IDA ``blackboard.py`` tool only handles
``related_by_behavior``). This module owns the dispatch table that routes
each action to a ``_bb_action_*`` handler, the governance gate that runs
once per dispatch (phase auto-transition, contract check, strict policy),
and the bounded evidence-gravity snapshot fired only when a write creates a
new entry.

Analyst memory lives in the workspace findings table (written through the
store); machinery — crawler state, trace tasks, evidence-gravity snapshots,
and the per-session phase/policy core — lives in ``bb_machinery`` /
``bb_tasks`` owned by :mod:`blackboard_orchestration`. The phase/policy
machines are in :mod:`server_blackboard_phase`, trace tasks in
:mod:`server_blackboard_trace`, and the IDB-publishing surface in
:mod:`server_blackboard_idb`.

Canonical keep=true response shapes (write/search/frontier/next_target/
crawler_status/list/read/coverage/export) are composed from
:mod:`blackboard_shapes` so the pinned contracts stay in one place.
"""

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import threading
from typing import Any

from ..config import _bounded_int, _coerce_bool
from ..errors import MCPError, is_error_result, make_error
from ..intelligence.helpers import parse_str_list
from ..stores.blackboard_store import STRATEGIES as BB_STRATEGIES, is_auto_name
from ..stores.symbol_db import SymbolDB
from .blackboard_orchestration import (
    EVIDENCE_GRAVITY_MAX_ITEMS,
    NS_GRAVITY,
    BlackboardOrchestrator,
)
from .blackboard_shapes import (
    STRATEGY_EMPTY_NOTES as _STRATEGY_EMPTY,
    STRATEGY_NOTES as _STRATEGY_NOTES,
    build_export_snapshot,
    coverage_response,
    crawler_status_response,
    entry_brief as _entry_brief,
    entry_collection_summary as _entry_collection_summary,
    frontier_response,
    list_response,
    next_target_response,
    read_response,
    search_response,
    snapshot_to_json,
    snapshot_to_markdown,
    write_response,
)
from .server_blackboard_idb import ServerBlackboardIdbMixin
from .server_blackboard_phase import ServerBlackboardPhaseMixin
from .server_blackboard_trace import ServerBlackboardTraceMixin

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

#: Lane name → store category for the working-set lanes.
_LANE_CATEGORY = {
    "lane_now": "wm_now",
    "lane_hypotheses": "hypothesis",
    "lane_facts": "fact",
    "lane_queue": "frontier",
    "lane_dead_ends": "dead_end",
}

#: Actions exempt from the phase contract gate — read-only / introspection.
_PHASE_GATE_EXEMPT_ACTIONS = frozenset({
    "phase_status", "phase_set", "working_set", "list", "read", "search",
    "state_health", "policy_set", "policy_status", "policy_check",
})

#: Actions whose response carries a phase snapshot.
_PHASE_SNAPSHOT_ACTIONS = frozenset({
    "write", "decision_card", "proposal_create", "proposal_list",
    "proposal_accept", "proposal_reject", "trace_ingest", "trace_status",
    "trace_run", "memory_compile", "phase_finalize", "working_set",
    "state_health", "policy_status", "policy_check", "phase_status",
    "phase_set",
})

#: Actions gated by the strict policy gate when enforced for the current phase.
_STRICT_POLICY_ACTIONS = frozenset({"proposal_accept", "trace_run"})

#: Actions that only need phase/policy state (no store open).
_POLICY_ONLY_ACTIONS = frozenset({
    "policy_set", "policy_status", "policy_check", "phase_status", "phase_set",
})

#: Dispatch table: blackboard action → handler method name.
_BLACKBOARD_ACTIONS: dict[str, str] = {
    # governance / phase
    "policy_set": "_bb_action_policy_set",
    "policy_status": "_bb_action_policy_status",
    "policy_check": "_bb_action_policy_check",
    "phase_status": "_bb_action_phase_status",
    "phase_set": "_bb_action_phase_set",
    "phase_tick": "_bb_action_phase_tick",
    # analyst memory
    "write": "_bb_action_write",
    "decision_card": "_bb_action_decision_card",
    "memory_compile": "_bb_action_memory_compile",
    "phase_finalize": "_bb_action_memory_compile",
    # proposal lifecycle (over real entries)
    "proposal_create": "_bb_action_proposal_create",
    "proposal_list": "_bb_action_proposal_list",
    "proposal_accept": "_bb_action_proposal_accept",
    "proposal_reject": "_bb_action_proposal_reject",
    # trace tasks
    "trace_ingest": "_bb_action_trace_ingest",
    "trace_status": "_bb_action_trace_status",
    "trace_run": "_bb_action_trace_run",
    # lanes / state
    "working_set": "_bb_action_working_set",
    "state_health": "_bb_action_state_health",
    # file / export
    "export": "_bb_action_export",
    "notes_import": "_bb_action_notes_import",
    # CRUD
    "list": "_bb_action_list",
    "search": "_bb_action_search",
    "read": "_bb_action_read",
    "update": "_bb_action_update",
    "delete": "_bb_action_delete",
    "clear": "_bb_action_clear",
    "stats": "_bb_action_stats",
    "coverage": "_bb_action_coverage",
    "merge": "_bb_action_merge",
    "prune": "_bb_action_prune",
    "contradict": "_bb_action_contradict",
    "resolve": "_bb_action_resolve",
    "next_target": "_bb_action_next_target",
    "frontier": "_bb_action_frontier",
    "add_evidence": "_bb_action_add_evidence",
    "calibrate": "_bb_action_calibrate",
    "decay": "_bb_action_decay",
    "campaign_summary": "_bb_action_campaign_summary",
    "workspace_brief": "_bb_action_workspace_brief",
    "mark_examined": "_bb_action_mark_examined",
    "recall": "_bb_action_recall",
    "publish_findings": "_bb_action_publish_findings",
    "import_annotations": "_bb_action_import_annotations",
    "conflicts": "_bb_action_conflicts",
    "stale": "_bb_action_stale",
    # crawler
    "start_crawler": "_bb_action_start_crawler",
    "stop_crawler": "_bb_action_stop_crawler",
    "crawler_status": "_bb_action_crawler_status",
    "accept": "_bb_action_accept",
    "reject": "_bb_action_reject",
}


def _coerce_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [p.strip() for p in value.split("|") if p.strip()]
    return []


class ServerBlackboardMixin(
    ServerBlackboardPhaseMixin, ServerBlackboardTraceMixin, ServerBlackboardIdbMixin
):
    # Phase/policy methods are in ServerBlackboardPhaseMixin (server_blackboard_phase.py)
    # Trace methods are in ServerBlackboardTraceMixin (server_blackboard_trace.py)
    # IDB-publish methods are in ServerBlackboardIdbMixin (server_blackboard_idb.py)

    def _orchestration(self) -> BlackboardOrchestrator:
        """Return the lazily-created orchestration layer for this host."""
        orch = getattr(self, "_bb_orchestrator", None)
        if orch is None:
            orch = BlackboardOrchestrator(self)
            self._bb_orchestrator = orch
        return orch

    def _bb_dispatch_gate(self, action, args, store, phase_state, policy_state) -> dict | None:
        """Run the governance gate once per dispatch.

        Order is deliberate and mirrors the original monolithic dispatch: log
        the action, run the phase auto-transition, check the phase contract,
        then (for the strict-policy actions) the policy gate. Returns a
        POLICY_DENIED envelope when a gate blocks the action; else None so
        dispatch proceeds to the action handler.
        """
        self._phase_log_action(phase_state, action, addr=str(args.get("addr") or "").strip())
        if store is not None:
            self._phase_auto_transition(
                phase_state, action, args if isinstance(args, dict) else {}, store
            )
            phase_block = self._phase_contract_check(
                phase_state, action, args if isinstance(args, dict) else {}, store
            )
        else:
            phase_block = None
        if phase_block and action not in _PHASE_GATE_EXEMPT_ACTIONS:
            return phase_block
        if self._phase_find_loop(phase_state):
            self._phase_transition(phase_state, "prove", "auto: loop detected, injecting escape-route")
        current_phase = str((phase_state or {}).get("phase") or "scout")
        if (
            action in _STRICT_POLICY_ACTIONS
            and self._bb_policy_enforced_for_phase(policy_state, current_phase)
        ):
            check = self._bb_policy_check(policy_state)
            if not check.get("ok"):
                return self._policy_denied(
                    phase_state,
                    policy_state,
                    "Strict policy gate failed before execution",
                )
        return None

    def _handle_blackboard(self, args: dict) -> dict:
        """Host-side blackboard handler.

        Wraps the dispatch so malformed numeric args (``int``/``float`` on
        caller strings) surface as an INVALID_ARGS envelope instead of raising
        a ValueError out of the dispatch layer, which would report an internal
        error to the MCP client.
        """
        try:
            return self._handle_blackboard_inner(args)
        except (TypeError, ValueError) as exc:
            return make_error(MCPError.INVALID_ARGS, str(exc))

    def _handle_blackboard_inner(self, args: dict) -> dict:
        """Dict-driven blackboard dispatch so it works without IDA runtime."""
        policy_state = self._bb_policy_bump()
        phase_state = self._phase_state()
        action = str(args.get("action") or "list").strip().lower()
        store = None
        if action not in _POLICY_ONLY_ACTIONS:
            store = self._get_blackboard_store()
            if store is None:
                detail = getattr(self, "_blackboard_store_error", "") or ""
                if detail:
                    return make_error(MCPError.DB_ERROR, f"BlackboardStore unavailable: {detail}")
                return make_error(MCPError.IO_ERROR, "BlackboardStore unavailable")
        gate = self._bb_dispatch_gate(action, args, store, phase_state, policy_state)
        if gate is not None:
            return gate
        handler_name = _BLACKBOARD_ACTIONS.get(action)
        handler = getattr(self, handler_name, None) if handler_name else None
        if handler is None or not callable(handler):
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported blackboard action: '{action}'",
                hint="Valid actions include write, read, list, search, update, workspace_brief, next_target, frontier, stats, and legacy analysis actions.",
            )
        result = handler(args, store, phase_state, policy_state)
        if not isinstance(result, dict):
            return {"ok": True, "result": result}
        if action in _PHASE_SNAPSHOT_ACTIONS and "phase" not in result:
            result = dict(result)
            result["phase"] = self._phase_snapshot(phase_state, store)
        return result

    # ------------------------------------------------------------------
    # Workspace path / seeding
    # ------------------------------------------------------------------

    def _session_blackboard_path(self, session_obj=None, sid: str | None = None) -> str:
        session = session_obj
        sid_text = str(sid or "").strip()
        if session is None and sid_text:
            try:
                session = self.session_mgr.get_session(sid_text)
            except Exception:
                session = None
        if session is None and self.current_session and sid_text:
            current_sid = str(getattr(self.current_session, "session_id", "") or "").upper()
            if current_sid == sid_text.upper():
                session = self.current_session
        if session is None and self.current_session and not sid_text:
            session = self.current_session

        binary_path = str(getattr(session, "binary_path", "") or "").strip() if session else ""
        if binary_path and os.path.isfile(binary_path):
            # The cache + first-open seed is a check-then-act pair: two
            # sessions of the same binary opening concurrently must not both
            # compute the digest and both seed/backup the same workspace.
            lock = getattr(self, "_blackboard_path_lock", None)
            if lock is None:
                lock = threading.Lock()
                self._blackboard_path_lock = lock
            with lock:
                cache = getattr(self, "_blackboard_path_cache", None)
                if not isinstance(cache, dict):
                    cache = {}
                    self._blackboard_path_cache = cache
                try:
                    stat = os.stat(binary_path)
                    # Binary identity only — NOT the session id. The workspace is
                    # shared by every session of the same binary so findings
                    # survive session close, session rebuild, and new sessions.
                    cache_key = (
                        os.path.realpath(binary_path),
                        stat.st_size,
                        stat.st_mtime_ns,
                    )
                except OSError:
                    cache_key = (os.path.realpath(binary_path), 0, 0)
                workspace_path = cache.get(cache_key)
                if not workspace_path:
                    digest = self._binary_sha256(binary_path)
                    if digest:
                        workspace_dir = os.path.join(self.cache_dir, "blackboards")
                        os.makedirs(workspace_dir, exist_ok=True)
                        workspace_path = os.path.join(
                            workspace_dir,
                            f"sha256-{digest}.db",
                        )
                        idb_path = str(getattr(session, "idb_path", "") or "").strip()
                        self._seed_shared_workspace(workspace_path, digest, idb_path)
                        cache[cache_key] = workspace_path
                if workspace_path:
                    return workspace_path

        idb_path = str(getattr(session, "idb_path", "") or "").strip() if session else ""
        if idb_path:
            return idb_path + ".blackboard.db"

        fallback_sid = sid_text or str(getattr(session, "session_id", "") or "").strip()
        if fallback_sid:
            return os.path.join(self.cache_dir, f"{fallback_sid}.blackboard.db")
        return ""

    def _seed_shared_workspace(self, workspace_path: str, digest: str, idb_path: str) -> None:
        """Adopt findings from earlier workspace layouts into the shared db.

        The workspace is binary-scoped (one db per binary digest), so a new
        session for the same binary starts with the accumulated
        investigation. Previous releases stored the workspace per session
        (``sha256-{digest}-{sid}.db``) or next to the IDB
        (``<idb>.blackboard.db``); those findings are seeded in exactly once,
        newest first, and never overwrite rows already present.

        ``_merge_workspace_rows`` uses INSERT OR IGNORE, so a row that exists
        in both sources keeps its original id rather than being duplicated.
        """
        # Only seed an empty workspace. A db with rows already reflects the
        # investigation; re-seeding could replace newer rows with older ones.
        if os.path.exists(workspace_path):
            try:
                with sqlite3.connect(workspace_path) as conn:
                    has_table = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
                    ).fetchone()
                    if has_table:
                        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                        if count > 0:
                            return
            except sqlite3.Error:
                return
        candidates: list[str] = []
        blackboards_dir = os.path.join(self.cache_dir, "blackboards")
        try:
            for name in os.listdir(blackboards_dir):
                if name.startswith(f"sha256-{digest}-") and name.endswith(".db"):
                    candidates.append(os.path.join(blackboards_dir, name))
        except OSError:
            pass
        # Legacy layout: <idb_path>.blackboard.db next to the database.
        if idb_path:
            legacy = idb_path + ".blackboard.db"
            if os.path.isfile(legacy):
                candidates.append(legacy)
        if not candidates:
            return
        try:
            ordered = sorted(candidates, key=os.path.getmtime, reverse=True)
            with sqlite3.connect(ordered[0]) as source, sqlite3.connect(workspace_path) as target:
                source.backup(target)
            for older in ordered[1:]:
                self._merge_workspace_rows(older, workspace_path)
        except (sqlite3.Error, OSError):
            pass

    @staticmethod
    def _merge_workspace_rows(source_path: str, target_path: str) -> None:
        """Copy rows from one workspace db into another without clobbering."""
        try:
            with sqlite3.connect(target_path) as target, sqlite3.connect(source_path) as source:
                tables = [
                    str(r[0])
                    for r in source.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                ]
                for table in tables:
                    try:
                        cols = [
                            str(c[1])
                            for c in source.execute(f'PRAGMA table_info("{table}")').fetchall()
                        ]
                        if not cols:
                            continue
                        col_sql = ",".join(f'"{c}"' for c in cols)
                        placeholders = ",".join("?" * len(cols))
                        rows = source.execute(f'SELECT {col_sql} FROM "{table}"').fetchall()
                        if rows:
                            target.executemany(
                                f'INSERT OR IGNORE INTO "{table}" ({col_sql}) VALUES ({placeholders})',
                                rows,
                            )
                    except sqlite3.Error:
                        continue
                target.commit()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------
    # Evidence gravity (bounded snapshot, fired on create)
    # ------------------------------------------------------------------

    def _evidence_gravity(self, store, source_entry_id: str, addr: str, source_text: str = "") -> dict[str, Any]:
        """Pull a bounded evidence snapshot around ``addr`` and persist it.

        Fired only when a write created a new entry. The response-carried view
        is ``{ok, entry_id, items, note}`` with at most
        ``EVIDENCE_GRAVITY_MAX_ITEMS`` items; the raw snapshot is stored in
        ``bb_machinery`` under the gravity namespace so it survives without
        polluting the analyst-facing findings table.
        """
        addr = str(addr or "").strip()
        if not addr or not hasattr(self, "_execute_tool"):
            return {"ok": False, "reason": "no_addr_or_runtime"}
        pulls = []
        probes = [
            ("graph", {"action": "xref_graph", "addr": addr, "depth": 2, "max_items": 8}),
            ("code", {"action": "callers", "addr": addr, "limit": 8}),
            ("code", {"action": "callees", "addr": addr, "limit": 8}),
            ("code", {"action": "strings_in_func", "addr": addr, "limit": 8}),
            ("search", {"action": "find", "query": addr, "limit": 5}),
        ]
        for tool, targs in probes:
            try:
                res = self._execute_tool(tool, targs)
                pulls.append(
                    {
                        "tool": tool,
                        "args": targs,
                        "ok": bool(isinstance(res, dict) and not is_error_result(res)),
                        "result": res,
                    }
                )
            except Exception as exc:
                pulls.append({"tool": tool, "args": targs, "ok": False, "error": str(exc)})
        embedding_neighbors = []
        try:
            query = (source_text or "").strip() or addr
            sims = store.semantic_search(
                query=query,
                top_k=5,
                threshold=0.35,
                include_resolved=True,
                include_contradicted=False,
            )
            if isinstance(sims, list):
                for s in sims[:5]:
                    embedding_neighbors.append(
                        {
                            "entry_id": s.get("id"),
                            "addr": s.get("addr"),
                            "title": s.get("title"),
                            "category": s.get("category"),
                            "confidence": s.get("confidence"),
                        }
                    )
        except Exception:
            embedding_neighbors = []
        items = []
        for p in pulls:
            items.append(
                {
                    "tool": p.get("tool"),
                    "addr": addr,
                    "ok": bool(p.get("ok")),
                    "result": p.get("result")
                    if p.get("ok")
                    else {"error": str(p.get("error") or "probe failed")},
                }
            )
        for n in embedding_neighbors:
            items.append({"tool": "semantic", "addr": n.get("addr"), "ok": True, "result": n})
        items = items[:EVIDENCE_GRAVITY_MAX_ITEMS]
        snapshot = {
            "source_entry_id": source_entry_id,
            "addr": addr,
            "items": items,
            "note": f"bounded evidence gravity snapshot (max {EVIDENCE_GRAVITY_MAX_ITEMS} items)",
        }
        with contextlib.suppress(Exception):
            self._orchestration().machinery_set(store, NS_GRAVITY, source_entry_id, snapshot)
        return {
            "ok": True,
            "entry_id": source_entry_id,
            "items": items,
            "note": snapshot["note"],
        }

    # ------------------------------------------------------------------
    # Memory compiler
    # ------------------------------------------------------------------

    def _memory_compile(self, store, limit: int = 30, notes_path: str = "") -> dict[str, Any]:
        entries = store.list(include_resolved=True, include_contradicted=True, limit=max(200, limit * 4))
        facts = []
        open_h = []
        dead = []
        for e in entries:
            conf = float(e.get("confidence") or 0.0)
            cat = str(e.get("category") or "")
            contradicted = bool(e.get("contradicted"))
            resolved = bool(e.get("resolved"))
            if contradicted or cat == "dead_end":
                dead.append(_entry_brief(e))
                continue
            if conf >= 0.75 or cat == "fact":
                facts.append(_entry_brief(e))
            elif not resolved and cat in {"hypothesis", "wm_now", "frontier"}:
                open_h.append(_entry_brief(e))
        proposals = self._proposal_entries(store, status="proposed", limit=120)
        rename_batch = []
        for p in proposals:
            try:
                payload = json.loads(str(p.get("content") or "{}"))
            except Exception:
                payload = {}
            if str(payload.get("proposal_type") or "") != "rename":
                continue
            rename_batch.append(
                {
                    "proposal_id": p.get("id"),
                    "title": p.get("title"),
                    "spec": (payload.get("spec") or {}).get("renames", [])[:5],
                }
            )
        frontier = store.next_target(limit=limit)
        quest_logs = store.list(category="quest_log", include_resolved=True, include_contradicted=True, limit=400)
        quest_total = len(quest_logs)
        quest_completed = 0
        quest_failed = 0
        for q in quest_logs:
            tags = q.get("tags") or []
            if isinstance(tags, list) and "status:completed" in tags:
                quest_completed += 1
            elif isinstance(tags, list) and "status:failed" in tags:
                quest_failed += 1
        quest_completion_rate = (quest_completed / quest_total) if quest_total else 0.0
        contradictions = int((store.stats() or {}).get("contradicted") or 0)
        phase_quality_score = max(
            0.0,
            min(
                100.0,
                40.0
                + min(25.0, float(len(facts)) * 1.2)
                + min(25.0, float(len(rename_batch)) * 1.5)
                + min(20.0, quest_completion_rate * 20.0)
                - min(20.0, float(contradictions) * 3.0),
            ),
        )
        compiled = {
            "facts": facts[:limit],
            "open_hypotheses": open_h[:limit],
            "dead_ends": dead[:limit],
            "rename_batch": rename_batch[:limit],
            "next_frontier": frontier[:limit],
            "quest_metrics": {
                "total": quest_total,
                "completed": quest_completed,
                "failed": quest_failed,
                "completion_rate": round(quest_completion_rate, 3),
            },
            "phase_quality": {
                "score": round(phase_quality_score, 2),
                "contradictions": contradictions,
            },
        }
        notes_written = ""
        path_err = None
        if notes_path:
            notes_path, path_err = self._bb_confine_path(notes_path)
        if notes_path and not path_err:
            try:
                lines = [
                    "# Memory Compiler Snapshot",
                    "",
                    f"phase_quality_score: {compiled['phase_quality']['score']}",
                    f"contradictions: {compiled['phase_quality']['contradictions']}",
                    f"quest_completion_rate: {compiled['quest_metrics']['completion_rate']}",
                    "",
                    "## Facts",
                ]
                if compiled["facts"]:
                    for f in compiled["facts"][:limit]:
                        lines.append(f"- {f.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Open Hypotheses"])
                if compiled["open_hypotheses"]:
                    for h in compiled["open_hypotheses"][:limit]:
                        lines.append(f"- {h.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Dead Ends"])
                if compiled["dead_ends"]:
                    for d in compiled["dead_ends"][:limit]:
                        lines.append(f"- {d.get('summary')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Rename Batch"])
                if compiled["rename_batch"]:
                    for rb in compiled["rename_batch"][:limit]:
                        lines.append(f"- [{rb.get('proposal_id')}] {rb.get('title')}")
                else:
                    lines.append("- (none)")
                lines.extend(["", "## Next Frontier"])
                if compiled["next_frontier"]:
                    for nf in compiled["next_frontier"][:limit]:
                        lines.append(
                            f"- {nf.get('addr') or 'no-addr'} | {nf.get('title') or nf.get('name') or ''} | priority={nf.get('priority_score')}"
                        )
                else:
                    lines.append("- (none)")
                os.makedirs(os.path.dirname(os.path.abspath(notes_path)) or ".", exist_ok=True)
                with open(notes_path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines).strip() + "\n")
                notes_written = os.path.abspath(notes_path)
            except Exception:
                notes_written = ""
        cid = store.write(
            title="memory compiler snapshot",
            content=json.dumps(compiled, ensure_ascii=True),
            category="wm_now",
            addr="",
            tags=["memory_compiler", "snapshot"],
            confidence=0.82,
            source="memory_compile",
            source_type="compiler",
        )
        return {"ok": True, "entry_id": cid, "notes_path": notes_written or None, **compiled}

    # ------------------------------------------------------------------
    # Proposal / lifecycle helpers
    # ------------------------------------------------------------------

    def _write_proposal_entry(
        self,
        store,
        *,
        proposal_type: str,
        title: str,
        spec: dict[str, Any],
        addr: str = "",
        confidence: float = 0.7,
        source: str = "proposal_create",
        verification_spec: dict[str, Any] | None = None,
        extra_tags: list[str] | None = None,
    ) -> str:
        """Write a real proposal entry with its lifecycle status in the payload."""
        payload = {
            "proposal_type": proposal_type,
            "spec": spec,
            "verification_spec": verification_spec or {},
            "status": "proposed",
        }
        tags = [f"proposal_type:{proposal_type}", "status:proposed", "proposal_lifecycle"]
        if extra_tags:
            tags.extend(str(t) for t in extra_tags if str(t).strip())
        return store.write(
            title=title,
            content=json.dumps(payload, ensure_ascii=True),
            category="proposal",
            addr=str(addr or "").strip(),
            tags=tags,
            confidence=float(confidence or 0.7),
            source=source,
            source_type="proposal",
            status="proposed",
        )

    def _write_crawler_proposal(
        self, store, *, addr: str, title: str, content: str, behavior_tags: list[str] | None = None
    ) -> str:
        """Write a crawler-generated rename proposal as a real store entry."""
        name = self._proposal_name_candidate(title)
        payload = {
            "proposal_type": "rename",
            "spec": {"renames": [{"addr": str(addr or "").strip(), "name": name}]},
            "verification_spec": {"kind": "symbol_name_match"},
            "status": "proposed",
            "source_crawler": True,
            "summary": str(content or "")[:220],
        }
        tags = ["proposal_type:rename", "status:proposed", "proposal_lifecycle", "crawler"]
        if behavior_tags:
            tags.extend(str(t) for t in behavior_tags[:8] if str(t).strip())
        return store.write(
            title=title,
            content=json.dumps(payload, ensure_ascii=True),
            category="proposal",
            addr=str(addr or "").strip(),
            tags=tags,
            confidence=0.55,
            source="crawler",
            source_type="proposal",
            status="proposed",
        )

    @staticmethod
    def _proposal_name_candidate(title: str) -> str:
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", str(title or "").strip())[:48].strip("_")
        if candidate and candidate[0].isdigit():
            candidate = "_" + candidate
        return candidate or "sub_candidate"

    def _apply_lifecycle_status(self, store, entry_id: str, status: str, reason: str = "") -> dict[str, Any] | None:
        """Transition a proposal/lifecycle entry and keep column + payload in sync.

        Returns the updated entry, or None when the entry is missing.
        """
        entry = store.read(entry_id)
        if entry is None:
            return None
        status = str(status or "").strip().lower()
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        new_tags = self._proposal_status_replace(tags, status)
        payload = {}
        try:
            payload = json.loads(str(entry.get("content") or "{}"))
        except Exception:
            payload = {}
        payload["status"] = status
        if reason:
            payload["last_reason"] = str(reason)[:200]
        ok = store.update(
            entry_id,
            tags=new_tags,
            content=json.dumps(payload, ensure_ascii=True),
        )
        if ok:
            with contextlib.suppress(Exception):
                store.update(entry_id, status=status)
        return store.read(entry_id) if ok else entry

    def _verified_proposal_addrs(self, store, limit: int = 400) -> set:
        out = set()
        try:
            proposals = store.list(
                category="proposal",
                include_resolved=True,
                include_contradicted=True,
                limit=limit,
            )
            for p in proposals:
                tags = p.get("tags") or []
                if not (isinstance(tags, list) and "status:verified" in tags):
                    continue
                if p.get("addr"):
                    out.add(str(p.get("addr")))
                payload = {}
                try:
                    payload = json.loads(str(p.get("content") or "{}"))
                except Exception:
                    payload = {}
                spec = payload.get("spec") or {}
                for row in spec.get("renames", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
                for row in spec.get("patches", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
                for row in spec.get("types", []):
                    a = str((row or {}).get("addr") or "").strip()
                    if a:
                        out.add(a)
        except Exception:
            pass
        return out

    def _lane_fetch(self, store, lane: str, limit: int) -> list[dict[str, Any]]:
        category = _LANE_CATEGORY.get(lane, "general")
        if lane == "lane_queue":
            targets = store.next_target(limit=limit)
            verified_addrs = self._verified_proposal_addrs(store)
            items = []
            for t in targets:
                addr = str(t.get("addr") or "")
                priority = float(t.get("priority_score") or 0.0)
                if addr and addr in verified_addrs:
                    priority += 0.2
                items.append({
                    "id": str(t.get("entry_id") or ""),
                    "category": "frontier",
                    "title": str(t.get("title") or t.get("name") or ""),
                    "content": str(t.get("summary") or ""),
                    "addr": addr,
                    "confidence": float(t.get("confidence") or 0.0),
                    "source_type": str(t.get("source_type") or "queue"),
                    "priority_score": round(priority, 4),
                    "tags": ["queue"] + (["proposal_verified_boost"] if addr in verified_addrs else []),
                })
            items.sort(key=lambda x: float(x.get("priority_score") or 0.0), reverse=True)
            return items
        kwargs = {
            "category": category,
            "limit": limit,
            "include_resolved": lane == "lane_dead_ends",
            "include_contradicted": False,
        }
        if lane != "lane_dead_ends":
            kwargs["min_confidence"] = 0.0
        return store.list(**kwargs)

    def _state_health(self, store) -> dict[str, Any]:
        stats = store.stats() or {}
        total = int(stats.get("total_entries") or 0)
        by_cat = stats.get("by_category") or {}
        unresolved = int(stats.get("unresolved") or 0)
        contradicted = int(stats.get("contradicted") or 0)
        avg_conf = float(stats.get("avg_confidence") or 0.0)
        now_count = int(by_cat.get("wm_now", 0) or 0)
        hyp_count = int(by_cat.get("hypothesis", 0) or 0)
        fact_count = int(by_cat.get("fact", 0) or 0)
        dead_count = int(by_cat.get("dead_end", 0) or 0)
        score = 100
        if total == 0:
            score -= 40
        if now_count == 0:
            score -= 20
        if hyp_count > 0 and fact_count == 0:
            score -= 10
        if avg_conf < 0.45:
            score -= 10
        if contradicted > max(2, unresolved // 2):
            score -= 10
        if dead_count == 0:
            score -= 5
        score = max(0, min(100, score))
        if now_count == 0:
            fix = "Write a `lane_now` decision card with the active objective and next verification step."
        elif fact_count == 0:
            fix = "Promote one high-confidence hypothesis into `lane_facts` after verification."
        elif avg_conf < 0.45:
            fix = "Calibrate weak entries and resolve or contradict stale low-confidence cards."
        else:
            fix = "Run `working_set` and follow the top `lane_queue` target."
        return {
            "state_health": score,
            "signals": {
                "total_entries": total,
                "wm_now": now_count,
                "hypotheses": hyp_count,
                "facts": fact_count,
                "dead_ends": dead_count,
                "avg_confidence": round(avg_conf, 3),
                "contradicted": contradicted,
            },
            "recommended_action": fix,
        }

    # ------------------------------------------------------------------
    # Filesystem sandbox
    # ------------------------------------------------------------------

    def _bb_path_root(self) -> str | None:
        """Root directory that blackboard file actions may read/write.

        Mirrors the memory tool's sandbox: an explicit env override, else the
        directory of the current IDB, else the host cache dir. Every path a
        caller passes to export / notes_import / memory_compile must resolve
        under this root so the bridge can never read or overwrite arbitrary
        host files.
        """
        env_root = os.environ.get("IDA_MCP_BLACKBOARD_ROOT")
        if env_root:
            try:
                return os.path.realpath(os.path.expanduser(env_root))
            except Exception:
                return None
        session = getattr(self, "current_session", None)
        idb_path = getattr(session, "idb_path", None) if session else None
        if idb_path:
            try:
                return os.path.realpath(os.path.dirname(idb_path))
            except Exception:
                pass
        cache_dir = getattr(self, "cache_dir", None)
        if cache_dir:
            return os.path.realpath(cache_dir)
        return None

    def _bb_confine_path(self, raw_path: str) -> tuple[str, str | None]:
        """Resolve a caller-supplied path inside the blackboard root.

        Returns ``(resolved, error_envelope)``. ``resolved`` is a real path
        under the root when OK; otherwise it is empty and the envelope explains
        why. ``..`` traversal and symlinked components are rejected, matching
        the memory tool's filesystem sandbox.
        """
        path = str(raw_path or "").strip()
        if not path:
            return "", make_error(MCPError.INVALID_ARGS, "path required")
        root = self._bb_path_root()
        if not root:
            return "", make_error(
                MCPError.INVALID_ARGS,
                "blackboard file action: no allowed root configured "
                "(set IDA_MCP_BLACKBOARD_ROOT or open a session).",
            )
        try:
            canonical = os.path.realpath(os.path.join(root, path))
        except Exception:
            return "", make_error(MCPError.INVALID_ARGS, "blackboard file action: invalid path")
        try:
            common = os.path.commonpath([root, canonical])
        except ValueError:
            return "", make_error(
                MCPError.INVALID_ARGS,
                "blackboard file action: path escapes allowed root",
            )
        if common != root:
            return "", make_error(
                MCPError.INVALID_ARGS,
                "blackboard file action: path escapes allowed root",
            )
        if self._bb_path_has_symlink(canonical, root):
            return "", make_error(
                MCPError.INVALID_ARGS,
                "blackboard file action: symbolic links are not allowed in path",
            )
        return canonical, None

    @staticmethod
    def _bb_path_has_symlink(abs_path: str, allowed_root: str) -> bool:
        if not abs_path or not allowed_root:
            return True
        try:
            rel = os.path.relpath(abs_path, allowed_root)
        except ValueError:
            return True
        if rel.startswith("..") or os.path.isabs(rel):
            return True
        parts = rel.split(os.sep)
        current = allowed_root
        for part in parts:
            if not part:
                continue
            current = os.path.join(current, part)
            if os.path.islink(current):
                return True
        return False

    # ------------------------------------------------------------------
    # Findings export (canonical snapshot via blackboard_shapes)
    # ------------------------------------------------------------------

    def _findings_export(
        self,
        store,
        fmt: str = "json",
        path: str = "",
        kind: str = "",
        status: str = "",
        category: str = "",
        tag: str = "",
        addr: str = "",
        min_confidence: float = 0.0,
        include_resolved: bool = True,
        include_contradicted: bool = True,
        limit: int = 0,
    ) -> dict[str, Any]:
        """Export the investigation in the findings format, JSON or Markdown.

        This is the full-fidelity snapshot of the workspace, carrying
        everything the ``ida_write_finding`` contract can express, so a
        report, another tool, or a later session can consume it without
        losing evidence.
        """
        page_size = 1000
        offset = 0
        entries: list[dict[str, Any]] = []
        cap = max(0, int(limit))
        while True:
            page = store.list(
                category=category.strip() or None,
                addr=addr.strip() or None,
                tag=tag.strip() or None,
                min_confidence=min_confidence,
                include_resolved=include_resolved,
                include_contradicted=include_contradicted,
                kind=kind.strip() or None,
                status=status.strip() or None,
                limit=page_size,
                offset=offset,
            )
            for row in page:
                if cap and len(entries) >= cap:
                    break
                entries.append(row)
            if len(page) < page_size or (cap and len(entries) >= cap):
                break
            offset += page_size
        stats = store.stats() or {}
        snapshot = build_export_snapshot(entries, stats=stats)
        if fmt == "markdown":
            content = snapshot_to_markdown(snapshot)
        else:
            content = snapshot_to_json(snapshot)
        if path.strip():
            out_path, path_err = self._bb_confine_path(path)
            if path_err:
                return path_err
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(content + ("\n" if fmt == "markdown" else ""))
            return {
                "ok": True,
                "format": fmt,
                "path": out_path,
                "entries": len(entries),
                "stats": snapshot["stats"],
            }
        return {
            "ok": True,
            "format": fmt,
            "content": content,
            "entries": len(entries),
            "stats": snapshot["stats"],
        }

    def _notes_import(
        self,
        store,
        notes_path: str,
        lane: str = "lane_hypotheses",
        confidence: float = 0.65,
        auto_trace: bool = False,
        trace_depth: int = 2,
        trace_limit: int = 8,
    ) -> dict[str, Any]:
        notes_path, path_err = self._bb_confine_path(notes_path)
        if path_err:
            return path_err
        if not os.path.exists(notes_path):
            return make_error(MCPError.NOT_FOUND, f"Notes file not found: {notes_path}")
        category = _LANE_CATEGORY.get(lane, "hypothesis")
        imported = 0
        trace_tasks = []
        with open(notes_path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line.startswith("- "):
                    continue
                text = line[2:].strip()
                if not text or text.startswith(("(empty)", "(none)")):
                    continue
                title = text[:140]
                if store.exists_similar("", category, title):
                    continue
                store.write(
                    title=title,
                    content=text,
                    category=category,
                    addr="",
                    tags=["notes_import", lane],
                    confidence=float(confidence),
                    source="notes_import",
                    source_type="human_notes",
                )
                imported += 1
                task_id = self._maybe_auto_trace_from_text(
                    store,
                    source_entry_id="",
                    source_text=text,
                    auto_trace=auto_trace,
                    depth=trace_depth,
                    limit=trace_limit,
                )
                if task_id:
                    trace_tasks.append(task_id)
        return {
            "ok": True,
            "path": os.path.abspath(notes_path),
            "imported": imported,
            "lane": lane,
            "trace_tasks_created": len(trace_tasks),
            "trace_task_ids": trace_tasks[:20],
        }

    # ------------------------------------------------------------------
    # Proposal spec validation + verification + execution
    # ------------------------------------------------------------------

    def _validate_rename_spec(self, spec: dict[str, Any]) -> str | None:
        if not isinstance(spec, dict):
            return "rename_spec must be an object"
        renames = spec.get("renames")
        if not isinstance(renames, list) or not renames:
            return "rename_spec.renames must be a non-empty list"
        for idx, row in enumerate(renames):
            if not isinstance(row, dict):
                return f"rename_spec.renames[{idx}] must be an object"
            addr = str(row.get("addr") or "").strip()
            name = str(row.get("name") or "").strip()
            if not addr:
                return f"rename_spec.renames[{idx}].addr required"
            if not name:
                return f"rename_spec.renames[{idx}].name required"
        return None

    def _validate_patch_spec(self, spec: dict[str, Any]) -> str | None:
        if not isinstance(spec, dict):
            return "patch_spec must be an object"
        patches = spec.get("patches")
        if not isinstance(patches, list) or not patches:
            return "patch_spec.patches must be a non-empty list"
        for idx, row in enumerate(patches):
            if not isinstance(row, dict):
                return f"patch_spec.patches[{idx}] must be an object"
            addr = str(row.get("addr") or "").strip()
            asm = str(row.get("asm") or row.get("bytes") or "").strip()
            if not addr:
                return f"patch_spec.patches[{idx}].addr required"
            if not asm:
                return f"patch_spec.patches[{idx}].asm or .bytes required"
        return None

    def _validate_proposal_spec(self, proposal_type: str, spec: dict[str, Any]) -> str | None:
        if proposal_type == "rename":
            return self._validate_rename_spec(spec)
        if proposal_type == "patch":
            return self._validate_patch_spec(spec)
        if proposal_type == "type":
            if not isinstance(spec, dict):
                return "type_spec must be an object"
            items = spec.get("types")
            if not isinstance(items, list) or not items:
                return "type_spec.types must be a non-empty list"
            return None
        return None

    def _proposal_entries(self, store, status: str = "", limit: int = 100) -> list[dict[str, Any]]:
        entries = store.list(category="proposal", include_resolved=True, include_contradicted=True, limit=limit)
        if status:
            status = status.strip().lower()
            return [e for e in entries if self._proposal_status(e) == status]
        return entries

    def _proposal_status_replace(self, tags: list[str], new_status: str) -> list[str]:
        clean = [t for t in tags if not str(t).startswith("status:")]
        clean.append(f"status:{new_status}")
        return clean

    def _proposal_status(self, entry: dict[str, Any]) -> str:
        """Effective lifecycle status of a proposal.

        proposal_create/accept/reject write the status into the JSON payload,
        which is authoritative. The ``status:*`` tags are only advisory: the
        store unions tags, so they accumulate and cannot express replacement.
        """
        payload = {}
        try:
            payload = json.loads(str(entry.get("content") or "{}"))
        except Exception:
            payload = {}
        content_status = str(payload.get("status") or "").strip().lower()
        if content_status:
            return content_status
        tags = entry.get("tags") or []
        if isinstance(tags, list):
            statuses = [t.split(":", 1)[1] for t in tags if str(t).startswith("status:")]
            for st in ("verified", "failed", "accepted", "rejected"):
                if st in statuses:
                    return st
            if statuses:
                return statuses[0]
        return "proposed"

    def _symbol_at(self, addr: str) -> str:
        """Read the symbol currently applied at an address, if a runtime is live."""
        if not hasattr(self, "_execute_tool"):
            return ""
        try:
            res = self._execute_tool("data", {"action": "lookup", "query": addr})
            if isinstance(res, dict) and not is_error_result(res):
                return str(res.get("name") or "")
        except Exception:
            pass
        return ""

    def _proposal_verify(self, proposal_type: str, spec: dict[str, Any]) -> dict[str, Any]:
        """Verify a proposal spec before execution.

        Rename proposals additionally check the live symbol table when an IDB
        hook is available: a name an analyst applied (not an auto-name) is
        never overwritten. Patch/type proposals are verified structurally.
        """
        checks = []
        problems = []
        if proposal_type == "rename":
            for row in (spec or {}).get("renames", []):
                addr = str((row or {}).get("addr") or "").strip()
                name = str((row or {}).get("name") or "").strip()
                if not addr or not name:
                    problems.append(f"rename row missing addr/name: {row!r}")
                    continue
                checks.append({"kind": "symbol_name_match", "addr": addr, "name": name})
                current = self._symbol_at(addr)
                if current and not is_auto_name(current):
                    problems.append(f"{addr} is already named {current!r}; refusing to overwrite")
        else:
            checks.append({"kind": "spec_structure", "proposal_type": proposal_type})
        return {
            "ok": not problems,
            "checks": checks[:20],
            "problems": problems[:20],
            "note": "Verification passed." if not problems else "Verification failed: " + "; ".join(problems[:5]),
        }

    def _proposal_execute(self, proposal_type: str, spec: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self, "_execute_tool"):
            return {"ok": True, "applied": 0, "note": "Execution hook unavailable in this runtime."}
        applied = 0
        if proposal_type == "rename":
            for r in spec.get("renames", []):
                addr = str(r.get("addr") or "").strip()
                name = str(r.get("name") or "").strip()
                if not addr or not name:
                    continue
                try:
                    res = self._execute_tool("annotation", {"action": "label", "addr": addr, "name": name})
                    if isinstance(res, dict) and not is_error_result(res):
                        applied += 1
                except Exception:
                    pass
        elif proposal_type == "patch":
            # Patch execution is not implemented on the host. Report the
            # non-execution honestly so proposal_accept marks the proposal
            # 'failed' instead of rewarding an unapplied patch as 'verified'.
            return {
                "ok": False,
                "applied": 0,
                "failed": [],
                "note": "Patch execution is not implemented; the proposal was not applied to the IDB.",
            }
        return {"ok": True, "applied": applied}

    # ------------------------------------------------------------------
    # Store access
    # ------------------------------------------------------------------

    def _get_blackboard_store(self):
        """Return a BlackboardStore scoped to the current session workspace.

        On failure, the underlying cause is recorded on
        ``self._blackboard_store_error`` (cleared on success) so callers can
        surface a real DB/lock problem instead of an opaque "unavailable".
        """
        self._blackboard_store_error = None
        try:
            if type(self)._blackboard_module is None:
                import importlib.util
                # SCRIPT_DIR is host/server/; blackboard.py is at ida_pro_mcp/ida_mcp/tools/.
                bb_path = os.path.join(SCRIPT_DIR, "..", "..", "ida_mcp", "tools", "blackboard.py")
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
            db_path = self._session_blackboard_path()
            if not str(db_path or "").strip():
                return None
            return mod.BlackboardStore(db_path=db_path)
        except Exception as exc:
            self._blackboard_store_error = str(exc)
            return None

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

    # ------------------------------------------------------------------
    # Cross-session hypothesis round-trip via the symbol DB
    # ------------------------------------------------------------------

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
            bb_path = self._session_blackboard_path(session_obj=session_obj)
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

    # ------------------------------------------------------------------
    # Per-action handlers (governance / phase)
    # ------------------------------------------------------------------

    def _bb_action_policy_set(self, args, store, phase_state, policy_state) -> dict:
        strict_mode = _coerce_bool(args.get("strict_mode"), policy_state.get("strict_mode", False))
        max_age = _bounded_int(args.get("max_staleness_calls", policy_state.get("max_staleness_calls", 6)), 6, min_value=1, max_value=100)
        require_ws = _coerce_bool(args.get("require_working_set"), policy_state.get("require_working_set", True))
        require_dw = _coerce_bool(args.get("require_decision_or_write"), policy_state.get("require_decision_or_write", True))
        enforce_phases = args.get("enforce_phases", policy_state.get("enforce_phases", ["commit", "finalize"]))
        if isinstance(enforce_phases, str):
            enforce_phases = parse_str_list(enforce_phases)
        if not isinstance(enforce_phases, list) or not enforce_phases:
            enforce_phases = ["commit", "finalize"]
        policy_state["strict_mode"] = strict_mode
        policy_state["max_staleness_calls"] = max_age
        policy_state["require_working_set"] = require_ws
        policy_state["require_decision_or_write"] = require_dw
        policy_state["enforce_phases"] = [str(p).strip().lower() for p in enforce_phases]
        self._policy_persist(policy_state)
        check = self._bb_policy_check(policy_state)
        check["ok"] = True
        check["note"] = "Policy updated."
        return check

    def _bb_action_policy_status(self, args, store, phase_state, policy_state) -> dict:
        return {
            "ok": True,
            "policy": self._bb_policy_snapshot(policy_state),
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_policy_check(self, args, store, phase_state, policy_state) -> dict:
        out = self._bb_policy_check(policy_state)
        out["phase"] = self._phase_snapshot(phase_state, store)
        return out

    def _bb_action_phase_status(self, args, store, phase_state, policy_state) -> dict:
        return {"ok": True, "phase": self._phase_snapshot(phase_state, store)}

    def _bb_action_phase_set(self, args, store, phase_state, policy_state) -> dict:
        phase = str(args.get("phase") or "").strip().lower()
        if phase not in {"scout", "prove", "commit", "finalize"}:
            return make_error(MCPError.INVALID_ARGS, "phase must be one of: scout, prove, commit, finalize")
        auto = _coerce_bool(args.get("auto_transition"), phase_state.get("auto_transition", True))
        phase_state["auto_transition"] = auto
        self._phase_transition(phase_state, phase, "manual set")
        return {"ok": True, "phase": self._phase_snapshot(phase_state, store)}

    def _bb_action_phase_tick(self, args, store, phase_state, policy_state) -> dict:
        limit = _bounded_int(args.get("limit", 3), 3, min_value=1, max_value=20)
        return self._phase_tick(phase_state, store, limit=limit)

    # ------------------------------------------------------------------
    # Per-action handlers (analyst memory)
    # ------------------------------------------------------------------

    def _bb_action_write(self, args, store, phase_state, policy_state) -> dict:
        title = str(args.get("name") or args.get("title") or "").strip()
        if not title:
            return make_error(MCPError.INVALID_ARGS, "name/title required for write")
        raw_tags = args.get("tags")
        if isinstance(raw_tags, list):
            tags = [str(t).strip() for t in raw_tags if str(t).strip()]
        elif isinstance(raw_tags, str):
            tags = parse_str_list(raw_tags)
        else:
            tags = []
        evidence = args.get("evidence")
        if not isinstance(evidence, list):
            evidence = []
        try:
            result = store.upsert_finding(
                title=title,
                content=str(args.get("notes") or args.get("content") or ""),
                category=str(args.get("category") or "general"),
                addr=str(args.get("addr") or ""),
                tags=tags,
                confidence=float(args.get("confidence", 0.5)),
                evidence=evidence,
                source=str(args.get("source") or "manual"),
                kind=str(args.get("kind") or "finding"),
                status=str(args.get("status") or "open"),
                priority=float(args.get("priority", 0.5)),
            )
        except (TypeError, ValueError) as exc:
            return make_error(MCPError.INVALID_ARGS, str(exc))
        eid = result["entry_id"]
        self._bb_policy_mark(policy_state, "write")
        gravity = None
        if result.get("created"):
            gravity = self._evidence_gravity(
                store,
                source_entry_id=eid,
                addr=str(args.get("addr") or ""),
                source_text=str(args.get("notes") or args.get("content") or ""),
            )
        return write_response(
            result,
            action="write",
            gravity=gravity,
            phase=self._phase_snapshot(phase_state, store),
        )

    def _bb_action_decision_card(self, args, store, phase_state, policy_state) -> dict:
        claim = str(args.get("claim") or args.get("title") or "").strip()
        if not claim:
            return make_error(MCPError.INVALID_ARGS, "claim/title required for decision_card")
        lane = str(args.get("lane") or "lane_hypotheses").strip()
        category = _LANE_CATEGORY.get(lane, "hypothesis")
        evidence_for = _coerce_str_list(args.get("evidence_for"))
        evidence_against = _coerce_str_list(args.get("evidence_against"))
        next_step = str(args.get("next_step") or args.get("next_verification_step") or "").strip()
        expires_hours = int(args.get("expires_hours") or 0)
        card = {
            "claim": claim,
            "evidence_for": evidence_for,
            "evidence_against": evidence_against,
            "next_verification_step": next_step,
            "expires_after_hours": expires_hours,
            "created_by": "decision_card",
        }
        tag_list = [lane, "decision_card"]
        addr = str(args.get("addr") or "").strip()
        conf = float(args.get("confidence", 0.65))
        content = json.dumps(card, ensure_ascii=True)
        eid = store.write(
            title=claim,
            content=content,
            category=category,
            addr=addr,
            tags=tag_list,
            confidence=conf,
            source="decision_card",
            source_type="decision_card",
        )
        self._bb_policy_mark(policy_state, "decision")
        auto_trace = _coerce_bool(args.get("auto_trace"), True)
        trace_depth = _bounded_int(args.get("trace_depth", 2), 2, min_value=1, max_value=6)
        trace_limit = _bounded_int(args.get("trace_limit", 8), 8, min_value=1, max_value=50)
        trace_task_id = self._maybe_auto_trace_from_text(
            store,
            source_entry_id=eid,
            source_text=f"{claim}\n{card.get('next_verification_step') or ''}\n{addr}",
            auto_trace=auto_trace,
            depth=trace_depth,
            limit=trace_limit,
        )
        gravity = self._evidence_gravity(store, source_entry_id=eid, addr=addr, source_text=claim)
        return {
            "ok": True,
            "entry_id": eid,
            "lane": lane,
            "card": card,
            "trace_task_id": trace_task_id,
            "gravity": gravity,
            "phase": self._phase_snapshot(phase_state, store),
            "note": "Decision card stored. Use working_set to verify it appears in the active lane.",
        }

    def _bb_action_memory_compile(self, args, store, phase_state, policy_state) -> dict:
        result = self._memory_compile(
            store,
            limit=_bounded_int(args.get("limit", 30), 30, min_value=5, max_value=200),
            notes_path=str(args.get("notes_path") or args.get("path") or "").strip(),
        )
        result["phase"] = self._phase_snapshot(phase_state, store)
        return result

    # ------------------------------------------------------------------
    # Per-action handlers (proposal lifecycle over real entries)
    # ------------------------------------------------------------------

    def _bb_action_proposal_create(self, args, store, phase_state, policy_state) -> dict:
        proposal_type = str(args.get("proposal_type") or args.get("type") or "").strip().lower()
        if proposal_type not in {"rename", "patch", "type"}:
            return make_error(MCPError.INVALID_ARGS, "proposal_type must be one of: rename, patch, type")
        title = str(args.get("title") or f"{proposal_type} proposal").strip()
        spec_raw = args.get("spec")
        if isinstance(spec_raw, str):
            try:
                spec_raw = json.loads(spec_raw)
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "spec must be a JSON object")
        if not isinstance(spec_raw, dict):
            return make_error(MCPError.INVALID_ARGS, "spec must be an object")
        err = self._validate_proposal_spec(proposal_type, spec_raw)
        if err:
            return make_error(MCPError.INVALID_ARGS, err)
        confidence = float(args.get("confidence", 0.7))
        eid = self._write_proposal_entry(
            store,
            proposal_type=proposal_type,
            title=title,
            spec=spec_raw,
            addr=str(args.get("addr") or "").strip(),
            confidence=confidence,
            source="proposal_create",
            verification_spec=args.get("verification_spec"),
        )
        return {
            "ok": True,
            "proposal_id": eid,
            "status": "proposed",
            "proposal_type": proposal_type,
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_proposal_list(self, args, store, phase_state, policy_state) -> dict:
        status = str(args.get("status") or "").strip().lower()
        limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=500)
        entries = self._proposal_entries(store, status=status, limit=limit)
        parsed = []
        for e in entries:
            payload = {}
            try:
                payload = json.loads(str(e.get("content") or "{}"))
            except Exception:
                payload = {}
            parsed.append(
                {
                    "proposal_id": e.get("id"),
                    "title": e.get("title"),
                    "confidence": e.get("confidence"),
                    "status": self._proposal_status(e),
                    "proposal_type": payload.get("proposal_type") or "unknown",
                    "spec": payload.get("spec") or {},
                }
            )
        return {
            "ok": True,
            "count": len(parsed),
            "proposals": parsed,
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_proposal_accept(self, args, store, phase_state, policy_state) -> dict:
        proposal_id = str(args.get("proposal_id") or args.get("entry_id") or "").strip()
        if not proposal_id:
            return make_error(MCPError.INVALID_ARGS, "proposal_id required")
        entry = store.read(proposal_id)
        if not entry or str(entry.get("category") or "") != "proposal":
            return make_error(MCPError.NOT_FOUND, f"Proposal '{proposal_id}' not found")
        payload = {}
        try:
            payload = json.loads(str(entry.get("content") or "{}"))
        except Exception:
            return make_error(MCPError.INVALID_ARGS, "Proposal content is not valid JSON")
        proposal_type = str(payload.get("proposal_type") or "").strip().lower()
        spec = payload.get("spec") or {}
        err = self._validate_proposal_spec(proposal_type, spec)
        if err:
            return make_error(MCPError.INVALID_ARGS, f"Proposal spec invalid: {err}")
        dry_run = _coerce_bool(args.get("dry_run"), False)
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        if dry_run:
            verify = self._proposal_verify(proposal_type, spec)
            return {
                "ok": True,
                "proposal_id": proposal_id,
                "status": "accepted",
                "dry_run": True,
                "verification": verify,
                "note": "Preview only; the proposal was not modified.",
            }
        verify = self._proposal_verify(proposal_type, spec)
        if verify.get("ok"):
            exec_res = self._proposal_execute(proposal_type, spec)
        else:
            exec_res = {"ok": False, "applied": 0, "failed": [], "note": "skipped: pre-execute verification failed"}
        status = "verified" if (exec_res.get("ok") and verify.get("ok")) else "failed"
        new_tags = self._proposal_status_replace(tags, status)
        meta = payload
        meta["status"] = status
        meta["last_apply"] = exec_res
        meta["last_verify"] = verify
        store.update(proposal_id, tags=new_tags, content=json.dumps(meta, ensure_ascii=True))
        with contextlib.suppress(Exception):
            store.update(proposal_id, status=status)
        store.write(
            title=f"proposal_feedback {proposal_id} {status}",
            content=json.dumps(
                {
                    "proposal_id": proposal_id,
                    "proposal_type": proposal_type,
                    "status": status,
                    "execution_ok": bool(exec_res.get("ok")),
                    "verification_ok": bool(verify.get("ok")),
                    "verification": verify,
                },
                ensure_ascii=True,
            ),
            category="proposal_feedback",
            addr=str(entry.get("addr") or ""),
            tags=[f"proposal_id:{proposal_id}", f"status:{status}", "proposal_feedback"],
            confidence=1.0 if status == "verified" else 0.3,
            source="proposal_accept",
            source_type="proposal_feedback",
        )
        return {
            "ok": bool(exec_res.get("ok") and verify.get("ok")),
            "proposal_id": proposal_id,
            "status": status,
            "execution": exec_res,
            "verification": verify,
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_proposal_reject(self, args, store, phase_state, policy_state) -> dict:
        proposal_id = str(args.get("proposal_id") or args.get("entry_id") or "").strip()
        if not proposal_id:
            return make_error(MCPError.INVALID_ARGS, "proposal_id required")
        entry = store.read(proposal_id)
        if not entry or str(entry.get("category") or "") != "proposal":
            return make_error(MCPError.NOT_FOUND, f"Proposal '{proposal_id}' not found")
        reason = str(args.get("reason") or "rejected_by_llm").strip()
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        new_tags = self._proposal_status_replace(tags, "rejected")
        meta = {}
        try:
            meta = json.loads(str(entry.get("content") or "{}"))
        except Exception:
            meta = {}
        meta["status"] = "rejected"
        ok = store.update(proposal_id, tags=new_tags, content=json.dumps(meta, ensure_ascii=True))
        if not ok:
            return make_error(MCPError.IO_ERROR, f"Failed to reject proposal '{proposal_id}'")
        with contextlib.suppress(Exception):
            store.update(proposal_id, status="rejected")
        store.write(
            title=f"Rejected proposal {proposal_id}",
            content=reason,
            category="dead_end",
            addr=str(entry.get("addr") or ""),
            tags=["proposal_rejected"],
            confidence=1.0,
            source="proposal_reject",
            source_type="proposal",
        )
        return {
            "ok": True,
            "proposal_id": proposal_id,
            "status": "rejected",
            "reason": reason,
            "phase": self._phase_snapshot(phase_state, store),
        }

    # ------------------------------------------------------------------
    # Per-action handlers (trace tasks)
    # ------------------------------------------------------------------

    def _bb_action_trace_ingest(self, args, store, phase_state, policy_state) -> dict:
        source_entry_id = str(args.get("entry_id") or args.get("source_entry_id") or "").strip()
        source_text = str(args.get("text") or "").strip()
        if source_entry_id and not source_text:
            src = store.read(source_entry_id)
            if not src:
                return make_error(MCPError.NOT_FOUND, f"Entry '{source_entry_id}' not found")
            source_text = f"{src.get('title') or ''}\n{src.get('content') or ''}"
        if not source_text:
            return make_error(MCPError.INVALID_ARGS, "trace_ingest requires text or entry_id")
        depth = _bounded_int(args.get("depth", 2), 2, min_value=1, max_value=6)
        limit = _bounded_int(args.get("limit", 8), 8, min_value=1, max_value=50)
        task_id = self._create_trace_task(store, source_entry_id, source_text, depth=depth, limit=limit)
        return {
            "ok": True,
            "trace_task_id": task_id,
            "status": "pending",
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_trace_status(self, args, store, phase_state, policy_state) -> dict:
        status = str(args.get("status") or "").strip().lower()
        limit = _bounded_int(args.get("limit", 100), 100, min_value=1, max_value=500)
        summaries = self._orchestration().trace_status_rows(store, status, limit)
        return {
            "ok": True,
            "count": len(summaries),
            "tasks": summaries,
            "phase": self._phase_snapshot(phase_state, store),
        }

    def _bb_action_trace_run(self, args, store, phase_state, policy_state) -> dict:
        limit = _bounded_int(args.get("limit", 3), 3, min_value=1, max_value=20)
        result = self._orchestration().run_pending_trace_tasks(store, limit)
        result["phase"] = self._phase_snapshot(phase_state, store)
        return result

    # ------------------------------------------------------------------
    # Per-action handlers (lanes / state)
    # ------------------------------------------------------------------

    def _bb_action_working_set(self, args, store, phase_state, policy_state) -> dict:
        limit = _bounded_int(args.get("limit", 10), 10, min_value=1, max_value=50)
        lanes = {}
        for lane in ("lane_now", "lane_hypotheses", "lane_facts", "lane_queue", "lane_dead_ends"):
            lane_entries = self._lane_fetch(store, lane, limit)
            lanes[lane] = {
                "count": len(lane_entries),
                "items": [_entry_brief(e) for e in lane_entries[:limit]],
            }
        self._bb_policy_mark(policy_state, "working_set")
        escape = store.next_target(limit=3) if self._phase_find_loop(phase_state) else []
        return {
            "ok": True,
            "lanes": lanes,
            "state_health": self._state_health(store),
            "policy_check": self._bb_policy_check(policy_state),
            "phase": self._phase_snapshot(phase_state, store),
            "escape_route_targets": escape,
            "note": "Read lane_now and lane_queue first, then verify/resolve hypothesis cards.",
        }

    def _bb_action_state_health(self, args, store, phase_state, policy_state) -> dict:
        return {
            "ok": True,
            **self._state_health(store),
            "phase": self._phase_snapshot(phase_state, store),
        }

    # ------------------------------------------------------------------
    # Per-action handlers (file / export)
    # ------------------------------------------------------------------

    def _bb_action_export(self, args, store, phase_state, policy_state) -> dict:
        fmt = str(args.get("format") or "json").strip().lower()
        if fmt not in {"json", "markdown"}:
            return make_error(MCPError.INVALID_ARGS, "format must be 'json' or 'markdown'")
        export_limit = _bounded_int(args.get("limit", 0), 0, min_value=0, max_value=50000)
        return self._findings_export(
            store,
            fmt=fmt,
            path=str(args.get("path") or "").strip(),
            kind=str(args.get("kind") or "").strip(),
            status=str(args.get("status") or "").strip(),
            category=str(args.get("category") or "").strip(),
            tag=str(args.get("tag") or "").strip(),
            addr=str(args.get("addr") or "").strip(),
            min_confidence=float(args.get("min_confidence", 0.0)),
            include_resolved=_coerce_bool(args.get("include_resolved"), True),
            include_contradicted=_coerce_bool(args.get("include_contradicted"), True),
            limit=export_limit,
        )

    def _bb_action_notes_import(self, args, store, phase_state, policy_state) -> dict:
        notes_path = str(args.get("notes_path") or args.get("path") or "re_notes.md").strip()
        lane = str(args.get("lane") or "lane_hypotheses").strip()
        confidence = float(args.get("confidence", 0.65))
        auto_trace = _coerce_bool(args.get("auto_trace"), False)
        trace_depth = _bounded_int(args.get("trace_depth", 2), 2, min_value=1, max_value=6)
        trace_limit = _bounded_int(args.get("trace_limit", 8), 8, min_value=1, max_value=50)
        return self._notes_import(
            store,
            notes_path,
            lane=lane,
            confidence=confidence,
            auto_trace=auto_trace,
            trace_depth=trace_depth,
            trace_limit=trace_limit,
        )

    # ------------------------------------------------------------------
    # Per-action handlers (CRUD)
    # ------------------------------------------------------------------

    def _bb_action_list(self, args, store, phase_state, policy_state) -> dict:
        entries = store.list(
            category=str(args.get("category") or "").strip() or None,
            addr=str(args.get("addr") or "").strip() or None,
            tag=str(args.get("tag") or "").strip() or None,
            min_confidence=float(args.get("min_confidence", 0.0)),
            limit=_bounded_int(args.get("limit", 100), 100, min_value=1, max_value=1000),
            offset=_bounded_int(args.get("offset", 0), 0, min_value=0),
            include_resolved=_coerce_bool(args.get("include_resolved"), True),
            include_contradicted=_coerce_bool(args.get("include_contradicted"), False),
            kind=str(args.get("kind") or "").strip() or None,
            status=str(args.get("status") or "").strip() or None,
        )
        return list_response(entries)

    def _bb_action_search(self, args, store, phase_state, policy_state) -> dict:
        query = str(args.get("query") or args.get("pattern") or "").strip()
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query/pattern required for blackboard search")
        entries = store.semantic_search(
            query=query,
            top_k=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500),
            threshold=float(args.get("threshold", 0.4)),
            category=str(args.get("category") or "").strip() or None,
            include_resolved=_coerce_bool(args.get("include_resolved"), True),
            include_contradicted=_coerce_bool(args.get("include_contradicted"), False),
        )
        return search_response(query, entries)

    def _bb_action_read(self, args, store, phase_state, policy_state) -> dict:
        entry = store.read(str(args.get("entry_id") or ""))
        if entry is None:
            return make_error(MCPError.NOT_FOUND, "Entry not found")
        return read_response(entry)

    def _bb_action_update(self, args, store, phase_state, policy_state) -> dict:
        entry_id = str(args.get("entry_id") or "").strip()
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        updates = {
            k: v
            for k, v in (args or {}).items()
            if k not in {"action", "entry_id"}
        }
        if not updates:
            return make_error(MCPError.INVALID_ARGS, "No update fields provided")
        status = str(updates.pop("status", "") or "").strip().lower()
        reason = str(updates.pop("reason", "") or "").strip()
        if status:
            try:
                transition_fields = {
                    field: updates.pop(field)
                    for field in ("content", "confidence", "priority", "tags")
                    if field in updates
                }
                entry = store.transition(entry_id, status=status, reason=reason, **transition_fields)
            except ValueError as exc:
                return make_error(MCPError.INVALID_ARGS, str(exc))
            if entry is None:
                return make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
            if updates:
                # Remaining fields (category, addr, kind, ...) are not part
                # of the transition contract; apply them via update.
                store.update(entry_id, embed=False, **updates)
                entry = store.read(entry_id)
            return {"ok": True, "action": "update", "entry": entry}
        ok = store.update(entry_id, embed=False, **updates)
        return {"ok": ok, "action": "update", "entry": store.read(entry_id)} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found or no valid fields")

    def _bb_action_delete(self, args, store, phase_state, policy_state) -> dict:
        ok = store.delete(str(args.get("entry_id") or ""))
        return {
            "ok": ok,
            "action": "delete",
            "scope": "entire_binary_workspace",
            "note": "The workspace DB is shared by every session of this binary; "
            "deleting an entry removes it for all sessions, not just this one.",
        }

    def _bb_action_clear(self, args, store, phase_state, policy_state) -> dict:
        count = store.clear(category=str(args.get("category") or "").strip() or None)
        return {
            "ok": True,
            "deleted": count,
            "scope": "entire_binary_workspace",
            "note": "Cleared the binary-wide workspace shared by every session of "
            "this binary, not just the current session.",
        }

    def _bb_action_stats(self, args, store, phase_state, policy_state) -> dict:
        return {"ok": True, **store.stats()}

    def _bb_action_coverage(self, args, store, phase_state, policy_state) -> dict:
        cov = store.coverage()
        analyzed = int(cov.get("examined") or 0)
        total = int((store.stats() or {}).get("total_entries") or 0)
        return coverage_response(analyzed, total)

    def _bb_action_merge(self, args, store, phase_state, policy_state) -> dict:
        result = store.auto_merge(
            addr=str(args.get("addr") or "").strip(),
            category=str(args.get("category") or "").strip(),
            similarity_threshold=float(args.get("similarity_threshold", 0.85)),
        )
        return {"ok": True, **result}

    def _bb_action_prune(self, args, store, phase_state, policy_state) -> dict:
        result = store.prune(
            max_entries=_bounded_int(args.get("max_entries", 1000), 1000, min_value=1, max_value=100000),
            min_q_value=float(args.get("min_q_value", 0.0)),
            older_than_days=int(args.get("older_than_days", 0)),
        )
        return {
            "ok": True,
            **result,
            "scope": "entire_binary_workspace",
            "note": "Pruned the binary-wide workspace shared by every session of "
            "this binary, not just the current session.",
        }

    def _bb_action_contradict(self, args, store, phase_state, policy_state) -> dict:
        eid = str(args.get("entry_id") or "").strip()
        reason = str(args.get("reason") or "").strip()
        if not eid or not reason:
            return make_error(MCPError.INVALID_ARGS, "entry_id and reason required")
        ok = store.contradict(eid, reason)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")

    def _bb_action_resolve(self, args, store, phase_state, policy_state) -> dict:
        eid = str(args.get("entry_id") or "").strip()
        if not eid:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        ok = store.mark_resolved(eid)
        return {"ok": ok} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{eid}' not found")

    def _bb_action_next_target(self, args, store, phase_state, policy_state) -> dict:
        rpc_fn = None
        idb_ref = str(getattr(self.current_session, "idb_path", "") or "") if self.current_session else ""
        if idb_ref:
            def rpc_fn(tool, payload):
                return self.call_tool(tool, idb_ref, **payload)
        limit = _bounded_int(args.get("limit", 5), 5, min_value=1, max_value=100)
        query = args.get("query")
        strategy = str(args.get("strategy") or "").strip().lower()
        if strategy:
            try:
                result = store.targets(strategy, limit=limit, rpc_fn=rpc_fn, query=query)
            except ValueError as exc:
                return make_error(MCPError.INVALID_ARGS, str(exc))
            targets = result["targets"]
            note = _STRATEGY_NOTES.get(strategy, "")
            if not targets:
                note += _STRATEGY_EMPTY.get(strategy, " Nothing matched this strategy.")
        else:
            targets = store.next_target(limit=limit, rpc_fn=rpc_fn, query=query)
            strategy = "unresolved"
            note = _STRATEGY_NOTES["unresolved"]
            if not targets:
                note += (
                    " The workspace has no open threads yet. Try"
                    " strategy='coverage' for functions nobody has read."
                )
        return next_target_response(
            strategy,
            targets,
            strategies=BB_STRATEGIES,
            note=note.strip(),
            query=query,
        )

    def _bb_action_frontier(self, args, store, phase_state, policy_state) -> dict:
        limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200)
        rpc_fn = self._idb_rpc()
        try:
            targets_res = store.targets("frontier", limit=limit, query=args.get("query"), rpc_fn=rpc_fn)
        except ValueError as exc:
            return make_error(MCPError.INVALID_ARGS, str(exc))
        results = targets_res.get("targets", [])
        return frontier_response(results)

    def _bb_action_add_evidence(self, args, store, phase_state, policy_state) -> dict:
        entry_id = str(args.get("entry_id") or "").strip()
        evidence_type = str(args.get("evidence_type") or args.get("type") or "").strip()
        value = str(args.get("value") or "").strip()
        if not entry_id or not evidence_type or not value:
            return make_error(MCPError.INVALID_ARGS, "entry_id, evidence_type/type, and value required")
        ok = store.add_evidence(entry_id, evidence_type=evidence_type, value=value, weight=float(args.get("weight", 1.0)))
        return {"ok": ok, "entry_id": entry_id} if ok else make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")

    def _bb_action_calibrate(self, args, store, phase_state, policy_state) -> dict:
        entry_id = str(args.get("entry_id") or "").strip()
        if not entry_id:
            return make_error(MCPError.INVALID_ARGS, "entry_id required")
        new_conf = store.calibrate_confidence(entry_id)
        if new_conf is None:
            return make_error(MCPError.NOT_FOUND, f"Entry '{entry_id}' not found")
        return {"ok": True, "entry_id": entry_id, "confidence": new_conf}

    def _bb_action_decay(self, args, store, phase_state, policy_state) -> dict:
        half_life = float(args.get("half_life_days", 14.0) or 14.0)
        min_conf = float(args.get("min_confidence", 0.1) or 0.1)
        updated = store.decay_stale_confidence(half_life_days=half_life, min_confidence=min_conf)
        return {"ok": True, "decayed": updated, "half_life_days": half_life, "min_confidence": min_conf}

    def _bb_action_campaign_summary(self, args, store, phase_state, policy_state) -> dict:
        return {"ok": True, "summary": store.campaign_summary()}

    def _bb_action_workspace_brief(self, args, store, phase_state, policy_state) -> dict:
        return {
            "ok": True,
            "brief": store.workspace_brief(
                limit=_bounded_int(args.get("limit", 8), 8, min_value=1, max_value=25)
            ),
        }

    def _bb_action_mark_examined(self, args, store, phase_state, policy_state) -> dict:
        try:
            result = store.record_examination(
                addr=str(args.get("addr") or ""),
                verdict=str(args.get("verdict") or "boring"),
                note=str(args.get("note") or args.get("content") or ""),
                name=str(args.get("name") or ""),
            )
        except ValueError as exc:
            return make_error(MCPError.INVALID_ARGS, str(exc))
        self._bb_policy_mark(policy_state, "write")
        return {"ok": True, "action": "mark_examined", **result}

    def _bb_action_recall(self, args, store, phase_state, policy_state) -> dict:
        addrs = _coerce_str_list(args.get("addrs") or args.get("addr"))
        return {
            "ok": True,
            **store.recall(
                addrs,
                limit=_bounded_int(args.get("limit", 6), 6, min_value=1, max_value=25),
            ),
        }

    def _bb_action_publish_findings(self, args, store, phase_state, policy_state) -> dict:
        return self._publish_findings(store, args)

    def _bb_action_import_annotations(self, args, store, phase_state, policy_state) -> dict:
        return self._import_annotations(store, args)

    def _bb_action_conflicts(self, args, store, phase_state, policy_state) -> dict:
        entries = store.conflicts(
            limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200)
        )
        return {
            "ok": True,
            "entries": entries,
            "count": len(entries),
            "summary": _entry_collection_summary(entries),
        }

    def _bb_action_stale(self, args, store, phase_state, policy_state) -> dict:
        entries = store.stale_entries(
            limit=_bounded_int(args.get("limit", 20), 20, min_value=1, max_value=200)
        )
        return {
            "ok": True,
            "entries": entries,
            "count": len(entries),
            "note": "Recorded before the code at these addresses changed.",
        }

    # ------------------------------------------------------------------
    # Per-action handlers (crawler)
    # ------------------------------------------------------------------

    def _bb_action_start_crawler(self, args, store, phase_state, policy_state) -> dict:
        orch = self._orchestration()
        running = orch.start_crawler(store, probe=None, notify_fn=getattr(self, "_send_notification", None))
        return {
            "ok": True,
            "running": running,
            "note": "Crawler walks frontier targets and writes real proposed entries into the shared workspace.",
        }

    def _bb_action_stop_crawler(self, args, store, phase_state, policy_state) -> dict:
        self._orchestration().stop_crawler()
        return {"ok": True, "running": False}

    def _bb_action_crawler_status(self, args, store, phase_state, policy_state) -> dict:
        orch = self._orchestration()
        proposals = orch.pending_proposal_rows(store, limit=50)
        return crawler_status_response(
            running=orch.crawler_is_running(),
            pending_proposals=len(proposals),
            addresses_visited=orch.crawler_visited_count(),
            proposals=proposals[:10],
        )

    def _bb_action_accept(self, args, store, phase_state, policy_state) -> dict:
        return self._bb_action_proposal_accept(args, store, phase_state, policy_state)

    def _bb_action_reject(self, args, store, phase_state, policy_state) -> dict:
        return self._bb_action_proposal_reject(args, store, phase_state, policy_state)

