from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
import sqlite3
import threading
import time
from typing import Any

from ..batch_manager import BatchManager
from ..config import _env_float
from ..errors import MCPError, is_error_result, make_error
from ..policy import PolicyDecision, ack_from_args, evaluate_policy
from .server_client_state import ServerClientStateMixin, _ClientRequestState

_BACKGROUND_ACTIONS = {
    "submit": "_bg_submit",
    "status": "_bg_status",
    "cancel": "_bg_cancel",
    "result": "_bg_result",
    "list": "_bg_list",
    "wait": "_bg_wait",
}

# Guards lazy initialisation of per-server background state (locks/dicts) so
# two concurrent submit threads cannot create two different RLock objects and
# then "protect" the same shared dict with different locks.
_LAZY_STATE_LOCK = threading.RLock()

# Upper bound on how long background(action='wait') may block the request
# thread. A caller can pass None (wait forever) or an arbitrarily large
# timeout, which would park a stdio request/connection thread indefinitely
# behind a stuck worker (cancel() cannot free a running pool slot either).
# Cap the effective wait so a stuck task degrades to a status poll instead.
# Override with IDA_MCP_BG_WAIT_MAX_SECONDS.
_BG_WAIT_MAX_SECONDS = _env_float(
    "IDA_MCP_BG_WAIT_MAX_SECONDS", 3600.0, min_value=1.0
)


class BackgroundMixin(ServerClientStateMixin):

    def _bind_background_run(self, run_fn, *, session: Any = None):
        """Preserve submitting-client ownership for ThreadPoolExecutor workers."""
        ctx = contextvars.copy_context()

        def bound(task):
            def inner():
                state_fn = getattr(self, "_client_request_state", None)
                if callable(state_fn):
                    parent = state_fn()
                    # copy_context copies bindings, not values: the worker would
                    # otherwise share the client's _ClientRequestState object, so
                    # its current_session / pending_* writes would leak into
                    # concurrent requests on the same connection (and vice
                    # versa). Run the task against a private copy instead.
                    var = self._state_var()
                    worker = _ClientRequestState(
                        vertex_compat=bool(getattr(self, "default_vertex_compat", False)),
                    )
                    worker.owned_session_ids = set(getattr(parent, "owned_session_ids", set()) or set())
                    worker.owned_sessions_by_agent = {
                        name: set(ids)
                        for name, ids in (getattr(parent, "owned_sessions_by_agent", {}) or {}).items()
                    }
                    worker.current_session_by_agent = dict(
                        getattr(parent, "current_session_by_agent", {}) or {}
                    )
                    # A background submission may be made while one agent is
                    # bound for the current call. Preserve that identity in
                    # the private worker state so its session and ownership
                    # remain agent-scoped instead of silently becoming a
                    # connection-global task.
                    worker.active_agent = getattr(parent, "active_agent", None)
                    if session is not None:
                        sid = str(getattr(session, "session_id", "") or "")
                        if sid:
                            # Keep the client's ownership grant so it can later
                            # retrieve the task's status/result via _bg_*.
                            active_agent = getattr(parent, "active_agent", None)
                            if active_agent:
                                parent.owned_sessions_by_agent.setdefault(
                                    active_agent, set()
                                ).add(sid)
                                worker.owned_sessions_by_agent.setdefault(
                                    active_agent, set()
                                ).add(sid)
                            else:
                                parent.owned_session_ids.add(sid)
                                worker.owned_session_ids.add(sid)
                        worker.current_session = session
                    var.set(worker)
                elif session is not None:
                    # Fallback when the connection-state helper is unavailable.
                    self.current_session = session
                return run_fn(task)

            return ctx.run(inner)

        return bound

    @staticmethod
    def _semantic_binary_digest(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _semantic_load_profiles_compatible(left: Any, right: Any) -> bool:
        keys = {
            "processor", "loader", "base", "base_address", "load_address",
            "image_base", "bitness", "bits", "endian",
        }
        left_options = dict(getattr(left, "analysis_options", None) or {})
        right_options = dict(getattr(right, "analysis_options", None) or {})
        for key in keys:
            left_value = left_options.get(key)
            right_value = right_options.get(key)
            if left_value not in (None, "") and right_value not in (None, ""):
                if str(left_value).strip().lower() != str(right_value).strip().lower():
                    return False
        return True

    def _seed_index_from_matching_binary(self, session: Any) -> dict[str, Any]:
        lock = getattr(self, "_semantic_index_reuse_lock", None)
        if lock is None:
            # Double-checked initialisation under a module lock so concurrent
            # submit threads converge on one RLock guarding the copy/backup.
            with _LAZY_STATE_LOCK:
                lock = getattr(self, "_semantic_index_reuse_lock", None)
                if lock is None:
                    lock = threading.RLock()
                    self._semantic_index_reuse_lock = lock
        with lock:
            return self._seed_index_from_matching_binary_unlocked(session)

    def _seed_index_from_matching_binary_unlocked(self, session: Any) -> dict[str, Any]:
        """Copy a completed exact-binary index into this session's private DB."""
        target_db = f"{session.idb_path}.embeddings.db"

        def _row_counts(path: str) -> tuple[int, int]:
            if not os.path.isfile(path):
                return 0, 0
            try:
                with contextlib.closing(sqlite3.connect(path)) as conn:
                    total = int(conn.execute("SELECT COUNT(*) FROM func_embeddings").fetchone()[0])
                    columns = {
                        str(row[1]) for row in conn.execute("PRAGMA table_info(func_embeddings)")
                    }
                    full = 0
                    if "index_quality" in columns:
                        full = int(
                            conn.execute(
                                "SELECT COUNT(*) FROM func_embeddings WHERE index_quality='full'"
                            ).fetchone()[0]
                        )
                    return total, full
            except (OSError, sqlite3.Error, TypeError, ValueError):
                return 0, 0

        existing_count, _ = _row_counts(target_db)
        if existing_count:
            return {"reused": False, "reason": "target_index_present", "functions": existing_count}
        binary_path = str(getattr(session, "binary_path", "") or "")
        if not os.path.isfile(binary_path):
            return {"reused": False, "reason": "binary_unavailable"}

        target_stat = os.stat(binary_path)
        target_digest = self._semantic_binary_digest(binary_path)
        digest_cache = {os.path.realpath(binary_path): target_digest}
        candidates: list[tuple[int, int, Any, str]] = []
        for candidate in self.session_mgr.discover_sessions():
            if str(candidate.session_id) == str(session.session_id):
                continue
            if not self._semantic_load_profiles_compatible(session, candidate):
                continue
            candidate_binary = str(getattr(candidate, "binary_path", "") or "")
            source_db = f"{candidate.idb_path}.embeddings.db"
            total, full = _row_counts(source_db)
            if not total or not os.path.isfile(candidate_binary):
                continue
            try:
                candidate_stat = os.stat(candidate_binary)
                if candidate_stat.st_size != target_stat.st_size:
                    continue
                real_candidate = os.path.realpath(candidate_binary)
                candidate_digest = digest_cache.get(real_candidate)
                if candidate_digest is None:
                    candidate_digest = self._semantic_binary_digest(candidate_binary)
                    digest_cache[real_candidate] = candidate_digest
                if candidate_digest != target_digest:
                    continue
            except OSError:
                continue
            candidates.append((full, total, candidate, source_db))

        if not candidates:
            return {
                "reused": False,
                "reason": "no_compatible_index",
                "binary_sha256": target_digest,
            }
        full, total, source_session, source_db = max(candidates, key=lambda row: (row[0], row[1]))
        os.makedirs(os.path.dirname(target_db) or ".", exist_ok=True)
        # The sqlite connection context manager commits/rolls back but never
        # closes; wrap in closing() so the connections are explicitly released
        # (close() also rolls back any uncommitted work on an error path).
        with contextlib.closing(sqlite3.connect(source_db)) as source, contextlib.closing(sqlite3.connect(target_db)) as target:
            source.backup(target)
            if os.path.isfile(session.idb_path):
                idb_stat = os.stat(session.idb_path)
                source_fingerprint = hashlib.sha256(
                    f"{session.idb_path}:{idb_stat.st_size}:{idb_stat.st_mtime_ns}".encode()
                ).hexdigest()
            else:
                source_fingerprint = hashlib.sha256(str(session.idb_path).encode()).hexdigest()
            metadata = {
                "source_idb_path": str(session.idb_path),
                "source_binary_path": binary_path,
                "source_binary_sha256": target_digest,
                "source_fingerprint": source_fingerprint,
                "reused_from_session": str(source_session.session_id),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            target.executemany(
                """
                INSERT INTO embedding_meta(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                metadata.items(),
            )
            target.commit()
        assembler = getattr(self, "assembler", None)
        embedder = getattr(assembler, "_embedder", None)
        if embedder is not None:
            # FunctionEmbeddingIndex performs the authoritative model format,
            # dimension, schema, and source-fingerprint compatibility check.
            from ..intelligence.embeddings import FunctionEmbeddingIndex

            validated = FunctionEmbeddingIndex(target_db, embedder)
            if validated.size == 0 and total:
                return {
                    "reused": False,
                    "reason": "incompatible_embedding_profile",
                    "from_session": str(source_session.session_id),
                    "binary_sha256": target_digest,
                }
        return {
            "reused": True,
            "from_session": str(source_session.session_id),
            "functions": total,
            "full_quality_functions": full,
            "binary_sha256": target_digest,
        }

    def _semantic_index_job_state(self) -> tuple[Any, dict[str, str]]:
        lock = getattr(self, "_semantic_index_jobs_lock", None)
        if lock is None:
            # Double-checked initialisation under a module lock so concurrent
            # submit threads converge on one RLock; otherwise two threads could
            # create two different locks and both "guard" the same
            # _semantic_index_tasks dict, letting two jobs for one session in.
            with _LAZY_STATE_LOCK:
                lock = getattr(self, "_semantic_index_jobs_lock", None)
                if lock is None:
                    lock = threading.RLock()
                    self._semantic_index_jobs_lock = lock
        active = getattr(self, "_semantic_index_tasks", None)
        if active is None:
            with _LAZY_STATE_LOCK:
                active = getattr(self, "_semantic_index_tasks", None)
                if active is None:
                    active = {}
                    self._semantic_index_tasks = active
        return lock, active

    @staticmethod
    def _validate_semantic_index_scope(args: dict[str, Any]) -> dict | None:
        def _positive(name: str, *, allow_zero: bool = False) -> dict | None:
            value = args.get(name)
            if value is None:
                return None
            try:
                number = int(value)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, f"{name} must be an integer")
            if number < 0 or (number == 0 and not allow_zero):
                return make_error(MCPError.INVALID_ARGS, f"{name} must be greater than zero")
            return None

        for field in ("limit", "_index_total_limit", "_index_slice_size", "radius", "min_size", "max_size"):
            if error := _positive(field, allow_zero=field in {"min_size", "max_size"}):
                return error
        if args.get("radius") is not None and not args.get("addr"):
            return make_error(MCPError.INVALID_ARGS, "address is required when radius is set")
        if bool(args.get("start")) != bool(args.get("end")):
            return make_error(MCPError.INVALID_ARGS, "start and end must be provided together")

        def _range_error(start: Any, end: Any, label: str) -> dict | None:
            try:
                start_int = int(str(start), 0)
                end_int = int(str(end), 0)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, f"{label} must contain hexadecimal or integer addresses")
            if end_int <= start_int:
                return make_error(MCPError.INVALID_ARGS, f"{label} end must be greater than start")
            return None

        if args.get("start") is not None:
            if error := _range_error(args.get("start"), args.get("end"), "range"):
                return error
        ranges = args.get("ranges")
        if ranges is not None:
            if not isinstance(ranges, list) or not ranges:
                return make_error(MCPError.INVALID_ARGS, "ranges must be a non-empty array")
            for index, item in enumerate(ranges):
                if not isinstance(item, dict) or set(item) != {"start", "end"}:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"ranges[{index}] must contain exactly start and end",
                    )
                if error := _range_error(item["start"], item["end"], f"ranges[{index}]"):
                    return error
        min_size = args.get("min_size")
        max_size = args.get("max_size")
        if min_size is not None and max_size is not None and int(min_size) > int(max_size):
            return make_error(MCPError.INVALID_ARGS, "min_size cannot exceed max_size")
        return None

    def _submit_semantic_index(self, args: dict[str, Any], idb_ref: Any) -> dict:
        """Run a complete semantic-index request as small, interruptible RPC slices."""
        session = self._resolve_session_from_idb_ref(idb_ref)
        if not session:
            return make_error(
                MCPError.FILE_NOT_FOUND,
                f"No session found for idb reference: {idb_ref}",
            )
        ownership_error = self._ensure_client_owns_session(session)
        if ownership_error:
            return ownership_error
        validation_error = self._validate_semantic_index_scope(args)
        if validation_error:
            return validation_error

        session_id = str(session.session_id)
        lock, active = self._semantic_index_job_state()
        with lock:
            previous_id = active.get(session_id)
            if previous_id:
                status = self._batch_manager.status(previous_id)
                if status and status[0].get("state") in {"pending", "running"}:
                    return {
                        "ok": True,
                        "task_id": previous_id,
                        "state": status[0]["state"],
                        "background": True,
                        "reused": True,
                        "message": "A semantic-index job is already active for this IDA session.",
                    }

            request_args = dict(args)
            request_args.pop("_background", None)
            raw_slice_size = request_args.pop("_index_slice_size", None)
            quality = str(request_args.get("mode") or "fast").strip().lower()
            default_slice_size = 8 if quality == "full" else 64
            slice_size = max(1, min(256, int(raw_slice_size or default_slice_size)))
            raw_total_limit = request_args.pop("_index_total_limit", request_args.pop("limit", None))
            total_limit = int(raw_total_limit) if raw_total_limit is not None else None
            initial_cursor = request_args.pop("start_after", None)
            request_args.pop("index_limit", None)
            scope = {
                key: request_args[key]
                for key in ("start", "end", "addr", "radius", "ranges", "query", "min_size", "max_size")
                if request_args.get(key) is not None
            }

            def _run(task):
                cursor = str(initial_cursor) if initial_cursor else None
                indexed = attempted = failed = passes = 0
                eligible = None
                last_index: dict[str, Any] = {}
                limit_reached = False
                scope_complete = False
                fully_indexed = False
                pseudocode_chars = 0
                document_chars = 0
                stall_count = 0
                stalled = False
                self._update_session_indexing_metadata(
                    session_id,
                    indexing_mode=f"semantic_{quality}",
                    indexing_state="running",
                    semantic_index_task_id=task.task_id,
                    semantic_indexed_count=0,
                )
                try:
                    # Skip the full-binary similarity scan when the request is
                    # scoped (range/limit/radius) — scanning all 34k+ functions
                    # to seed a 5-function index is wasteful and hits the RPC timeout.
                    _is_scoped = (
                        total_limit is not None
                        or scope.get("start") is not None
                        or scope.get("end") is not None
                        or scope.get("ranges") is not None
                        or (scope.get("addr") is not None and scope.get("radius") is not None)
                    )
                    if _is_scoped:
                        reuse = {}
                    else:
                        task.progress = {"state": "matching_binary", "quality": quality}
                        reuse = self._seed_index_from_matching_binary(session)
                    while not task._cancel_event.is_set():
                        remaining = None if total_limit is None else total_limit - attempted
                        if remaining is not None and remaining <= 0:
                            limit_reached = True
                            break
                        pass_size = slice_size if remaining is None else min(slice_size, remaining)
                        rpc_args = dict(request_args)
                        rpc_args["action"] = "index_fast"
                        rpc_args["index_limit"] = pass_size
                        if cursor:
                            rpc_args["start_after"] = cursor

                        result = self.call_tool("intelligence", session.idb_path, **rpc_args)
                        if is_error_result(result):
                            task.result = result
                            message = result.get("message") or result.get("error") or "semantic indexing failed"
                            raise RuntimeError(str(message))

                        passes += 1
                        indexed += int(result.get("indexed") or 0)
                        pass_attempted = int(result.get("attempted") or 0)
                        attempted += pass_attempted
                        failed += int(result.get("failed") or 0)
                        eligible = result.get("eligible", eligible)
                        last_index = dict(result.get("index") or {})
                        fully_indexed = bool(result.get("fully_indexed"))
                        pass_input = result.get("input") or {}
                        pseudocode_chars += int(pass_input.get("pseudocode_chars") or 0)
                        document_chars += int(pass_input.get("document_chars") or 0)
                        next_cursor = result.get("next_cursor")
                        complete = bool(result.get("complete"))
                        task.progress = {
                            "passes": passes,
                            "indexed": indexed,
                            "attempted": attempted,
                            "failed": failed,
                            "eligible": eligible,
                            "next_cursor": next_cursor,
                            "quality": quality,
                        }
                        self._update_session_indexing_metadata(
                            session_id,
                            indexing_state="running",
                            semantic_indexed_count=indexed,
                            semantic_index_progress=task.progress,
                        )
                        if complete or not next_cursor:
                            scope_complete = complete
                            break
                        if next_cursor == cursor and pass_attempted == 0:
                            raise RuntimeError("semantic index made no progress at the resume cursor")
                        if next_cursor == cursor:
                            # The embedder failed every candidate in this pass
                            # and returned the same resume cursor. Give the
                            # backend a bounded number of recovery passes (it
                            # recycles a timed-out llama-server) before
                            # abandoning the job as a partial, resumable
                            # result instead of spinning forever.
                            stall_count += 1
                            if stall_count >= 3:
                                stalled = True
                                break
                        else:
                            stall_count = 0
                        cursor = str(next_cursor)
                        # Release the per-runtime RPC lane between slices and
                        # give interactive calls a chance to acquire it.
                        time.sleep(0.01)

                    if task._cancel_event.is_set():
                        self._update_session_indexing_metadata(
                            session_id,
                            indexing_state="cancelled",
                            indexing_complete=False,
                            semantic_indexed_count=indexed,
                            semantic_index_progress=task.progress,
                        )
                        return {"ok": True, "cancelled": True, "next_cursor": cursor}
                    if stalled:
                        # The embedder could not make forward progress at a
                        # stable resume cursor. Do not report this as a total
                        # failure (earlier passes may have indexed functions)
                        # and do not claim completion. Surface the resume
                        # cursor and mark the job so the caller can retry.
                        self._update_session_indexing_metadata(
                            session_id,
                            indexing_state="stalled",
                            indexing_complete=False,
                            semantic_indexed_count=indexed,
                            semantic_index_progress=task.progress,
                        )
                        return {
                            "ok": True,
                            "stalled": True,
                            "quality": quality,
                            "passes": passes,
                            "indexed": indexed,
                            "attempted": attempted,
                            "failed": failed,
                            "eligible": eligible,
                            "complete": False,
                            "fully_indexed": False,
                            "limit_reached": False,
                            "next_cursor": cursor,
                            "scope": scope,
                            "binary_match": reuse,
                            "index": last_index,
                            "input": {
                                "pseudocode_chars": pseudocode_chars,
                                "document_chars": document_chars,
                            },
                            "message": (
                                "Semantic indexing stalled: the embedding backend made no "
                                "forward progress for 3 consecutive passes. Resume with "
                                f"start_after={cursor!r} once the embedder recovers."
                            ),
                        }
                    result = {
                        "ok": True,
                        "quality": quality,
                        "passes": passes,
                        "indexed": indexed,
                        "attempted": attempted,
                        "failed": failed,
                        "eligible": eligible,
                        "complete": scope_complete and not limit_reached,
                        "fully_indexed": fully_indexed and scope_complete and not limit_reached,
                        "limit_reached": limit_reached,
                        "next_cursor": cursor if limit_reached or not scope_complete else None,
                        "scope": scope,
                        "binary_match": reuse,
                        "index": last_index,
                        "input": {
                            "pseudocode_chars": pseudocode_chars,
                            "document_chars": document_chars,
                        },
                    }
                    self._update_session_indexing_metadata(
                        session_id,
                        indexing_state="complete" if scope_complete and not limit_reached else "limit_reached",
                        indexing_complete=scope_complete and not limit_reached,
                        semantic_indexed_count=indexed,
                        semantic_index_progress=result,
                    )
                    return result
                except Exception:
                    self._update_session_indexing_metadata(
                        session_id,
                        indexing_state="failed",
                        indexing_complete=False,
                        semantic_index_progress=task.progress,
                    )
                    raise

            def _index_run(task):
                try:
                    return _run(task)
                finally:
                    # Drop the completed job's entry so a long-lived daemon
                    # that opens many sessions does not retain every finished
                    # BatchTask (and its Future/cancel event) for the server
                    # lifetime. Only clear the entry if it still names this
                    # task — a later submit for the same session may have
                    # overwritten it with a newer job.
                    with lock:
                        if active.get(session_id) == task.task_id:
                            active.pop(session_id, None)

            task_id = self._batch_manager.submit(
                action="semantic_index",
                args={
                    "quality": quality,
                    "limit": total_limit,
                    "slice_size": slice_size,
                    "scope": scope,
                },
                session_id=session_id,
                run_fn=self._bind_background_run(_index_run, session=session),
            )
            active[session_id] = task_id

        return {
            "ok": True,
            "task_id": task_id,
            "state": "pending",
            "background": True,
            "quality": quality,
            "limit": total_limit,
            "slice_size": slice_size,
            "scope": scope,
            "message": "Semantic indexing is running in the background; use ida_index_status with this task_id.",
        }

    def _background_policy_preflight(
        self, *, script: Any, tool_call: Any, purpose: Any = None
    ) -> dict | None:
        # Evaluate against the session's resolved policy mode (operator
        # baseline merged with the session's policy_mode), matching the gate
        # the synchronous dispatch path applies. Hardcoding "assist" made a
        # background WRITE submission without ack be rejected even in a
        # permissive deployment that would WARN-and-allow synchronously.
        mode = self._resolve_policy_mode()
        if script:
            decision = evaluate_policy(
                "background",
                "script",
                mode=mode,
                purpose=purpose,
                ack=False,
            )
            return make_error(
                getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                "background script execution is not supported; submit a tool_call instead",
                hint="Use background(action='submit', tool_call={'tool':'...', 'args': {...}}).",
                details=decision.to_dict(),
            )

        if tool_call:
            if not isinstance(tool_call, dict):
                return make_error(MCPError.INVALID_ARGS, "tool_call must be an object")
            tool = str(tool_call.get("tool") or tool_call.get("name") or "").strip()
            call_args = tool_call.get("args") or tool_call.get("arguments") or {}
            if not tool:
                return make_error(MCPError.INVALID_ARGS, "tool_call.tool required")
            if not isinstance(call_args, dict):
                return make_error(MCPError.INVALID_ARGS, "tool_call.args must be an object")
            decision = evaluate_policy(
                tool,
                call_args.get("action"),
                mode=mode,
                # A caller may set _purpose on the background request itself,
                # not just inside tool_call.args; honour both.
                purpose=call_args.get("_purpose") or purpose,
                ack=ack_from_args(call_args),
            )
            if decision.decision in {PolicyDecision.BLOCK, PolicyDecision.REQUIRE_ACK}:
                return make_error(
                    getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                    "Background tool call requires explicit acknowledgement before queueing",
                    hint="Add _risk_ack=true to tool_call.args after verifying the action is authorized.",
                    details=decision.to_dict(),
                )
        return None

    @property
    def _batch_manager(self) -> BatchManager:
        manager = getattr(self, "_batch_mgr", None)
        if manager is None:
            # The first background request can arrive concurrently with
            # another request on the same host. Double-checked initialization
            # keeps both callers on one task map and one executor.
            with _LAZY_STATE_LOCK:
                manager = getattr(self, "_batch_mgr", None)
                if manager is None:
                    manager = BatchManager()
                    self._batch_mgr = manager
        return manager

    def _handle_background(self, args: dict) -> dict:
        action = str(args.get("action") or "list").strip().lower()
        handler_name = _BACKGROUND_ACTIONS.get(action)
        if handler_name is None:
            valid = ", ".join(sorted(_BACKGROUND_ACTIONS.keys()))
            return make_error(
                MCPError.INVALID_ARGS,
                f"Invalid background action '{action}'. Valid: {valid}",
            )
        return getattr(self, handler_name)(args)

    def _bg_submit(self, args: dict) -> dict:
        script = args.get("script")
        tool_call = args.get("tool_call")
        if not script and not tool_call:
            return make_error(
                MCPError.INVALID_ARGS,
                "background submit requires 'script' (Python source) or 'tool_call' "
                "(dict with 'tool', 'action', 'args' keys)",
            )
        # Background work runs in a worker thread, which deliberately does
        # not inherit a daemon connection's context. Capture the submitting
        # client's active session now so the task stays bound to its IDA
        # runtime instead of falling back to another client's session later.
        session_id = args.get("session_id")
        if not session_id:
            current = getattr(self, "current_session", None)
            session_id = getattr(current, "session_id", None)
        target_session = None
        if session_id and hasattr(self, "session_mgr"):
            target_session = self.session_mgr.get_session(str(session_id))
            if target_session is None:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for session_id: {session_id}",
                )
            # The worker is granted ownership of the target session (and the
            # submitting connection keeps a grant so it can retrieve the task
            # later), so the caller must already own it — or adopt it when no
            # live foreign owner holds it. Without this gate,
            # background(submit, session_id=<any>) would let a caller queue
            # tool calls (including misc.python) against another connection's
            # locked session.
            ownership_error = self._ensure_client_owns_session(target_session)
            if ownership_error:
                return ownership_error
        policy_error = self._background_policy_preflight(
            script=script, tool_call=tool_call, purpose=args.get("_purpose")
        )
        if policy_error:
            return policy_error
        # Scripts are always rejected by _background_policy_preflight above, so
        # only tool_call tasks ever reach the pool.
        action = "tool_call"

        def _run(task):
            # The worker runs against a private _ClientRequestState (see
            # _bind_background_run), so pointing current_session at the task's
            # target session cannot leak into the client's active session.
            if task.session_id and hasattr(self, "session_mgr"):
                try:
                    target = self.session_mgr.get_session(task.session_id)
                    if target:
                        self.current_session = target
                except Exception:
                    pass
            tc = task.args.get("tool_call")
            if tc and isinstance(tc, dict):
                if hasattr(self, "_execute_tool"):
                    return self._execute_tool(
                        tc.get("tool", "") or tc.get("name", ""),
                        tc.get("args", {}) or tc.get("arguments", {}),
                    )
                return {"status": "ok", "tool_call": tc}
            return {"status": "unknown"}

        task_id = self._batch_manager.submit(
            action=action,
            args={"script": script, "tool_call": tool_call},
            session_id=session_id,
            run_fn=self._bind_background_run(
                _run,
                session=(
                    target_session
                    if target_session is not None
                    else getattr(self, "current_session", None)
                ),
            ),
        )
        return {"task_id": task_id, "state": "pending"}

    def _owned_batch_session_ids(self) -> set[str] | None:
        """Session IDs this connection may see in BatchManager, or None if unenforced."""
        owns = getattr(self, "_client_owns_session", None)
        if not callable(owns):
            return None
        owned: set[str] = set()
        state = getattr(self, "_client_request_state", None)
        if callable(state):
            request_state = state()
            for sid in getattr(request_state, "owned_session_ids", set()) or set():
                if owns(str(sid)):
                    owned.add(str(sid))
        current = getattr(self, "current_session", None)
        sid = getattr(current, "session_id", None)
        if sid and owns(str(sid)):
            owned.add(str(sid))
        return owned

    def _filter_owned_batch_tasks(self, tasks: list[dict]) -> list[dict]:
        owned = self._owned_batch_session_ids()
        if owned is None:
            return tasks
        return [task for task in tasks if str(task.get("session_id") or "") in owned]

    def _require_owned_batch_task(self, task_id: str) -> dict | None:
        """Return an error if task_id is missing or belongs to another client."""
        tasks = self._batch_manager.status(task_id)
        if not tasks:
            return make_error(MCPError.NOT_FOUND, f"task {task_id} not found")
        owned = self._owned_batch_session_ids()
        if owned is None:
            return None
        if not self._filter_owned_batch_tasks(tasks):
            return make_error(
                MCPError.NOT_FOUND,
                f"task {task_id} not found",
                hint="Background tasks are visible only to the MCP client that owns their session.",
            )
        return None

    def _bg_status(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if task_id:
            denied = self._require_owned_batch_task(str(task_id))
            if denied:
                return denied
            tasks = self._batch_manager.status(task_id)
            return {"ok": True, "tasks": self._filter_owned_batch_tasks(tasks)}
        tasks = self._batch_manager.status(None)
        return {"ok": True, "tasks": self._filter_owned_batch_tasks(tasks)}

    def _bg_result(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        denied = self._require_owned_batch_task(str(task_id))
        if denied:
            return denied
        return self._batch_manager.result(str(task_id))

    def _bg_cancel(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        denied = self._require_owned_batch_task(str(task_id))
        if denied:
            return denied
        return self._batch_manager.cancel(str(task_id))

    def _bg_list(self, args: dict) -> dict:
        state = args.get("state")
        session_id = args.get("session_id")
        tasks = self._filter_owned_batch_tasks(self._batch_manager.list_tasks(state))
        if session_id:
            owned = self._owned_batch_session_ids()
            if owned is not None and str(session_id) not in owned:
                return {"ok": True, "tasks": []}
            tasks = [t for t in tasks if t.get("session_id") == session_id]
        return {"ok": True, "tasks": tasks}

    def _bg_wait(self, args: dict) -> dict:
        task_id = args.get("task_id")
        if not task_id:
            return make_error(MCPError.INVALID_ARGS, "task_id required")
        denied = self._require_owned_batch_task(str(task_id))
        if denied:
            return denied
        timeout = args.get("timeout")
        if timeout is not None:
            try:
                timeout = float(timeout)
            except (TypeError, ValueError):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "timeout must be a number",
                    hint="Provide a numeric timeout in seconds, e.g. timeout=30.",
                )
        else:
            # None previously meant "wait forever", which parks the request
            # thread indefinitely behind a stuck worker. Treat it as the cap.
            timeout = _BG_WAIT_MAX_SECONDS
        # Cap a huge timeout too: an unbounded wait on a stuck worker holds a
        # pool slot (cancel() cannot free a running one) and blocks the whole
        # request loop. A capped wait returns the current task state and the
        # caller can poll again.
        timeout = min(timeout, _BG_WAIT_MAX_SECONDS)
        return self._batch_manager.wait(str(task_id), timeout=timeout)
