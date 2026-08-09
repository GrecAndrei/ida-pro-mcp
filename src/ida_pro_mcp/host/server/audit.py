#!/usr/bin/env python3
"""
Structured audit logging for all MCP tool calls.

Writes JSONL to <cache_dir>/audit/YYYY-MM/audit_YYYY-MM-DD.jsonl
Each line is a deterministic, tamper-evident log record.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import threading
import time
from datetime import UTC, datetime
from itertools import islice
from typing import Any

# Max container items serialized to compute result_size; larger results are
# sampled so the byte count never costs a full O(result) serialization.
_RESULT_SIZE_SAMPLE_CAP = 8192


def _sample_value(value: Any) -> Any:
    """Return a bounded sample of a container for size estimation."""
    if isinstance(value, dict):
        return {
            k: _sample_value(v)
            for k, v in islice(value.items(), _RESULT_SIZE_SAMPLE_CAP)
        }
    if isinstance(value, (list, tuple)):
        return [_sample_value(v) for v in islice(value, _RESULT_SIZE_SAMPLE_CAP)]
    return value


def _bounded_result_size(result: Any) -> int:
    """Approximate serialized size of the audit result.

    Small results are measured exactly. Large ones (big disassemblies, raw byte
    hexdumps, batch members) are sampled so the byte count never costs a full
    O(result) serialization on the hot path; the value is then a floor.
    """
    if result is None:
        return 0
    if isinstance(result, (str, bytes)):
        return len(result)
    sample = _sample_value(result)
    with contextlib.suppress(Exception):
        return len(json.dumps(sample, default=str))
    return 0


def _shallow(value: Any, depth: int = 0, max_items: int = 16) -> Any:
    """Return a canonical, bounded-depth, bounded-size JSON-serializable form.

    Used for the audit args hash (so huge or oddly-typed args hash fast and
    never raise under ``sort_keys``) and for ``args_preview`` (so the preview is
    cheap to serialize and cannot bloat the record with a giant container).
    Containers are truncated at ``max_items`` with a ``<+N>`` marker; arbitrary
    objects are reduced to their repr.
    """
    if depth >= 3:
        return "<truncated>"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        count = 0
        for k, v in value.items():
            if count >= max_items:
                out[f"<+{len(value) - count}>"] = True
                break
            out[str(k)] = _shallow(v, depth + 1, max_items)
            count += 1
        return out
    if isinstance(value, (list, tuple)):
        items = [_shallow(v, depth + 1, max_items) for v in islice(value, max_items)]
        if len(value) > len(items):
            items.append(f"<+{len(value) - len(items)}>")
        return items
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()[:128]
    try:
        return repr(value)
    except Exception:
        return "<unrepr>"


def _canonical_args_hash(args: Any) -> str:
    """Stable, failure-proof hash of tool args for the audit record.

    Best-effort: on any unexpected failure returns the ``<unhashable>`` marker
    so the audit record is never dropped because the args could not be hashed
    (e.g. mixed int/str keys raise TypeError under ``sort_keys`` on the raw
    dict; a shallow form plus ``default=str`` avoids that).
    """
    try:
        return hashlib.sha256(
            json.dumps(_shallow(args), sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
    except Exception:
        return "<unhashable>"


class AuditLogger:
    """
    Per-call audit logger. Writes JSONL, rotates daily, caps total size.
    """

    def __init__(self, base_dir: str | None = None, max_mb: float = 256.0):
        self.base_dir = base_dir or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "audit"
        )
        os.makedirs(self.base_dir, exist_ok=True)
        self.max_bytes = int(max_mb * 1024 * 1024)
        self._lock = threading.Lock()
        self._file: Any | None = None
        self._current_path: str | None = None
        self._total_written = 0
        self._pending = 0
        self._last_flush = 0.0

    def _open_for_date(self, dt: datetime) -> Any:
        month_dir = os.path.join(self.base_dir, dt.strftime("%Y-%m"))
        os.makedirs(month_dir, exist_ok=True)
        path = os.path.join(month_dir, f"audit_{dt.strftime('%Y-%m-%d')}.jsonl")
        if self._current_path == path and self._file is not None:
            return self._file
        if self._file is not None:
            with contextlib.suppress(Exception):
                self._file.close()
        self._file = open(path, "a", encoding="utf-8")
        self._current_path = path
        return self._file

    def _maybe_prune_old(self):
        """If total audit dir exceeds max_bytes, delete oldest month dirs."""
        try:
            total = 0
            month_dirs = []
            for root, _dirs, files in os.walk(self.base_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    total += os.path.getsize(fp)
                if root != self.base_dir and os.path.basename(root).count("-") == 1:
                    month_dirs.append(root)
            if total <= self.max_bytes:
                return
            month_dirs.sort()
            # Never prune the currently-open month: unlink()-ing the file this
            # logger still holds open orphans the fd (Linux), so the rest of the
            # month's records would vanish on close. If the current month alone
            # exceeds the cap it simply stays until it rotates.
            current_month = datetime.now(UTC).strftime("%Y-%m")
            month_dirs = [d for d in month_dirs if os.path.basename(d) != current_month]
            while total > self.max_bytes and month_dirs:
                oldest = month_dirs.pop(0)
                for f in os.listdir(oldest):
                    fp = os.path.join(oldest, f)
                    total -= os.path.getsize(fp)
                    os.remove(fp)
                os.rmdir(oldest)
        except Exception:
            pass

    def log(
        self,
        tool: str,
        action: str,
        args: dict[str, Any],
        result: Any,
        latency_ms: float,
        session_id: str | None = None,
        guardrail_mode: str | None = None,
        guardrail_blocked: bool = False,
        error: str | None = None,
    ) -> None:
        """Write a single audit record.

        Best-effort: a disk-full / permission / serialization failure (open,
        write, json.dumps on a circular result) is reported to stderr and
        swallowed so it can never fail the tool call that already produced a
        valid result.
        """
        try:
            now = datetime.now(UTC)
            record: dict[str, Any] = {
                "ts": now.isoformat(),
                "unix_ms": int(time.time() * 1000),
                "session_id": session_id,
                "tool": tool,
                "action": action,
                # Hash args to detect tampering without logging sensitive values.
                # Uses a canonical shallow form (bounded depth + truncated
                # containers) so huge or oddly-typed args (mixed int/str keys
                # raise TypeError under sort_keys on the raw dict) hash fast and
                # can never drop the whole audit record.
                "args_hash": _canonical_args_hash(args),
                "args_keys": sorted(str(k) for k in (args.keys() if isinstance(args, dict) else [])),
                "latency_ms": round(latency_ms, 3),
                "guardrail_mode": guardrail_mode,
                "guardrail_blocked": guardrail_blocked,
                "error": error,
                "result_type": type(result).__name__,
                "result_size": _bounded_result_size(result),
            }
            # Include truncated args for non-sensitive tools (no paths, no raw
            # bytes, no executed source). `idb` carries a full session/IDB path
            # for host-side tools (wiki/blackboard/session/gadgets), which return
            # before the dispatcher pops it — it belongs in the no-paths set too.
            # `code` is the arbitrary script payload for misc python/idc and is
            # redacted like raw_bytes rather than written to the log in plaintext.
            if tool not in {"blackboard", "session", "batch"} and isinstance(args, dict):
                safe_args = {
                    k: v
                    for k, v in args.items()
                    if k not in {"idb", "raw_bytes", "binary_path", "idb_path", "path", "code"}
                }
                if safe_args:
                    # Bounded preview over the shallow form so a huge container
                    # arg costs O(16) items to serialize, never a full dump.
                    record["args_preview"] = json.dumps(
                        _shallow(safe_args), sort_keys=True, default=str
                    )[:500]

            # Hold the lock only around the file write; building the record (arg
            # hashing, preview, result-size sampling) is pure computation and
            # must not serialize other threads' log() calls behind a slow dump.
            with self._lock:
                f = self._open_for_date(now)
                line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
                f.write(line)
                self._pending += 1
                self._total_written += len(line)
                # Coalesce small bursts: flush at most every 16 records or 1s
                # instead of per-record, so a firehose of tiny calls never
                # serializes the audit lock behind individual flushes. The
                # close() path always flushes, so nothing is lost on clean exit.
                now_mono = time.monotonic()
                if self._pending >= 16 or (now_mono - self._last_flush) >= 1.0:
                    f.flush()
                    self._pending = 0
                    self._last_flush = now_mono
                if self._total_written > 1024 * 1024:
                    self._maybe_prune_old()
                    self._total_written = 0
        except Exception as exc:
            with contextlib.suppress(Exception):
                sys.stderr.write(
                    f"[ida-pro-mcp] audit log write failed for {tool}/{action}: {exc}\n"
                )

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                with contextlib.suppress(Exception):
                    self._file.flush()
                with contextlib.suppress(Exception):
                    self._file.close()
                self._file = None
                self._current_path = None
