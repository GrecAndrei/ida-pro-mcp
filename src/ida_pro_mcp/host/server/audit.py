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
import threading
import time
from datetime import UTC, datetime
from typing import Any


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
        """Write a single audit record."""
        with self._lock:
            now = datetime.now(UTC)
            record: dict[str, Any] = {
                "ts": now.isoformat(),
                "unix_ms": int(time.time() * 1000),
                "session_id": session_id,
                "tool": tool,
                "action": action,
                # Hash args to detect tampering without logging sensitive values
                "args_hash": hashlib.sha256(
                    json.dumps(args, sort_keys=True, default=str).encode()
                ).hexdigest()[:16],
                "args_keys": sorted(args.keys()) if isinstance(args, dict) else [],
                "latency_ms": round(latency_ms, 3),
                "guardrail_mode": guardrail_mode,
                "guardrail_blocked": guardrail_blocked,
                "error": error,
                "result_type": type(result).__name__,
                "result_size": len(json.dumps(result, default=str)) if result is not None else 0,
            }
            # Include truncated args for non-sensitive tools (no paths, no raw bytes)
            if tool not in {"blackboard", "session", "batch"} and isinstance(args, dict):
                safe_args = {k: v for k, v in args.items() if k not in {"raw_bytes", "binary_path", "idb_path", "path"}}
                record["args_preview"] = json.dumps(safe_args, default=str)[:500]

            f = self._open_for_date(now)
            line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
            f.write(line)
            f.flush()
            self._total_written += len(line)
            if self._total_written > 1024 * 1024:
                self._maybe_prune_old()
                self._total_written = 0

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                with contextlib.suppress(Exception):
                    self._file.close()
                self._file = None
                self._current_path = None
