#!/usr/bin/env python3
"""
Autogenic semantics: zero-prior latent symbol induction.

This module intentionally avoids domain keyword lists and regex heuristics.
It builds symbols from raw structural recurrence and updates utilities from
observed outcomes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


class AutogenicSemanticField:
    """Induce latent symbols from raw payload structure."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".ida-pro-mcp", "autogenic_semantics.db"
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS symbols (
                    token TEXT PRIMARY KEY,
                    sid TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 0,
                    utility REAL NOT NULL DEFAULT 0.5,
                    updated_ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pairs (
                    a TEXT NOT NULL,
                    b TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 0,
                    updated_ts REAL NOT NULL,
                    PRIMARY KEY (a, b)
                )
                """
            )
            conn.commit()

    def _stable(self, obj: Any) -> str:
        try:
            return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            return str(obj)

    def _emit_structure_tokens(self, obj: Any, path: str = "") -> List[str]:
        out: List[str] = []
        if isinstance(obj, dict):
            out.append(f"n:{path}:dict:{len(obj)}")
            for k in sorted(obj.keys(), key=lambda x: str(x)):
                kp = f"{path}.{k}" if path else str(k)
                out.append(f"k:{kp}")
                out.extend(self._emit_structure_tokens(obj[k], kp))
            return out
        if isinstance(obj, list):
            out.append(f"n:{path}:list:{len(obj)}")
            for i, v in enumerate(obj[:32]):
                out.extend(self._emit_structure_tokens(v, f"{path}[{i}]"))
            return out
        if isinstance(obj, (int, float, bool)):
            out.append(f"v:{path}:num:{str(obj)[:24]}")
            return out
        sval = str(obj)
        out.append(f"v:{path}:str:{len(sval)}")
        b = sval.encode("utf-8", errors="ignore")
        for n in (3, 4):
            if len(b) < n:
                continue
            for i in range(min(len(b) - n + 1, 64)):
                frag = b[i : i + n]
                out.append(f"g{n}:{frag.hex()}")
        return out

    def _sid(self, token: str) -> str:
        h = hashlib.blake2b(token.encode("utf-8", errors="ignore"), digest_size=8).hexdigest()
        return f"s_{h}"

    def induce(self, payload: Any, tool: str = "", action: str = "") -> List[str]:
        """Induce latent symbols for a payload."""
        root = {"tool": tool, "action": action, "payload": payload}
        tokens = self._emit_structure_tokens(root)
        counts = Counter(tokens)
        # Compression pressure: repeated tokens get higher priority.
        ranked = sorted(counts.items(), key=lambda kv: (kv[1], len(kv[0])), reverse=True)
        chosen = [tok for tok, _ in ranked[:128]]
        symbols = [self._sid(tok) for tok in chosen]
        with self._lock:
            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                for tok in chosen:
                    sid = self._sid(tok)
                    conn.execute(
                        """
                        INSERT INTO symbols(token, sid, seen_count, utility, updated_ts)
                        VALUES(?, ?, 1, 0.5, ?)
                        ON CONFLICT(token) DO UPDATE SET
                            seen_count = seen_count + 1,
                            updated_ts = excluded.updated_ts
                        """,
                        (tok, sid, now),
                    )
                uniq = sorted(set(symbols))
                for i in range(len(uniq)):
                    for j in range(i + 1, len(uniq)):
                        a, b = uniq[i], uniq[j]
                        conn.execute(
                            """
                            INSERT INTO pairs(a, b, seen_count, updated_ts)
                            VALUES(?, ?, 1, ?)
                            ON CONFLICT(a, b) DO UPDATE SET
                                seen_count = seen_count + 1,
                                updated_ts = excluded.updated_ts
                            """,
                            (a, b, now),
                        )
                conn.commit()
        # Dedup keep order
        seen = set()
        out = []
        for s in symbols:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out[:32]

    def update_symbol_utility(self, symbols: List[str], reward: float, alpha: float = 0.2):
        if not symbols:
            return
        with self._lock:
            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                for sid in set(symbols):
                    cur = conn.cursor()
                    cur.execute("SELECT utility FROM symbols WHERE sid = ? LIMIT 1", (sid,))
                    row = cur.fetchone()
                    if row is None:
                        continue
                    old_u = float(row[0])
                    new_u = old_u + alpha * (reward - old_u)
                    conn.execute(
                        "UPDATE symbols SET utility = ?, updated_ts = ? WHERE sid = ?",
                        (new_u, now, sid),
                    )
                conn.commit()

    def symbol_utilities(self, symbols: List[str]) -> float:
        if not symbols:
            return 0.5
        vals = []
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            for sid in set(symbols):
                cur.execute("SELECT utility FROM symbols WHERE sid = ? LIMIT 1", (sid,))
                row = cur.fetchone()
                if row is not None:
                    vals.append(float(row[0]))
        if not vals:
            return 0.5
        return max(vals)
