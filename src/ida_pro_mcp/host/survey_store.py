from __future__ import annotations

import os
import json
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional

def _resolve_survey_db_path(db_path: Optional[str] = None) -> str:
    if db_path:
        return db_path
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    root = (
        os.environ.get("IDA_MCP_CACHE_DIR")
        or os.environ.get("IDA_MCP_DATA_DIR")
        or os.path.join(xdg, "ida-pro-mcp")
    )
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "re_experience.db")

class SurveyStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = _resolve_survey_db_path(db_path)
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_surveys (
                    addr TEXT PRIMARY KEY,
                    status TEXT, -- DORMANT, ACTIVE, DEFERRED
                    variables TEXT, -- JSON list of candidates
                    dependencies TEXT, -- JSON list of addresses
                    deferred_until TEXT, -- JSON list of user-deferred addresses
                    reason TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS re_experience (
                    id TEXT PRIMARY KEY,
                    address INTEGER,
                    ida_pseudocode TEXT,
                    ghidra_pseudocode TEXT,
                    llm_rationale TEXT,
                    resolved_source TEXT,
                    applied_changes TEXT, -- JSON
                    timestamp REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS visited_addresses (
                    addr TEXT PRIMARY KEY
                )
            """)
            conn.commit()

    def add_visited_address(self, addr: str):
        with self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO visited_addresses (addr) VALUES (?)", (addr,))
            conn.commit()

    def get_visited_addresses(self) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT addr FROM visited_addresses").fetchall()
            return [r[0] for r in rows]

    def clear_visited_addresses(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM visited_addresses")
            conn.commit()

    def get_survey(self, addr: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT addr, status, variables, dependencies, deferred_until, reason FROM active_surveys WHERE addr = ?",
                (addr,)
            ).fetchone()
            if row:
                return {
                    "addr": row[0],
                    "status": row[1],
                    "variables": json.loads(row[2]) if row[2] else [],
                    "dependencies": json.loads(row[3]) if row[3] else [],
                    "deferred_until": json.loads(row[4]) if row[4] else [],
                    "reason": row[5]
                }
        return None

    def list_surveys(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT addr, status, variables, dependencies, deferred_until, reason FROM active_surveys").fetchall()
            out = []
            for r in rows:
                out.append({
                    "addr": r[0],
                    "status": r[1],
                    "variables": json.loads(r[2]) if r[2] else [],
                    "dependencies": json.loads(r[3]) if r[3] else [],
                    "deferred_until": json.loads(r[4]) if r[4] else [],
                    "reason": r[5]
                })
            return out

    def save_survey(self, addr: str, status: str, variables: List[str], dependencies: List[str], deferred_until: List[str] = None, reason: str = ""):
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO active_surveys (addr, status, variables, dependencies, deferred_until, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    addr,
                    status,
                    json.dumps(variables),
                    json.dumps(dependencies),
                    json.dumps(deferred_until or []),
                    reason
                )
            )
            conn.commit()

    def delete_survey(self, addr: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM active_surveys WHERE addr = ?", (addr,))
            conn.commit()

    def save_experience(self, id_val: str, address: int, ida_pseudocode: str, ghidra_pseudocode: str, llm_rationale: str, resolved_source: str, applied_changes: Dict[str, Any]):
        import time
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO re_experience (id, address, ida_pseudocode, ghidra_pseudocode, llm_rationale, resolved_source, applied_changes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    id_val,
                    address,
                    ida_pseudocode,
                    ghidra_pseudocode,
                    llm_rationale,
                    resolved_source,
                    json.dumps(applied_changes),
                    time.time()
                )
            )
            conn.commit()
