"""
KnowledgeGraph — structured firmware understanding layer.

Separate SQLite tables (same db file as blackboard) for:
  systems          — call-graph clusters implementing one capability
  struct_instances — inferred data structures with member offsets
  state_machines   — detected state machines with transitions
  gaps             — expected-but-not-found capabilities
  attack_surface   — reachability from external inputs
  peripherals      — MMIO peripheral map

All tables live in the same .blackboard.db file so joins work.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ── helpers ───────────────────────────────────────────────────────────────────

def _j(v) -> str:
    return json.dumps(v or [], ensure_ascii=False)

def _jd(v) -> str:
    return json.dumps(v or {}, ensure_ascii=False)

def _now() -> float:
    return time.time()


class KnowledgeGraph:
    """
    Firmware knowledge graph stored in the blackboard SQLite file.

    Usage:
        kg = KnowledgeGraph(db_path)
        sid = kg.add_system("Packet RX pipeline", ["0x401000","0x402000"])
        kg.add_struct("wifi_frame_t", members=[{offset:0,size:1,name:"frame_ctrl"}])
        kg.add_gap("WPA key derivation", why="All WPA2 firmware must derive PTK/GTK")
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_tables()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    # ── schema ────────────────────────────────────────────────────────────────

    def _init_tables(self):
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS kg_systems (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT,
                    members     TEXT DEFAULT '[]',   -- JSON [addr, ...]
                    entry_points TEXT DEFAULT '[]',  -- JSON [addr, ...]
                    exit_points  TEXT DEFAULT '[]',  -- JSON [addr, ...]
                    data_structs TEXT DEFAULT '[]',  -- JSON [struct_id, ...]
                    state_vars   TEXT DEFAULT '[]',  -- JSON [addr, ...]
                    tags         TEXT DEFAULT '[]',
                    confidence   REAL DEFAULT 0.5,
                    coverage_pct REAL DEFAULT 0.0,   -- 0-100
                    source       TEXT DEFAULT 'engine',
                    created_at   REAL,
                    updated_at   REAL
                );

                CREATE TABLE IF NOT EXISTS kg_structs (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    size_bytes  INTEGER DEFAULT 0,
                    members     TEXT DEFAULT '[]',   -- JSON [{offset,size,type,name,evidence}]
                    seen_at     TEXT DEFAULT '[]',   -- JSON [{addr,access_type,offset}]
                    creation_sites TEXT DEFAULT '[]',
                    flow_path   TEXT DEFAULT '[]',   -- JSON [addr, ...] ordered pipeline
                    confidence  REAL DEFAULT 0.5,
                    source      TEXT DEFAULT 'engine',
                    created_at  REAL,
                    updated_at  REAL
                );

                CREATE TABLE IF NOT EXISTS kg_state_machines (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    state_var   TEXT,               -- addr of global holding state
                    states      TEXT DEFAULT '[]',  -- JSON [{value,name,description}]
                    transitions TEXT DEFAULT '[]',  -- JSON [{from,to,trigger_addr,condition}]
                    handlers    TEXT DEFAULT '{}',  -- JSON {state_value: handler_addr}
                    system_id   TEXT,               -- FK to kg_systems
                    confidence  REAL DEFAULT 0.5,
                    source      TEXT DEFAULT 'engine',
                    created_at  REAL,
                    updated_at  REAL
                );

                CREATE TABLE IF NOT EXISTS kg_gaps (
                    id          TEXT PRIMARY KEY,
                    expected    TEXT NOT NULL,       -- what we expect to find
                    why         TEXT,                -- why we expect it
                    hints       TEXT DEFAULT '[]',   -- JSON [hint_string, ...]
                    candidates  TEXT DEFAULT '[]',   -- JSON [addr, ...]
                    filled_by   TEXT,                -- addr or system_id once found
                    priority    REAL DEFAULT 0.5,
                    gap_type    TEXT DEFAULT 'capability', -- capability|protocol|hardware|security
                    binary_type TEXT DEFAULT '',     -- wifi_firmware|router|iot|unknown
                    resolved    INTEGER DEFAULT 0,
                    created_at  REAL,
                    updated_at  REAL
                );

                CREATE TABLE IF NOT EXISTS kg_attack_surface (
                    id              TEXT PRIMARY KEY,
                    entry_point     TEXT NOT NULL,   -- addr
                    name            TEXT,
                    reachable_from  TEXT DEFAULT 'unknown',
                    input_type      TEXT DEFAULT 'unknown',
                    max_input_size  INTEGER DEFAULT 0,
                    has_length_check INTEGER DEFAULT 0,
                    parsing_depth   INTEGER DEFAULT 0,
                    call_stack      TEXT DEFAULT '[]',  -- JSON [addr, ...]
                    known_vulns     TEXT DEFAULT '[]',  -- JSON [bb_entry_id, ...]
                    fuzz_priority   REAL DEFAULT 0.5,
                    confidence      REAL DEFAULT 0.5,
                    source          TEXT DEFAULT 'engine',
                    created_at      REAL,
                    updated_at      REAL
                );

                CREATE TABLE IF NOT EXISTS kg_peripherals (
                    id          TEXT PRIMARY KEY,
                    base_addr   TEXT NOT NULL,
                    name        TEXT,
                    periph_type TEXT DEFAULT 'unknown', -- uart|spi|dma|crypto|rf|timer|gpio
                    registers   TEXT DEFAULT '[]',  -- JSON [{offset,name,access_pattern}]
                    drivers     TEXT DEFAULT '[]',  -- JSON [addr, ...]
                    irq_num     INTEGER DEFAULT -1,
                    evidence    TEXT DEFAULT '[]',
                    confidence  REAL DEFAULT 0.5,
                    source      TEXT DEFAULT 'engine',
                    created_at  REAL,
                    updated_at  REAL
                );

                CREATE INDEX IF NOT EXISTS idx_kgs_name ON kg_systems(name);
                CREATE INDEX IF NOT EXISTS idx_kgst_name ON kg_structs(name);
                CREATE INDEX IF NOT EXISTS idx_kgsm_var ON kg_state_machines(state_var);
                CREATE INDEX IF NOT EXISTS idx_kgg_type ON kg_gaps(gap_type);
                CREATE INDEX IF NOT EXISTS idx_kgg_resolved ON kg_gaps(resolved);
                CREATE INDEX IF NOT EXISTS idx_kgas_ep ON kg_attack_surface(entry_point);
                CREATE INDEX IF NOT EXISTS idx_kgp_base ON kg_peripherals(base_addr);
            """)
            c.commit()

    # ── systems ───────────────────────────────────────────────────────────────

    def add_system(self, name: str, members: List[str],
                   description: str = "", entry_points: Optional[List[str]] = None,
                   exit_points: Optional[List[str]] = None,
                   tags: Optional[List[str]] = None,
                   confidence: float = 0.5) -> str:
        sid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            c.execute(
                "INSERT INTO kg_systems VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, name, description, _j(members),
                 _j(entry_points), _j(exit_points),
                 _j([]), _j([]), _j(tags),
                 confidence, 0.0, "engine", now, now)
            )
            c.commit()
        return sid

    def update_system(self, sid: str, **kwargs) -> bool:
        allowed = {"name", "description", "members", "entry_points", "exit_points",
                   "data_structs", "state_vars", "tags", "confidence", "coverage_pct"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = _now()
        for k in ("members", "entry_points", "exit_points", "data_structs",
                  "state_vars", "tags"):
            if k in updates:
                updates[k] = _j(updates[k])
        sets = ", ".join(f"{k}=?" for k in updates)
        with self._conn() as c:
            n = c.execute(f"UPDATE kg_systems SET {sets} WHERE id=?",
                          (*updates.values(), sid)).rowcount
            c.commit()
        return n > 0

    def get_system(self, sid: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM kg_systems WHERE id=?", (sid,)).fetchone()
        return self._sys_row(row) if row else None

    def list_systems(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM kg_systems ORDER BY confidence DESC").fetchall()
        return [self._sys_row(r) for r in rows]

    def _sys_row(self, r) -> Dict:
        d = dict(r)
        for k in ("members", "entry_points", "exit_points", "data_structs",
                  "state_vars", "tags"):
            d[k] = json.loads(d.get(k) or "[]")
        return d

    def find_system_for_addr(self, addr: str) -> Optional[Dict]:
        """Return the system that contains this address as a member."""
        for sys in self.list_systems():
            if addr in sys["members"]:
                return sys
        return None

    def add_member_to_system(self, sid: str, addr: str) -> bool:
        sys = self.get_system(sid)
        if not sys:
            return False
        members = sys["members"]
        if addr not in members:
            members.append(addr)
            return self.update_system(sid, members=members)
        return True

    # ── structs ───────────────────────────────────────────────────────────────

    def add_struct(self, name: str,
                   members: Optional[List[Dict]] = None,
                   size_bytes: int = 0,
                   confidence: float = 0.5) -> str:
        sid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            c.execute(
                "INSERT INTO kg_structs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, name, size_bytes, _j(members), _j([]), _j([]),
                 _j([]), confidence, "engine", now, now)
            )
            c.commit()
        return sid

    def record_struct_access(self, struct_id: str, addr: str,
                              access_type: str, offset: int) -> bool:
        with self._conn() as c:
            row = c.execute("SELECT seen_at FROM kg_structs WHERE id=?",
                            (struct_id,)).fetchone()
            if not row:
                return False
            seen = json.loads(row[0] or "[]")
            seen.append({"addr": addr, "access_type": access_type,
                         "offset": offset, "ts": _now()})
            c.execute("UPDATE kg_structs SET seen_at=?, updated_at=? WHERE id=?",
                      (_j(seen), _now(), struct_id))
            c.commit()
        return True

    def get_struct(self, struct_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM kg_structs WHERE id=?",
                            (struct_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        for k in ("members", "seen_at", "creation_sites", "flow_path"):
            d[k] = json.loads(d.get(k) or "[]")
        return d

    def list_structs(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM kg_structs ORDER BY confidence DESC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ("members", "seen_at", "creation_sites", "flow_path"):
                d[k] = json.loads(d.get(k) or "[]")
            result.append(d)
        return result

    def find_struct_by_offset_pattern(self, offsets: List[int],
                                       threshold: Optional[float] = None) -> Optional[Dict]:
        """Find best matching struct by offset overlap using adaptive gating."""
        offsets_set = set(offsets)
        if not offsets_set:
            return None
        best = None
        best_score = 0.0
        scored: List[Tuple[float, Dict]] = []
        for s in self.list_structs():
            known = {m.get("offset") for m in s.get("members", [])}
            if not known:
                continue
            overlap = len(offsets_set & known) / max(len(offsets_set | known), 1)
            scored.append((overlap, s))
            if overlap > best_score:
                best_score = overlap
                best = s
        if not best:
            return None
        if threshold is not None:
            return best if best_score >= float(threshold) else None
        overlaps = sorted(float(x[0]) for x in scored)
        if not overlaps:
            return None
        # Adaptive gate: top candidate must exceed robust center + spread.
        q50 = overlaps[len(overlaps) // 2]
        q75 = overlaps[min(len(overlaps) - 1, int(round((len(overlaps) - 1) * 0.75)))]
        spread = max(0.0, q75 - q50)
        adaptive_gate = min(0.98, q75 + (0.25 * spread))
        if len(overlaps) == 1:
            return best if best_score > 0.0 else None
        if best_score >= adaptive_gate:
            return best
        # Secondary adaptive fallback: keep weak-but-unique matches when no other
        # candidate is close to the top score.
        runner_up = overlaps[-2] if len(overlaps) >= 2 else 0.0
        if best_score > runner_up:
            return best
        return None

    # ── state machines ────────────────────────────────────────────────────────

    def add_state_machine(self, name: str, state_var: str,
                           states: Optional[List[Dict]] = None,
                           confidence: float = 0.5,
                           system_id: str = "") -> str:
        sid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            c.execute(
                "INSERT INTO kg_state_machines VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, name, state_var, _j(states), _j([]),
                 _jd({}), system_id or None, confidence, "engine", now, now)
            )
            c.commit()
        return sid

    def add_transition(self, sm_id: str, from_state: Any, to_state: Any,
                        trigger_addr: str, condition: str = "") -> bool:
        with self._conn() as c:
            row = c.execute("SELECT transitions FROM kg_state_machines WHERE id=?",
                            (sm_id,)).fetchone()
            if not row:
                return False
            trans = json.loads(row[0] or "[]")
            trans.append({"from": from_state, "to": to_state,
                          "trigger_addr": trigger_addr, "condition": condition,
                          "ts": _now()})
            c.execute("UPDATE kg_state_machines SET transitions=?, updated_at=? WHERE id=?",
                      (_j(trans), _now(), sm_id))
            c.commit()
        return True

    def get_state_machine(self, sm_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM kg_state_machines WHERE id=?",
                            (sm_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        for k in ("states", "transitions"):
            d[k] = json.loads(d.get(k) or "[]")
        d["handlers"] = json.loads(d.get("handlers") or "{}")
        return d

    def list_state_machines(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM kg_state_machines ORDER BY confidence DESC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ("states", "transitions"):
                d[k] = json.loads(d.get(k) or "[]")
            d["handlers"] = json.loads(d.get("handlers") or "{}")
            result.append(d)
        return result

    # ── gaps ──────────────────────────────────────────────────────────────────

    def add_gap(self, expected: str, why: str = "",
                hints: Optional[List[str]] = None,
                priority: float = 0.5,
                gap_type: str = "capability",
                binary_type: str = "") -> str:
        gid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            c.execute(
                "INSERT INTO kg_gaps VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (gid, expected, why, _j(hints), _j([]),
                 None, priority, gap_type, binary_type, 0, now, now)
            )
            c.commit()
        return gid

    def fill_gap(self, gap_id: str, filled_by: str) -> bool:
        with self._conn() as c:
            n = c.execute(
                "UPDATE kg_gaps SET filled_by=?, resolved=1, updated_at=? WHERE id=?",
                (filled_by, _now(), gap_id)
            ).rowcount
            c.commit()
        return n > 0

    def add_gap_candidate(self, gap_id: str, addr: str) -> bool:
        with self._conn() as c:
            row = c.execute("SELECT candidates FROM kg_gaps WHERE id=?",
                            (gap_id,)).fetchone()
            if not row:
                return False
            cands = json.loads(row[0] or "[]")
            if addr not in cands:
                cands.append(addr)
            c.execute("UPDATE kg_gaps SET candidates=?, updated_at=? WHERE id=?",
                      (_j(cands), _now(), gap_id))
            c.commit()
        return True

    def list_gaps(self, resolved: bool = False) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM kg_gaps WHERE resolved=? ORDER BY priority DESC",
                (1 if resolved else 0,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["hints"] = json.loads(d.get("hints") or "[]")
            d["candidates"] = json.loads(d.get("candidates") or "[]")
            result.append(d)
        return result

    # ── attack surface ────────────────────────────────────────────────────────

    def add_attack_surface(self, entry_point: str, name: str = "",
                            reachable_from: str = "unknown",
                            input_type: str = "unknown",
                            call_stack: Optional[List[str]] = None,
                            confidence: float = 0.5) -> str:
        aid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            c.execute(
                "INSERT INTO kg_attack_surface VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, entry_point, name, reachable_from, input_type,
                 0, 0, 0, _j(call_stack), _j([]),
                 0.5, confidence, "engine", now, now)
            )
            c.commit()
        return aid

    def list_attack_surface(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM kg_attack_surface ORDER BY fuzz_priority DESC"
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["call_stack"] = json.loads(d.get("call_stack") or "[]")
            d["known_vulns"] = json.loads(d.get("known_vulns") or "[]")
            result.append(d)
        return result

    def update_attack_surface(self, aid: str, **kwargs) -> bool:
        allowed = {"name", "reachable_from", "input_type", "max_input_size",
                   "has_length_check", "parsing_depth", "call_stack",
                   "known_vulns", "fuzz_priority", "confidence"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = _now()
        for k in ("call_stack", "known_vulns"):
            if k in updates:
                updates[k] = _j(updates[k])
        sets = ", ".join(f"{k}=?" for k in updates)
        with self._conn() as c:
            n = c.execute(f"UPDATE kg_attack_surface SET {sets} WHERE id=?",
                          (*updates.values(), aid)).rowcount
            c.commit()
        return n > 0

    # ── peripherals ───────────────────────────────────────────────────────────

    def add_peripheral(self, base_addr: str, name: str = "",
                        periph_type: str = "unknown",
                        drivers: Optional[List[str]] = None,
                        confidence: float = 0.5) -> str:
        pid = uuid.uuid4().hex[:10]
        now = _now()
        with self._conn() as c:
            # Don't duplicate
            existing = c.execute(
                "SELECT id FROM kg_peripherals WHERE base_addr=?", (base_addr,)
            ).fetchone()
            if existing:
                return existing[0]
            c.execute(
                "INSERT INTO kg_peripherals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, base_addr, name, periph_type,
                 _j([]), _j(drivers), -1, _j([]),
                 confidence, "engine", now, now)
            )
            c.commit()
        return pid

    def record_peripheral_access(self, base_addr: str, driver_addr: str,
                                   offset: int, access_type: str = "rw") -> str:
        """Record that driver_addr accesses peripheral at base_addr+offset."""
        with self._conn() as c:
            row = c.execute(
                "SELECT id, registers, drivers FROM kg_peripherals WHERE base_addr=?",
                (base_addr,)
            ).fetchone()
            if not row:
                pid = self.add_peripheral(base_addr, confidence=0.4)
                row = c.execute(
                    "SELECT id, registers, drivers FROM kg_peripherals WHERE id=?",
                    (pid,)
                ).fetchone()
            pid, regs_json, drivers_json = row[0], row[1], row[2]
            regs = json.loads(regs_json or "[]")
            drivers = json.loads(drivers_json or "[]")
            # Add register if new offset
            if not any(r.get("offset") == offset for r in regs):
                regs.append({"offset": offset, "name": f"reg_{offset:03x}",
                             "access_pattern": access_type})
            if driver_addr not in drivers:
                drivers.append(driver_addr)
            c.execute(
                "UPDATE kg_peripherals SET registers=?, drivers=?, updated_at=? WHERE id=?",
                (_j(regs), _j(drivers), _now(), pid)
            )
            c.commit()
        return pid

    def list_peripherals(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM kg_peripherals ORDER BY confidence DESC"
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ("registers", "drivers"):
                d[k] = json.loads(d.get(k) or "[]")
            d["evidence"] = json.loads(d.get("evidence") or "[]")
            result.append(d)
        return result

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> Dict:
        with self._conn() as c:
            n_sys = c.execute("SELECT COUNT(*) FROM kg_systems").fetchone()[0]
            n_struct = c.execute("SELECT COUNT(*) FROM kg_structs").fetchone()[0]
            n_sm = c.execute("SELECT COUNT(*) FROM kg_state_machines").fetchone()[0]
            n_gap_open = c.execute("SELECT COUNT(*) FROM kg_gaps WHERE resolved=0").fetchone()[0]
            n_gap_filled = c.execute("SELECT COUNT(*) FROM kg_gaps WHERE resolved=1").fetchone()[0]
            n_as = c.execute("SELECT COUNT(*) FROM kg_attack_surface").fetchone()[0]
            n_periph = c.execute("SELECT COUNT(*) FROM kg_peripherals").fetchone()[0]
        return {
            "systems": n_sys,
            "structs": n_struct,
            "state_machines": n_sm,
            "gaps_open": n_gap_open,
            "gaps_filled": n_gap_filled,
            "attack_surface_entries": n_as,
            "peripherals": n_periph,
        }
