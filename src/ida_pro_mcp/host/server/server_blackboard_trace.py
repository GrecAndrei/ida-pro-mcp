"""Trace task management for the blackboard mixin.

Extracted from server_blackboard.py to keep the main handler focused.
This mixin provides:
  - Entity extraction from text (addresses, symbols, addr→name pairs)
  - Trace task creation and execution
  - Auto-proposal generation from trace results
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..errors import is_error_result

_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")
_SYMBOL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,63}\b")
_ADDR_NAME_RE = re.compile(
    r"(?P<addr>0x[0-9a-fA-F]{4,16})\s*(?:->|:|=|-)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]{2,63})"
)


class ServerBlackboardTraceMixin:
    """Trace task creation, execution, and auto-proposal generation."""

    def _extract_trace_entities(self, text: str) -> dict[str, Any]:
        addrs = sorted({m.group(0) for m in _ADDR_RE.finditer(text or "")})
        symbols = []
        for m in _SYMBOL_RE.finditer(text or ""):
            s = m.group(0)
            if s.lower().startswith("lane_"):
                continue
            if s.lower().startswith("status"):
                continue
            if s.startswith("0x"):
                continue
            symbols.append(s)
        symbols = sorted(set(symbols))[:50]
        pairs = []
        for m in _ADDR_NAME_RE.finditer(text or ""):
            addr = m.group("addr")
            name = m.group("name")
            if addr and name:
                pairs.append({"addr": addr, "name": name})
        seen = set()
        uniq_pairs = []
        for p in pairs:
            key = (p["addr"], p["name"])
            if key in seen:
                continue
            seen.add(key)
            uniq_pairs.append(p)
        return {"addrs": addrs, "symbols": symbols, "addr_name_pairs": uniq_pairs}

    def _create_trace_task(self, store, source_entry_id: str, source_text: str, depth: int, limit: int) -> str:
        entities = self._extract_trace_entities(source_text)
        payload = {
            "source_entry_id": source_entry_id,
            "depth": depth,
            "limit": limit,
            "entities": entities,
            "status": "pending",
        }
        title = f"trace_task from {source_entry_id or 'text'} ({len(entities.get('addrs', []))} addrs)"
        return store.write(
            title=title,
            content=json.dumps(payload, ensure_ascii=True),
            category="trace_task",
            addr=(entities.get("addrs") or [""])[0],
            tags=["trace_task", "status:pending"],
            confidence=0.7,
            source="trace_ingest",
            source_type="trace",
        )

    def _maybe_auto_trace_from_text(
        self,
        store,
        source_entry_id: str,
        source_text: str,
        auto_trace: bool = True,
        depth: int = 2,
        limit: int = 8,
    ) -> str | None:
        if not auto_trace:
            return None
        entities = self._extract_trace_entities(source_text or "")
        if not entities.get("addrs") and not entities.get("addr_name_pairs"):
            return None
        return self._create_trace_task(
            store,
            source_entry_id=source_entry_id,
            source_text=source_text,
            depth=depth,
            limit=limit,
        )

    def _set_task_status(self, store, entry: dict[str, Any], status: str, payload: dict[str, Any]) -> None:
        tags = entry.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        new_tags = [t for t in tags if not str(t).startswith("status:")]
        new_tags.append(f"status:{status}")
        # The payload's status is the authoritative record; the store unions
        # tags, so status tags accumulate and cannot express replacement.
        payload = dict(payload or {})
        payload["status"] = status
        store.update(entry.get("id"), tags=new_tags, content=json.dumps(payload, ensure_ascii=True))

    def _auto_proposals_from_trace(self, store, trace_entry_id: str, pairs: list[dict[str, str]]) -> int:
        created = 0
        for p in pairs:
            spec = {"renames": [{"addr": p.get("addr"), "name": p.get("name")}]}
            err = self._validate_rename_spec(spec)
            if err:
                continue
            title = f"rename proposal from trace {trace_entry_id}: {p.get('addr')} -> {p.get('name')}"
            if store.exists_similar(str(p.get("addr") or ""), "proposal", title):
                continue
            content = json.dumps(
                {
                    "proposal_type": "rename",
                    "spec": spec,
                    "verification_spec": {"kind": "symbol_name_match"},
                    "status": "proposed",
                    "source_trace_task": trace_entry_id,
                },
                ensure_ascii=True,
            )
            store.write(
                title=title,
                content=content,
                category="proposal",
                addr=str(p.get("addr") or ""),
                tags=["proposal_lifecycle", "status:proposed", "proposal_type:rename", "trace_auto"],
                confidence=0.68,
                source="trace_auto",
                source_type="proposal",
            )
            created += 1
        return created

    def _run_trace_task(self, store, entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        entities = payload.get("entities") or {}
        addrs = entities.get("addrs") or []
        symbols = entities.get("symbols") or []
        pairs = list(entities.get("addr_name_pairs") or [])
        depth = int(payload.get("depth") or 2)
        limit = int(payload.get("limit") or 8)
        collected = []
        for addr in addrs[:limit]:
            if hasattr(self, "_execute_tool"):
                try:
                    xr = self._execute_tool(
                        "graph",
                        {"action": "xref_graph", "addr": addr, "depth": depth, "format": "json", "max_items": 12},
                    )
                    if isinstance(xr, dict) and not is_error_result(xr):
                        collected.append({"kind": "xref", "addr": addr, "result": xr})
                except Exception as exc:
                    collected.append({"kind": "xref_error", "addr": addr, "error": str(exc)})
        for sym in symbols[:5]:
            if hasattr(self, "_execute_tool"):
                try:
                    sr = self._execute_tool("search", {"action": "find", "query": sym, "limit": 5})
                    if isinstance(sr, dict) and not is_error_result(sr):
                        collected.append({"kind": "symbol", "symbol": sym, "result": sr})
                except Exception as exc:
                    collected.append({"kind": "symbol_error", "symbol": sym, "error": str(exc)})

        # Derive additional addr->name pairs from evidence text
        for item in collected:
            text = json.dumps(item, ensure_ascii=True)
            parsed = self._extract_trace_entities(text)
            for pair in parsed.get("addr_name_pairs", []):
                if pair not in pairs:
                    pairs.append(pair)

        evidence_ok = [c for c in collected if c.get("kind") in ("xref", "symbol")]
        derived_summary = {
            "trace_task_id": entry.get("id"),
            "evidence_count": len(evidence_ok),
            "addrs": addrs[:limit],
            "symbols": symbols[:8],
            "pairs": pairs[:20],
        }
        # Only record an evidence entry when something was actually gathered,
        # and keep it out of the hypothesis lane: it is an evidence record,
        # never a user-facing claim, and `_memory_compile` would otherwise
        # count each one as an open hypothesis forever.
        if evidence_ok:
            store.write(
                title=f"trace evidence {entry.get('id')}",
                content=json.dumps(derived_summary, ensure_ascii=True),
                category="trace_evidence",
                addr=(addrs or [""])[0],
                tags=["trace_derived", "evidence"],
                confidence=0.62,
                source="trace_run",
                source_type="trace",
            )
        proposal_count = self._auto_proposals_from_trace(store, str(entry.get("id")), pairs[:20])
        return {
            "ok": True,
            "evidence_count": len(evidence_ok),
            "derived_pairs": len(pairs),
            "proposals_created": proposal_count,
        }
