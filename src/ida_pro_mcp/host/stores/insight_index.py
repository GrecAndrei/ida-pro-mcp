#!/usr/bin/env python3
"""
L1 Insight Index — Fast in-memory routing index for hierarchical memory tiering.

Memory tiering (L0-L4):
  L0: Meta Rules (schemas.py — TOOL_ACTIONS)
  L1: Insight Index (this module)
  L2: Global Facts (patterns.py — GlobalFactsDatabase)
  L3: Task Skills (session.py — skills)
  L4: Session Archive (blackboard.py + preference store)

The Insight Index provides O(1) tag-based routing to functions and memory
tiers. It is always resident in memory and aggressively pruned to stay
under the context budget.

No LLM dependencies. Standard library only.
"""

import contextlib
import json
import os
import threading
import time
from collections import OrderedDict, defaultdict
from typing import Any

# Canonical behavior tags for reverse engineering functions
CANONICAL_TAGS = frozenset({
    "crypto",
    "network",
    "file_io",
    "registry",
    "process",
    "string_decode",
    "allocator",
    "exception_handler",
    "obfuscation",
    "compression",
    "hashing",
    "encoding",
    "parser",
    "main",
    "init",
    "cleanup",
    "loop",
    "recursive",
    "thunk",
    "library",
    "data",
})


class InsightIndex:
    """
    L1 Insight Index: fast in-memory routing index.

    Maps behavior tags and function addresses across memory tiers for O(1)
    lookup.  Persisted to JSON on shutdown and reloaded on startup.

    Attributes:
        _tag_map: Dict[tag, List[func_addr]] — primary tag index.
        _func_map: Dict[func_addr, Dict[str, Any]] — per-function metadata.
        _access_log: OrderedDict recording access counts for promotion heuristics.
        _lock: threading.RLock for thread-safe operations.
    """

    def __init__(self, persistence_path: str | None = None):
        self._tag_map: dict[str, list[str]] = defaultdict(list)
        self._func_map: dict[str, dict[str, Any]] = {}
        self._access_log: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()
        self._persistence_path = persistence_path
        self._dirty = False
        self._last_save = 0.0
        if persistence_path:
            self._load()

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def _mark_dirty(self) -> None:
        """Mark index as modified and autosave if enough time has passed."""
        self._dirty = True
        now = time.time()
        if self._persistence_path and now - self._last_save > 60:
            self._last_save = now
            self._dirty = False
            self.save()

    def index_function(self, func_addr: str, attributes: dict[str, Any]) -> None:
        """
        Add or update a function in the insight index.

        Parameters
        ----------
        func_addr : str
            Function address (e.g., "0x401000") or unique identifier.
        attributes : dict
            Must contain at least a "behavior_tags" key (list of str).
            Optional keys: "tier" (str), "target_id" (str), "name" (str).

        Example
        -------
            index.index_function("0x401000", {
                "behavior_tags": ["crypto", "network"],
                "name": "encrypt_and_send",
                "tier": "L2",
                "target_id": "fact_abc123",
            })
        """
        addr = str(func_addr).lower()
        tags = list(attributes.get("behavior_tags", []))
        meta = {
            "addr": addr,
            "name": attributes.get("name", ""),
            "tier": attributes.get("tier", ""),
            "target_id": attributes.get("target_id", ""),
            "tags": tags,
            "indexed_at": time.time(),
            "access_count": 0,
        }

        with self._lock:
            # Remove stale tag mappings if re-indexing
            if addr in self._func_map:
                old_tags = self._func_map[addr].get("tags", [])
                for tag in old_tags:
                    lst = self._tag_map.get(tag)
                    if lst and addr in lst:
                        lst.remove(addr)

            self._func_map[addr] = meta
            for tag in tags:
                tag = tag.lower()
                if addr not in self._tag_map[tag]:
                    self._tag_map[tag].append(addr)
        self._mark_dirty()

    def rebuild(self, functions: list[tuple[str, dict[str, Any]]]) -> None:
        """
        Bulk-rebuild the entire index. Used on binary load.

        Parameters
        ----------
        functions : list of (func_addr, attributes)
        """
        with self._lock:
            self._tag_map.clear()
            self._func_map.clear()
            self._access_log.clear()
            for addr, attrs in functions:
                self.index_function(addr, attrs)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_function(self, func_addr: str) -> dict[str, Any] | None:
        """Get metadata for a single function by address."""
        addr = str(func_addr).lower()
        with self._lock:
            meta = self._func_map.get(addr)
            if meta:
                meta["access_count"] = meta.get("access_count", 0) + 1
                return dict(meta)
            return None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | None = None) -> None:
        """Serialize index to JSON."""
        target = path or self._persistence_path
        if not target:
            return
        with self._lock:
            payload = {
                "func_map": self._func_map,
                "tag_map": dict(self._tag_map.items()),
                "saved_at": time.time(),
            }
        tmp = target + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, target)
            self._dirty = False
            self._last_save = time.time()
        except Exception:
            with contextlib.suppress(OSError):
                os.remove(tmp)

    def _load(self) -> None:
        """Deserialize index from JSON."""
        path = self._persistence_path
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
            func_map = payload.get("func_map", {})
            tag_map = payload.get("tag_map", {})
            with self._lock:
                self._func_map = func_map
                self._tag_map = defaultdict(list)
                for tag, addrs in tag_map.items():
                    self._tag_map[tag] = list(addrs)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total_funcs = len(self._func_map)
            total_tags = len(self._tag_map)
            tag_counts = {tag: len(addrs) for tag, addrs in self._tag_map.items()}
            return {
                "total_functions": total_funcs,
                "total_tags": total_tags,
                "tag_histogram": tag_counts,
                "persistence_path": self._persistence_path,
            }

    def __len__(self) -> int:
        return len(self._func_map)

    def __repr__(self) -> str:
        return f"<InsightIndex: {len(self._func_map)} functions, {len(self._tag_map)} tags>"
