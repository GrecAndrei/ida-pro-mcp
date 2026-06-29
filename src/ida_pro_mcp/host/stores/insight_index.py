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
        if persistence_path:
            self._load()

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

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

    def remove_function(self, func_addr: str) -> bool:
        """Remove a function and its tag mappings. Returns True if found."""
        addr = str(func_addr).lower()
        with self._lock:
            if addr not in self._func_map:
                return False
            old_tags = self._func_map[addr].get("tags", [])
            for tag in old_tags:
                lst = self._tag_map.get(tag)
                if lst and addr in lst:
                    lst.remove(addr)
            del self._func_map[addr]
            self._access_log.pop(addr, None)
            return True

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

    def query_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """
        Query functions by a single behavior tag.

        Returns list of function metadata dicts in <1ms for any tag.
        """
        tag = tag.lower()
        with self._lock:
            addrs = self._tag_map.get(tag, [])
            results = []
            for addr in addrs:
                meta = self._func_map.get(addr)
                if meta:
                    meta["access_count"] = meta.get("access_count", 0) + 1
                    results.append(dict(meta))
            return results

    def query_by_tags(
        self, tags: list[str], mode: str = "and"
    ) -> list[dict[str, Any]]:
        """
        Query functions by multiple behavior tags.

        Parameters
        ----------
        tags : list of str
            Behavior tags to match.
        mode : str
            "and" — function must have ALL tags (intersection).
            "or"  — function must have ANY tag (union).

        Returns list of function metadata dicts.
        """
        tags = [t.lower() for t in tags if t]
        if not tags:
            return []

        with self._lock:
            if mode == "and":
                # Start with the shortest candidate list
                candidates: set | None = None
                for tag in tags:
                    addrs = set(self._tag_map.get(tag, []))
                    if candidates is None:
                        candidates = addrs
                    else:
                        candidates &= addrs
                    if not candidates:
                        return []
                result_addrs = list(candidates) if candidates else []
            else:  # "or"
                result_addrs = []
                seen = set()
                for tag in tags:
                    for addr in self._tag_map.get(tag, []):
                        if addr not in seen:
                            seen.add(addr)
                            result_addrs.append(addr)

            results = []
            for addr in result_addrs:
                meta = self._func_map.get(addr)
                if meta:
                    meta["access_count"] = meta.get("access_count", 0) + 1
                    results.append(dict(meta))
            return results

    def query_by_name(self, name_pattern: str) -> list[dict[str, Any]]:
        """Substring match against function names (case-insensitive)."""
        pattern = name_pattern.lower()
        with self._lock:
            results = []
            for _addr, meta in self._func_map.items():
                if pattern in meta.get("name", "").lower():
                    meta["access_count"] = meta.get("access_count", 0) + 1
                    results.append(dict(meta))
            return results

    def get_function(self, func_addr: str) -> dict[str, Any] | None:
        """Get metadata for a single function by address."""
        addr = str(func_addr).lower()
        with self._lock:
            meta = self._func_map.get(addr)
            if meta:
                meta["access_count"] = meta.get("access_count", 0) + 1
                return dict(meta)
            return None

    def get_all_tags(self) -> list[str]:
        """Return all known tags sorted alphabetically."""
        with self._lock:
            return sorted(self._tag_map.keys())

    def get_tag_histogram(self) -> dict[str, int]:
        """Return {tag: count} for all indexed tags."""
        with self._lock:
            return {tag: len(addrs) for tag, addrs in self._tag_map.items()}

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
    # Promotion / Demotion helpers
    # ------------------------------------------------------------------

    def get_hot_functions(self, min_accesses: int = 3, limit: int = 50) -> list[dict[str, Any]]:
        """Return functions accessed >= min_accesses (promotion candidates)."""
        with self._lock:
            items = [
                dict(meta) for meta in self._func_map.values()
                if meta.get("access_count", 0) >= min_accesses
            ]
            items.sort(key=lambda x: -x.get("access_count", 0))
            return items[:limit]

    def get_stale_functions(self, max_accesses: int = 1, staleness_days: int = 30) -> list[str]:
        """Return function addresses with low access and old index time (demotion candidates)."""
        cutoff = time.time() - (staleness_days * 86400)
        with self._lock:
            return [
                meta["addr"]
                for meta in self._func_map.values()
                if meta.get("access_count", 0) <= max_accesses
                and meta.get("indexed_at", 0) < cutoff
            ]

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
