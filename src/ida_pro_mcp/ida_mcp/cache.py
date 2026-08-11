"""
LRU cache for read-only tool results.

Caches results from @idaread-decorated tools to avoid redundant
IDA API calls when the same query is repeated (common with LLMs).
The cache is automatically invalidated when any @idawrite operation
is performed, since writes may change the database state.

Cache keys are canonicalized (numeric strings -> int, address lists
normalized + sorted, kwargs equal to a tool's signature default dropped)
so that LLM rephrasing of the same query — "0x401000" vs 4198400 vs
"0x401000" — hits the same LRU entry instead of three.

Writes invalidate narrowly: only entries whose key references the written
address family (same 4 KiB page) plus whole-walk entries with no address
at all (a rename changes ``list_functions``). A write that carries no
address falls back to the full physical clear, matching ``invalidate_all``.
"""

import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Dict

# Write invalidation scopes by "address family": two addresses are in the
# same family when they share the same 4 KiB page. A patch/rename/comment at
# an address invalidates cached reads of the same page; reads of other pages
# survive so a small edit does not flush every cached walk in the database.
_ADDRESS_FAMILY_SHIFT = 12

# Keys that name addresses/offsets in tool args. The set is deliberately
# generous (over-invalidation only costs a cache miss; under-invalidation
# would serve stale data). Values that do not parse as integers/hex (e.g.
# symbol names passed as ``target``) are ignored.
_ADDRESS_ARG_KEYS = frozenset({
    "addr", "address", "ea", "va", "start", "end", "from", "to",
    "target", "value", "offset", "base", "baseaddr", "rebased_addr",
    "from_ea", "to_ea", "function", "window", "data",
})


def _parse_addr(value: Any) -> int | None:
    """Coerce an address-like value to an int, or None when not one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except ValueError:
            return None
    return None


def canonicalize_value(value: Any) -> Any:
    """Canonicalize one tool-arg value for stable cache keys.

    - ``"0x401000"`` / ``"4198400"`` -> ``4198400`` (int) so hex and decimal
      spellings of the same address hit the same entry.
    - address lists -> a sorted tuple of ints (``[0x2000, 0x1000]`` is the
      same set as ``["0x2000", "0x1000"]``).
    - dicts -> sorted (key, value) tuples for order-independent keys.
    """
    if isinstance(value, str):
        s = value.strip()
        if s:
            try:
                return int(s, 0)
            except ValueError:
                pass
        return value
    if isinstance(value, (list, tuple)):
        items = tuple(canonicalize_value(x) for x in value)
        if items and all(isinstance(x, int) for x in items):
            return tuple(sorted(items))
        return items
    if isinstance(value, dict):
        return tuple(sorted((str(k), canonicalize_value(v)) for k, v in value.items()))
    return value


def canonicalize_kwargs(kwargs: dict, defaults: dict | None = None) -> dict:
    """Canonicalize *kwargs* for cache keys.

    Drops keys whose canonical value equals the tool signature's canonical
    default (so ``count="100"`` on a ``count=100`` default key matches
    ``count`` omitted), then canonicalizes the remainder.
    """
    out = {}
    for key, value in kwargs.items():
        canon = canonicalize_value(value)
        if defaults is not None and key in defaults:
            if canon == canonicalize_value(defaults[key]):
                continue
        out[key] = canon
    return out


def extract_addresses(kwargs: dict) -> frozenset[int]:
    """Collect the address values referenced by *kwargs*.

    Used to scope write invalidation to the written address family and to
    fingerprint cached read entries.
    """
    addrs: set[int] = set()
    if isinstance(kwargs, dict):
        for key in _ADDRESS_ARG_KEYS:
            if key in kwargs:
                parsed = _parse_addr(kwargs[key])
                if parsed is not None:
                    addrs.add(parsed)
        addrs_list = kwargs.get("addrs")
        if isinstance(addrs_list, (list, tuple)):
            for item in addrs_list:
                parsed = _parse_addr(item)
                if parsed is not None:
                    addrs.add(parsed)
        elif isinstance(addrs_list, str):
            for tok in re.split(r"[,\s]+", addrs_list.strip()):
                parsed = _parse_addr(tok)
                if parsed is not None:
                    addrs.add(parsed)
    return frozenset(addrs)


class ToolResultCache:
    """Thread-safe LRU cache for IDA MCP tool results."""

    def __init__(self, max_entries: int = 256, ttl_seconds: float = 300.0):
        """
        Args:
            max_entries: Maximum number of cached results.
            ttl_seconds: Time-to-live for each cache entry in seconds.
        """
        self._cache: OrderedDict[str, tuple[float, int, Any, frozenset[int]]] = OrderedDict()
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._write_generation = 0  # Bumped on every whole-cache write operation
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(tool_name: str, kwargs: dict) -> str:
        """Create a stable cache key from tool name and arguments."""
        canonical_kwargs = canonicalize_kwargs(kwargs)
        # Sort keys for deterministic hashing
        canonical = json.dumps(
            {"tool": tool_name, "args": canonical_kwargs}, sort_keys=True, default=str
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, tool_name: str, kwargs: dict, *, with_age: bool = False):
        """Retrieve a cached result, or None if not found/expired.

        If ``with_age`` is False (default), returns the stored result or
        None (legacy single-return contract).

        If ``with_age`` is True, returns ``(result, age_seconds)`` where
        ``age_seconds`` is how long ago the entry was stored. On miss,
        ``result is None`` and ``age_seconds == 0.0``.
        """
        key = self._make_key(tool_name, kwargs)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return (None, 0.0) if with_age else None

            timestamp, gen, result, _fingerprint = entry
            # Check TTL
            if time.time() - timestamp > self._ttl:
                del self._cache[key]
                self._misses += 1
                return (None, 0.0) if with_age else None
            # Check if a whole-cache write has happened since this was cached.
            # Narrow address-scoped invalidations physically remove only their
            # entries and do NOT bump the generation, so surviving entries stay
            # live across a small edit.
            if gen != self._write_generation:
                del self._cache[key]
                self._misses += 1
                return (None, 0.0) if with_age else None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            age = time.time() - timestamp
            return (result, age) if with_age else result

    def put(self, tool_name: str, kwargs: dict, result: Any) -> None:
        """Store a result in the cache."""
        key = self._make_key(tool_name, kwargs)
        fingerprint = extract_addresses(kwargs)
        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_entries:
                self._cache.popitem(last=False)
            self._cache[key] = (time.time(), self._write_generation, result, fingerprint)

    def invalidate_for_write(self, kwargs: dict) -> None:
        """Invalidate cache entries affected by one write operation.

        Narrow scope: a write that references an address (patch/rename/comment/
        set_type at an address) removes only entries whose key references the
        same address family (4 KiB page), plus whole-walk entries with no
        address at all (a rename changes ``list_functions`` output). Reads of
        unrelated pages survive, so a small edit does not flush every cached
        result in the database.

        A write with NO address (a whole-database write, or a name-keyed write)
        falls back to the full physical clear — the same conservative contract
        as ``invalidate_all()``. The explicit ``invalidate_all()`` method keeps
        its documented physical-clear behavior for callers that want it.
        """
        write_addrs = extract_addresses(kwargs)
        with self._lock:
            if not write_addrs:
                self._write_generation += 1
                self._cache.clear()
                return
            write_pages = {addr >> _ADDRESS_FAMILY_SHIFT for addr in write_addrs}
            to_remove = []
            for key, (_ts, _gen, _result, fingerprint) in self._cache.items():
                if not fingerprint:
                    # Whole-walk read (no address in the key): any write may
                    # change the database it walked, so it cannot be trusted.
                    to_remove.append(key)
                else:
                    read_pages = {addr >> _ADDRESS_FAMILY_SHIFT for addr in fingerprint}
                    if read_pages & write_pages:
                        to_remove.append(key)
            for key in to_remove:
                del self._cache[key]
            # Surviving entries keep their stored generation, which still
            # equals self._write_generation (unchanged): they stay valid.

    def invalidate_all(self) -> None:
        """Invalidate all cached entries (called on whole-database writes).

        Entries are physically dropped rather than merely generation-stamped:
        after a write the cache holds no live entries, ``stats()["entries"]``
        reports 0, and stale large results are released instead of lingering
        in the LRU until a ``get`` happens to observe the new generation.
        """
        with self._lock:
            self._write_generation += 1
            self._cache.clear()

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._cache),
                "max_entries": self._max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 3) if total > 0 else 0,
                "write_generation": self._write_generation,
            }

    def clear(self) -> None:
        """Clear all cached entries and reset stats."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0


# Global cache instance
TOOL_CACHE = ToolResultCache()
