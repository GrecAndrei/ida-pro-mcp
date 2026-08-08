"""
LRU cache for read-only tool results.

Caches results from @idaread-decorated tools to avoid redundant
IDA API calls when the same query is repeated (common with LLMs).
The cache is automatically invalidated when any @idawrite operation
is performed, since writes may change the database state.
"""

import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Any, Dict


class ToolResultCache:
    """Thread-safe LRU cache for IDA MCP tool results."""

    def __init__(self, max_entries: int = 256, ttl_seconds: float = 300.0):
        """
        Args:
            max_entries: Maximum number of cached results.
            ttl_seconds: Time-to-live for each cache entry in seconds.
        """
        self._cache: OrderedDict[str, tuple[float, int, Any]] = OrderedDict()
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._write_generation = 0  # Bumped on every write operation
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _make_key(tool_name: str, kwargs: dict) -> str:
        """Create a stable cache key from tool name and arguments."""
        # Sort keys for deterministic hashing
        canonical = json.dumps({"tool": tool_name, "args": kwargs}, sort_keys=True, default=str)
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

            timestamp, gen, result = entry
            # Check TTL
            if time.time() - timestamp > self._ttl:
                del self._cache[key]
                self._misses += 1
                return (None, 0.0) if with_age else None
            # Check if a write has happened since this was cached
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
        with self._lock:
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_entries:
                self._cache.popitem(last=False)
            self._cache[key] = (time.time(), self._write_generation, result)

    def invalidate_all(self) -> None:
        """Invalidate all cached entries (called on write operations).

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
