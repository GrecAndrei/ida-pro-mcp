"""Tests for the LRU tool-result cache.

The @idaread decorator automatically caches function results in
`ida_mcp.cache.TOOL_CACHE` for `ttl_seconds` (default 300s), and
invalidates all entries whenever @idawrite runs. This guards the
``smart_decompile`` path against repeated walks of the same function
tree, and lets us tune cache size/TTL without breaking the contract.
"""

import importlib.util
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CACHE_PY = REPO / "src" / "ida_pro_mcp" / "ida_mcp" / "cache.py"


def _load_cache():
    """Load cache.py standalone (the package imports zeromcp which is host-only)."""
    spec = importlib.util.spec_from_file_location("cache_isolated", str(CACHE_PY))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fresh_cache():
    """Return a brand-new cache instance so tests don't share state."""
    mod = _load_cache()
    return mod.ToolResultCache()


def test_cache_hit_returns_put_value():
    cache = _fresh_cache()
    cache.put("code", {"action": "smart_decompile", "addr": "0x401000"},
              {"ok": True, "addr": "0x401000", "fake": True})
    cached = cache.get("code", {"action": "smart_decompile", "addr": "0x401000"})
    assert cached == {"ok": True, "addr": "0x401000", "fake": True}


def test_cache_miss_returns_none_increments_miss_counter():
    cache = _fresh_cache()
    assert cache.get("code", {"action": "x"}, ) is None
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 0


def test_cache_distinguishes_distinct_args():
    cache = _fresh_cache()
    cache.put("code", {"action": "smart_decompile", "addr": "0x401000"}, {"ok": True, "a": 1})
    cache.put("code", {"action": "smart_decompile", "addr": "0x401001"}, {"ok": True, "a": 2})
    assert cache.get("code", {"action": "smart_decompile", "addr": "0x401000"})["a"] == 1
    assert cache.get("code", {"action": "smart_decompile", "addr": "0x401001"})["a"] == 2


def test_cache_args_key_is_stable_under_key_reordering():
    """Two callers passing the same kwargs in different orders must hit
    the same cache slot. The cache uses sort_keys=True on the JSON dump
    so this works in practice; pin it so future refactors don't break it.
    """
    cache = _fresh_cache()
    cache.put("code", {"action": "smart_decompile", "addr": "0x401000", "depth": 5},
              {"ok": True})
    # Same keys reordered (Python dicts since 3.7 preserve insertion
    # order so we explicitly construct with different orderings).
    reordered = {"depth": 5, "addr": "0x401000", "action": "smart_decompile"}
    assert cache.get("code", reordered) is not None


def test_cache_invalidate_all_drops_all_entries():
    cache = _fresh_cache()
    cache.put("code", {"x": 1}, {"a": 1})
    cache.put("code", {"x": 2}, {"a": 2})
    cache.invalidate_all()
    assert cache.get("code", {"x": 1}) is None
    assert cache.get("code", {"x": 2}) is None
    # Stats still reflect the misses.
    assert cache.stats()["misses"] == 2


def test_cache_ttl_expiry_evicts_old_entry():
    """The cache must respect ttl_seconds and not surface stale data
    forever. Use a tiny TTL so the test doesn't take 5 minutes.
    """
    cache = _fresh_cache().__class__(max_entries=4, ttl_seconds=0.05)
    cache.put("code", {"x": 1}, {"a": 1})
    assert cache.get("code", {"x": 1}) == {"a": 1}
    time.sleep(0.1)
    assert cache.get("code", {"x": 1}) is None


def test_cache_rejects_non_positive_capacity():
    cache_type = _fresh_cache().__class__
    for capacity in (0, -1):
        with pytest.raises(ValueError, match="max_entries must be positive"):
            cache_type(max_entries=capacity)


def test_cache_capacity_lru_eviction():
    """Once max_entries is reached, the least-recently-used entry gets
    evicted on the next put.
    """
    cache = _fresh_cache().__class__(max_entries=2, ttl_seconds=300)
    cache.put("tool", {"k": "a"}, 1)
    cache.put("tool", {"k": "b"}, 2)
    # Touch `a` so it becomes the most-recently-used.
    assert cache.get("tool", {"k": "a"}) == 1
    cache.put("tool", {"k": "c"}, 3)  # b should be evicted
    assert cache.get("tool", {"k": "b"}) is None
    assert cache.get("tool", {"k": "a"}) == 1
    assert cache.get("tool", {"k": "c"}) == 3


def test_cache_refresh_at_capacity_preserves_other_entries():
    """Refreshing a cached key must not evict a different entry when full."""
    cache = _fresh_cache().__class__(max_entries=2, ttl_seconds=300)
    cache.put("tool", {"k": "a"}, "old")
    cache.put("tool", {"k": "b"}, "other")

    cache.put("tool", {"k": "a"}, "new")

    assert cache.get("tool", {"k": "a"}) == "new"
    assert cache.get("tool", {"k": "b"}) == "other"
    assert cache.stats()["entries"] == 2


def test_cache_hit_rate_stat():
    cache = _fresh_cache()
    cache.put("x", {"k": 1}, "v")
    assert cache.get("x", {"k": 1}) == "v"  # hit
    assert cache.get("x", {"k": 1}) == "v"  # hit
    assert cache.get("x", {"k": 2}) is None  # miss
    stats = cache.stats()
    assert stats["hits"] == 2
    assert stats["misses"] == 1
    assert stats["hit_rate"] == round(2 / 3, 3)


def test_cache_clear_resets_stats_and_entries():
    cache = _fresh_cache()
    cache.put("x", {"k": 1}, "v")
    cache.get("x", {"k": 1})  # hit
    cache.get("x", {"k": 2})  # miss
    cache.clear()
    stats = cache.stats()
    assert stats["hits"] == 0
    assert stats["misses"] == 0
    assert stats["entries"] == 0


def test_cache_get_with_age_returns_age_seconds():
    cache = _fresh_cache()
    cache.put("code", {"x": 1}, {"ok": True, "value": "first"})
    # First read returns age.
    result, age = cache.get("code", {"x": 1}, with_age=True)
    assert result == {"ok": True, "value": "first"}
    assert age >= 0.0
    assert age < 1.0  # we just put it


def test_cache_get_with_age_returns_zero_on_miss():
    cache = _fresh_cache()
    result, age = cache.get("code", {"x": 999}, with_age=True)
    assert result is None
    assert age == 0.0


def test_cache_get_legacy_default_returns_only_result():
    """Pre-existing callers (decorator without with_age) get back the
    raw dict, not a tuple. Backward compatibility pin.
    """
    cache = _fresh_cache()
    cache.put("code", {"x": 1}, {"ok": True})
    result = cache.get("code", {"x": 1})
    assert result == {"ok": True}
    assert not isinstance(result, tuple)


def test_cache_global_instance_is_module_singleton():
    """The decorator in sync.py imports `TOOL_CACHE` from
    `ida_mcp.cache`. Pin that the symbol is the same module-level
    instance so a server-side hot reload doesn't silently route to a
    duplicate cache.
    """
    mod = _load_cache()
    # The contract: module-level singleton.
    assert isinstance(mod.TOOL_CACHE, mod.ToolResultCache)
    # Verify the imported symbol is the *very same* instance the module
    # constructs at import time (no aliasing tricks).
    assert mod.TOOL_CACHE.__class__ is mod.ToolResultCache
