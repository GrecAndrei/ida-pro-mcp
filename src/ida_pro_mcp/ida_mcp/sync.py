import copy
import functools
import inspect
import logging
import math
import os
import queue
import threading
from contextlib import contextmanager
from enum import IntEnum

import ida_kernwin
import idaapi

try:
    from ida_pro_mcp.ida_mcp.rpc import McpToolError
except ImportError:
    try:
        from rpc import McpToolError
    except ImportError:
        from .rpc import McpToolError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

def _parse_kernel_version():
    parts = idaapi.get_kernel_version().split(".")
    nums = []
    for p in parts[:2]:
        digits = "".join(c for c in p if c.isdigit())
        nums.append(int(digits) if digits else 0)
    while len(nums) < 2:
        nums.append(0)
    return nums[0], nums[1]

ida_major, ida_minor = _parse_kernel_version()


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


logger = logging.getLogger(__name__)


class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


# Track in-flight execute_sync callbacks. A set (rather than a LIFO queue) is
# used deliberately: the re-entrancy guard below must NOT pop the outer
# callback's marker before raising, or the outer ``finally`` would block on an
# empty queue and hang IDA's main thread.
_in_flight: "set[str]" = set()

# Timeout for execute_sync results. Configurable via env so long read
# operations (full disassembly of a huge function, deep callgraph) can be
# tuned without editing code.
_SYNC_TIMEOUT_ENV = "IDA_MCP_SYNC_TIMEOUT"


def _sync_timeout() -> float:
    try:
        timeout = float(os.environ.get(_SYNC_TIMEOUT_ENV, "30"))
    except (TypeError, ValueError):
        return 30.0
    return max(1.0, timeout) if math.isfinite(timeout) else 30.0


# Bypass-synchronization knob. Originally a module-level constant, but a
# constant is load-order-sensitive and defeats the @idaread/@idawrite safety
# net for every tool call. We now check the bypass state at call time and
# expose ``bypass_sync()`` so callers can scope the bypass to a specific block.
BYPASS_SYNC_ENV = "IDA_MCP_BYPASS_SYNC"

# Thread-local bypass flag. ``bypass_sync()`` must NOT use os.environ: the
# background crawler (blackboard.py) holds its ``with bypass_sync(...)`` open
# for its entire loop, so a process-global flag would make every unrelated
# tool call on an HTTP handler thread in that window drop the execute_sync
# safety wrapper too, running IDA APIs unsynchronized from a non-main thread.
_bypass_local = threading.local()


def is_bypass_sync() -> bool:
    return (
        os.environ.get(BYPASS_SYNC_ENV) == "1"
        or bool(getattr(_bypass_local, "active", False))
    )


# Backwards-compat alias. Existing code that does ``from sync import
# BYPASS_SYNC`` still gets a truthy value at import time, matching the old
# behavior. The runtime check is what matters for the safety wrapper.
BYPASS_SYNC = is_bypass_sync()


@contextmanager
def bypass_sync(reason: str = ""):
    """Temporarily bypass the @idaread/@idawrite safety wrapper for the
    CURRENT THREAD only.

    Use this only for code paths that must call into the IDA SDK from a
    non-main thread (e.g. a background crawler) and therefore cannot use
    the @idaread/@idawrite safety wrapper. The bypass is scoped to the
    calling thread: other threads (e.g. HTTP handler threads serving
    unrelated tool calls) still go through execute_sync serialization.
    """
    prev = getattr(_bypass_local, "active", False)
    _bypass_local.active = True
    try:
        if reason:
            logger.debug("bypass_sync entered: %s", reason)
        yield
    finally:
        _bypass_local.active = prev


def _is_batch() -> bool:
    """Return True when IDA runs in batch/headless mode, across IDA versions.

    ``idaapi.is_batch()`` was removed in IDA 9.x; the canonical read there is
    ``ida_kernwin.cvar.batch`` (as used by the official SDK example
    ``decompile_entry_points.py``).  Older 7.x builds still expose
    ``idaapi.is_batch()``.  Fall back conservatively to False — treating an
    unknown state as interactive is safe (we may take the slower sync path).
    """
    fn = getattr(idaapi, "is_batch", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("idaapi.is_batch() failed (%s); falling back", exc)
    batch = getattr(ida_kernwin, "cvar", None)
    if batch is not None:
        try:
            return bool(getattr(batch, "batch", False))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ida_kernwin.cvar.batch read failed (%s)", exc)
    return False


def _sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    # DEADLOCK PROTECTION: Nuclear Option
    # If the server script says we are in the main thread, WE ARE.
    if is_bypass_sync():
        logger.info(f"Bypassing sync for {ff.__name__}")
        return ff()

    # DEADLOCK PROTECTION 1: Main thread check
    if threading.current_thread() is threading.main_thread():
        return ff()

    # DEADLOCK PROTECTION 2: Batch mode usually implies main thread execution.
    if _is_batch():
        return ff()

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = f"Invalid safety mode {safety_mode} over function {ff.__name__}"
        logger.error(error_str)
        raise IDASyncError(error_str)

    # NOTE: This is not actually a queue, there is one item in it at most
    res_container = queue.Queue()

    def runned():
        if _in_flight:
            caller = next(iter(_in_flight))
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {caller}"
            raise IDASyncError(error_str)

        _in_flight.add(ff.__name__)
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            # discard() never blocks, so a nested-call guard failure above
            # cannot strand the outer callback waiting on an empty queue.
            _in_flight.discard(ff.__name__)

    ida_kernwin.execute_sync(runned, safety_mode)

    # TIMEOUT PROTECTION: Don't wait forever for the result.
    # The queued callback still runs later on the main thread; its result is
    # simply dropped, so the timeout reports a failure but never aborts work.
    timeout = _sync_timeout()
    try:
        res = res_container.get(timeout=timeout)
    except queue.Empty:
        logger.error(f"IDA execute_sync timed out for {ff.__name__} after {timeout}s")
        raise IDASyncError(f"IDA execute_sync timed out for {ff.__name__} after {timeout}s") from None

    if isinstance(res, Exception):
        raise res
    return res

def sync_wrapper(ff, safety_mode: IDASafety):
    """Run a synchronized IDA callback without forcing global batch mode.

    For MCP use we want IDA to stay responsive while background auto-analysis
    continues, which matches normal interactive IDA behavior better than
    toggling ``idc.batch(1)`` around every tool call.
    """
    return _sync_wrapper(ff, safety_mode)


def _tool_cache():
    """Resolve the shared :class:`~ida_pro_mcp.ida_mcp.cache.ToolResultCache`
    singleton.

    Both @idaread and @idawrite MUST resolve the same module instance, or a
    write-invalidation silently no-ops against the cache reads use, yielding
    stale reads after writes. The canonical resolution order mirrors
    ``tools/intelligence.py``: ``ida_mcp.ida_mcp.cache`` first (flat-plugin
    layout), then the flat ``cache`` fallback, then the editable-install
    ``ida_pro_mcp.ida_mcp.cache`` path. Importing via a different path (e.g.
    ``ida_pro_mcp.ida_mcp.cache`` alone) yields a second module instance with
    its own TOOL_CACHE.
    """
    for import_path in (
        "ida_mcp.ida_mcp.cache",
        "cache",
        "ida_pro_mcp.ida_mcp.cache",
    ):
        try:
            module = __import__(import_path, fromlist=["TOOL_CACHE"])
            return module.TOOL_CACHE
        except (ImportError, AttributeError):
            continue
    return None


def _signature_defaults(f) -> dict:
    """Best-effort map of a tool function's parameter defaults.

    Returns {} when the signature is unavailable (C functions, wrapped
    callables without __wrapped__). Defaults are used to drop kwargs equal to
    the schema default from the cache key, so ``count=100`` on a ``count=100``
    default matches a call that omits it.
    """
    try:
        sig = inspect.signature(f)
    except (TypeError, ValueError):
        return {}
    defaults = {}
    for name, param in sig.parameters.items():
        if param.default is not inspect.Parameter.empty:
            defaults[name] = param.default
    return defaults


def _cache_key_kwargs(f, kwargs: dict) -> dict:
    """Canonicalize *kwargs* for cache-key purposes (not the real call).

    Numeric strings become ints and args equal to the tool's default are
    dropped, so an LLM rephrasing an address as "0x401000" / 4198400 or an
    explicit default hits the same LRU entry. The function is still called
    with the caller's original kwargs.
    """
    try:
        from ida_mcp.ida_mcp.cache import canonicalize_kwargs
    except ImportError:
        try:
            from cache import canonicalize_kwargs
        except ImportError:
            from ida_pro_mcp.ida_mcp.cache import canonicalize_kwargs
    return canonicalize_kwargs(kwargs, defaults=_signature_defaults(f))


def idawrite(f):
    """Decorator for marking a function as modifying the IDB.

    Invalidation is narrowed to entries whose key references the written
    address family (see ``ToolResultCache.invalidate_for_write``) instead of
    clearing all 256 entries on every write; a write with no address falls
    back to the full physical clear.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Invalidate read cache on any write operation
        cache = _tool_cache()
        if cache is not None:
            invalidate = getattr(cache, "invalidate_for_write", None)
            if callable(invalidate):
                invalidate(kwargs)
            else:
                # Older cache instances without the narrow path.
                cache.invalidate_all()
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper


def idaread(f):
    """Decorator for marking a function as reading from the IDB.

    Cache contract:
    - On a cache hit the returned dict is annotated with
      ``{"_cache_hit": True, "_cache_age_seconds": <float>}`` so the
      caller (and agent) can verify whether IDA was hit or the result
      was served from the LRU cache.
    - On a cache miss the dict is stored unchanged; consumers that need
      a stable shape across hits/misses should ignore the ``_cache_*``
      fields.
    - The TTL is governed by ``ToolResultCache(ttl_seconds=...)``.
    - Cache keys are canonicalized (numeric strings -> int, args equal to a
      signature default dropped) so LLM rephrasing hits the LRU.
    - ``@idawrite`` invalidates narrowly by address family instead of
      clearing the whole cache.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Check cache first (same singleton @idawrite invalidates)
        cache = _tool_cache()

        if cache is not None:
            cache_kwargs = _cache_key_kwargs(f, kwargs)
            cached, age = cache.get(f.__name__, cache_kwargs, with_age=True)
            if cached is not None:
                if isinstance(cached, dict):
                    # Copy before annotating: the stored object must never
                    # receive the _cache_* markers, or later hits would see
                    # a stale age and a first-caller's mutation.
                    cached = dict(cached)
                    cached.setdefault("_cache_hit", True)
                    cached["_cache_age_seconds"] = round(age, 3)
                return cached

        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        result = sync_wrapper(ff, idaapi.MFF_READ)

        # Store in cache (only dict results that aren't errors). Store a copy
        # so the caller's object and the cached object never alias: mutation
        # of the returned dict downstream must not poison later cache hits.
        if cache is not None and isinstance(result, dict) and not result.get("error"):
            cache.put(f.__name__, _cache_key_kwargs(f, kwargs), copy.deepcopy(result))

        return result

    return wrapper
