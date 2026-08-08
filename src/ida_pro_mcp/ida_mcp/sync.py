import copy
import functools
import logging
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
        return max(1.0, float(os.environ.get(_SYNC_TIMEOUT_ENV, "30")))
    except ValueError:
        return 30.0


# Bypass-synchronization knob. Originally a module-level constant, but a
# constant is load-order-sensitive and defeats the @idaread/@idawrite safety
# net for every tool call. We now check the env var at call time and expose
# ``bypass_sync()`` so callers can scope the bypass to a specific block.
BYPASS_SYNC_ENV = "IDA_MCP_BYPASS_SYNC"


def is_bypass_sync() -> bool:
    return os.environ.get(BYPASS_SYNC_ENV) == "1"


# Backwards-compat alias. Existing code that does ``from sync import
# BYPASS_SYNC`` still gets a truthy value at import time, matching the old
# behavior. The runtime check is what matters for the safety wrapper.
BYPASS_SYNC = is_bypass_sync()


@contextmanager
def bypass_sync(reason: str = ""):
    """Temporarily set IDA_MCP_BYPASS_SYNC=1 for the duration of the block.

    Use this only for code paths that must call into the IDA SDK from a
    non-main thread (e.g. a background crawler) and therefore cannot use
    the @idaread/@idawrite safety wrapper.
    """
    prev = os.environ.get(BYPASS_SYNC_ENV)
    os.environ[BYPASS_SYNC_ENV] = "1"
    try:
        if reason:
            logger.debug("bypass_sync entered: %s", reason)
        yield
    finally:
        if prev is None:
            os.environ.pop(BYPASS_SYNC_ENV, None)
        else:
            os.environ[BYPASS_SYNC_ENV] = prev


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
    if idaapi.is_batch():
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


def idawrite(f):
    """Decorator for marking a function as modifying the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Invalidate read cache on any write operation
        cache = _tool_cache()
        if cache is not None:
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
    - The TTL is governed by ``ToolResultCache(ttl_seconds=...)`` and
      the cache is invalidated wholesale by ``@idawrite`` ops.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Check cache first (same singleton @idawrite invalidates)
        cache = _tool_cache()

        if cache is not None:
            cached, age = cache.get(f.__name__, kwargs, with_age=True)
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
            cache.put(f.__name__, kwargs, copy.deepcopy(result))

        return result

    return wrapper
