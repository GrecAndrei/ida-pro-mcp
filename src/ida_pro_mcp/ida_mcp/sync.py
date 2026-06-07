import logging
import os
import queue
import functools
import threading
from contextlib import contextmanager
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
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


call_stack = queue.LifoQueue()


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
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"   
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()

    ida_kernwin.execute_sync(runned, safety_mode)

    # TIMEOUT PROTECTION: Don't wait forever for the result
    try:
        res = res_container.get(timeout=30)
    except queue.Empty:
        logger.error(f"IDA execute_sync timed out for {ff.__name__}")
        raise IDASyncError(f"IDA execute_sync timed out for {ff.__name__}")

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


def idawrite(f):
    """Decorator for marking a function as modifying the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Invalidate read cache on any write operation
        try:
            from ida_pro_mcp.ida_mcp.cache import TOOL_CACHE
            TOOL_CACHE.invalidate_all()
        except ImportError:
            try:
                from cache import TOOL_CACHE
                TOOL_CACHE.invalidate_all()
            except ImportError:
                pass
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper


def idaread(f):
    """Decorator for marking a function as reading from the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        # Check cache first
        cache = None
        try:
            from ida_pro_mcp.ida_mcp.cache import TOOL_CACHE
            cache = TOOL_CACHE
        except ImportError:
            try:
                from cache import TOOL_CACHE
                cache = TOOL_CACHE
            except ImportError:
                pass

        if cache is not None:
            cached = cache.get(f.__name__, kwargs)
            if cached is not None:
                return cached

        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        result = sync_wrapper(ff, idaapi.MFF_READ)

        # Store in cache (only dict results that aren't errors)
        if cache is not None and isinstance(result, dict) and not result.get("error"):
            cache.put(f.__name__, kwargs, result)

        return result

    return wrapper


def is_window_active():
    """Returns whether IDA is currently active"""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    try:
        if using_pyside6:
            import PySide6.QtWidgets as QApplication
        else:
            import PyQt5.QtWidgets as QApplication

        app = QApplication.instance()
        if app is None:
            return False

        for widget in app.topLevelWidgets():
            if widget.isActiveWindow():
                return True
    except Exception:
        # Headless mode or other error (this is not a critical feature)
        pass
    return False
