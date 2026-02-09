import logging
import queue
import functools
import threading
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

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


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


import os

# Global flag to force-bypass synchronization (set via env var)
# This handles the "split brain" module import issue where ida_mcp.sync != sync
BYPASS_SYNC = os.environ.get("IDA_MCP_BYPASS_SYNC") == "1"

def _sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    # DEADLOCK PROTECTION: Nuclear Option
    # If the server script says we are in the main thread, WE ARE.
    if BYPASS_SYNC:
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

    def run_sync():
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

    ida_kernwin.execute_sync(run_sync, safety_mode)

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
    """Wrapper to enable batch mode during IDA synchronization."""
    old_batch = idc.batch(1)
    try:
        return _sync_wrapper(ff, safety_mode)
    finally:
        idc.batch(old_batch)


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
