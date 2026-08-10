"""Emulate a program with the IDA debugger (``ida_dbg``-backed).

Exposes a single MCP tool ``emulate`` with granular actions::

    info, backend, start, state, step, run_to, suspend, continue,
    stop, get_reg, set_reg, read_mem, set_mem

Backend selection
-----------------
The tool auto-selects a debugger backend by calling ``load_debugger`` for each
name in ``_BACKEND_CANDIDATES`` in order (``Emulator``, ``emulator``, ``linux``,
``bochs``, ``gdb``) and keeps the first that succeeds, caching the selection and
the reason in module globals for the rest of the session. ``emulate(action=
"backend", name=...)`` tries an explicit name first and falls back to the
candidate order. Backend identity (``backend``), the selection reason
(``backend_reason``), and the candidate list (``backend_candidates``) are
reported on every successful response so callers can reason about which engine
served them.

Why ``@idawrite`` and not ``@idaread``
--------------------------------------
The emulated process is inherently volatile — registers, memory, and the
run/suspend state change on every step. ``@idaread`` would cache results keyed
on the call arguments (a repeated ``get_reg(name="rax")`` or ``state()`` would
be served from the 300s tool-result cache and return stale values), which breaks
write-then-read roundtrips. ``@idawrite`` executes on the IDA main thread
(safe for ``ida_dbg`` calls) and invalidates the cache on every invocation, so
each state-reading action reflects the live debugger. This matches the
``modify.py`` tool pattern.

Governance
----------
Mutating actions (``start``/``step``/``run_to``/``suspend``/``continue``/
``stop``/``set_reg``/``set_mem``) run the governance engine first when
``governed`` is true (the default). Pass ``governed=False`` to skip the gate —
the live-integration suite does this to keep its assertions
backend-independent.
"""

import ctypes
import os
import time

try:
    from ._common import *  # noqa: F403
except ImportError:
    from _common import *  # noqa: F403  type: ignore[import-not-found]

try:
    from .governance_engine import evaluate_operation  # noqa: F401
except ImportError:
    from governance_engine import evaluate_operation  # noqa: F401  type: ignore[import-not-found]

try:
    import ida_dbg
except ImportError:
    ida_dbg = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Module-global backend cache (reset per test by the host-side unit suite).
# ---------------------------------------------------------------------------
_BACKEND = None
_BACKEND_REASON = ""
_PROCESS_STARTED = False

_BACKEND_CANDIDATES = ["Emulator", "emulator", "linux", "bochs", "gdb"]

_VALID_ACTIONS = (
    "info", "backend", "start", "state", "step", "run_to",
    "suspend", "continue", "stop", "get_reg", "set_reg", "read_mem", "set_mem",
)

_MUTATING_ACTIONS = frozenset(
    {"start", "step", "run_to", "suspend", "continue", "stop", "set_reg", "set_mem"}
)

_STEP_METHODS = {"into": "step_into", "over": "step_over", "ret": "step_until_ret"}

_TIMEOUT_MS_DEFAULT = 30000
_STEP_MULTI_COUNT_MAX = 10000
_MEM_READ_MAX = 4096
_STATE_POLL_INTERVAL = 0.02


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _inf_bitness_or_64() -> int:
    """Return the IDB application bitness, defaulting to 64 under tests.

    The isolated-repo test stub's ``_common`` does not define ``_inf_bitness``,
    so it must be looked up defensively via ``globals()``.
    """
    fn = globals().get("_inf_bitness")
    if callable(fn):
        try:
            return int(fn())
        except Exception:
            pass
    return 64


def _backend_str() -> str:
    return _BACKEND if _BACKEND else "none"


def _hex_reg(value) -> str:
    try:
        return hex(int(value))
    except (TypeError, ValueError):
        return str(value)


def _current_ip():
    """Hex string of the debugger IP, or None when unavailable."""
    fn = getattr(ida_dbg, "get_ip_val", None)
    if not callable(fn):
        return None
    try:
        v = fn()
    except Exception:
        return None
    if v is None:
        return None
    try:
        return hex(int(v))
    except (TypeError, ValueError):
        return str(v)


def _as_int_opt(value):
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _hex_to_bytes(data):
    """Parse a hex string (tolerant of spaces/commas/0x/underscores)."""
    clean = str(data).strip().replace(" ", "").replace(",", "").replace("_", "")
    if clean.lower().startswith("0x"):
        clean = clean[2:]
    if not clean or len(clean) % 2 != 0:
        return None
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return None


def _running_states():
    """Process states that mean 'currently executing' (read defensively)."""
    states = set()
    for attr in ("DSTATE_RUNNING", "DSTATE_RUN"):
        v = getattr(ida_dbg, attr, None)
        if isinstance(v, int):
            states.add(v)
    return states


def _active_states():
    """Process states that mean 'a debuggee is alive' (suspended or running)."""
    states = set()
    for attr in (
        "DSTATE_RUNNING", "DSTATE_RUN", "DSTATE_SUSP",
        "DSTATE_DEBUGGING", "DSTATE_QUITTING",
    ):
        v = getattr(ida_dbg, attr, None)
        if isinstance(v, int):
            states.add(v)
    return states


def _state_name() -> str:
    try:
        st = ida_dbg.get_process_state()
    except Exception:
        return "unknown"
    for attr, name in (
        ("DSTATE_SUSP", "suspended"),
        ("DSTATE_RUNNING", "running"),
        ("DSTATE_RUN", "running"),
        ("DSTATE_IDLE", "idle"),
        ("DSTATE_NOT_RUN", "not_run"),
        ("DSTATE_EXIT", "exited"),
    ):
        v = getattr(ida_dbg, attr, None)
        if isinstance(v, int) and v == st:
            return name
    return "unknown"


def _process_running() -> bool:
    try:
        st = ida_dbg.get_process_state()
    except Exception:
        return bool(_PROCESS_STARTED)
    return st in _active_states()


def _wait_not_running(deadline: float) -> bool:
    """Block until the debuggee leaves a running state or *deadline* passes."""
    running = _running_states()
    while time.time() < deadline:
        try:
            st = ida_dbg.get_process_state()
        except Exception:
            st = None
        if st is None or st not in running:
            return True
        time.sleep(_STATE_POLL_INTERVAL)
    return False


def _pump_suspended(timeout_ms: int) -> bool:
    """Drive the debugger event loop until the process suspends.

    ida_dbg's ``start_process``/``suspend_process``/``step_into``/``run_to``
    post asynchronous requests that are only completed when IDA's main thread
    processes debugger events. The MCP server never runs a GUI event loop, so
    on native backends those requests would otherwise sit unprocessed and the
    process would never actually suspend — leaving ``get_process_state`` in a
    running state and register/step/read_mem calls failing. ``wait_for_next_event``
    processes the pending event inline.

    Returns False only when a timeout code is observed (the suspension did not
    happen within *timeout_ms*); any other outcome (success event, error code,
    absent function/flag — i.e. a fake ``ida_dbg``) is treated as "the current
    state is authoritative" so host-side unit tests are unaffected.
    """
    wfn = getattr(ida_dbg, "wait_for_next_event", None)
    if not callable(wfn):
        return True
    flag = getattr(ida_dbg, "WFNE_SUSP", None)
    if not isinstance(flag, int):
        return True
    try:
        evt = wfn(flag, max(0, int(timeout_ms)))
    except Exception:
        return True
    # DEC_TIMEOUT == 0; negative codes are DEC_ERROR/DEC_NOTASK.
    return not (evt == 0 or evt is None)


def _ip_reg_name() -> str:
    try:
        arch = get_arch()
    except Exception:
        arch = None
    bits = _inf_bitness_or_64()
    try:
        if is_x86_family(arch):
            return "rip" if bits == 64 else "eip"
    except Exception:
        pass
    return "pc"


def _set_ip(ea) -> None:
    reg = _ip_reg_name()
    if not reg:
        return
    fn = getattr(ida_dbg, "set_reg_val", None)
    if not callable(fn):
        return
    try:
        fn(reg, int(ea))
    except Exception:
        pass


def _arch_name() -> str:
    try:
        return str(get_arch())
    except Exception:
        return "unknown"


def _common_register_names():
    """Curated register names for the individual-read fallback in ``info``."""
    try:
        arch = get_arch()
    except Exception:
        arch = None
    bits = _inf_bitness_or_64()
    try:
        if is_x86_family(arch):
            if bits == 64:
                return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "rflags"]
            return ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip", "eflags"]
    except Exception:
        pass
    try:
        if is_arm_family(arch):
            if bits == 64:
                return [f"x{i}" for i in range(31)] + ["sp", "pc"]
            return [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"]
    except Exception:
        pass
    try:
        if is_mips_family(arch):
            return ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "fp", "ra", "pc"]
    except Exception:
        pass
    return ["pc"]


def _read_all_registers():
    """Return ``(registers: dict[str,str], available: bool)``."""
    regs = {}
    fn = getattr(ida_dbg, "get_reg_vals", None)
    if callable(fn):
        try:
            vals = fn()
            if isinstance(vals, dict):
                for k, v in vals.items():
                    regs[str(k)] = _hex_reg(v)
                if regs:
                    return regs, True
        except Exception:
            pass
    got = 0
    gfn = getattr(ida_dbg, "get_reg_val", None)
    if callable(gfn):
        for name in _common_register_names():
            try:
                v = gfn(name)
            except Exception:
                continue
            if v is not None:
                regs[str(name)] = _hex_reg(v)
                got += 1
    return regs, got > 0


# ---------------------------------------------------------------------------
# Governance gate
# ---------------------------------------------------------------------------
def _governance_check(action: str, governed: bool, addr=None, value="") -> dict | None:
    """Return an error envelope when the governance engine blocks *action*."""
    if not governed or action not in _MUTATING_ACTIONS:
        return None
    try:
        result = evaluate_operation("execution", addr=addr, proposed_value=value)
    except Exception:
        return None
    if isinstance(result, dict) and not result.get("approved", True):
        return make_error(
            MCPError.GOVERNANCE_BLOCKED,
            f"emulate({action}) blocked by governance",
            hint="Pass governed=False to run the emulated action without the governance gate, "
            "or acknowledge the operation explicitly.",
        )
    return None


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
def _try_load(name: str) -> bool:
    fn = getattr(ida_dbg, "load_debugger", None)
    if not callable(fn):
        return False
    try:
        return bool(fn(name, False))
    except Exception:
        return False


def _select_backend(name=None, force=False):
    """Load a backend, caching the result. Returns the backend name or None."""
    global _BACKEND, _BACKEND_REASON
    if name:
        if _try_load(name):
            _BACKEND = name
            _BACKEND_REASON = f"load_debugger('{name}') succeeded"
            return name
        for cand in _BACKEND_CANDIDATES:
            if cand == name:
                continue
            if _try_load(cand):
                _BACKEND = cand
                _BACKEND_REASON = f"load_debugger('{cand}') succeeded"
                return cand
        return None
    if _BACKEND and not force:
        return _BACKEND
    for cand in _BACKEND_CANDIDATES:
        if _try_load(cand):
            _BACKEND = cand
            _BACKEND_REASON = f"load_debugger('{cand}') succeeded"
            return cand
    return None


def _no_backend_error():
    return make_error(
        MCPError.EMULATION_ERROR,
        "No emulation backend could be loaded",
        hint="None of the candidates (Emulator, emulator, linux, bochs, gdb) accepted "
        "load_debugger(). Install a debugger plugin or check the IDA debugger setup.",
    )


def _require_backend():
    if _BACKEND:
        return None
    if _select_backend() is not None:
        return None
    return _no_backend_error()


def _best_effort_stop() -> None:
    """Tear down a live debuggee without surfacing errors (restart semantics)."""
    global _PROCESS_STARTED
    for method in ("stop_process", "exit_process"):
        fn = getattr(ida_dbg, method, None)
        if not callable(fn):
            continue
        try:
            fn()
        except Exception:
            continue
    _PROCESS_STARTED = False


def _suspend_if_needed(timeout_sec: float = 10.0) -> bool:
    """Bring a running debuggee to a suspended state (best-effort).

    After ``start_process`` many backends (notably the native ``linux``
    debugger) leave the process *running*, which makes ``get_ip_val``,
    ``get_reg_val`` and stepping fail. Suspending first yields the
    deterministic "started and paused" state that emulation callers expect.
    Returns True when the process is not executing afterwards.
    """
    running = _running_states()
    try:
        st = ida_dbg.get_process_state()
    except Exception:
        st = None
    if st is not None and st not in running:
        return True  # already suspended (or exited/idle)
    fn = getattr(ida_dbg, "suspend_process", None)
    if not callable(fn):
        return False
    try:
        fn()
    except Exception:
        return False
    # The suspend request is processed by the debugger event loop; pump it so a
    # running native debuggee actually reaches a suspended state.
    _pump_suspended(int(timeout_sec * 1000))
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            st = ida_dbg.get_process_state()
        except Exception:
            st = None
        if st is None or st not in running:
            return True
        time.sleep(_STATE_POLL_INTERVAL)
    return False


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------
def _action_info():
    if not _BACKEND:
        _select_backend()
    regs, avail = _read_all_registers()
    return {
        "ok": True,
        "action": "info",
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
        "why_chosen": _BACKEND_REASON or "no backend loaded",
        "process_state": _state_name(),
        "process_running": _process_running(),
        "current_ip": _current_ip(),
        "registers": regs,
        "registers_available": avail,
        "arch": _arch_name(),
    }


def _action_backend(name=None, force=None):
    if name is None and _BACKEND and not force:
        return {
            "ok": True,
            "action": "backend",
            "backend": _backend_str(),
            "backend_reason": _BACKEND_REASON,
            "backend_candidates": list(_BACKEND_CANDIDATES),
        }
    sel = _select_backend(name=name, force=bool(force))
    if sel is None:
        return _no_backend_error()
    return {
        "ok": True,
        "action": "backend",
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_state():
    return {
        "ok": True,
        "action": "state",
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
        "process_state": _state_name(),
        "process_running": _process_running(),
        "current_ip": _current_ip(),
    }


def _action_start(governed, start_addr, input_file, args, dir_):
    global _PROCESS_STARTED
    g = _governance_check("start", governed, addr=_as_int_opt(start_addr), value=(input_file or args or ""))
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    # Restart semantics: if a debuggee from an earlier action is still alive,
    # tear it down first so `start` is idempotent for callers (agents, tests)
    # that share one IDA session.
    if _process_running() or _PROCESS_STARTED:
        _best_effort_stop()
    start_fn = getattr(ida_dbg, "start_process", None)
    if not callable(start_fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no start_process()",
            hint="The loaded backend does not implement process start.",
        )
    path = input_file or None
    argstr = args or None
    if dir_:
        try:
            os.chdir(dir_)
        except Exception as e:
            return handle_error(e, "emulate.start")
    try:
        if argstr:
            ret = start_fn(path, argstr)
        else:
            ret = start_fn(path)
    except Exception as e:
        return handle_error(e, "emulate.start")
    # start_process returns 1 on success, 0/-1 on failure. bool(-1) is True, so
    # compare against 1 to avoid treating a rejected start as a started process.
    _PROCESS_STARTED = (ret == 1)
    if not _PROCESS_STARTED:
        return make_error(
            MCPError.EMULATION_ERROR,
            "start_process() returned failure",
            hint="The backend refused to start the emulated process.",
        )
    if start_addr:
        ea, verr = validate_addr(start_addr)
        if verr:
            return verr
        _set_ip(ea)
    # Native backends leave the process running after start; pause it so the
    # debuggee is in a deterministic "started and suspended" state where
    # get_reg/step/read_mem/run_to are well-defined.
    _suspend_if_needed()
    return {
        "ok": True,
        "action": "start",
        "started": True,
        "start_addr": str(start_addr) if start_addr else None,
        "process_running": True,
        "process_state": _state_name(),
        "current_ip": _current_ip(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_step(governed, mode, count, timeout_ms):
    mode = mode or "into"
    if mode not in _STEP_METHODS:
        return make_error(
            MCPError.INVALID_ARGS,
            f"Invalid step mode: {mode!r}",
            hint="mode must be one of: into, over, ret",
        )
    g = _governance_check("step", governed)
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    try:
        count = int(count or 1)
    except (TypeError, ValueError):
        return make_error(MCPError.INVALID_ARGS, f"count must be an integer, got {count!r}")
    if count < 1:
        return make_error(MCPError.INVALID_ARGS, "count must be >= 1")
    count = min(count, _STEP_MULTI_COUNT_MAX)
    try:
        timeout_ms = int(timeout_ms or _TIMEOUT_MS_DEFAULT)
    except (TypeError, ValueError):
        timeout_ms = _TIMEOUT_MS_DEFAULT
    if timeout_ms < 0:
        timeout_ms = _TIMEOUT_MS_DEFAULT
    method = _STEP_METHODS[mode]
    fn = getattr(ida_dbg, method, None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            f"ida_dbg has no {method}()",
            hint=f"The loaded backend does not implement {mode} stepping.",
        )
    steps_done = 0
    for _ in range(count):
        try:
            accepted = bool(fn())
        except Exception as e:
            return handle_error(e, "emulate.step")
        if not accepted:
            # The backend rejected the step request (e.g. no thread context on
            # a native debugger that never registered threads). Honest count:
            # report how many steps actually ran, not how many were requested.
            continue
        steps_done += 1
        _pump_suspended(timeout_ms)
        deadline = time.time() + max(0.0, timeout_ms) / 1000.0
        if not _wait_not_running(deadline):
            return make_error(
                MCPError.EMULATION_TIMEOUT,
                "emulation step did not suspend within timeout",
                recoverable=True,
            )
    return {
        "ok": True,
        "action": "step",
        "mode": mode,
        "count": count,
        "steps_done": steps_done,
        "process_state": _state_name(),
        "process_running": _process_running(),
        "current_ip": _current_ip(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_run_to(governed, address, timeout_ms):
    if not address:
        return make_error(MCPError.INVALID_ARGS, "address is required for run_to")
    g = _governance_check("run_to", governed, addr=_as_int_opt(address))
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    ea, verr = validate_addr(address)
    if verr:
        return verr
    try:
        timeout_ms = int(timeout_ms or _TIMEOUT_MS_DEFAULT)
    except (TypeError, ValueError):
        timeout_ms = _TIMEOUT_MS_DEFAULT
    if timeout_ms < 0:
        timeout_ms = _TIMEOUT_MS_DEFAULT
    fn = getattr(ida_dbg, "run_to", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no run_to()",
            hint="The loaded backend does not implement run_to.",
        )
    try:
        accepted = bool(fn(ea))
    except Exception as e:
        return handle_error(e, "emulate.run_to")
    reached = False
    if accepted:
        _pump_suspended(timeout_ms)
        deadline = time.time() + max(0.0, timeout_ms) / 1000.0
        if not _wait_not_running(deadline):
            return make_error(
                MCPError.EMULATION_TIMEOUT,
                f"run_to did not reach {str(address)} within timeout",
                recoverable=True,
            )
        reached = True
    return {
        "ok": True,
        "action": "run_to",
        "target": str(address),
        "address": str(address),
        "reached": reached,
        "process_state": _state_name(),
        "process_running": _process_running(),
        "current_ip": _current_ip(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_get_reg(governed, name, names):
    if not name and not names:
        return make_error(MCPError.INVALID_ARGS, "name or names is required for get_reg")
    err = _require_backend()
    if err:
        return err
    fn = getattr(ida_dbg, "get_reg_val", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no get_reg_val()",
            hint="The loaded backend does not implement register reads.",
        )
    regs = {}
    unavailable = []
    for n in (names if names else [name]):
        try:
            v = fn(str(n))
        except Exception:
            # A backend without a register context cannot serve this register;
            # report it as unavailable rather than failing the whole read.
            unavailable.append(str(n))
            continue
        if v is not None:
            regs[str(n)] = _hex_reg(v)
        else:
            unavailable.append(str(n))
    return {
        "ok": True,
        "action": "get_reg",
        "regs": regs,
        "unavailable": unavailable,
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_set_reg(governed, name, value):
    if not name:
        return make_error(MCPError.INVALID_ARGS, "name is required for set_reg")
    if value is None:
        return make_error(MCPError.INVALID_ARGS, "value is required for set_reg")
    g = _governance_check("set_reg", governed, value=str(value))
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    try:
        num = int(str(value), 0)
    except (TypeError, ValueError):
        return make_error(
            MCPError.INVALID_ARGS,
            f"Invalid register value: {value!r}",
            hint="Pass an integer or a 0x-prefixed hex string.",
        )
    fn = getattr(ida_dbg, "set_reg_val", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no set_reg_val()",
            hint="The loaded backend does not implement register writes.",
        )
    try:
        fn(str(name), num)
    except Exception as e:
        return handle_error(e, "emulate.set_reg")
    return {
        "ok": True,
        "action": "set_reg",
        "name": str(name),
        "value": hex(num),
        "written": True,
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _read_dbg_memory(ea: int, size: int) -> bytes | None:
    """Read up to *size* bytes of debuggee memory, or None when unreadable.

    ``ida_dbg.read_dbg_memory`` binds ``void *`` in a way that rejects every
    buffer shape on some IDA builds (bulk reads then fail), so a per-byte
    ``get_dbg_byte`` fallback covers backends whose thread context is missing.
    Returns None only when neither path could produce any bytes.
    """
    fn = getattr(ida_dbg, "read_dbg_memory", None)
    if callable(fn):
        try:
            buf = ctypes.create_string_buffer(size)
            n = int(fn(ea, buf, size) or 0)
            if n > 0:
                return bytes(buf.raw[:n])
        except Exception:
            pass
    gb = getattr(ida_dbg, "get_dbg_byte", None)
    if callable(gb):
        out = bytearray()
        try:
            for i in range(size):
                v = gb(ea + i)
                if v is None or v < 0:
                    break
                out.append(v & 0xFF)
        except Exception:
            pass
        if out:
            return bytes(out)
    return None


def _action_read_mem(governed, address, size):
    if not address:
        return make_error(MCPError.INVALID_ARGS, "address is required for read_mem")
    err = _require_backend()
    if err:
        return err
    try:
        size = int(size or 16)
    except (TypeError, ValueError):
        return make_error(MCPError.INVALID_ARGS, f"size must be an integer, got {size!r}")
    size = max(1, min(size, _MEM_READ_MAX))
    ea, verr = validate_addr(address)
    if verr:
        return verr
    raw = _read_dbg_memory(ea, size)
    if raw is None:
        return make_error(
            MCPError.EMULATION_ERROR,
            "the loaded backend could not read debugger memory",
            hint="The debugger must be attached to a suspended process to read memory.",
        )
    n = len(raw)
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    return {
        "ok": True,
        "action": "read_mem",
        "address": str(address),
        "size": n,
        "data": raw.hex(),
        "ascii": ascii_repr,
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_set_mem(governed, address, data):
    if not address:
        return make_error(MCPError.INVALID_ARGS, "address is required for set_mem")
    if not data:
        return make_error(MCPError.INVALID_ARGS, "data is required for set_mem")
    raw = _hex_to_bytes(data)
    if raw is None:
        return make_error(
            MCPError.INVALID_ARGS,
            f"data must be valid hex, got {data!r}",
            hint="Pass a hex string such as '9090' or '90 90'.",
        )
    g = _governance_check("set_mem", governed, addr=_as_int_opt(address), value=str(data))
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    ea, verr = validate_addr(address)
    if verr:
        return verr
    fn = getattr(ida_dbg, "write_dbg_memory", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no write_dbg_memory()",
            hint="The loaded backend does not implement memory writes.",
        )
    try:
        buf = ctypes.create_string_buffer(raw, len(raw))
        n = fn(ea, buf, len(raw))
    except Exception as e:
        return handle_error(e, "emulate.set_mem")
    return {
        "ok": True,
        "action": "set_mem",
        "address": str(address),
        "written": True,
        "size": int(n or 0),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_stop(governed, unload):
    g = _governance_check("stop", governed)
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    stopped = False
    for method in ("stop_process", "exit_process"):
        fn = getattr(ida_dbg, method, None)
        if not callable(fn):
            continue
        try:
            fn()
            stopped = True
            break
        except Exception:
            continue
    if not stopped:
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has neither stop_process() nor exit_process()",
            hint="The loaded backend does not implement process teardown.",
        )
    global _PROCESS_STARTED
    _PROCESS_STARTED = False
    if unload:
        global _BACKEND, _BACKEND_REASON
        _BACKEND = None
        _BACKEND_REASON = ""
    return {
        "ok": True,
        "action": "stop",
        "stopped": True,
        "process_running": False,
        "process_state": _state_name(),
        "current_ip": _current_ip(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_suspend(governed):
    g = _governance_check("suspend", governed)
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    fn = getattr(ida_dbg, "suspend_process", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no suspend_process()",
            hint="The loaded backend does not implement suspend.",
        )
    try:
        fn()
    except Exception as e:
        return handle_error(e, "emulate.suspend")
    return {
        "ok": True,
        "action": "suspend",
        "suspended": True,
        "process_state": _state_name(),
        "process_running": _process_running(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


def _action_continue(governed):
    g = _governance_check("continue", governed)
    if g:
        return g
    err = _require_backend()
    if err:
        return err
    fn = getattr(ida_dbg, "continue_process", None)
    if not callable(fn):
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg has no continue_process()",
            hint="The loaded backend does not implement continue.",
        )
    try:
        fn()
    except Exception as e:
        return handle_error(e, "emulate.continue")
    return {
        "ok": True,
        "action": "continue",
        "continued": True,
        "process_state": _state_name(),
        "process_running": _process_running(),
        "backend": _backend_str(),
        "backend_reason": _BACKEND_REASON,
        "backend_candidates": list(_BACKEND_CANDIDATES),
    }


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------
@tool
@idawrite
def emulate(
    action: Annotated[Literal[
        "info", "backend", "start", "state", "step", "run_to",
        "suspend", "continue", "stop", "get_reg", "set_reg", "read_mem", "set_mem",
    ], "Emulation action"],
    name: Annotated[Optional[str], "Backend name (backend) or register name (get_reg/set_reg)"] = None,
    names: Annotated[Optional[list], "Registers to read in one get_reg call"] = None,
    value: Annotated[Optional[Any], "Register value for set_reg (hex string like '0x10' or integer)"] = None,
    address: Annotated[Optional[str], "Target address for run_to/read_mem/set_mem"] = None,
    size: Annotated[Optional[int], "Byte count for read_mem (default 16, max 4096)"] = None,
    data: Annotated[Optional[str], "Hex bytes to write for set_mem (e.g. '9090')"] = None,
    start_addr: Annotated[Optional[str], "Optional start address for start"] = None,
    args: Annotated[Optional[str], "Process argv string for start"] = None,
    input_file: Annotated[Optional[str], "Input file path for start"] = None,
    dir: Annotated[Optional[str], "Working directory for start"] = None,
    count: Annotated[Optional[int], "Step count for step (default 1)"] = None,
    mode: Annotated[Optional[str], "Step mode (into|over|ret, default 'into')"] = None,
    force: Annotated[Optional[bool], "Reload the backend even if one is loaded (backend action)"] = None,
    unload: Annotated[Optional[bool], "Unload the backend after stop"] = None,
    governed: Annotated[Optional[bool], "Run the governance pre-check on mutating actions (default true)"] = None,
    timeout_ms: Annotated[Optional[int], "Per-action timeout in milliseconds (default 30000)"] = None,
    **kwargs,
) -> dict:
    """Emulate a program with the IDA debugger (ida_dbg-backed).

    ``emulate`` drives the IDA debugger/emulator module to run a process and
    inspect or mutate its registers and memory without touching the IDB. The
    tool auto-selects a backend (Emulator -> linux -> bochs -> gdb); every
    response carries ``backend``/``backend_reason``/``backend_candidates`` so
    callers can tell which engine served them.
    """
    if ida_dbg is None:
        return make_error(
            MCPError.EMULATION_ERROR,
            "ida_dbg is not available in this build",
            hint="The IDA debugger module (ida_dbg) is required for emulation.",
        )
    try:
        action = str(action or "").strip()
    except Exception:
        action = ""
    if action not in _VALID_ACTIONS:
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unknown emulate action: {action!r}",
            hint=f"Valid actions: {', '.join(_VALID_ACTIONS)}",
        )
    governed = True if governed is None else bool(governed)
    try:
        if action == "info":
            return _action_info()
        if action == "backend":
            return _action_backend(name=name, force=force)
        if action == "start":
            return _action_start(
                governed=governed,
                start_addr=start_addr,
                input_file=input_file,
                args=args,
                dir_=dir,
            )
        if action == "state":
            return _action_state()
        if action == "step":
            return _action_step(governed=governed, mode=mode, count=count, timeout_ms=timeout_ms)
        if action == "run_to":
            return _action_run_to(governed=governed, address=address, timeout_ms=timeout_ms)
        if action == "suspend":
            return _action_suspend(governed=governed)
        if action == "continue":
            return _action_continue(governed=governed)
        if action == "stop":
            return _action_stop(governed=governed, unload=unload)
        if action == "get_reg":
            return _action_get_reg(governed=governed, name=name, names=names)
        if action == "set_reg":
            return _action_set_reg(governed=governed, name=name, value=value)
        if action == "read_mem":
            return _action_read_mem(governed=governed, address=address, size=size)
        if action == "set_mem":
            return _action_set_mem(governed=governed, address=address, data=data)
        return make_error(MCPError.ACTION_NOT_FOUND, f"Unknown emulate action: {action!r}")
    except Exception as e:
        return handle_error(e, "emulate")
