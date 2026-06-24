#!/usr/bin/env python3
"""Runtime/session orchestration helpers for IDAMCPServer."""

from __future__ import annotations

import glob
import json
import os
import re
import shlex
import shutil
import signal
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..config import (
    _bounded_int,
    _normalize_session_id,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error
from .server_runtime_leases import ServerRuntimeLeasesMixin

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Processors that imply a raw-binary/firmware load (no native container format).
# Mirrored in _build_ida_command (-Tbin) and the post-load fix_segments step.
FIRMWARE_RAW_PROCS = (
    "arm", "mips", "mipsl", "mipsb", "ppc", "ppcl", "tricore",
    "rx", "v850", "rl78", "stm8",
)

# IDA loader names that produce correctly-typed segments natively; for these the
# post-load segment repair must NOT run (it would force data segments to
# SEG_CODE+EXEC and, for 64-bit PEs, downgrade .text to 32-bit -> MERR_ONLY64).
NATIVE_LOADERS = (
    "pe", "pe64", "elf", "elf64", "macho", "macho64",
    "coff", "ar", "omf", "dos", "dos/exe",
)


def _is_raw_bin_load(opts: dict) -> bool:
    """True when IDA loads the binary as a raw blob (-Tbin), so segments need
    post-load repair. For native PE/ELF/Mach-O, IDA's loader already sets the
    correct class/type/perm/bitness and repair is destructive."""
    proc = str(opts.get("processor") or "").lower()
    loader = str(opts.get("loader") or "").lower()
    if loader in NATIVE_LOADERS:
        return False
    if loader == "bin":
        return True
    # No explicit loader: raw-bin only for firmware archs. metapc with no
    # loader is left to IDA auto-detection (PE/ELF native, or raw x86 blob).
    return proc in FIRMWARE_RAW_PROCS


def _resolve_max_rpc_bytes() -> int:
    try:
        cap = int(os.environ.get("IDA_MCP_MAX_RPC_BYTES", str(64 * 1024 * 1024)))
    except (TypeError, ValueError):
        cap = 64 * 1024 * 1024
    return max(4096, min(cap, 256 * 1024 * 1024))


MAX_RPC_REQUEST_SIZE = _resolve_max_rpc_bytes()


def _popen_new_session_kwargs() -> dict:
    """Return the kwargs that put a Popen child in its own process group.

    Without this, os.killpg() on POSIX will signal the MCP server's own
    group (taking out the parent) and taskkill /T on Windows will walk
    siblings instead of just the IDA tree.
    """
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _kill_process_tree(proc: subprocess.Popen, grace_seconds: float = 2.0) -> None:
    """Kill a subprocess and all of its descendants.

    On Windows, ``Popen.terminate()``/``Popen.kill()`` only signals the direct
    child.  IDA's ``idat.exe`` is a tiny launcher that spawns ``ida.exe`` as a
    separate process, so killing the launcher leaves the real IDA process
    orphaned, holding the unpacked .id0/.id1 files open.  We use ``taskkill
    /T /F`` to walk the process tree.

    On POSIX, ``os.killpg`` against a process started in a new process group
    will signal the whole tree.
    """
    if proc.poll() is not None:
        return
    pid = proc.pid
    if pid is None:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(pid)],
                capture_output=True,
                timeout=grace_seconds + 3,
            )
        except Exception:
            pass
        try:
            proc.wait(timeout=grace_seconds)
        except Exception:
            pass
        return
    # POSIX: child must be in its own process group (set via
    # _popen_new_session_kwargs in the matching Popen call). If the group
    # is gone (ProcessLookupError) the child already exited; do not try
    # to kill the parent's group.
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        log_rpc(f"Process group already gone for pid {pid}; nothing to kill")
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        log_rpc(f"Process group vanished after getpgid for pid {pid}")
        return
    except Exception as exc:
        log_rpc(f"killpg(SIGTERM) failed for pid {pid}: {exc}")
    try:
        proc.wait(timeout=grace_seconds)
        return
    except Exception:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        log_rpc(f"Process group vanished before SIGKILL for pid {pid}")
    except Exception as exc:
        log_rpc(f"killpg(SIGKILL) failed for pid {pid}: {exc}")


class ServerRuntimeMixin(ServerRuntimeLeasesMixin):
    def _ida_binary_names(self) -> List[str]:
            if sys.platform == "win32":
                base_names = ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]
            else:
                base_names = ["idat", "idat64", "ida", "ida64"]
            ida_dir = getattr(self, "_ida_dir", None)
            if not ida_dir:
                return base_names
            existing = []
            for name in base_names:
                path = os.path.join(ida_dir, name)
                if os.path.isfile(path):
                    existing.append(name)
            return existing + [n for n in base_names if n not in existing]

    def _is_executable_file(self, path: str) -> bool:
            if not path:
                return False
            if not os.path.isfile(path):
                return False
            if os.name == "nt":
                return True
            return os.access(path, os.X_OK)

    def _detect_ida_dir(self):
            for env_name in ("IDADIR", "IDA_DIR"):
                env_dir = os.environ.get(env_name)
                if not env_dir:
                    continue
                env_dir = os.path.realpath(os.path.expanduser(env_dir))
                if os.path.isdir(env_dir):
                    return env_dir
                if self._is_executable_file(env_dir):
                    return os.path.dirname(env_dir)

            env_idat = os.environ.get("IDA_MCP_IDAT")
            if env_idat:
                env_idat = os.path.realpath(os.path.expanduser(env_idat))
                if self._is_executable_file(env_idat):
                    return os.path.dirname(env_idat)

            cands: List[str] = []
            if sys.platform == "win32":
                cands.extend(
                    [
                        r"C:\Program Files\IDA Professional 9.2",
                        r"C:\Program Files\IDA Pro 9.2",
                        r"C:\Program Files\IDA Professional 9.1",
                        r"C:\Program Files\IDA Pro 9.1",
                        r"C:\Program Files\IDA Professional 9.0",
                        r"C:\Program Files\IDA Pro 9.0",
                        r"C:\Program Files\IDA Professional",
                        r"C:\Program Files\IDA Pro",
                    ]
                )
            elif sys.platform == "linux":
                home = str(Path.home())
                patterns = [
                    "/opt/ida*",
                    "/opt/IDA*",
                    "/opt/idapro*",
                    "/opt/IDAPro*",
                    "/usr/local/ida*",
                    "/usr/local/IDA*",
                    "/usr/local/idapro*",
                    "/usr/local/IDAPro*",
                    os.path.join(home, "ida*"),
                    os.path.join(home, "IDA*"),
                    os.path.join(home, "idapro*"),
                    os.path.join(home, "IDAPro*"),
                ]
                for pattern in patterns:
                    cands.extend(glob.glob(pattern))
            else:
                # macOS and other Unix-like platforms
                cands.extend(
                    [
                        "/Applications/IDA Professional 9.2.app/Contents/MacOS",
                        "/Applications/IDA Pro 9.2.app/Contents/MacOS",
                        "/Applications/IDA Professional.app/Contents/MacOS",
                        "/Applications/IDA Pro.app/Contents/MacOS",
                    ]
                )

            binary_names = self._ida_binary_names()
            for c in cands:
                c = os.path.realpath(os.path.expanduser(c))
                if not os.path.isdir(c):
                    continue
                for name in binary_names:
                    if self._is_executable_file(os.path.join(c, name)):
                        return c

            for name in binary_names:
                resolved = shutil.which(name)
                if resolved:
                    return os.path.dirname(os.path.realpath(resolved))
            return ""

    def _find_idat(self):
            env_idat = os.environ.get("IDA_MCP_IDAT")
            if env_idat:
                env_idat = os.path.realpath(os.path.expanduser(env_idat))
                if self._is_executable_file(env_idat):
                    return env_idat

            if not self.ida_dir:
                self.ida_dir = self._detect_ida_dir()

            for name in self._ida_binary_names():
                if self.ida_dir:
                    p = os.path.join(self.ida_dir, name)
                    if self._is_executable_file(p):
                        return p
                resolved = shutil.which(name)
                if resolved and self._is_executable_file(resolved):
                    return os.path.realpath(resolved)

            if not self.ida_dir:
                return ""
            return ""

    def _tail_text_file(self, path: Optional[str], tail_lines: int = 40) -> str:
            if not path:
                return ""
            if not os.path.exists(path):
                return ""
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                return "".join(lines[-max(1, int(tail_lines)) :]).strip()
            except Exception:
                return ""

    def _get_ida_diagnostics(
            self, stdout_log=None, stderr_log=None, tail_lines: int = 40
        ):
            out_log = stdout_log or os.path.join(self.cache_dir, "ida_stdout.log")
            err_log = stderr_log
            if err_log is None and out_log:
                # Best effort: derive sibling stderr path for per-session logs.
                err_guess = out_log.replace("ida_stdout_", "ida_stderr_")
                if err_guess != out_log:
                    err_log = err_guess
            out_tail = self._tail_text_file(out_log, tail_lines=tail_lines)
            err_tail = self._tail_text_file(err_log, tail_lines=tail_lines)
            if not out_tail and not err_tail:
                return "No log available."
            blocks = []
            if out_tail:
                blocks.append(f"[stdout]\n{out_tail}")
            if err_tail:
                blocks.append(f"[stderr]\n{err_tail}")
            return "\n\n".join(blocks)

    def _collect_ida_state_snapshot(
        self,
        runtime: Optional[dict] = None,
        stdout_log: Optional[str] = None,
        stderr_log: Optional[str] = None,
        current_tool: Optional[str] = None,
        current_args: Optional[dict] = None,
        call_started_at: Optional[float] = None,
        tail_lines: int = 5,
        include_process_stats: bool = True,
    ) -> dict:
        """
        Build a compact snapshot of what IDA is doing right now, suitable for
        attaching to long-running tool call responses and `session(status)`.

        Always returns a dict. No exception is raised on failure — partial
        data is better than no data.
        """
        snapshot: dict = {
            "ts": time.time(),
        }
        if current_tool is not None:
            snapshot["current_tool"] = current_tool
        if current_args is not None:
            try:
                args_str = json.dumps(current_args, default=str)
                if len(args_str) > 200:
                    args_str = args_str[:197] + "..."
                snapshot["current_args"] = args_str
            except Exception:
                snapshot["current_args"] = "<unserializable>"
        if call_started_at is not None:
            snapshot["call_elapsed_sec"] = round(time.time() - float(call_started_at), 2)

        proc = None
        if isinstance(runtime, dict):
            proc = runtime.get("process")
        if proc is None:
            snapshot["process_alive"] = False
        else:
            try:
                exit_code = proc.poll()
                if exit_code is not None:
                    snapshot["process_alive"] = False
                    snapshot["process_exit_code"] = int(exit_code)
                else:
                    snapshot["process_alive"] = True
                    snapshot["process_pid"] = int(proc.pid) if proc.pid else None
                    if include_process_stats:
                        try:
                            import resource  # POSIX
                            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
                            snapshot["process_cpu_user_sec"] = round(ru.ru_utime, 2)
                            snapshot["process_cpu_sys_sec"] = round(ru.ru_stime, 2)
                            snapshot["process_rss_kb"] = int(ru.ru_maxrss)
                        except Exception:
                            pass
                        try:
                            with open(f"/proc/{int(proc.pid)}/stat", "rb") as _sf:
                                parts = _sf.read().split()
                            if len(parts) > 23:
                                snapshot["process_state"] = parts[2].decode("ascii", errors="ignore")
                                snapshot["process_utime_ticks"] = int(parts[13])
                                snapshot["process_stime_ticks"] = int(parts[14])
                                snapshot["process_threads"] = int(parts[19])
                        except Exception:
                            pass
            except Exception as e:
                snapshot["process_alive"] = None
                snapshot["process_error"] = str(e)[:200]

        if not stdout_log and isinstance(runtime, dict):
            stdout_log = runtime.get("stdout_log")
        if not stderr_log and isinstance(runtime, dict):
            stderr_log = runtime.get("stderr_log")
        if not stderr_log and stdout_log:
            err_guess = stdout_log.replace("ida_stdout_", "ida_stderr_")
            if err_guess != stdout_log:
                stderr_log = err_guess
        if stdout_log:
            tail = self._tail_text_file(stdout_log, tail_lines=tail_lines)
            if tail:
                snapshot["ida_stdout_tail"] = tail
        if stderr_log:
            tail = self._tail_text_file(stderr_log, tail_lines=tail_lines)
            if tail:
                snapshot["ida_stderr_tail"] = tail

        return snapshot

    def _send_rpc_raw(self, request, port, timeout=5, auth_token: Optional[str] = None):
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect(("127.0.0.1", port))
                payload = dict(request) if isinstance(request, dict) else request
                token = auth_token
                if not token and isinstance(payload, dict):
                    with self._runtime_lock:
                        for runtime in self.session_runtimes.values():
                            if int(runtime.get("port") or 0) == int(port):
                                token = str(runtime.get("auth_token") or "")
                                break
                if token and isinstance(payload, dict):
                    payload["session_token"] = token
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if len(data) > MAX_RPC_REQUEST_SIZE:
                    raise ValueError(
                        f"RPC request exceeds {MAX_RPC_REQUEST_SIZE} byte cap"
                    )
                s.sendall(len(data).to_bytes(4, "big") + data)
                # 30s default (was hardcoded 60s) — env: IDA_MCP_RPC_TIMEOUT
                try:
                    recv_timeout = int(os.environ.get("IDA_MCP_RPC_TIMEOUT", "30"))
                except Exception:
                    recv_timeout = 30
                recv_timeout = max(1, min(recv_timeout, 600))
                s.settimeout(recv_timeout)
                lb = b""
                while len(lb) < 4:
                    c = s.recv(4 - len(lb))
                    if not c:
                        raise EOFError()
                    lb += c
                rl = int.from_bytes(lb, "big")
                if rl > MAX_RPC_REQUEST_SIZE:
                    raise ValueError(
                        f"RPC response exceeds {MAX_RPC_REQUEST_SIZE} byte cap"
                    )
                rd = b""
                while len(rd) < rl:
                    c = s.recv(min(4096, rl - len(rd)))
                    if not c:
                        raise EOFError()
                    rd += c
                return json.loads(rd.decode("utf-8"))
            finally:
                s.close()

    def _kill_ida_process(self, runtime: dict, grace_sec: float = 3.0) -> dict:
        """
        Forcefully terminate the IDA process associated with a session runtime.
        Tries SIGTERM, then SIGKILL after grace_sec. Returns a status dict.
        """
        result: dict = {
            "attempted": False,
            "terminated": False,
            "signaled": None,
        }
        proc = runtime.get("process") if isinstance(runtime, dict) else None
        if proc is None:
            result["error"] = "no_process_in_runtime"
            return result
        result["attempted"] = True
        result["pid"] = int(proc.pid) if proc.pid else None
        try:
            exit_code = proc.poll()
        except Exception:
            exit_code = None
        if exit_code is not None:
            result["terminated"] = True
            result["signaled"] = "already_exited"
            result["exit_code"] = int(exit_code)
            return result
        try:
            proc.terminate()
            result["signaled"] = "SIGTERM"
        except Exception as e:
            result["terminate_error"] = str(e)[:200]
        try:
            proc.wait(timeout=grace_sec)
            result["terminated"] = True
            result["exit_code"] = proc.returncode
            return result
        except Exception:
            pass
        try:
            proc.kill()
            result["signaled"] = "SIGKILL"
        except Exception as e:
            result["kill_error"] = str(e)[:200]
        try:
            proc.wait(timeout=grace_sec)
            result["terminated"] = True
            result["exit_code"] = proc.returncode
        except Exception as e:
            result["final_wait_error"] = str(e)[:200]
        return result

    def _extract_library_init_failure(self, diag: str) -> Optional[dict]:
            if not isinstance(diag, str) or not diag.strip():
                return None
            low = diag.lower()
            has_phrase = ("library init failed" in low) or (
                "library initialization failed" in low
            )
            err_code = None
            m_err = re.search(r"\berr(?:or)?\s*[:=]?\s*(\d+)\b", low)
            if m_err:
                try:
                    err_code = int(m_err.group(1))
                except Exception:
                    err_code = None
            has_err2 = bool(re.search(r"\berr(?:or)?\s*[:=]?\s*2\b", low))
            if not has_phrase and not has_err2:
                return None

            causes: List[str] = []
            hints: List[str] = []
            if (
                "cannot open shared object file" in low
                or "no such file or directory" in low
                or "failed to load shared library" in low
            ):
                causes.append("Missing shared runtime library (loader error).")
                hints.append(
                    "Verify IDA runtime dependencies are installed and loadable (ldd on idat64)."
                )
            if "glibcxx" in low or "cxxabi" in low:
                causes.append("C++ runtime ABI mismatch (libstdc++ / libc++ conflict).")
                hints.append(
                    "Unset conflicting LD_LIBRARY_PATH entries or use system-compatible libstdc++."
                )
            if "qt.qpa.plugin" in low or "xcb" in low or "qt platform plugin" in low:
                causes.append("Qt platform/plugin initialization failure.")
                hints.append(
                    "Check Qt plugin paths and system GUI/runtime deps (e.g. xcb plugin packages)."
                )
            if (
                "wrong elf class" in low
                or "bad cpu type" in low
                or "exec format error" in low
            ):
                causes.append("Binary/runtime architecture mismatch.")
                hints.append(
                    "Use the correct IDA binary for host architecture and compatible target runtime."
                )
            if "permission denied" in low:
                causes.append(
                    "Filesystem permission error while loading runtime components."
                )
                hints.append(
                    "Fix file execute/read permissions on IDA installation and plugins."
                )
            if "plugin" in low and "failed" in low:
                causes.append(
                    "A plugin failed during startup and broke library initialization."
                )
                hints.append("Disable third-party plugins and retry startup.")
            if "python" in low and ("init" in low or "module" in low):
                causes.append("Embedded Python/runtime initialization mismatch.")
                hints.append(
                    "Ensure no conflicting PYTHONHOME/PYTHONPATH overrides are injected."
                )
            if not causes:
                causes.append("Generic library initialization failure.")
                hints.append("Inspect stdout/stderr tails for missing dependency details.")

            return {
                "detected": True,
                "error_code": err_code,
                "err2": bool(has_err2 or (err_code == 2)),
                "causes": causes,
                "recommendations": hints,
            }

    def _is_library_init_err2(self, diag: str) -> bool:
            info = self._extract_library_init_failure(diag)
            if not info:
                return False
            if info.get("error_code") == 2:
                return True
            if info.get("err2"):
                return True
            # Preserve previous behavior: phrase alone still triggers recovery path.
            return bool(info.get("detected"))

    def _normalize_ida_args(
            self, ida_args: Optional[Union[str, List[str]]]
        ) -> List[str]:
            if ida_args is None:
                return []
            if isinstance(ida_args, str):
                parts = shlex.split(ida_args)
            elif isinstance(ida_args, list):
                parts = []
                for p in ida_args:
                    if p is None:
                        continue
                    part = str(p)
                    # Explicitly reject empty entries after normalization.
                    if part == "":
                        raise ValueError("ida_args cannot include empty entries")
                    parts.append(part)
            else:
                raise ValueError("ida_args must be a string or list of strings")
            cleaned = []
            # Reserved for server-managed script/log/output IDB wiring.
            forbidden_prefixes = ("-S", "-L", "-o")
            for arg in parts:
                if "\x00" in arg:
                    raise ValueError("ida_args cannot include null bytes")
                # Args are passed via subprocess list (no shell), so metacharacters aren't interpreted.
                if any(
                    (ord(ch) < 32 and ch not in ("\t", "\n", "\r")) or ch == "\x7f"
                    for ch in arg
                ):
                    raise ValueError("ida_args cannot include control characters")
                if any(arg.startswith(prefix) for prefix in forbidden_prefixes):
                    raise ValueError(f"ida_args cannot include {arg} (reserved by server)")
                if arg == "-A":
                    log_rpc("Ignoring redundant -A flag in ida_args")
                    continue
                cleaned.append(arg)
            return cleaned

    @staticmethod
    def _pop_first(mapping: dict, keys: List[str], default: Any = None) -> Any:
            for key in keys:
                if key in mapping:
                    return mapping.pop(key)
            return default

    def _load_session_macros(self):
            self._session_macros = {}
            try:
                with open(self._macro_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except FileNotFoundError:
                return
            except Exception:
                return
            if not isinstance(raw, dict):
                return
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                name = str(value.get("name") or key).strip()
                data = value.get("data")
                if not name or not isinstance(data, dict):
                    continue
                self._session_macros[key.lower()] = {
                    "name": name,
                    "data": data,
                    "updated_at": value.get("updated_at"),
                }

    def _save_session_macros(self):
            try:
                tmp = self._macro_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._session_macros, f, indent=2, ensure_ascii=False)
                os.replace(tmp, self._macro_path)
            except Exception:
                pass

    def _normalize_macro_name(self, value: Any) -> Optional[str]:
            if value is None:
                return None
            name = str(value).strip()
            if not name:
                return None
            name = re.sub(r"\s+", " ", name)[:80]
            return name or None

    def _record_activity(
            self,
            tool_name: str,
            call_args: Any,
            result: Any,
            *,
            session_id: Optional[str] = None,
        ):
            if not isinstance(call_args, dict):
                return
            if not isinstance(result, dict) or is_error_result(result):
                return
            sid = session_id
            if not sid:
                sid = _normalize_session_id(call_args.get("session_id"))
            if not sid and self.current_session:
                sid = self.current_session.session_id
            if not sid:
                return
            self._session_last_activity[sid] = time.time()

            action = call_args.get("action")
            if not isinstance(action, str):
                action = ""

            # Auto-nudge tracking — use UsageIntelligence.observe if available, else auto_nudge
            try:
                ui = getattr(self, "_usage_intel", None)
                if ui:
                    ui.observe(
                        tool_name, action,
                        session_id=sid or "",
                        addr=call_args.get("addr"),
                    )
                else:
                    from .auto_nudge import record_tool_call
                    record_tool_call(
                        sid,
                        tool_name,
                        action,
                        addr=call_args.get("addr"),
                        query=call_args.get("query") or call_args.get("pattern"),
                    )
            except Exception:
                pass

            addresses: List[str] = []
            for field in ("addr", "address", "ea"):
                raw_addr = call_args.get(field)
                if isinstance(raw_addr, int):
                    addresses.append(hex(raw_addr))
                elif isinstance(raw_addr, str):
                    addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addr)[:4])
            raw_addrs = call_args.get("addrs")
            if isinstance(raw_addrs, str):
                addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addrs)[:8])
            elif isinstance(raw_addrs, list):
                for raw_addr in raw_addrs[:8]:
                    if isinstance(raw_addr, int):
                        addresses.append(hex(raw_addr))
                    elif isinstance(raw_addr, str):
                        addresses.extend(re.findall(r"0x[0-9a-fA-F]+", raw_addr)[:2])
            if isinstance(result.get("items"), list):
                for item in result["items"][:16]:
                    if not isinstance(item, dict):
                        continue
                    addr = item.get("address") or item.get("addr")
                    if addr is None and isinstance(item.get("address_ea"), int):
                        addr = hex(item.get("address_ea"))
                    if isinstance(addr, str) and addr.startswith("0x"):
                        addresses.append(addr.lower())
            matches = result.get("matches")
            if isinstance(matches, str):
                addresses.extend(re.findall(r"0x[0-9a-fA-F]+", matches)[:16])
            deduped_addresses: List[str] = []
            seen = set()
            for addr in addresses:
                a = addr.lower()
                if a in seen:
                    continue
                seen.add(a)
                deduped_addresses.append(a)

            entry = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "session_id": sid,
                "tool": tool_name,
                "action": action,
                "addresses": deduped_addresses[:8],
                "topic": result.get("resolved_topic") or result.get("topic"),
                "target": result.get("target")
                or result.get("query")
                or result.get("pattern"),
            }
            self._activity_log.append(entry)
            if len(self._activity_log) > self._activity_log_max:
                self._activity_log = self._activity_log[-self._activity_log_max :]

            # Also persist into session skill/activity store so dashboard counters,
            # phase progression, and dead-end detection reflect real tool usage.
            try:
                self.session_mgr.log_activity(
                    sid,
                    tool=tool_name,
                    action=action or "",
                    result=json.dumps(
                        {
                            "addresses": deduped_addresses[:4],
                            "topic": entry.get("topic"),
                            "target": entry.get("target"),
                        },
                        ensure_ascii=False,
                    )[:400],
                )
            except Exception:
                pass

    def _build_recent_workset(
            self,
            sid: str,
            n: int,
            include_bookmarks: bool,
            include_items: bool,
        ) -> dict:
            n = _bounded_int(n, 20, min_value=1, max_value=200)
            entries: List[Dict[str, Any]] = []
            seen = set()
            for row in reversed(self._activity_log):
                if row.get("session_id") != sid:
                    continue
                key = (
                    row.get("tool"),
                    row.get("action"),
                    tuple(row.get("addresses") or []),
                    row.get("topic"),
                    row.get("target"),
                )
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    {
                        "kind": "activity",
                        "ts": row.get("ts"),
                        "tool": row.get("tool"),
                        "action": row.get("action"),
                        "addresses": row.get("addresses") or [],
                        "topic": row.get("topic"),
                        "target": row.get("target"),
                    }
                )
                if len(entries) >= n:
                    break

            if include_bookmarks:
                bm_res = self.bookmark_mgr.list(sid, {"limit": max(1, n), "offset": 0})
                for bm in bm_res.get("bookmarks", [])[:n]:
                    if not isinstance(bm, dict):
                        continue
                    entries.append(
                        {
                            "kind": "bookmark",
                            "ts": bm.get("timestamp"),
                            "address": bm.get("addr"),
                            "name": bm.get("name"),
                            "category": bm.get("category"),
                            "tags": bm.get("tags") or [],
                        }
                    )
                    if len(entries) >= (n * 2):
                        break

            lines: List[str] = []
            for item in entries:
                if item.get("kind") == "bookmark":
                    lines.append(
                        f"{item.get('ts', '')}  bookmark  {item.get('address', '')}  {item.get('name', '')}".strip()
                    )
                    continue
                addr_part = ",".join(item.get("addresses") or [])
                tail_parts = [item.get("tool"), item.get("action")]
                if addr_part:
                    tail_parts.append(addr_part)
                if item.get("topic"):
                    tail_parts.append(str(item.get("topic")))
                elif item.get("target"):
                    tail_parts.append(str(item.get("target")))
                tail = "  ".join([p for p in tail_parts if p])
                lines.append(f"{item.get('ts', '')}  {tail}".strip())

            out = {
                "ok": True,
                "action": "recent_workset",
                "session_id": sid,
                "workset": "\n".join(lines),
                "count": len(entries),
            }
            if include_items:
                out["items"] = entries
            return out

    def _update_session_indexing_metadata(self, session_id: str, **updates: Any) -> None:
            try:
                sess = self.session_mgr.sessions.get(session_id)
                if not sess:
                    return
                sess.metadata = dict(sess.metadata or {})
                sess.metadata.update(updates)
                self.session_mgr._save_metadata(sess)
            except Exception:
                pass

    def _collect_idle_index_targets(self, session_id: str, limit: int = 16) -> List[str]:
            targets: List[str] = []
            seen = set()
            for row in reversed(self._activity_log):
                if row.get("session_id") != session_id:
                    continue
                for addr in row.get("addresses") or []:
                    if not isinstance(addr, str):
                        continue
                    norm = addr.lower()
                    if not norm.startswith("0x") or norm in seen:
                        continue
                    seen.add(norm)
                    targets.append(norm)
                    if len(targets) >= limit:
                        return targets
            return targets

    def _seed_idle_index_targets(self, session_id: str, server_port: int, limit: int = 12) -> List[str]:
            targets: List[str] = []
            seen = set()

            def _push(addr: Any) -> None:
                if isinstance(addr, int):
                    norm = hex(addr).lower()
                elif isinstance(addr, str):
                    match = re.search(r"0x[0-9a-fA-F]+", addr)
                    if not match:
                        return
                    norm = match.group(0).lower()
                else:
                    return
                if norm in seen:
                    return
                seen.add(norm)
                targets.append(norm)

            try:
                res = self._send_rpc_raw(
                    {"tool": "idb", "args": {"action": "entrypoints"}},
                    server_port,
                    timeout=float(self._idle_index_rpc_timeout),
                )
                if isinstance(res, dict) and not is_error_result(res):
                    for entry in res.get("entrypoints") or []:
                        if not isinstance(entry, dict):
                            continue
                        _push(entry.get("addr"))
                        if len(targets) >= limit:
                            return targets
            except Exception as e:
                log_rpc(f"[idle-index] entrypoint seed failed for {session_id}: {e}")

            try:
                res = self._send_rpc_raw(
                    {
                        "tool": "data",
                        "args": {"action": "functions", "count": limit},
                    },
                    server_port,
                    timeout=float(self._idle_index_rpc_timeout),
                )
                if isinstance(res, dict) and not is_error_result(res):
                    for line in str(res.get("functions") or "").splitlines():
                        _push(line)
                        if len(targets) >= limit:
                            return targets
            except Exception as e:
                log_rpc(f"[idle-index] function seed failed for {session_id}: {e}")
            return targets

    def _start_idle_index_worker(self, session_id: str, server_port: int) -> None:
            self._stop_idle_index_worker(session_id, join_timeout=0.2)
            stop_event = threading.Event()

            def _worker() -> None:
                seeded = False
                indexed: set[str] = set()
                self._update_session_indexing_metadata(
                    session_id,
                    indexing_mode="hotset_idle",
                    indexing_state="scheduled",
                    hot_indexed_count=0,
                    indexing_complete=False,
                )
                log_rpc(f"[idle-index] Scheduled hotset warmup for {session_id}")
                while not stop_event.wait(1.0):
                    with self._runtime_lock:
                        runtime = self.session_runtimes.get(session_id)
                    if not self._runtime_alive(runtime):
                        return
                    if int(self._session_inflight_calls.get(session_id, 0) or 0) > 0:
                        continue
                    last_activity = float(self._session_last_activity.get(session_id, 0.0) or 0.0)
                    if last_activity and (time.time() - last_activity) < float(self._idle_index_delay_seconds):
                        continue

                    targets = self._collect_idle_index_targets(
                        session_id,
                        limit=max(int(self._idle_index_slice_size) * 4, int(self._idle_index_seed_limit)),
                    )
                    if not targets and not seeded:
                        targets = self._seed_idle_index_targets(
                            session_id,
                            server_port,
                            limit=int(self._idle_index_seed_limit),
                        )
                        seeded = True
                    pending = [addr for addr in targets if addr not in indexed]
                    if not pending:
                        continue

                    self._update_session_indexing_metadata(
                        session_id,
                        indexing_mode="hotset_idle",
                        indexing_state="warming",
                        hot_indexed_count=len(indexed),
                        indexing_complete=bool(indexed),
                    )
                    worked = 0
                    for addr in pending[: int(self._idle_index_slice_size)]:
                        if stop_event.is_set():
                            return
                        if int(self._session_inflight_calls.get(session_id, 0) or 0) > 0:
                            break
                        last_activity = float(self._session_last_activity.get(session_id, 0.0) or 0.0)
                        if last_activity and (time.time() - last_activity) < float(self._idle_index_delay_seconds):
                            break
                        try:
                            res = self._send_rpc_raw(
                                {
                                    "tool": "intelligence",
                                    "args": {"action": "structural_refresh", "addr": addr},
                                },
                                server_port,
                                timeout=float(self._idle_index_rpc_timeout),
                            )
                            if isinstance(res, dict) and not is_error_result(res) and res.get("ok"):
                                indexed.add(addr)
                                worked += 1
                        except Exception as e:
                            log_rpc(f"[idle-index] structural_refresh failed for {session_id} {addr}: {e}")
                            break
                    if worked:
                        self._update_session_indexing_metadata(
                            session_id,
                            indexing_mode="hotset_idle",
                            indexing_state="partial",
                            hot_indexed_count=len(indexed),
                            indexing_complete=True,
                        )
                        log_rpc(
                            f"[idle-index] Warmed {worked} hot function(s) for {session_id}; total={len(indexed)}"
                        )

            t = threading.Thread(
                target=_worker,
                daemon=True,
                name=f"idle-index-{session_id}",
            )
            with self._idle_index_lock:
                self._idle_index_stop_events[session_id] = stop_event
                self._idle_index_threads[session_id] = t
            t.start()

    def _stop_idle_index_worker(self, session_id: str, join_timeout: float = 1.0) -> None:
            with self._idle_index_lock:
                stop_event = self._idle_index_stop_events.pop(session_id, None)
                thread = self._idle_index_threads.pop(session_id, None)
            if stop_event is not None:
                stop_event.set()
            if thread and thread.is_alive() and thread is not threading.current_thread():
                try:
                    thread.join(timeout=max(0.0, float(join_timeout or 0.0)))
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Analysis-state observability
    #
    # The host refuses to block on IDA auto-analysis (it starts the RPC
    # server immediately and lets analysis run in the background), so callers
    # are blind between "create" and "ready". These helpers give an honest
    # picture of what IDA is doing RIGHT NOW, sourced from IDA's own
    # auto_is_ok() via the idb(action='state') RPC — not from the host's
    # idle-indexing worker, which is an orthogonal process whose state was
    # previously (mis)reported as "analysis_ready".
    # ------------------------------------------------------------------

    def _query_ida_state(self, sid: str, timeout: float = 3.0) -> Optional[dict]:
            """Fresh, honest IDA state snapshot via idb(action='state').

            Returns the idb_state() dict (analysis.is_ok, analysis.active,
            inventory.functions_qty, ...) or None if the runtime is gone or
            the RPC fails. Cheap: O(1) SDK calls, no function iteration.
            """
            with self._runtime_lock:
                runtime = self.session_runtimes.get(sid)
            if not self._runtime_alive(runtime):
                return None
            port = runtime.get("port") if isinstance(runtime, dict) else None
            if not isinstance(port, int) or port <= 0:
                return None
            try:
                res = self._send_rpc_raw(
                    {"tool": "idb", "args": {"action": "state"}},
                    port,
                    timeout=timeout,
                    auth_token=runtime.get("auth_token") if isinstance(runtime, dict) else None,
                )
            except Exception:
                return None
            if isinstance(res, dict) and not is_error_result(res) and res.get("ok"):
                return res
            return None

    def _start_analysis_watchdog(self, session_id: str, server_port: int) -> None:
            """Start a per-session host thread that watches IDA's real analysis
            progress and flags the session as 'stalled' when the process is
            alive but analysis stops advancing. Idempotent: restarting a
            session replaces any prior watchdog for it.
            """
            self._stop_analysis_watchdog(session_id, join_timeout=0.2)
            stop_event = threading.Event()

            interval = float(getattr(self, "_analysis_watchdog_interval", 5))
            stall_threshold = float(getattr(self, "_analysis_watchdog_stall_seconds", 120))

            def _worker() -> None:
                last_funcs: Optional[int] = None
                stall_since: Optional[float] = None  # ts when progress last stalled
                last_is_ok: Optional[bool] = None
                self._update_session_indexing_metadata(
                    session_id,
                    analysis_state="starting",
                    analysis_stall_seconds=0,
                    analysis_is_ok=None,
                    analysis_functions_qty=None,
                )
                log_rpc(f"[watchdog] Started for {session_id}")
                while not stop_event.wait(interval):
                    with self._runtime_lock:
                        runtime = self.session_runtimes.get(session_id)
                    if not self._runtime_alive(runtime):
                        return
                    state = self._query_ida_state(session_id, timeout=float(interval))
                    if not state:
                        # RPC failed but process alive — keep watching; treat
                        # as no signal rather than declaring stalled.
                        continue
                    analysis = state.get("analysis") or {}
                    inventory = state.get("inventory") or {}
                    is_ok = bool(analysis.get("is_ok"))
                    active = bool(analysis.get("active"))
                    funcs = inventory.get("functions_qty")
                    try:
                        funcs_i = int(funcs) if funcs is not None else None
                    except Exception:
                        funcs_i = None

                    now = time.time()
                    if is_ok:
                        # Analysis queue is empty — done (for now).
                        stall_since = None
                        verdict = "ready"
                    else:
                        # Analysis in progress. Stall if function count has
                        # not advanced since the last poll. (func count can be
                        # None early in load — don't count that as progress.)
                        progressed = (
                            funcs_i is not None
                            and last_funcs is not None
                            and funcs_i > last_funcs
                        )
                        if progressed or last_funcs is None:
                            stall_since = None
                            verdict = "analyzing"
                        elif stall_since is None:
                            stall_since = now
                            verdict = "analyzing"
                        else:
                            verdict = "analyzing"
                        if stall_since is not None:
                            stall_sec = now - stall_since
                            if stall_sec >= stall_threshold:
                                verdict = "stalled"
                                log_rpc(
                                    f"[watchdog] {session_id} STALLED: no "
                                    f"function-count progress for {int(stall_sec)}s "
                                    f"(funcs={funcs_i})"
                                )

                    last_funcs = funcs_i
                    last_is_ok = is_ok
                    stall_sec_report = (
                        round(time.time() - stall_since, 1) if stall_since else 0
                    )
                    self._update_session_indexing_metadata(
                        session_id,
                        analysis_state=verdict,
                        analysis_stall_seconds=stall_sec_report,
                        analysis_is_ok=is_ok,
                        analysis_active=active,
                        analysis_functions_qty=funcs_i,
                    )

            t = threading.Thread(
                target=_worker,
                daemon=True,
                name=f"ida-watchdog-{session_id}",
            )
            with self._analysis_watchdog_lock:
                self._analysis_watchdog_stop_events[session_id] = stop_event
                self._analysis_watchdog_threads[session_id] = t
            t.start()

    def _stop_analysis_watchdog(self, session_id: str, join_timeout: float = 1.0) -> None:
            with self._analysis_watchdog_lock:
                stop_event = self._analysis_watchdog_stop_events.pop(session_id, None)
                thread = self._analysis_watchdog_threads.pop(session_id, None)
            if stop_event is not None:
                stop_event.set()
            if thread and thread.is_alive() and thread is not threading.current_thread():
                try:
                    thread.join(timeout=max(0.0, float(join_timeout or 0.0)))
                except Exception:
                    pass

    def _json_safe_value(self, value: Any) -> Any:
            """Recursively convert non-JSON-safe values to safe representations."""
            if isinstance(value, bytes):
                try:
                    return value.decode("utf-8")
                except Exception:
                    return {"_bytes_hex": value.hex()}
            if isinstance(value, bytearray):
                return self._json_safe_value(bytes(value))
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    try:
                        key = k if isinstance(k, str) else str(k)
                    except Exception:
                        key = "<non_string_key>"
                    out[key] = self._json_safe_value(v)
                return out
            if isinstance(value, (list, tuple)):
                return [self._json_safe_value(v) for v in value]
            if isinstance(value, set):
                return [self._json_safe_value(v) for v in value]
            return value

    def _serialize_payload(self, payload: Any, opts: dict) -> str:
            payload = self._json_safe_value(payload)
            if opts.get("mode") == "full":
                return json.dumps(payload, ensure_ascii=False, indent=2)
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _build_ida_command(
            self, session, log_file, script_path, use_existing_idb: bool, effective_idb_path: Optional[str] = None
        ):
            cmd = [self.idat_exe, "-A"]
            cmd.extend(session.ida_args or [])

            # For new databases, inject processor/loader CLI flags so IDA loads
            # with the correct architecture from the start instead of defaulting
            # to metapc and requiring a post-load switch.
            if not use_existing_idb:
                opts = session.analysis_options or {}
                ida_prefixes = {str(a)[:2] for a in (session.ida_args or [])}
                if opts.get("processor") and "-p" not in ida_prefixes:
                    cmd.append(f"-p{opts['processor']}")
                loader = opts.get("loader")
                if loader and "-T" not in ida_prefixes:
                    cmd.append(f"-T{loader}")
                elif not loader and "-T" not in ida_prefixes:
                    # Default to raw binary loader for any non-PE/ELF/Mach-O binary.
                    # Without explicit loader, IDA picks OBJ which creates BSS/DATA
                    # segments with wrong bitness, blocking code analysis entirely.
                    # Firmware archs (arm/mips/ppc/tricore/etc.) always get -Tbin.
                    proc = str(opts.get("processor") or "").lower()
                    if proc in FIRMWARE_RAW_PROCS:
                        cmd.append("-Tbin")
                    elif str(opts.get("loader") or "") == "bin":
                        cmd.append("-Tbin")
                    # For unknown processors with no explicit loader, let IDA's
                    # auto-detection handle it — but the pre-analysis hook will
                    # fix segment class/type/perm if needed.
                # Apply inferred load base so IDA maps the binary at the correct
                # address from the start (e.g. AIC8800D80 WFFW at 0x120000).
                if opts.get("baseaddr") is not None and "-b" not in ida_prefixes:
                    try:
                        # IDA -b flag is in 16-byte paragraphs, not bytes.
                        paragraphs = int(opts["baseaddr"]) // 16
                        cmd.append(f"-b{paragraphs:#x}")
                    except (TypeError, ValueError):
                        pass
                # skip_analysis=true: pass -c to create IDB without running auto-analysis.
                # Use for large/raw binaries where analysis blocks indefinitely.
                # After session create, call analysis(action='run') to trigger manually.
                if opts.get("skip_analysis") or opts.get("no_analysis"):
                    if "-c" not in (session.ida_args or []):
                        cmd.append("-c")

            cmd.append(f"-S{script_path}")
            cmd.append(f"-L{log_file}")
            if use_existing_idb:
                # For packed .i64, effective_idb_path is the binary_path (the packed .i64)
                idb_to_open = effective_idb_path or session.idb_path
                cmd.append(idb_to_open)
            else:
                cmd.append(f"-o{session.idb_path}")
                if session.binary_path:
                    cmd.append(session.binary_path)
            return cmd

    def _backup_idb(self, idb_path: str) -> Optional[str]:
            if not idb_path or not os.path.exists(idb_path):
                return None
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{idb_path}.corrupt.{timestamp}"
            try:
                os.replace(idb_path, backup_path)
                log_rpc(f"Backed up corrupt IDB to {backup_path}")
                return backup_path
            except Exception as e:
                log_rpc(f"Failed to backup corrupt IDB {idb_path}: {e}")
                return None

    def _cleanup_stale_idb_family(self, idb_path: str) -> None:
            """Remove stale sidecar files that can block fresh IDB creation."""
            if not idb_path:
                return
            base, ext = os.path.splitext(idb_path)
            family_exts = [
                ".id0",
                ".id1",
                ".nam",
                ".til",
                ".dmp",
                ".asm",
                ".i64",
                ".idb",
            ]
            for fam_ext in family_exts:
                path = f"{base}{fam_ext}"
                if not os.path.exists(path):
                    continue
                try:
                    os.remove(path)
                    log_rpc(f"Removed stale IDB artifact: {path}")
                except Exception as e:
                    log_rpc(f"Failed to remove stale IDB artifact {path}: {e}")

    def _cleanup_packed_idb_siblings(self, packed_idb_path: str) -> List[str]:
            """Remove stale unpacked siblings (.id0/.id1/.nam/.til/.schemaboot.db/...) next
            to a packed .i64 IDB. Leaving them in place causes IDA to find the unpacked
            base, refuse to start (Permission denied / error 4), and abort the open
            before the existing packed IDB is even consulted.

            Two naming patterns exist depending on the IDA workflow:
              1) Legacy: <binary>.id0 / .id1 / .nam / .til (base strips .i64)
              2) Modern: <binary>.i64.blackboard.db / .embeddings.db (base keeps .i64)
            We cover both forms by computing both the splitext base and the full stem.
            """
            removed: List[str] = []
            if not packed_idb_path:
                return removed
            base, ext = os.path.splitext(packed_idb_path)
            sibling_exts = [
                ".id0",
                ".id1",
                ".id2",
                ".id3",
                ".id4",
                ".nam",
                ".til",
                ".dmp",
                ".asm",
                ".i64",
                ".idb",
                ".schemaboot.db",
                ".schemaboot.db-shm",
                ".schemaboot.db-wal",
                ".blackboard.db",
                ".blackboard.db-shm",
                ".blackboard.db-wal",
                ".embeddings.db",
                ".embeddings.db-shm",
                ".embeddings.db-wal",
            ]
            seen_paths: set = set()
            for stem in (base, packed_idb_path):
                if not stem:
                    continue
                for fam_ext in sibling_exts:
                    path = f"{stem}{fam_ext}"
                    if path in seen_paths:
                        continue
                    seen_paths.add(path)
                    if not os.path.exists(path):
                        continue
                    # Don't clobber the actual packed IDB the user is opening.
                    try:
                        if os.path.realpath(path) == os.path.realpath(packed_idb_path):
                            continue
                    except Exception:
                        pass
                    try:
                        os.remove(path)
                        removed.append(path)
                        log_rpc(f"Removed packed-IDB sibling: {path}")
                    except Exception as e:
                        log_rpc(f"Failed to remove packed-IDB sibling {path}: {e}")
            return removed

    def _terminate_ida_processes_for_path(self, target_path: str) -> List[int]:
            """Best-effort terminate any idat/ida processes whose command line references
            the given target. Returns the list of PIDs that were killed. Used to recover
            from orphaned IDA processes that still hold the IDB / unpacked sidecars.
            """
            killed: List[int] = []
            if not target_path:
                return killed
            target_norm = os.path.realpath(os.path.abspath(target_path)).lower()
            if not target_norm:
                return killed
            try:
                have_psutil = True
            except Exception:
                have_psutil = False
            proc_iter = None
            if have_psutil:
                try:
                    import psutil as _ps
                    proc_iter = _ps.process_iter(["pid", "name", "cmdline"])
                except Exception:
                    proc_iter = None
            if proc_iter is None:
                try:
                    out = subprocess.run(
                        ["wmic", "process", "where", "name like '%idat%' or name like '%ida%'",
                         "get", "ProcessId,CommandLine", "/format:list"],
                        capture_output=True, text=True, timeout=10,
                    )
                    block_pid = None
                    for line in (out.stdout or "").splitlines():
                        line = line.rstrip()
                        if line.lower().startswith("processid"):
                            try:
                                block_pid = int(line.split(":", 1)[1].strip())
                            except Exception:
                                block_pid = None
                        elif line.lower().startswith("commandline"):
                            cmd = line.split(":", 1)[1].strip().lower()
                            if target_norm in cmd and block_pid:
                                try:
                                    subprocess.run(
                                        ["taskkill", "/T", "/F", "/PID", str(block_pid)],
                                        capture_output=True, timeout=5,
                                    )
                                    killed.append(block_pid)
                                except Exception:
                                    pass
                                block_pid = None
                        else:
                            block_pid = None
                except Exception:
                    pass
                return killed
            for proc in proc_iter:
                try:
                    name = (proc.info.get("name") or "").lower()
                except Exception:
                    name = ""
                if not (("ida" in name) and (name.endswith("t") or name.endswith(".exe") or name == "ida" or name == "ida.exe")):
                    if "idat" not in name and "ida" not in name:
                        continue
                try:
                    cmdline_parts = proc.info.get("cmdline") or []
                    cmdline = " ".join(cmdline_parts).lower() if cmdline_parts else ""
                except Exception:
                    cmdline = ""
                if not cmdline or target_norm not in cmdline:
                    continue
                try:
                    pid = int(proc.info.get("pid") or 0)
                except Exception:
                    pid = 0
                if not pid:
                    continue
                try:
                    if sys.platform == "win32":
                        subprocess.run(
                            ["taskkill", "/T", "/F", "/PID", str(pid)],
                            capture_output=True, timeout=5,
                        )
                    else:
                        try:
                            os.killpg(os.getpgid(pid), signal.SIGTERM)
                        except Exception:
                            proc.kill()
                    killed.append(pid)
                    log_rpc(f"Terminated stale IDA pid={pid} holding {target_norm}")
                except Exception as e:
                    log_rpc(f"Failed to terminate stale IDA pid={pid}: {e}")
            return killed

    def _nuclear_reset(self, idb_path, aggressive: bool = False):
            if not idb_path:
                return

            base = idb_path.rsplit(".", 1)[0]

            lock_exts = [
                ".mcp.lock",  # Legacy MCP session lock for exclusive IDB access
                ".lock",
            ]
            all_exts = [
                ".id0",
                ".id1",
                ".id2",
                ".id3",
                ".id4",
                ".nam",
                ".til",
                ".idb_info",
                ".seg",
                ".sig",
                ".ids",
            ]

            cleanup_exts = all_exts if aggressive else lock_exts
            for ext in cleanup_exts:
                try:
                    p = base + ext
                    if os.path.exists(p):
                        os.remove(p)
                        log_rpc(f"Cleaned up temp file: {p}")
                except Exception as e:
                    log_rpc(f"Failed to clean up {base + ext}: {e}")

            if aggressive and os.path.exists(idb_path):
                try:
                    if os.path.getsize(idb_path) < 100:
                        log_rpc(f"IDB appears corrupted (too small): {idb_path}")
                        os.remove(idb_path)
                        log_rpc(f"Removed corrupted IDB: {idb_path}")
                except Exception as e:
                    log_rpc(f"Failed to check IDB size: {e}")

    def _start_server(self, session):
            opts = session.analysis_options or {}
            preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
            has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
            self._nuclear_reset(
                session.idb_path, aggressive=bool(opts.get("aggressive_cleanup"))
            )

            # Validate IDA installation
            if not self.idat_exe or not self._is_executable_file(self.idat_exe):
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    "IDA executable not found. Set IDADIR or IDA_MCP_IDAT, or ensure idat64/idat is in PATH.",
                    details={"ida_dir": self.ida_dir, "idat_exe": self.idat_exe},
                )

            # DYNAMIC PORT ASSIGNMENT
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            server_port = sock.getsockname()[1]
            sock.close()

            log_rpc(f"Assigned dynamic port: {server_port}")

            # server_script.py lives at the package root (ida_pro_mcp/).
            # SCRIPT_DIR is host/server/, so the package root is two levels up.
            script_path = os.path.join(os.path.dirname(os.path.dirname(SCRIPT_DIR)), "server_script.py")

            # Environment for IDA
            env = os.environ.copy()
            ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
            if ida_runtime_dir:
                env["IDADIR"] = ida_runtime_dir
            env["IDA_MCP_PORT"] = str(server_port)
            session_token = secrets.token_urlsafe(32)
            env["IDA_MCP_SESSION_TOKEN"] = session_token
            env["IDA_MCP_BYPASS_SYNC"] = "1"
            env["IDA_MCP_SESSION_ID"] = session.session_id
            env["IDA_MCP_CACHE_DIR"] = self.cache_dir
            env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
            # For packed .i64 IDBs, never force pre-analysis architecture
            # overrides onto an existing database — the IDB already encodes the
            # correct processor/bitness, and forcing a different processor here
            # causes IDA to unload the existing IDP module and abort with
            # "Database initialization failed with error 4".
            force_preload = has_preload_request and not getattr(session, "packed_idb", False)
            env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if force_preload else "0"

            # Determine whether to open existing IDB or create new one
            # Packed .i64 databases should be opened directly as existing IDBs
            if getattr(session, "packed_idb", False):
                use_existing_idb = True
                # Use the binary_path (the packed .i64) as the IDB to open
                effective_idb_path = session.binary_path
            else:
                use_existing_idb = os.path.exists(session.idb_path)
                effective_idb_path = session.idb_path
            env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"

            sid_tag = session.session_id
            log_file = os.path.join(self.cache_dir, f"ida_mcp_{sid_tag}.log")
            stdout_log = os.path.join(self.cache_dir, f"ida_stdout_{sid_tag}.log")
            stderr_log = os.path.join(self.cache_dir, f"ida_stderr_{sid_tag}.log")

            # Launch IDA: Open existing IDB if present, otherwise analyze binary
            if use_existing_idb:
                log_rpc(f"Opening existing session IDB: {effective_idb_path}")
                # If this is a packed .i64 IDB, kill any orphaned IDA processes
                # still holding the unpacked siblings (.id0/.id1/.nam/.til) next
                # to the packed file. Without this, the next launch hits
                # "Permission denied" on .id0 and aborts with
                # "Database initialization failed with error 4".
                # We intentionally do NOT delete the sibling files - they are
                # IDA's working state (a re-openable cache) and on a 3 GB+ IDB
                # thrashing them on every launch wastes GB of disk I/O. If the
                # siblings are corrupted, IDA will surface the error and the
                # user can clean manually.
                if getattr(session, "packed_idb", False):
                    killed = self._terminate_ida_processes_for_path(effective_idb_path)
                    if killed:
                        log_rpc(
                            f"Pre-launch cleanup killed {len(killed)} stale IDA process(es) "
                            f"for {effective_idb_path}"
                        )
            else:
                log_rpc(
                    f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
                )
                # Ensure session directory exists
                os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
                self._cleanup_stale_idb_family(session.idb_path)
            cmd = self._build_ida_command(session, log_file, script_path, use_existing_idb, effective_idb_path)

            log_rpc(f"Launching IDA: {' '.join(cmd)}")

            stdout_fh = open(stdout_log, "a", encoding="utf-8")
            stderr_fh = open(stderr_log, "a", encoding="utf-8")
            _handles_transferred = False
            try:
                server_process = subprocess.Popen(
                    cmd,
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    env=env,
                    **_popen_new_session_kwargs(),
                )

                # WAIT FOR STARTUP using ping
                startup_timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "90"))
                start_time = time.time()
                ida_crashed = False
                exit_code = None
                actual_port = server_port
                while time.time() - start_time < startup_timeout:
                    exit_code = server_process.poll()
                    if exit_code is not None:
                        ida_crashed = True
                        break

                    try:
                        res = self._send_rpc_raw(
                            {"type": "ping"},
                            server_port,
                            timeout=0.5,
                            auth_token=session_token,
                        )
                        if res.get("pong"):
                            # IDA may have rebound to an ephemeral port if
                            # the host's pre-allocated one was taken in the
                            # TOCTOU window. Trust the port IDA reports.
                            try:
                                actual_port = int(res.get("port") or server_port)
                            except Exception:
                                actual_port = server_port
                            log_rpc(
                                f"IDA RPC listener is ready for {session.idb_path} on port {actual_port}"
                            )
                            runtime = {
                                "process": server_process,
                                "port": actual_port,
                                "idb_path": session.idb_path,
                                "stdout_log": stdout_log,
                                "stderr_log": stderr_log,
                                "auth_token": session_token,
                                "log_handles": [stdout_fh, stderr_fh],
                            }
                            with self._runtime_lock:
                                self.session_runtimes[session.session_id] = runtime
                            self._write_runtime_lease(session.session_id, runtime)
                            _handles_transferred = True
                            apply_res = self._apply_session_options(session, runtime)
                            if is_error_result(apply_res):
                                return apply_res
                            # Start lightweight host services immediately, and defer
                            # structural indexing until the session goes idle.
                            self._start_session_background_services(session, actual_port)
                            return {
                                "ok": True,
                                "idb_path": session.idb_path,
                                "current_options": apply_res.get("current_options"),
                                "bootstrap_report": apply_res.get("bootstrap_report"),
                                "apply_steps": apply_res.get("apply_steps"),
                                "steps_done": apply_res.get("steps_done"),
                                "analysis_in_progress": True,
                                "indexing_state": "idle_hot_scheduled",
                                "hint": "IDA RPC is ready. Auto-analysis continues in background, and hot structural indexing starts only after the session goes idle.",
                            }
                    except Exception:
                        pass
                    time.sleep(0.5)

                if ida_crashed:
                    diag = self._get_ida_diagnostics(stdout_log, stderr_log)
                    if self._is_library_init_err2(diag):
                        return self._attempt_session_recovery(session, diag, server_port)
                    lib_init = self._extract_library_init_failure(diag)
                    details = {"log": diag}
                    if lib_init:
                        details["library_init"] = lib_init
                    return make_error(
                        MCPError.IDA_CRASHED,
                        f"IDA exited with code {exit_code}",
                        details=details,
                    )

                return make_error(
                    MCPError.IDA_TIMEOUT, f"IDA failed to initialize within {startup_timeout}s."
                )
            finally:
                # On any non-success return, the log handles were never
                # handed off to a registered runtime — close them so we do
                # not leak file descriptors across repeated failed starts.
                if not _handles_transferred:
                    for fh in (stdout_fh, stderr_fh):
                        try:
                            fh.close()
                        except Exception:
                            pass

    def _launch_and_wait(self, session, server_port, sanitize_env: bool = False):
            # SCRIPT_DIR is host/server/; server_script.py is at the package root.
            script_path = os.path.join(os.path.dirname(os.path.dirname(SCRIPT_DIR)), "server_script.py")
            env = os.environ.copy()
            ida_runtime_dir = self.ida_dir or os.path.dirname(self.idat_exe)
            if ida_runtime_dir:
                env["IDADIR"] = ida_runtime_dir
            env["IDA_MCP_PORT"] = str(server_port)
            session_token = secrets.token_urlsafe(32)
            env["IDA_MCP_SESSION_TOKEN"] = session_token
            env["IDA_MCP_BYPASS_SYNC"] = "1"
            env["IDA_MCP_SESSION_ID"] = session.session_id
            env["IDA_MCP_CACHE_DIR"] = self.cache_dir
            env["IDA_MCP_PRE_ANALYSIS_OPTS"] = json.dumps(session.analysis_options or {})
            opts = session.analysis_options or {}
            preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
            has_preload_request = any(k in opts and opts.get(k) is not None for k in preload_keys)
            env["IDA_MCP_FORCE_PRE_ANALYSIS_OPTS"] = "1" if has_preload_request else "0"
            # Packed .i64 databases should be opened directly as existing IDBs
            if getattr(session, "packed_idb", False):
                use_existing_idb = True
                effective_idb_path = session.binary_path
            else:
                use_existing_idb = os.path.exists(session.idb_path)
                effective_idb_path = session.idb_path
            env["IDA_MCP_USE_EXISTING_IDB"] = "1" if use_existing_idb else "0"
            if sanitize_env:
                for k in (
                    "LD_LIBRARY_PATH",
                    "DYLD_LIBRARY_PATH",
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "QT_PLUGIN_PATH",
                    "QT_QPA_PLATFORM_PLUGIN_PATH",
                ):
                    env.pop(k, None)
            sid_tag = session.session_id
            log_file = os.path.join(self.cache_dir, f"ida_mcp_{sid_tag}.log")
            stdout_log = os.path.join(self.cache_dir, f"ida_stdout_{sid_tag}.log")
            stderr_log = os.path.join(self.cache_dir, f"ida_stderr_{sid_tag}.log")

            if use_existing_idb:
                log_rpc(f"Opening existing session IDB: {effective_idb_path}")
            else:
                log_rpc(
                    f"Creating new IDB for binary: {session.binary_path} -> {session.idb_path}"
                )
                os.makedirs(os.path.dirname(session.idb_path), exist_ok=True)
            cmd = self._build_ida_command(session, log_file, script_path, use_existing_idb, effective_idb_path)

            stdout_fh = open(stdout_log, "a", encoding="utf-8")
            stderr_fh = open(stderr_log, "a", encoding="utf-8")
            _handles_transferred = False
            try:
                server_process = subprocess.Popen(
                    cmd,
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    env=env,
                    **_popen_new_session_kwargs(),
                )

                startup_timeout = int(os.environ.get("IDA_MCP_STARTUP_TIMEOUT", "90"))
                start_time = time.time()
                while time.time() - start_time < startup_timeout:
                    exit_code = server_process.poll()
                    if exit_code is not None:
                        diag = self._get_ida_diagnostics(stdout_log, stderr_log)
                        return {
                            "error": True,
                            "exit_code": exit_code,
                            "log": diag,
                            "library_init": self._extract_library_init_failure(diag),
                            "sanitize_env": sanitize_env,
                        }

                    try:
                        res = self._send_rpc_raw(
                            {"type": "ping"},
                            server_port,
                            timeout=0.5,
                            auth_token=session_token,
                        )
                        if res.get("pong"):
                            # Trust the port IDA reports (TOCTOU self-heal).
                            try:
                                actual_port = int(res.get("port") or server_port)
                            except Exception:
                                actual_port = server_port
                            log_rpc(
                                f"IDA RPC listener is ready for {session.idb_path} on port {actual_port}"
                            )
                            runtime = {
                                "process": server_process,
                                "port": actual_port,
                                "idb_path": session.idb_path,
                                "stdout_log": stdout_log,
                                "stderr_log": stderr_log,
                                "auth_token": session_token,
                                "log_handles": [stdout_fh, stderr_fh],
                            }
                            with self._runtime_lock:
                                self.session_runtimes[session.session_id] = runtime
                            self._write_runtime_lease(session.session_id, runtime)
                            _handles_transferred = True
                            return {"ok": True, "idb_path": session.idb_path, "port": actual_port}
                    except Exception:
                        pass
                    time.sleep(0.5)

                return {"error": True, "reason": "timeout"}
            finally:
                if not _handles_transferred:
                    for fh in (stdout_fh, stderr_fh):
                        try:
                            fh.close()
                        except Exception:
                            pass

    def _attempt_session_recovery(self, session, diag, server_port):
            opts = session.analysis_options or {}
            lib_init = self._extract_library_init_failure(diag)
            if opts.get("recover") is False:
                details = {"log": diag, "recovery_attempted": False}
                if lib_init:
                    details["library_init"] = lib_init
                return make_error(
                    MCPError.IDA_CRASHED,
                    "IDA failed with 'library init failed' and recovery is disabled.",
                    details=details,
                )
            if lib_init:
                log_rpc(
                    f"Detected library init failure (err={lib_init.get('error_code')}) "
                    f"causes={lib_init.get('causes')} - attempting recovery..."
                )
            else:
                log_rpc("Detected library init failure - attempting recovery...")
            self._cleanup_runtime(session.session_id)
            time.sleep(1)

            backup_path = None
            if opts.get("backup_on_recover", True):
                backup_path = self._backup_idb(session.idb_path)
            self._nuclear_reset(
                session.idb_path, aggressive=bool(opts.get("aggressive_cleanup", True))
            )

            # If the failed launch was a packed-IDB open, the cause is almost
            # always an orphan IDA process still holding the unpacked siblings
            # (.id0/.id1/.nam/.til) next to the packed file from a previous
            # crashed run. Kill those processes so the next attempt can open
            # the siblings for read/write.
            # We intentionally do NOT delete the sibling files - they are
            # IDA's working state and on a 3 GB+ IDB thrashing them on every
            # recovery wastes GB of disk I/O. If the siblings are corrupted,
            # IDA will surface the error and the user can clean manually.
            if getattr(session, "packed_idb", False) and session.binary_path:
                killed = self._terminate_ida_processes_for_path(session.binary_path)
                if killed:
                    log_rpc(
                        f"Recovery killed {len(killed)} stale IDA process(es) "
                        f"holding {session.binary_path}"
                    )

            if not session.binary_path or not os.path.exists(session.binary_path):
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    "Recovery requires the original binary path (missing or invalid).",
                    details={
                        "binary_path": session.binary_path,
                        "backup": backup_path,
                        "log": diag,
                    },
                )

            session.analysis_applied = False
            self.session_mgr._save_metadata(session)

            result = self._launch_and_wait(session, server_port)
            if "error" in result and result.get("library_init"):
                # One extra attempt with sanitized runtime env to avoid host LD/Python contamination.
                retry_result = self._launch_and_wait(
                    session, server_port, sanitize_env=True
                )
                if "error" not in retry_result:
                    result = retry_result
                else:
                    result["sanitized_retry"] = retry_result
            if "error" in result:
                details = {"log": diag, "backup": backup_path, "recovery_attempted": True}
                if lib_init:
                    details["library_init"] = lib_init
                if isinstance(result.get("sanitized_retry"), dict):
                    details["sanitized_retry"] = {
                        "exit_code": result["sanitized_retry"].get("exit_code"),
                        "library_init": result["sanitized_retry"].get("library_init"),
                    }
                return make_error(
                    MCPError.IDA_CRASHED,
                    "IDA failed to recover the session after cleanup.",
                    details=details,
                )

            runtime = self.session_runtimes.get(session.session_id)
            if runtime:
                apply_res = self._apply_session_options(session, runtime)
                if is_error_result(apply_res):
                    return apply_res
                result["current_options"] = apply_res.get("current_options")

            if backup_path:
                result["backup"] = backup_path
            return result

    def _apply_session_options(self, session, runtime):
            opts = session.analysis_options or {}
            if not opts:
                return {"ok": True}
            if session.analysis_applied and opts.get("apply_once", True):
                log_rpc(
                    f"Skipping analysis options for session {session.session_id} (already applied)"
                )
                return {
                    "ok": True,
                    "skipped": True,
                    "note": "analysis_options already applied",
                }

            port = runtime.get("port")
            if not port:
                return make_error(MCPError.IDA_CRASHED, "Missing runtime port")

            # Stream apply progress so a long create() is not a black box.
            # The MCP stdio server is serial, so a client cannot poll
            # session(status) mid-create; instead we emit live progress
            # notifications and mirror the current step into session metadata.
            apply_steps: List[Dict[str, Any]] = []

            def _progress(step: str, status: str = "start", detail: Any = None) -> None:
                try:
                    self._update_session_indexing_metadata(
                        session.session_id,
                        apply_progress={
                            "step": step,
                            "status": status,
                            "ts": time.time(),
                        },
                    )
                except Exception:
                    pass
                try:
                    params: Dict[str, Any] = {
                        "progressToken": f"apply:{session.session_id}",
                        "progress": {"step": step, "status": status},
                    }
                    if detail is not None:
                        params["progress"]["detail"] = detail
                    self._send_notification(
                        {"method": "notifications/progress", "params": params}
                    )
                except Exception:
                    pass

            def _record(step: str, res: Any) -> None:
                ok = True
                if isinstance(res, dict):
                    ok = not is_error_result(res)
                apply_steps.append({"step": step, "ok": ok})
                _progress(step, "done" if ok else "error")

            actions = []
            options_payload = {}
            if isinstance(opts.get("options"), dict):
                options_payload.update(opts.get("options") or {})
            for key in ("baseaddr", "start_ea", "min_ea", "max_ea"):
                if key in opts and opts[key] is not None:
                    options_payload[key] = opts[key]
            if options_payload:
                actions.append({"action": "set_options", "options": options_payload})

            if any(k in opts for k in ("processor", "bitness", "endian", "flags")):
                action_args = {"action": "set_architecture"}
                for k in ("processor", "bitness", "endian", "flags"):
                    if k in opts and opts[k] is not None:
                        action_args[k] = opts[k]
                actions.append(action_args)

            loader_value = opts.get("value")
            if loader_value is None and "loader_options" in opts:
                loader_value = opts.get("loader_options")
            if loader_value is not None:
                loader_args = {"action": "set_loader_options", "value": loader_value}
                if opts.get("loader"):
                    loader_args["loader"] = opts["loader"]
                actions.append(loader_args)

            extra_actions = opts.get("analysis_actions")
            if isinstance(extra_actions, list):
                for action_args in extra_actions:
                    if isinstance(action_args, dict) and action_args.get("action"):
                        actions.append(action_args)

            reanalyze = opts.get("reanalyze")

            if actions:
                _progress("apply_options", "start", detail=[a.get("action") for a in actions if isinstance(a, dict)])
            for action_args in actions:
                res = self._send_rpc_raw({"tool": "analysis", "args": action_args}, port)
                if is_error_result(res):
                    _record(action_args.get("action", "apply_options"), res)
                    return res
                _record(action_args.get("action", "apply_options"), res)

            # After setting architecture, synchronously fix segment state for
            # raw-binary/firmware loads BEFORE reanalyze or bootstrap run. IDA's
            # raw binary loader creates BSS/DATA segments that block
            # create_insn() and add_func(). This fix sets class→CODE,
            # type=SEG_CODE, perm|=SEGPERM_EXEC, bitness from opts, and T=1
            # for ARM Thumb. It MUST NOT run for native PE/ELF/Mach-O: IDA's
            # loader already types those segments correctly, and forcing
            # SEG_CODE+EXEC on data segments (or bitness=32 on a 64-bit .text)
            # breaks analysis — the latter makes Hex-Rays return MERR_ONLY64
            # (-25) for every function.
            if _is_raw_bin_load(opts):
                _progress("fix_segments", "start")
                # Map requested bitness to IDA's seg.bitness (0=16,1=32,2=64);
                # default to 32-bit for raw firmware blobs.
                _target_bitness = {16: 0, 32: 1, 64: 2}.get(
                    int(opts.get("bitness") or 32), 1
                )
                try:
                    self._send_rpc_raw({
                        "tool": "misc",
                        "args": {
                            "action": "python",
                            "code": """\
import idaapi, ida_segment, ida_segregs, idc, idautils
for seg_ea in idautils.Segments():
    seg = idaapi.getseg(seg_ea)
    if not seg:
        continue
    cur_class = ida_segment.get_segm_class(seg)
    if cur_class != "CODE":
        ida_segment.set_segm_class(seg, "CODE")
    if seg.type != idaapi.SEG_CODE:
        seg.type = idaapi.SEG_CODE
        ida_segment.update_segm(seg)
    if not (seg.perm & idaapi.SEGPERM_EXEC):
        seg.perm |= idaapi.SEGPERM_EXEC
        ida_segment.update_segm(seg)
    if hasattr(seg, 'bitness') and seg.bitness != __TARGET_BITNESS__:
        seg.bitness = __TARGET_BITNESS__
        ida_segment.update_segm(seg)
""".replace("__TARGET_BITNESS__", str(_target_bitness))
                        }
                    }, port, timeout=5)
                except Exception as e:
                    log_rpc(f"Segment fix RPC failed: {e}")
                try:
                    proc = str(opts.get('processor') or '').lower()
                    if 'arm' in proc:
                        self._send_rpc_raw({
                            "tool": "misc",
                            "args": {
                                "action": "python",
                                "code": """\
import idaapi, idc, ida_segregs, idautils
for seg_ea in idautils.Segments():
    seg = idaapi.getseg(seg_ea)
    if seg:
        try:
            idc.split_sreg_range(seg.start_ea, 'T', 1, 2)
        except Exception:
            ida_segregs.split_sreg_range(seg.start_ea, 'T', 1, 2)
"""
                            }
                        }, port, timeout=5)
                except Exception as e:
                    log_rpc(f"Thumb T=1 RPC failed: {e}")
                _record("fix_segments", {"ok": True})

            if actions and (reanalyze is None or reanalyze):
                _progress("reanalyze", "start")
                reanalyze_args = {"action": "reanalyze"}
                if opts.get("start") is not None:
                    reanalyze_args["start"] = opts.get("start")
                if opts.get("end") is not None:
                    reanalyze_args["end"] = opts.get("end")
                res = self._send_rpc_raw({"tool": "analysis", "args": reanalyze_args}, port)
                if is_error_result(res):
                    _record("reanalyze", res)
                    return res
                _record("reanalyze", res)

            bootstrap_knowledge = {"chip_family": None, "imported_symbol_count": 0}
            bootstrap_report = None
            _progress("bootstrap_knowledge", "start")
            try:
                chip_res = self._send_rpc_raw(
                    {"tool": "knowledge", "args": {"action": "chip_identify"}},
                    port,
                )
                if isinstance(chip_res, dict) and not is_error_result(chip_res):
                    prof = chip_res.get("profile")
                    if isinstance(prof, dict) and prof.get("chip_family"):
                        bootstrap_knowledge["chip_family"] = prof.get("chip_family")
                import_res = self._send_rpc_raw(
                    {
                        "tool": "knowledge",
                        "args": {
                            "action": "import_symbols",
                            "min_confidence": float(opts.get("symbol_import_min_confidence", 0.8)),
                            "limit": int(opts.get("symbol_import_limit", 200)),
                        },
                    },
                    port,
                )
                if isinstance(import_res, dict) and not is_error_result(import_res):
                    bootstrap_knowledge["imported_symbol_count"] = int(import_res.get("imported", 0) or 0)
            except Exception:
                pass
            _record("bootstrap_knowledge", {"ok": True})

            _progress("firmware_bootstrap", "start")
            try:
                chip_family = str(opts.get("chip_family") or bootstrap_knowledge.get("chip_family") or "").strip()
                if chip_family:
                    fw_args = {
                        "action": "bootstrap",
                        "chip_family": chip_family,
                        "load_base": opts.get("baseaddr"),
                        "memory_map": opts.get("memory_map") or [],
                        "peripheral_addresses": opts.get("peripheral_addresses") or [],
                        "post_load_actions": opts.get("post_load_actions") or [],
                    }
                    fw_res = self._send_rpc_raw({"tool": "firmware_view", "args": fw_args}, port)
                    if isinstance(fw_res, dict) and not is_error_result(fw_res):
                        bootstrap_report = fw_res.get("bootstrap_report") or fw_res
            except Exception:
                bootstrap_report = None
            _record("firmware_bootstrap", {"ok": True})

            if opts.get("apply_once", True):
                session.analysis_applied = True
            self.session_mgr._save_metadata(session)
            _progress("verify_architecture", "start")
            current_options = {}
            try:
                current_options = self._send_rpc_raw(
                    {"tool": "analysis", "args": {"action": "get_options"}}, port
                )
            except Exception:
                pass

            # Strict verification for architecture-sensitive loads.
            try:
                expected_proc = opts.get("processor")
                expected_bits = opts.get("bitness")
                expected_end = opts.get("endian")
                got = current_options.get("result") if isinstance(current_options, dict) else None
                if isinstance(got, dict):
                    got_proc = str(got.get("procname") or "").strip().lower()
                    got_bits = got.get("app_bitness")
                    got_be = got.get("is_be")
                    mismatches = []
                    if expected_proc is not None:
                        eproc = str(expected_proc).strip().lower()
                        if got_proc and got_proc != eproc:
                            mismatches.append(f"processor expected={eproc} got={got_proc}")
                    if expected_bits is not None:
                        try:
                            if int(got_bits) != int(expected_bits):
                                mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                        except Exception:
                            mismatches.append(f"bitness expected={expected_bits} got={got_bits}")
                    if expected_end is not None:
                        end_norm = str(expected_end).strip().lower()
                        want_be = end_norm in ("be", "big", "big_endian", "big-endian", "bigendian", "1", "true")
                        if got_be is not None and bool(got_be) != bool(want_be):
                            mismatches.append(f"endian expected={'be' if want_be else 'le'} got={'be' if bool(got_be) else 'le'}")
                    if mismatches:
                        return make_error(
                            MCPError.IDA_ERROR,
                            "Architecture preload did not stick after analysis option application",
                            details={
                                "mismatches": mismatches,
                                "expected": {"processor": expected_proc, "bitness": expected_bits, "endian": expected_end},
                                "current_options": got,
                                "hint": "Create a fresh session with architecture block and avoid reusing existing IDBs for incompatible binaries.",
                            },
                        )
            except Exception:
                pass
            _record("verify_architecture", {"ok": True})
            # Persist the apply transcript so session(status) can show what the
            # (black-box) startup actually did, and clear the live marker.
            try:
                self._update_session_indexing_metadata(
                    session.session_id,
                    apply_progress=None,
                    last_apply_steps=apply_steps,
                    last_apply_at=time.time(),
                )
            except Exception:
                pass
            return {
                "ok": True,
                "current_options": current_options if not is_error_result(current_options) else None,
                "bootstrap_knowledge": bootstrap_knowledge,
                "bootstrap_report": bootstrap_report,
                "apply_steps": apply_steps,
                "steps_done": len(apply_steps),
            }

    def _start_session_background_services(self, session, server_port: int) -> None:
            session_id = str(getattr(session, "session_id", "") or "").strip()
            if not session_id:
                return
            self._session_last_activity[session_id] = time.time()
            self._update_session_indexing_metadata(
                session_id,
                indexing_mode="hotset_idle",
                indexing_state="scheduled",
                hot_indexed_count=0,
                indexing_complete=False,
            )
            try:
                from ..analysis.analysis_engine import AnalysisEngine

                bb_path = self._session_blackboard_path(session_obj=session, sid=session_id)
                proposals_path = os.path.join(self.cache_dir, f"{session_id}.proposals.db")
                engine = AnalysisEngine(
                    session_id=session_id,
                    rpc_fn=lambda tool, args: self._send_rpc_raw(
                        {"tool": tool, "args": args}, server_port, timeout=30.0
                    ),
                    notify_fn=self._send_notification,
                    bb_path=bb_path,
                    proposals_path=proposals_path,
                    embeddings_dir=self.cache_dir,
                )
                engine.start()
                self._analysis_engines[session_id] = engine
                log_rpc(f"[idle-index] Analysis engine started for {session_id}")
            except Exception as e:
                log_rpc(f"[idle-index] Analysis engine failed to start (non-fatal): {e}")
            self._start_idle_index_worker(session_id, server_port)
            # Watchdog gives the host an honest picture of IDA's analysis
            # progress (and stalls) while the background analysis runs.
            self._start_analysis_watchdog(session_id, server_port)

    def _stop_analysis_engine(self, sid: str, join_timeout: float = 2.0) -> None:
            engine = getattr(self, "_analysis_engines", {}).pop(sid, None)
            if engine is None:
                return
            try:
                engine.stop(join_timeout=join_timeout)
            except TypeError:
                try:
                    engine.stop()
                except Exception:
                    pass
            except Exception:
                pass

    def _cleanup_runtime(self, sid):
            self._stop_idle_index_worker(sid, join_timeout=0.5)
            self._stop_analysis_watchdog(sid, join_timeout=0.5)
            self._stop_analysis_engine(sid)
            self._session_last_activity.pop(sid, None)
            self._session_inflight_calls.pop(sid, None)
            with self._runtime_lock:
                runtime = self.session_runtimes.pop(sid, None)
            self._remove_runtime_lease(sid)
            if not runtime:
                return
            proc = runtime.get("process")
            port = runtime.get("port")
            if proc:
                try:
                    self._send_rpc_raw({"type": "shutdown"}, port, timeout=1)
                except Exception:
                    pass
                # Use _kill_process_tree so the full idat.exe -> ida.exe
                # tree is terminated; otherwise ida.exe can be left
                # orphaned holding the unpacked .id0/.id1 files.
                _kill_process_tree(proc)
            for fh in runtime.get("log_handles", []):
                try:
                    fh.close()
                except Exception:
                    pass

    def _cleanup_all_runtimes(self):
            with self._runtime_lock:
                runtime_sids = list(self.session_runtimes.keys())
            for sid in runtime_sids:
                self._cleanup_runtime(sid)
            self._adopt_or_cleanup_stale_runtime_leases()

    def _resolve_session_from_idb_ref(self, idb_ref: Any) -> Optional[Session]:
            """Resolve idb references from session id, SID_* idb id/name, path, or basename."""
            from .session import Session  # lazy: break circular import
            if not isinstance(idb_ref, str):
                return None
            raw = idb_ref.strip()
            if not raw:
                return None

            sid = _normalize_session_id(raw)
            if sid:
                session = self.session_mgr.get_session(sid)
                if session:
                    return session

            base = os.path.basename(raw)
            # SID_* filenames encode the canonical 8-char session id (SESSION_ID_RE).
            sid_match = re.match(r"^SID_([A-Za-z0-9]{8})(?:_|$)", base)
            if sid_match:
                session = self.session_mgr.get_session(sid_match.group(1).upper())
                if session:
                    return session

            found = self.session_mgr.find_session_by_path(raw)
            if found:
                return found

            wanted = base.lower()
            if not wanted:
                return None
            for session in self.session_mgr.discover_sessions():
                if os.path.basename(session.idb_path or "").lower() == wanted:
                    return session
            return None
