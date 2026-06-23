"""
IDA RPC Server
Designed for stability in IDA 9.2 headless mode.
Uses non-blocking sockets for connection handling, but tool execution remains synchronous.
"""
import sys, os, json, socket, time, select, re, hmac
import inspect
from typing import get_args, get_origin, Literal, Annotated

# HEARTBEAT
import tempfile
ALIVE_FILE = os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), "ida_mcp_heartbeat.txt")
with open(ALIVE_FILE, "w") as f: f.write(str(time.time()))

def log_ev(msg):
    with open(ALIVE_FILE, "a") as f: f.write(f"[{time.ctime()}] {msg}\n")
    print(msg)

try:
    import idc, idautils, ida_segment
    log_ev("IDA modules imported")
except Exception as e:
    log_ev(f"CRITICAL: {e}")
    sys.exit(1)

# Path Setup
script_path = os.path.abspath(__file__)
_src_root = os.path.dirname(os.path.dirname(script_path))
_pkg_root = os.path.join(_src_root, "ida_pro_mcp")
_mcp_root = os.path.join(_pkg_root, "ida_mcp")
_tools_root = os.path.join(_mcp_root, "tools")
for p in [_src_root, _pkg_root, _mcp_root, _tools_root]:
    if p not in sys.path: sys.path.insert(0, p)

# IDA_MCP_BYPASS_SYNC is set by the host runtime (server_runtime.py) when
# launching IDA. Do not force it here at module import: the env var
# disables the @idaread/@idawrite safety wrapper globally, so it should
# only be active for code paths that opt in via the bypass_sync()
# context manager in ida_mcp.sync.

TOOLS = {}
# Actual port the bridge bound to. Set in run_server(); surfaced in ping
# responses so the host can learn the real port if it had to fall back to
# an ephemeral one (TOCTOU self-heal: if the host pre-allocated port was
# taken between host-close and our bind, we bind 0 and report back).
_BOUND_PORT = None
TOOL_ALIASES = {
    # Compatibility typo used by some wrappers.
    "xfer_analysis": "graph",
    # Legacy tool consolidated into graph (xref_analysis.py kept for back-compat
    # imports but routed to graph at the runtime layer as well as host).
    "xref_analysis": "graph",
    "c2_detect": "string_ops",
    # Dispatcher advertises the tool as 'governance'; IDA-side file is
    # 'governance_engine.py' (the file is the engine implementation).
    "governance": "governance_engine",
}
_ERROR_DETAIL_LEVEL = str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
if _ERROR_DETAIL_LEVEL not in {"none", "basic", "full"}:
    _ERROR_DETAIL_LEVEL = "basic"
_SESSION_TOKEN = str(os.environ.get("IDA_MCP_SESSION_TOKEN", "") or "")
try:
    _MAX_RPC_REQUEST_BYTES = int(os.environ.get("IDA_MCP_MAX_RPC_REQUEST_BYTES", "1048576"))
except Exception:
    _MAX_RPC_REQUEST_BYTES = 1048576
_MAX_RPC_REQUEST_BYTES = max(4096, min(_MAX_RPC_REQUEST_BYTES, 64 * 1024 * 1024))


def _trim_text(text, max_len=300):
    if not isinstance(text, str):
        return text
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}...(+{len(text) - max_len} chars)"


def _compact_detail_value(value, max_items=16):
    if isinstance(value, list):
        kept = value[:max_items]
        return kept, len(value) - len(kept)
    if isinstance(value, str):
        return _trim_text(value), 0
    return value, 0


def _compact_error_details(details):
    if not details:
        return None
    if _ERROR_DETAIL_LEVEL == "full":
        return details
    if _ERROR_DETAIL_LEVEL == "none":
        return None
    if not isinstance(details, dict):
        return _trim_text(str(details))
    out = {}
    for key, value in details.items():
        if key in {"traceback", "raw_bytes", "hexdump_full", "raw_request", "raw_response"}:
            continue
        compacted, remaining = _compact_detail_value(value)
        out[key] = compacted
        if remaining > 0:
            out[f"{key}_more"] = remaining
    return out or None


def _canonical_tool_name(name):
    if not isinstance(name, str):
        return name
    return TOOL_ALIASES.get(name, name)


def _try_load_single_tool(name):
    import importlib
    import importlib.util

    canonical = _canonical_tool_name(name)
    if canonical in TOOLS:
        return TOOLS[canonical], canonical, None
    tools_dir = os.path.join(_mcp_root, "tools")
    flat_path = os.path.join(tools_dir, f"{canonical}.py")
    package_init = os.path.join(tools_dir, canonical, "__init__.py")
    module_path = None
    module_kwargs = {}
    if os.path.exists(flat_path):
        module_path = flat_path
    elif os.path.exists(package_init):
        try:
            module = importlib.import_module(f"ida_mcp.tools.{canonical}")
            if hasattr(module, canonical):
                tool_func = getattr(module, canonical)
                TOOLS[canonical] = tool_func
                return tool_func, canonical, None
            return None, canonical, f"module 'ida_mcp.tools.{canonical}' missing callable '{canonical}'"
        except Exception as e:
            return None, canonical, str(e)
    else:
        return None, canonical, f"no tool file or package: {canonical}.py"
    try:
        spec = importlib.util.spec_from_file_location(canonical, module_path, **module_kwargs)
        module = importlib.util.module_from_spec(spec)
        sys.modules[canonical] = module
        spec.loader.exec_module(module)
        if hasattr(module, canonical):
            tool_func = getattr(module, canonical)
            TOOLS[canonical] = tool_func
            return tool_func, canonical, None
        return None, canonical, f"module '{canonical}' missing callable '{canonical}'"
    except Exception as e:
        return None, canonical, str(e)


def load_tools():
    global TOOLS
    try:
        tools_dir = os.path.join(_mcp_root, "tools")
        # tools_dir is on sys.path directly; use flat importlib to avoid
        # triggering ida_mcp/__init__.py → rpc.py → zeromcp which is not
        # available in the IDA process and would crash every tool load.
        import importlib
        import importlib.util
        for f in os.listdir(tools_dir):
            if f.endswith(".py") and f != "__init__.py":
                name = f[:-3]
                try:
                    spec = importlib.util.spec_from_file_location(
                        name, os.path.join(tools_dir, f)
                    )
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[name] = module          # flat name so intra-tool imports work
                    spec.loader.exec_module(module)
                    if hasattr(module, name): TOOLS[name] = getattr(module, name)
                except Exception as e: log_ev(f"Load error {name}: {e}")
        # Register aliases only if target exists
        for alias, target in TOOL_ALIASES.items():
            if target in TOOLS:
                TOOLS[alias] = TOOLS[target]
        log_ev(f"Loaded {len(TOOLS)} tools")
    except Exception as e: log_ev(f"Tool load error: {e}")

def _extract_literal(param_type):
    origin = get_origin(param_type)
    if origin is Annotated:
        param_type = get_args(param_type)[0]
        origin = get_origin(param_type)
    if origin is Literal:
        return list(get_args(param_type))
    return None

def _tool_signature_info(tool_func):
    try:
        sig = inspect.signature(tool_func)
    except Exception:
        return {"params": [], "required": [], "actions": []}
    params = []
    required = []
    for name, p in sig.parameters.items():
        if name == "kwargs" or p.kind == inspect.Parameter.VAR_KEYWORD:
            continue
        params.append(name)
        if p.default is inspect.Parameter.empty:
            required.append(name)
    actions = []
    try:
        hints = getattr(tool_func, "__annotations__", {})
        if "action" in hints:
            actions = _extract_literal(hints["action"]) or []
    except Exception:
        actions = []
    return {"params": params, "required": required, "actions": actions}

def _suggest_choice(value, choices):
    if not value or not choices:
        return None
    try:
        from ida_pro_mcp.services import best_match
    except ImportError:
        import difflib
        matches = difflib.get_close_matches(str(value), choices, n=1, cutoff=0.6)
    else:
        matches = best_match(str(value), list(choices), n=1, cutoff=0.6)
    return matches[0] if matches else None

def _build_error(tool_name, message, code="INVALID_ARGS", details=None, hint=None):
    res = {"error": True, "code": code, "message": message}
    if hint:
        res["hint"] = hint
    if details:
        compacted = _compact_error_details(details)
        if compacted:
            res["details"] = compacted
    return res

def process_single(r):
    if not isinstance(r, dict):
        return _build_error("bridge", "Invalid request format", code="INVALID_REQUEST")
        
    if _SESSION_TOKEN:
        provided = str(r.get("session_token") or "")
        if not provided or not hmac.compare_digest(provided, _SESSION_TOKEN):
            return _build_error(
                "auth",
                "Unauthorized session token",
                code="UNAUTHORIZED",
                hint="Use the host-managed authenticated session runtime.",
            )
            
    if r.get("type") == "ping":
        # Report the actual bound port so the host can self-heal if we had
        # to fall back to an ephemeral port (the pre-allocated one was taken).
        return {"pong": True, "port": _BOUND_PORT}
        
    tool_name = r.get("tool")
    args = r.get("args", {})
    log_ev(f"Calling tool: {tool_name}")
    try:
        canonical_tool = _canonical_tool_name(tool_name)
        if canonical_tool not in TOOLS:
            loaded_tool, loaded_name, load_err = _try_load_single_tool(tool_name)
            if loaded_tool:
                canonical_tool = loaded_name
                TOOLS[tool_name] = loaded_tool
                TOOLS[canonical_tool] = loaded_tool

        if canonical_tool not in TOOLS:
            available_tools = sorted(TOOLS.keys())
            res = _build_error(
                tool_name,
                f"Tool not found: {tool_name}",
                code="TOOL_NOT_FOUND",
                details={
                    "available_tools": available_tools[:20],
                    "available_tools_more": max(0, len(available_tools) - 20),
                    "canonical_tool": canonical_tool,
                    "load_error": load_err if 'load_err' in locals() else None,
                },
            )
        else:
            tool_func = TOOLS[canonical_tool]
            siginfo = _tool_signature_info(tool_func)
            # Pre-validate action if possible
            if "action" in args and siginfo["actions"]:
                action = args.get("action")
                if action not in siginfo["actions"]:
                    suggestion = _suggest_choice(action, siginfo["actions"])
                    details = {"available_actions": siginfo["actions"]}
                    if suggestion:
                        details["suggested_action"] = suggestion
                    res = _build_error(
                        tool_name,
                        f"Unknown action: {action}",
                        details=details,
                        hint="Use a valid action for this tool.",
                    )
                else:
                    res = tool_func(**args)
            else:
                res = tool_func(**args)

            if isinstance(res, dict) and res.get("error"):
                # Augment INVALID_ARGS with available actions/args and suggestions
                if res.get("code") in ("INVALID_ARGS", "UNKNOWN_ERROR"):
                    res.setdefault("details", {})
                    details = res["details"]
                    if siginfo.get("actions"):
                        details.setdefault("available_actions", siginfo["actions"])
                        action = args.get("action")
                        if action and action not in siginfo["actions"]:
                            suggestion = _suggest_choice(action, siginfo["actions"])
                            if suggestion:
                                details.setdefault("suggested_action", suggestion)
                                res.setdefault("hint", "Use a valid action for this tool.")
                    if siginfo.get("params"):
                        details.setdefault("available_args", siginfo["params"])
                    # Missing arg hint from message
                    msg = res.get("message", "")
                    m = re.search(r"([a-zA-Z_]+) required", msg)
                    if m:
                        missing_arg = m.group(1)
                        details.setdefault("missing_arg", missing_arg)
                        details.setdefault("required_args", siginfo.get("required", []))
                        res.setdefault("hint", "Provide the missing required argument.")
        return res
    except Exception as e:
        # Attach helpful hints for common arg mistakes
        tool_func = TOOLS.get(tool_name)
        siginfo = _tool_signature_info(tool_func) if tool_func else {"params": [], "required": [], "actions": []}
        msg = str(e)
        details = {"available_args": siginfo.get("params", [])}
        hint = None

        # Unexpected keyword argument
        m = re.search(r"unexpected keyword argument '([^']+)'", msg)
        if m:
            bad_arg = m.group(1)
            suggestion = _suggest_choice(bad_arg, siginfo.get("params", []))
            details["unexpected_arg"] = bad_arg
            if suggestion:
                details["suggested_arg"] = suggestion
            hint = "Remove the unexpected argument or use the suggested name."

        # Missing required positional argument
        m = re.search(r"missing .* required positional argument: '([^']+)'", msg)
        if m:
            missing_arg = m.group(1)
            details["required_args"] = siginfo.get("required", [])
            details["missing_arg"] = missing_arg
            hint = "Provide the missing required argument."

        return _build_error(tool_name, msg, details=details, hint=hint)

def run_server():
    global _BOUND_PORT
    port = int(os.environ.get("IDA_MCP_PORT", 13337))
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    # Bind with ephemeral fallback. The host pre-allocates a free port and
    # hands it to us via IDA_MCP_PORT, but there is a TOCTOU window between
    # the host closing its probe socket and our bind. If the port was taken
    # in that window, fall back to an ephemeral port (0) and report the
    # actual bound port back to the host in the ping response so it can
    # route subsequent RPCs to the right place instead of failing.
    bound_port = None
    for try_port in (port, 0):
        try:
            server_sock.bind(('127.0.0.1', try_port))
            bound_port = server_sock.getsockname()[1]
            break
        except OSError as e:
            if try_port == 0:
                raise
            log_ev(f"Port {try_port} unavailable ({e}); falling back to ephemeral")
    _BOUND_PORT = bound_port
    server_sock.listen(1)
    log_ev(f"Listening on {bound_port}")

    while True:
        conn = None
        try:
            # Poll for new connection
            readable, _, _ = select.select([server_sock], [], [], 0.05)
            if not readable:
                time.sleep(0.01)
                continue
                
            conn, _ = server_sock.accept()
            conn.settimeout(5.0) # 5s timeout for the actual request data
            log_ev("Connection accepted")
            
            raw_len = conn.recv(4)
            if not raw_len:
                continue
                
            length = int.from_bytes(raw_len, 'big')
            if length <= 0 or length > _MAX_RPC_REQUEST_BYTES:
                res = _build_error(
                    "bridge",
                    f"Invalid request size: {length}",
                    code="REQUEST_TOO_LARGE",
                    details={"max_bytes": _MAX_RPC_REQUEST_BYTES},
                    hint="Reduce payload size or increase IDA_MCP_MAX_RPC_REQUEST_BYTES for trusted local sessions.",
                )
                resp_json = json.dumps(res, separators=(",", ":")).encode("utf-8")
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
                continue
            data = b""
            while len(data) < length:
                chunk = conn.recv(min(length - len(data), 4096))
                if not chunk: break
                data += chunk
            if len(data) != length:
                res = _build_error(
                    "bridge",
                    "Truncated request body",
                    code="INVALID_REQUEST",
                    details={"expected": length, "received": len(data)},
                    hint="Ensure full request payload is sent with proper length prefix.",
                )
                resp_json = json.dumps(res, separators=(",", ":")).encode("utf-8")
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
                continue
                
            req = json.loads(data.decode('utf-8'))
            
            if isinstance(req, list):
                res = [process_single(r) for r in req]
            else:
                res = process_single(req)
                
            resp_json = json.dumps(res, separators=(",", ":")).encode('utf-8')
            conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
            
            log_ev("Request finished")
        except socket.timeout: log_ev("Socket timeout")
        except KeyboardInterrupt: break
        except Exception as e: log_ev(f"Loop error: {e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception as _e:
                    log_ev(f"Socket close failed: {_e}")

def _apply_pre_analysis_options():
    """Apply processor/bitness/endian/loader_options BEFORE auto-analysis."""
    raw = os.environ.get("IDA_MCP_PRE_ANALYSIS_OPTS", "{}")
    try:
        opts = json.loads(raw)
    except Exception:
        return
    if not opts:
        return

    # Skip for existing IDBs unless the host explicitly requests forced
    # pre-analysis application (used for architecture-sensitive firmware sessions).
    if os.environ.get("IDA_MCP_USE_EXISTING_IDB") == "1" and os.environ.get("IDA_MCP_FORCE_PRE_ANALYSIS_OPTS") != "1":
        return

    import idaapi
    import ida_ida
    import ida_loader

    processor = opts.get("processor")
    bitness = opts.get("bitness")
    endian = opts.get("endian")
    loader = opts.get("loader")
    loader_options = opts.get("value") or opts.get("loader_options")
    flags = opts.get("flags")

    changed = []
    warnings_list = []

    # Normalize architecture aliases via shared host helper when available.
    try:
        from ida_pro_mcp.services import normalize_arch_options as _norm_arch
        _norm, _meta = _norm_arch(
            {
                "processor": processor,
                "bitness": bitness,
                "endian": endian,
                "loader": loader,
                "value": loader_options,
                "flags": flags,
            }
        )
        processor = _norm.get("processor")
        bitness = _norm.get("bitness")
        endian = _norm.get("endian")
        loader = _norm.get("loader")
        loader_options = _norm.get("value") or _norm.get("loader_options")
        flags = _norm.get("flags")
    except Exception:
        # Fallback: keep prior values unchanged.
        pass

    # Processor
    if processor:
        try:
            current = ""
            if hasattr(idaapi, "get_inf_structure"):
                try:
                    inf = idaapi.get_inf_structure()
                    current = getattr(inf, "procname", "") if inf else ""
                except Exception as _e:
                    log_ev(f"get_inf_structure failed: {_e}")
            if current != processor:
                proc_flags = flags if flags is not None else getattr(
                    idaapi, "SETPROC_LOADER_NON_FATAL", idaapi.SETPROC_LOADER
                )
                ok = idaapi.set_processor_type(processor, proc_flags)
                changed.append(f"processor={processor} (ok={ok})")
            else:
                changed.append(f"processor={processor} (already set)")
        except Exception as e:
            warnings_list.append(f"processor={processor}: {e}")

    # Bitness
    if bitness is not None:
        try:
            if hasattr(ida_ida, "inf_set_app_bitness"):
                ida_ida.inf_set_app_bitness(int(bitness))
                changed.append(f"bitness={bitness}")
            else:
                warnings_list.append("inf_set_app_bitness unavailable")
        except Exception as e:
            warnings_list.append(f"bitness={bitness}: {e}")

    # Endian
    if endian:
        try:
            if hasattr(ida_ida, "inf_set_be"):
                be = str(endian).lower() in (
                    "be", "big", "big_endian", "big-endian", "bigendian", "1", "true"
                )
                le = str(endian).lower() in (
                    "le", "little", "little_endian", "little-endian", "littleendian", "0", "false"
                )
                if be or le:
                    ida_ida.inf_set_be(be)
                    changed.append(f"endian={'be' if be else 'le'}")
                else:
                    warnings_list.append(f"endian={endian}: invalid value")
            else:
                warnings_list.append("inf_set_be unavailable")
        except Exception as e:
            warnings_list.append(f"endian={endian}: {e}")

    # Loader options (best-effort before auto_wait)
    if loader_options and loader:
        try:
            if hasattr(ida_loader, "set_loader_options"):
                opts_str = loader_options
                if isinstance(opts_str, dict):
                    opts_str = ";".join(f"{k}={v}" for k, v in opts_str.items())
                ok = ida_loader.set_loader_options(loader, opts_str)
                changed.append(f"loader_options={ok}")
            else:
                warnings_list.append("set_loader_options unavailable")
        except Exception as e:
            warnings_list.append(f"loader_options: {e}")

    # Raw binary / firmware fix: set ALL segments to CODE and fix bitness.
    # IDA's raw binary loader creates BSS/DATA segments by default which
    # block instruction creation. Ensure every segment is CODE and 32-bit
    # when an ARM or firmware processor is loaded.
    proc_lower = str(processor or "").lower()
    is_firmware_arch = proc_lower in ("arm", "mips", "mipsl", "mipsb", "ppc", "ppcl", "tricore", "rx", "v850", "rl78", "stm8")
    if is_firmware_arch:
        try:
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                try:
                    cur_class = ida_segment.get_segm_class(seg)
                    if cur_class != "CODE":
                        ida_segment.set_segm_class(seg, "CODE")
                        changed.append(f"segment_class={cur_class}→CODE")
                except Exception as _e:
                    log_ev(f"set_segm_class failed for {hex(seg.start_ea)}: {_e}")
                try:
                    if seg.type != idaapi.SEG_CODE:
                        seg.type = idaapi.SEG_CODE
                        ida_segment.update_segm(seg)
                        changed.append("SEG_CODE type set")
                except Exception as _e:
                    log_ev(f"SEG_CODE type set failed for {hex(seg.start_ea)}: {_e}")
                try:
                    if not (seg.perm & idaapi.SEGPERM_EXEC):
                        seg.perm |= idaapi.SEGPERM_EXEC
                        ida_segment.update_segm(seg)
                        changed.append("SEGPERM_EXEC added")
                except Exception as _e:
                    log_ev(f"SEGPERM_EXEC set failed for {hex(seg.start_ea)}: {_e}")
                if bitness == 32:
                    try:
                        if hasattr(seg, "bitness") and seg.bitness != 1:
                            seg.bitness = 1
                            ida_segment.update_segm(seg)
                            changed.append("segment_bitness=32")
                    except Exception as _e:
                        try:
                            ida_segment.set_segm_addressing(seg, 1)
                            changed.append("segment_addressing=32bit")
                        except Exception as _e2:
                            log_ev(f"segment bitness set failed for {hex(seg.start_ea)}: {_e} / {_e2}")
            # ARM Cortex-M Thumb: set T=1 globally on all segments
            if "arm" in proc_lower:
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if seg:
                        try:
                            sr_auto = getattr(idc, "SR_auto", 2)
                            idc.split_sreg_range(seg.start_ea, "T", 1, sr_auto)
                            changed.append(f"T=1 set for {hex(seg.start_ea)}")
                        except Exception as _e:
                            log_ev(f"T=1 split_sreg_range fallback failed for {hex(seg.start_ea)}: {_e}")
        except Exception:
            log_ev("Segment fix failed (non-fatal)")

    if changed:
        log_ev(f"Pre-analysis options applied: {', '.join(changed)}")
    if warnings_list:
        log_ev(f"Pre-analysis warnings: {', '.join(warnings_list)}")


if __name__ == "__main__":
    _apply_pre_analysis_options()
    # Start server immediately — do NOT block on auto-analysis.
    # IDA continues analyzing in background; the server answers queries
    # as they come. Complex tools (decompile) may internally wait.
    log_ev("Starting server immediately (auto-analysis runs in background)...")
    load_tools()
    run_server()
