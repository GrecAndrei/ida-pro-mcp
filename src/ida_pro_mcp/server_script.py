"""
Truly Non-Blocking IDA Server
Designed for maximum stability in IDA 9.2 Headless.
Uses non-blocking sockets to ensure IDA main thread never hangs.
"""
import sys, os, json, socket, traceback, time, select, re
import inspect
import difflib
from typing import get_args, get_origin, Literal, Annotated

# HEARTBEAT
import tempfile
ALIVE_FILE = os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), "ida_mcp_heartbeat.txt")
with open(ALIVE_FILE, "w") as f: f.write(str(time.time()))

def log_ev(msg):
    with open(ALIVE_FILE, "a") as f: f.write(f"[{time.ctime()}] {msg}\n")
    print(msg)

try:
    import idaapi, idc, ida_auto
    log_ev("IDA modules imported")
except Exception as e:
    log_ev(f"CRITICAL: {e}")
    sys.exit(1)

# Path Setup
script_path = os.path.abspath(__file__)
_src_root = os.path.dirname(os.path.dirname(script_path))
_pkg_root = os.path.join(_src_root, "ida_pro_mcp")
_mcp_root = os.path.join(_pkg_root, "ida_mcp")
for p in [_src_root, _pkg_root, _mcp_root]:
    if p not in sys.path: sys.path.insert(0, p)

os.environ["IDA_MCP_BYPASS_SYNC"] = "1"

TOOLS = {}
TOOL_ALIASES = {
    # Compatibility typo used by some wrappers.
    "xfer_analysis": "xref_analysis",
    "c2_detect": "string_ops",
}
_ERROR_DETAIL_LEVEL = str(os.environ.get("IDA_MCP_ERROR_DETAIL_LEVEL", "basic")).strip().lower()
if _ERROR_DETAIL_LEVEL not in {"none", "basic", "full"}:
    _ERROR_DETAIL_LEVEL = "basic"


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

    canonical = _canonical_tool_name(name)
    if canonical in TOOLS:
        return TOOLS[canonical], canonical, None
    try:
        module = importlib.import_module(f"ida_mcp.tools.{canonical}")
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
        import importlib
        for f in os.listdir(tools_dir):
            if f.endswith(".py") and f != "__init__.py":
                name = f[:-3]
                try:
                    module = importlib.import_module(f"ida_mcp.tools.{name}")
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
    matches = difflib.get_close_matches(str(value), choices, n=1, cutoff=0.6)
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

def run_server():
    port = int(os.environ.get("IDA_MCP_PORT", 13337))
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setblocking(False)
    server_sock.bind(('127.0.0.1', port))
    server_sock.listen(1)
    log_ev(f"Listening on {port}")

    while True:
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
                conn.close()
                continue
                
            length = int.from_bytes(raw_len, 'big')
            data = b""
            while len(data) < length:
                chunk = conn.recv(min(length - len(data), 4096))
                if not chunk: break
                data += chunk
                
            req = json.loads(data.decode('utf-8'))
            
            if req.get("type") == "ping":
                resp = b'{"pong":true}'
                conn.sendall((len(resp)).to_bytes(4, 'big') + resp)
            else:
                tool_name = req.get("tool")
                args = req.get("args", {})
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

                    res = _build_error(tool_name, msg, details=details, hint=hint)
                
                resp_json = json.dumps(res, separators=(",", ":")).encode('utf-8')
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
            
            conn.close()
            log_ev("Request finished")
        except socket.timeout: log_ev("Socket timeout")
        except KeyboardInterrupt: break
        except Exception as e: log_ev(f"Loop error: {e}")

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

    # Normalize common architecture aliases used by MCP/LLMs.
    if processor is not None:
        ptxt = str(processor).strip().lower()
        proc_aliases = {
            "aarch64": "arm",
            "arm64": "arm",
            "armv8": "arm",
            "x64": "metapc",
            "x86_64": "metapc",
            "amd64": "metapc",
            "x86": "metapc",
            "i386": "metapc",
            "i686": "metapc",
            "mipsel": "mipsl",
            "mipseb": "mipsb",
            "ppc": "powerpc",
        }
        processor = proc_aliases.get(ptxt, ptxt)
        if bitness is None:
            implied_bits = {
                "aarch64": 64,
                "arm64": 64,
                "armv8": 64,
                "x64": 64,
                "x86_64": 64,
                "amd64": 64,
                "x86": 32,
                "i386": 32,
                "i686": 32,
                "mipsel": 32,
                "mipseb": 32,
            }.get(ptxt)
            if implied_bits is not None:
                bitness = implied_bits

    # Processor
    if processor:
        try:
            current = ""
            if hasattr(idaapi, "get_inf_structure"):
                try:
                    inf = idaapi.get_inf_structure()
                    current = getattr(inf, "procname", "") if inf else ""
                except Exception:
                    pass
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
