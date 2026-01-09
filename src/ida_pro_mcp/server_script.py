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
ALIVE_FILE = os.path.join(os.environ.get("TEMP", "C:\\temp"), "ida_mcp_heartbeat.txt")
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
        res["details"] = details
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
                    if tool_name not in TOOLS:
                        res = _build_error(
                            tool_name,
                            f"Tool not found: {tool_name}",
                            code="TOOL_NOT_FOUND",
                            details={"available_tools": sorted(TOOLS.keys())},
                        )
                    else:
                        tool_func = TOOLS[tool_name]
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
                
                resp_json = json.dumps(res).encode('utf-8')
                conn.sendall((len(resp_json)).to_bytes(4, 'big') + resp_json)
            
            conn.close()
            log_ev("Request finished")
        except socket.timeout: log_ev("Socket timeout")
        except KeyboardInterrupt: break
        except Exception as e: log_ev(f"Loop error: {e}")

if __name__ == "__main__":
    # Wait for IDA auto-analysis to complete before starting server
    log_ev("Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    log_ev("Auto-analysis complete!")
    
    load_tools()
    run_server()
