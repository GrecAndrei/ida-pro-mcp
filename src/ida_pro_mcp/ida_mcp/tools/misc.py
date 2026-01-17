from typing import Annotated, Optional, Literal, Union, Any
import sys
import io
import traceback

try:
    from rpc import tool, unsafe
    from sync import idawrite
    from error_handling import handle_error
except ImportError:
    from ..rpc import tool, unsafe
    from ..sync import idawrite
    from ..error_handling import handle_error

@tool
def misc(
    action: Literal["python", "idc", "load_sig"] = "python",
    expr: Optional[str] = None,
    code: Optional[str] = None,
    name: Optional[str] = None
) -> Any:
    """Miscellaneous utility tools for IDA."""
    if action == "python":
        # Support both 'expr' and 'code' for backward compatibility
        script = expr if expr else code
        if not script:
            return {"error": True, "message": "expr or code required"}
        result = execute_python(script)
        if isinstance(result, dict) and result.get("error"):
            return result
        return {"ok": True, **result}
    if action == "idc":
        script = expr if expr else code
        if not script:
            return {"error": True, "message": "expr or code required"}
        try:
            import idc
            res = idc.eval_idc(script)
            return {"ok": True, "result": res}
        except Exception:
            return {"error": True, "message": traceback.format_exc()}
    if action == "load_sig":
        if not name:
            return {"error": True, "message": "name required"}
        try:
            import ida_libfuncs
            ida_libfuncs.plan_to_apply_ldes(name)
            return {"ok": True, "name": name, "note": "Signature application planned"}
        except Exception:
            return {"error": True, "message": traceback.format_exc()}
    return {"error": True, "message": f"Unknown action: {action}"}

@idawrite
def execute_python(script: str):
    """Executes Python code in IDA context and returns stdout/stderr."""
    output = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = output
    sys.stderr = output
    
    try:
        # Multi-line or compound statements should go straight to exec.
        if "\n" in script or ";" in script:
            exec(script, globals())
            return {"output": output.getvalue()}

        try:
            res = eval(script, globals())
            if res is not None:
                print(res)
        except SyntaxError:
            exec(script, globals())
        return {"output": output.getvalue()}
    except SyntaxError as e:
        line = getattr(e, "lineno", None)
        offset = getattr(e, "offset", None)
        return {
            "error": True,
            "message": f"SyntaxError: {e.msg}",
            "details": {"line": line, "offset": offset, "text": e.text},
            "hint": "Use action=python with 'code' for multi-line scripts.",
        }
    except Exception:
        return {"error": True, "message": traceback.format_exc()}
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
