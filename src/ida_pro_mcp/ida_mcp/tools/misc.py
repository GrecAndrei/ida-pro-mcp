import traceback

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

@tool
def misc(
    action: Literal["python", "idc", "load_sig", "cache_stats", "read_file", "write_file"] = "python",
    expr: Optional[str] = None,
    code: Optional[str] = None,
    name: Optional[str] = None,
    path: Annotated[Optional[str], "File path for read_file/write_file"] = None,
    content: Annotated[Optional[str], "Content to write for write_file"] = None,
    encoding: Annotated[Optional[str], "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data."] = None,
) -> Any:
    """
    Miscellaneous utility tools for IDA.

    Actions:
    - python: Execute Python code in IDA context (use 'expr' or 'code')
    - idc: Execute IDC script (use 'expr' or 'code')
    - load_sig: Load a FLIRT signature by name
    - cache_stats: Show read-only tool cache statistics
    - read_file: Read a file from the host filesystem. Returns text content (utf-8 by default)
      or hex-encoded bytes if encoding='binary'. Params: path, encoding (optional)
    - write_file: Write content to a file on the host filesystem. Writes text (utf-8 by default)
      or decodes hex content if encoding='binary'. Params: path, content, encoding (optional)
    """
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
    if action == "cache_stats":
        try:
            from ida_mcp.cache import TOOL_CACHE
            return {"ok": True, **TOOL_CACHE.stats()}
        except ImportError:
            try:
                from cache import TOOL_CACHE
                return {"ok": True, **TOOL_CACHE.stats()}
            except ImportError:
                return {"ok": True, "message": "Cache not available"}
    if action == "read_file":
        if not path:
            return {"error": True, "message": "path required for read_file"}
        import os as _os
        try:
            resolved = _os.path.normpath(_os.path.abspath(path))
            if not _os.path.exists(resolved):
                return {"error": True, "message": f"File not found: {resolved}"}
            if not _os.path.isfile(resolved):
                return {"error": True, "message": f"Not a file: {resolved}"}
            enc = (encoding or "utf-8").strip().lower()
            if enc == "binary":
                with open(resolved, "rb") as f:
                    data = f.read()
                return {"ok": True, "path": resolved, "size": len(data), "content": data.hex(), "encoding": "binary"}
            else:
                with open(resolved, "r", encoding=enc, errors="replace") as f:
                    text = f.read()
                return {"ok": True, "path": resolved, "size": len(text), "content": text, "encoding": enc}
        except Exception:
            return {"error": True, "message": traceback.format_exc()}
    if action == "write_file":
        if not path:
            return {"error": True, "message": "path required for write_file"}
        if content is None:
            return {"error": True, "message": "content required for write_file"}
        import os as _os
        try:
            resolved = _os.path.normpath(_os.path.abspath(path))
            # Ensure parent directory exists
            parent = _os.path.dirname(resolved)
            if parent and not _os.path.exists(parent):
                _os.makedirs(parent, exist_ok=True)
            enc = (encoding or "utf-8").strip().lower()
            if enc == "binary":
                data = bytes.fromhex(content)
                with open(resolved, "wb") as f:
                    f.write(data)
                return {"ok": True, "path": resolved, "size": len(data), "encoding": "binary"}
            else:
                with open(resolved, "w", encoding=enc) as f:
                    f.write(content)
                return {"ok": True, "path": resolved, "size": len(content), "encoding": enc}
        except ValueError as ve:
            return {"error": True, "message": f"Invalid hex content for binary mode: {ve}"}
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
