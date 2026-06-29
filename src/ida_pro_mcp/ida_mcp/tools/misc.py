try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


def read_file_impl(path: str, encoding: Optional[str] = None) -> dict:
    """Shared filesystem read implementation for misc/project actions."""
    import os as _os
    try:
        resolved, path_err = validate_path_safe(path)
        if path_err:
            return path_err
        if not _os.path.exists(resolved):
            return make_error(
                MCPError.FILE_NOT_FOUND,
                f"File not found: {resolved}",
                details={"path": resolved},
            )
        if not _os.path.isfile(resolved):
            return make_error(
                MCPError.INVALID_FILE_FORMAT,
                f"Not a file: {resolved}",
                details={"path": resolved},
            )
        enc = (encoding or "utf-8").strip().lower()
        if enc == "binary":
            with open(resolved, "rb") as f:
                data = f.read()
            return {"ok": True, "path": resolved, "size": len(data), "content": data.hex(), "encoding": "binary"}
        with open(resolved, encoding=enc, errors="replace") as f:
            text = f.read()
        return {"ok": True, "path": resolved, "size": len(text), "content": text, "encoding": enc}
    except OSError as e:
        return make_error(
            MCPError.FILE_READ_ERROR,
            f"Read failed: {resolved}",
            details={"path": resolved, "errno": e.errno, "strerror": e.strerror or str(e)},
        )
    except Exception as e:
        return handle_error(e, context="read_file")


def write_file_impl(path: str, content: str, encoding: Optional[str] = None) -> dict:
    """Shared filesystem write implementation for misc/project actions."""
    import os as _os
    try:
        resolved, path_err = validate_path_safe(path)
        if path_err:
            return path_err
        parent = _os.path.dirname(resolved)
        if parent and not _os.path.exists(parent):
            _os.makedirs(parent, exist_ok=True)
        enc = (encoding or "utf-8").strip().lower()
        if enc == "binary":
            data = bytes.fromhex(content)
            with open(resolved, "wb") as f:
                f.write(data)
            return {"ok": True, "path": resolved, "size": len(data), "encoding": "binary"}
        with open(resolved, "w", encoding=enc) as f:
            f.write(content)
        return {"ok": True, "path": resolved, "size": len(content), "encoding": enc}
    except ValueError as ve:
        return make_error(
            MCPError.FILE_ENCODING_ERROR,
            f"Invalid hex content for binary mode: {ve}",
            details={"path": path, "encoding": "binary"},
        )
    except OSError as e:
        return make_error(
            MCPError.FILE_WRITE_ERROR,
            f"Write failed: {resolved}",
            details={"path": resolved, "errno": e.errno, "strerror": e.strerror or str(e)},
        )
    except Exception as e:
        return handle_error(e, context="write_file")


@tool
def misc(
    action: Literal["python", "idc", "load_sig", "cache_stats", "read_file", "write_file", "plugin_list", "plugin_run", "health"] = "python",
    expr: Optional[str] = None,
    code: Optional[str] = None,
    name: Optional[str] = None,
    path: Annotated[Optional[str], "File path for read_file/write_file"] = None,
    content: Annotated[Optional[str], "Content to write for write_file"] = None,
    encoding: Annotated[Optional[str], "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data."] = None,
    arg: Annotated[Optional[int], "Plugin argument for plugin_run"] = None,
    verbose: Annotated[Optional[bool], "Include per-runtime details for health action."] = None,
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
    - plugin_list: List discovered IDA plugins (filesystem-based)
    - plugin_run: Run an IDA plugin by name. Params: name, arg (optional)
    - health: Return host/IDA diagnostics. Params: verbose (optional)
    """
    if action == "python":
        # Support both 'expr' and 'code' for backward compatibility
        err = require_one_of(expr=expr, code=code)
        if err:
            return err
        script = expr if expr else code
        result = execute_python(script)
        if isinstance(result, dict) and result.get("error"):
            return result
        if isinstance(result, dict):
            out = {"ok": True, **result}
            out.setdefault("output", "")
            out.setdefault("result", None)
            if out.get("output") == "" and out.get("result") is None:
                out["note"] = "Script executed with no stdout and no expression result"
            return out
        return {"ok": True, "output": "", "result": None}
    if action == "idc":
        err = require_one_of(expr=expr, code=code)
        if err:
            return err
        script = expr if expr else code
        try:
            import idc
            res = idc.eval_idc(script)
            return {"ok": True, "result": res}
        except Exception as e:
            return handle_error(e, context="idc")
    if action == "load_sig":
        err = require_arg(name, "name")
        if err:
            return err
        try:
            import ida_libfuncs
            ida_libfuncs.plan_to_apply_ldes(name)
            return {"ok": True, "name": name, "note": "Signature application planned"}
        except Exception as e:
            return handle_error(e, context="load_sig")
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
        err = require_arg(path, "path")
        if err:
            return err
        return read_file_impl(path, encoding=encoding)
    if action == "write_file":
        err = require_arg(path, "path")
        if err:
            return err
        # content is optional (None means "not provided"). Empty strings are
        # allowed so callers can create zero-byte files.
        if content is None:
            return make_error(
                MCPError.MISSING_REQUIRED_ARG,
                "'content' parameter is required for write_file",
                hint="Provide the 'content' parameter (use '' for empty files).",
            )
        return write_file_impl(path, content, encoding=encoding)
    if action == "plugin_list":
        try:
            import pathlib

            import ida_loader
            plugin_dirs = []
            try:
                idadir = os.environ.get("IDADIR")
                if idadir:
                    plugin_dirs.append(os.path.join(idadir, "plugins"))
            except Exception:
                pass
            try:
                idausr = os.environ.get("IDAUSR") or os.path.join(pathlib.Path.home(), ".idapro")
                plugin_dirs.append(os.path.join(str(idausr), "plugins"))
            except Exception:
                pass
            discovered = []
            seen = set()
            exts = (".py", ".pyc", ".p64", ".plw", ".dll", ".so", ".dylib")
            for d in plugin_dirs:
                if not d or not os.path.isdir(d):
                    continue
                try:
                    for entry in os.listdir(d):
                        if not entry.lower().endswith(exts):
                            continue
                        full = os.path.join(d, entry)
                        key = os.path.realpath(full)
                        if key in seen:
                            continue
                        seen.add(key)
                        discovered.append({"name": entry, "path": full})
                except Exception:
                    continue
            return {
                "ok": True,
                "plugins": sorted(discovered, key=lambda x: x["name"].lower()),
                "count": len(discovered),
                "note": "Filesystem-based plugin listing (runtime enumeration API not available in this IDA build).",
            }
        except Exception as e:
            return handle_error(e, context="plugin_list")
    if action == "plugin_run":
        err = require_arg(name, "name")
        if err:
            return err
        try:
            import ida_loader
            plugin = ida_loader.find_plugin(name, True)
            if plugin in (None, -1):
                return make_error(
                    MCPError.PLUGIN_NOT_FOUND,
                    f"Plugin not found: {name}",
                    details={"name": name},
                    hint="Use misc(action='plugin_list') to see available plugins.",
                )
            if ida_loader.run_plugin(plugin, arg or 0):
                return {"ok": True, "name": name}
            return make_error(
                MCPError.PLUGIN_ERROR,
                f"Failed to run plugin: {name}",
                details={"name": name, "arg": arg},
            )
        except Exception as e:
            return handle_error(e, context="plugin_run")
    if action == "health":
        try:
            import platform
            info = {
                "ok": True,
                "ida_version": idaapi.get_kernel_version(),
                "python_version": platform.python_version(),
                "platform": platform.platform(),
            }
            if verbose:
                info["ida_path"] = idaapi.get_ida_subdir("") or ""
                info["cwd"] = os.getcwd()
            return info
        except Exception as e:
            return handle_error(e, context="health")
    return make_error(
        MCPError.ACTION_NOT_FOUND,
        f"Unknown action: {action}",
        details={"provided": action},
        hint="Valid actions: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health",
    )

_MAX_SCRIPT_LENGTH = 50000


@idawrite
def execute_python(script: str):
    """Executes Python code in IDA context and returns stdout/stderr."""
    if len(script) > _MAX_SCRIPT_LENGTH:
        return make_error(
            MCPError.SIZE_LIMIT_EXCEEDED,
            f"Script exceeds max length ({len(script)} > {_MAX_SCRIPT_LENGTH})",
            details={"length": len(script), "max": _MAX_SCRIPT_LENGTH},
            hint="Split the script into smaller chunks or reduce its size before submission.",
        )
    output = io.StringIO()
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = output
    sys.stderr = output

    # Use a copy of module globals to prevent pollution of live namespace
    _safe_globals = globals().copy()

    try:
        # Multi-line or compound statements should go straight to exec.
        if "\n" in script or ";" in script:
            exec(script, _safe_globals)
            return {"output": output.getvalue(), "result": None}

        try:
            res = eval(script, _safe_globals)
            if res is not None:
                print(res)
        except SyntaxError:
            exec(script, _safe_globals)
            res = None
        return {"output": output.getvalue(), "result": res}
    except SyntaxError as e:
        line = getattr(e, "lineno", None)
        offset = getattr(e, "offset", None)
        return make_error(
            MCPError.SCRIPT_ERROR,
            f"SyntaxError: {e.msg}",
            details={"line": line, "offset": offset, "text": e.text, "kind": "SyntaxError"},
            hint="Use action=python with 'code' for multi-line scripts.",
        )
    except Exception as e:
        return handle_error(e, context="execute_python")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
