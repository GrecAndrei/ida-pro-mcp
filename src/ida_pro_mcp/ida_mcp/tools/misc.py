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
    action: Literal["python", "idc", "load_sig", "list_sigs", "cache_stats", "read_file", "write_file", "plugin_list", "plugin_run", "health", "reload"] = "python",
    expr: Optional[str] = None,
    code: Optional[str] = None,
    name: Optional[str] = None,
    path: Annotated[Optional[str], "File path for read_file/write_file"] = None,
    content: Annotated[Optional[str], "Content to write for write_file"] = None,
    encoding: Annotated[Optional[str], "File encoding (default: utf-8). Use 'binary' for hex-encoded binary data."] = None,
    arg: Annotated[Optional[int], "Plugin argument for plugin_run"] = None,
    verbose: Annotated[Optional[bool], "Include per-runtime details for health action."] = None,
    module: Annotated[Optional[str], "Module to reload (for reload action, e.g. 'funcs')"] = None,
    modules: Annotated[Optional[str], "Comma-separated module list to reload (for reload action, e.g. 'funcs,search')"] = None,
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
    - reload: Re-import IDA-side tool modules without restarting. Pick up source
      changes instantly. Params: module (single name, e.g. 'funcs') or modules
      (comma-separated, e.g. 'funcs,search'). Use 'all' to reload every module
      in the tools package.
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
            # Plan and apply signature
            ida_libfuncs.plan_to_apply_ldes(name)
            # Try to trigger immediate application
            applied = False
            try:
                if hasattr(ida_libfuncs, "apply_ldes"):
                    ida_libfuncs.apply_ldes(name)
                    applied = True
                elif hasattr(ida_libfuncs, "apply_idasgn"):
                    ida_libfuncs.apply_idasgn(name)
                    applied = True
            except Exception:
                pass
            return {"ok": True, "name": name, "applied": applied,
                    "note": "Signature applied immediately" if applied else "Signature queued for auto-analysis. Run analysis(reanalyze) to apply."}
        except Exception as e:
            return handle_error(e, context="load_sig")
    if action == "list_sigs":
        try:
            import glob
            import os
            sig_dir = os.path.join(idaapi.idadir(""), "sig")
            pattern = (name or "").lower()
            sigs = []
            for path in sorted(glob.glob(os.path.join(sig_dir, "**", "*.sig"), recursive=True)):
                basename = os.path.splitext(os.path.basename(path))[0]
                if not pattern or pattern in basename.lower():
                    sigs.append({"name": basename, "path": path})
            # Also list currently applied signatures
            applied = [idaapi.get_idasgn_desc(i) for i in range(idaapi.get_idasgn_qty())]
            return {"ok": True, "available": sigs, "applied": applied,
                    "total": len(sigs), "total_applied": len(applied)}
        except Exception as e:
            return handle_error(e, context="list_sigs")
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
    if action == "reload":
        target = module or modules
        if not target:
            return make_error(
                MCPError.MISSING_REQUIRED_ARG,
                "module or modules param required for reload",
                hint="Use module='funcs' or modules='funcs,search'",
            )
        names = [n.strip() for n in target.split(",") if n.strip()]
        if names == ["all"]:
            from ida_mcp.tools import __all__ as _all_mods
            names = list(_all_mods)
        return {"ok": True, "reloaded": _reload_tools(names)}
    return make_error(
        MCPError.ACTION_NOT_FOUND,
        f"Unknown action: {action}",
        details={"provided": action},
        hint="Valid actions: python, idc, load_sig, cache_stats, read_file, write_file, plugin_list, plugin_run, health, reload",
    )

def _server_tools_registries(mod_name: str):
    """Find dicts that serve as the RPC server's TOOLS registry.

    ``server_script.load_tools()`` stores direct references to the loaded
    tool functions in a module-global ``TOOLS`` dict.  Reloading a module
    without re-pointing that dict keeps serving the *old* function object
    (with its old action Literal), which is why naive ``importlib.reload``
    appears to do nothing.  Return every matching dict so the caller can
    re-point them all.
    """
    import sys as _sys
    found = []
    for m in list(_sys.modules.values()):
        if m is None:
            continue
        try:
            tools = getattr(m, "TOOLS", None)
        except Exception:
            continue
        if isinstance(tools, dict) and mod_name in tools:
            found.append(tools)
    return found


def _reload_tool_module(mod_name: str):
    """Re-execute one tool module from source and re-point the server's
    TOOLS registry at the freshly loaded function.

    Flat tool files are re-executed under the same name/loader the RPC
    server uses at startup (``load_tools``), so intra-tool flat imports
    keep working.  Package tools (``search`` etc.) are reloaded under
    their package-qualified name via ``importlib.reload``.
    """
    import importlib
    import importlib.util
    import sys as _sys

    full_name = f"ida_mcp.tools.{mod_name}"
    flat = _sys.modules.get(mod_name)
    pkg = _sys.modules.get(full_name)
    mod = pkg or flat
    if mod is None:
        importlib.import_module(full_name)
        mod = _sys.modules.get(full_name) or _sys.modules.get(mod_name)
        status = "imported"
    else:
        status = "reloaded"

    if mod is None:
        return {"module": mod_name, "status": "error", "error": "module not importable"}

    file_path = getattr(mod, "__file__", None)
    is_package = bool(file_path) and str(file_path).endswith(os.path.join("tools", mod_name, "__init__.py"))
    if not is_package and file_path:
        spec = importlib.util.spec_from_file_location(mod_name, file_path)
        new_mod = importlib.util.module_from_spec(spec)
        _sys.modules[mod_name] = new_mod
        spec.loader.exec_module(new_mod)
    else:
        importlib.reload(mod)
        new_mod = mod

    result = {"module": mod_name, "status": status}
    new_tool = getattr(new_mod, mod_name, None)
    if new_tool is None:
        result["note"] = "no matching tool function on module"
        return result
    registries = _server_tools_registries(mod_name)
    for registry in registries:
        registry[mod_name] = new_tool
    if registries:
        result["note"] = f"server TOOLS registry updated ({len(registries)} dict(s))"
    return result


def _reload_tools(names):
    """Run the reload for a list of tool names; used by misc(action='reload')."""
    results = []
    for mod_name in names:
        if mod_name == "misc":
            results.append({"module": "misc", "status": "skipped", "note": "misc reloads itself on next call (avoid self-reload deadlock)"})
            continue
        try:
            results.append(_reload_tool_module(mod_name))
        except Exception as e:
            results.append({"module": mod_name, "status": "error", "error": str(e)})
    return results



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
