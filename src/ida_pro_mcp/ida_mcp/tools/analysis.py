try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import ida_loader
import ida_ida


# ============================================================================
# ANALYSIS - Loader/processor options and reanalysis
# ============================================================================

@tool
@idawrite
def analysis(
    action: Annotated[Literal["get_options", "set_options", "set_processor", "set_loader_options", "set_architecture", "reanalyze"],
                      "Action: get_options|set_options|set_processor|set_loader_options|set_architecture|reanalyze"],
    options: Annotated[Optional[dict], "Options dict for set_options"] = None,
    processor: Annotated[Optional[str], "Processor name for set_processor"] = None,
    flags: Annotated[Optional[int], "Processor flags (idaapi.SETPROC_*)"] = None,
    loader: Annotated[Optional[str], "Loader name (for set_loader_options)"] = None,
    value: Annotated[Optional[Union[str, dict]], "Loader options string or dict (for set_loader_options)"] = None,
    bitness: Annotated[Optional[int], "Target bitness (16/32/64) for set_architecture"] = None,
    endian: Annotated[Optional[str], "Target endian: le|be for set_architecture"] = None,
    start: Annotated[Optional[str], "Start address for reanalysis"] = None,
    end: Annotated[Optional[str], "End address for reanalysis"] = None,
    **kwargs
) -> dict:
    """
    Control analysis options and reanalysis behavior.

    Actions:
    - get_options: Return key analysis/processor settings.
    - set_options: Set select info options (baseaddr, start_ea, min_ea, max_ea).
    - set_processor: Switch processor type.
    - set_loader_options: Apply loader-specific options string.
    - set_architecture: Update processor/bitness/endian settings.
    - reanalyze: Re-run auto-analysis over a range.
    """
    try:
        def _get_app_bitness():
            if hasattr(ida_ida, "inf_get_app_bitness"):
                try:
                    return int(ida_ida.inf_get_app_bitness())
                except Exception:
                    pass
            inf = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
            if inf and hasattr(inf, "is_64bit") and inf.is_64bit():
                return 64
            if inf and hasattr(inf, "is_32bit_exactly") and inf.is_32bit_exactly():
                return 32
            lflags = getattr(idc, "INF_LFLAGS", None)
            if lflags is not None:
                try:
                    if idc.get_inf_attr(lflags) & 0x100:
                        return 64
                except Exception:
                    pass
            return None

        def _get_loader_name():
            if hasattr(ida_loader, "get_loader_name"):
                try:
                    return ida_loader.get_loader_name()
                except TypeError:
                    pass
            input_path = None
            if hasattr(ida_nalt, "get_input_file_path"):
                input_path = ida_nalt.get_input_file_path()
            elif hasattr(idaapi, "get_input_file_path"):
                input_path = idaapi.get_input_file_path()
            if input_path and hasattr(ida_loader, "get_loader_name"):
                try:
                    return ida_loader.get_loader_name(input_path)
                except Exception:
                    pass
            return None

        if action == "get_options":
            inf = None
            if hasattr(idaapi, "get_inf_structure"):
                try:
                    inf = idaapi.get_inf_structure()
                except Exception:
                    inf = None
            def safe_inf_attr(attr, default=None):
                if inf is not None and hasattr(inf, attr):
                    return getattr(inf, attr)
                return default
            def safe_idc_attr(name, default=None):
                key = getattr(idc, name, None)
                if key is None:
                    return default
                try:
                    return idc.get_inf_attr(key)
                except Exception:
                    return default

            procname = safe_inf_attr("procname", None) or safe_idc_attr("INF_PROCNAME", "")
            filetype = safe_inf_attr("filetype", None) or safe_idc_attr("INF_FILETYPE", None)
            is_64bit = inf.is_64bit() if inf and hasattr(inf, "is_64bit") else bool(safe_idc_attr("INF_LFLAGS", 0) & 0x100)
            is_be = inf.is_be() if inf and hasattr(inf, "is_be") else (ida_ida.inf_is_be() if hasattr(ida_ida, "inf_is_be") else False)
            app_bitness = _get_app_bitness()
            loader_name = _get_loader_name()

            return {
                "ok": True,
                "procname": procname,
                "filetype": filetype,
                "is_64bit": is_64bit,
                "is_be": is_be,
                "app_bitness": app_bitness,
                "loader": loader_name,
                "start_ea": hex(idaapi.inf_get_start_ea()) if hasattr(idaapi, "inf_get_start_ea") else None,
                "min_ea": hex(idaapi.inf_get_min_ea()) if hasattr(idaapi, "inf_get_min_ea") else None,
                "max_ea": hex(idaapi.inf_get_max_ea()) if hasattr(idaapi, "inf_get_max_ea") else None,
            }

        if action == "set_options":
            if not options or not isinstance(options, dict):
                return make_error(MCPError.INVALID_ARGS, "options dict required")
            mapping = {
                "baseaddr": getattr(idc, "INF_BASEADDR", None),
                "start_ea": getattr(idc, "INF_START_EA", None),
                "min_ea": getattr(idc, "INF_MIN_EA", None),
                "max_ea": getattr(idc, "INF_MAX_EA", None),
            }
            applied = {}
            for key, val in options.items():
                if key not in mapping or mapping[key] is None:
                    continue
                try:
                    cast_val = int(val)
                except (TypeError, ValueError):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"invalid value for {key}",
                        details={"key": key, "value": val},
                    )
                try:
                    idc.set_inf_attr(mapping[key], cast_val)
                except Exception as e:
                    return make_error(
                        MCPError.IDA_ERROR,
                        str(e),
                        details={"key": key, "value": cast_val},
                    )
                applied[key] = cast_val
            return {"ok": True, "applied": applied}

        if action == "set_processor":
            if not processor:
                return make_error(MCPError.INVALID_ARGS, "processor required")
            proc_flags = flags if flags is not None else idaapi.SETPROC_LOADER
            try:
                ok = idaapi.set_processor_type(processor, proc_flags)
            except RuntimeError as e:
                return make_error(
                    MCPError.IDA_ERROR,
                    str(e),
                    hint="Processor changes must be compatible with the loaded file. For mismatched architectures, use a raw binary or select the processor before loading.",
                    details={"processor": processor, "flags": proc_flags},
                )
            return {"ok": True, "processor": processor, "result": ok}

        if action == "set_loader_options":
            if value is None:
                return make_error(MCPError.INVALID_ARGS, "value required")
            loader_name = loader or _get_loader_name()
            if not loader_name:
                return make_error(MCPError.INVALID_ARGS, "loader required (could not determine current loader)")
            if not hasattr(ida_loader, "set_loader_options"):
                return make_error(MCPError.NOT_IMPLEMENTED, "set_loader_options not supported in this IDA version")
            opts = value
            if isinstance(value, dict):
                opts = ";".join([f"{k}={v}" for k, v in value.items()])
            try:
                import inspect
                params = inspect.signature(ida_loader.set_loader_options).parameters
                if len(params) >= 3:
                    ok = ida_loader.set_loader_options(loader_name, opts, 0)
                else:
                    ok = ida_loader.set_loader_options(loader_name, opts)
            except RuntimeError as e:
                return make_error(
                    MCPError.IDA_ERROR,
                    str(e),
                    hint="Loader options must match the active loader. Verify the loader name and option string.",
                    details={"loader": loader_name, "value": opts},
                )
            except Exception:
                try:
                    ok = ida_loader.set_loader_options(loader_name, opts)
                except Exception as e:
                    return make_error(
                        MCPError.IDA_ERROR,
                        str(e),
                        details={"loader": loader_name, "value": opts},
                    )
            return {"ok": True, "loader": loader_name, "result": ok}

        if action == "set_architecture":
            if not any([processor, bitness, endian]):
                return make_error(MCPError.INVALID_ARGS, "processor, bitness, or endian required")
            applied = {}
            if processor:
                proc_flags = flags if flags is not None else idaapi.SETPROC_LOADER
                try:
                    result = idaapi.set_processor_type(processor, proc_flags)
                except RuntimeError as e:
                    return make_error(
                        MCPError.IDA_ERROR,
                        str(e),
                        hint="Processor changes must be compatible with the loaded file. For mismatched architectures, use a raw binary or select the processor before loading.",
                        details={"processor": processor, "flags": proc_flags},
                    )
                applied["processor"] = {"value": processor, "result": result}
            if bitness is not None:
                if int(bitness) not in (16, 32, 64):
                    return make_error(MCPError.INVALID_ARGS, "bitness must be 16, 32, or 64")
                if hasattr(ida_ida, "inf_set_app_bitness"):
                    try:
                        max_ea = ida_ida.inf_get_max_ea()
                    except Exception:
                        max_ea = None
                    if max_ea is not None:
                        max_allowed = (1 << int(bitness)) - 1
                        if max_ea > max_allowed:
                            return make_error(
                                MCPError.INVALID_ARGS,
                                f"bitness {bitness} too small for address space",
                                details={"max_ea": hex(max_ea), "max_allowed": hex(max_allowed)},
                            )
                    try:
                        ida_ida.inf_set_app_bitness(int(bitness))
                    except Exception as e:
                        return make_error(
                            MCPError.IDA_ERROR,
                            str(e),
                            details={"bitness": int(bitness)},
                        )
                    applied["bitness"] = int(bitness)
                else:
                    return make_error(MCPError.NOT_IMPLEMENTED, "inf_set_app_bitness not supported in this IDA version")
            if endian:
                if hasattr(ida_ida, "inf_set_be"):
                    be = str(endian).lower() in ("be", "big", "big_endian", "big-endian", "bigendian", "1", "true")
                    le = str(endian).lower() in ("le", "little", "little_endian", "little-endian", "littleendian", "0", "false")
                    if not (be or le):
                        return make_error(MCPError.INVALID_ARGS, "endian must be le|be|little|big")
                    try:
                        ida_ida.inf_set_be(be)
                    except Exception as e:
                        return make_error(
                            MCPError.IDA_ERROR,
                            str(e),
                            details={"endian": "be" if be else "le"},
                        )
                    applied["endian"] = "be" if be else "le"
                else:
                    return make_error(MCPError.NOT_IMPLEMENTED, "inf_set_be not supported in this IDA version")
            return {"ok": True, "applied": applied}

        if action == "reanalyze":
            if start and end:
                s_ea, err = validate_addr(start)
                if err: return err
                e_ea, err = validate_addr(end)
                if err: return err
            else:
                s_ea = idaapi.inf_get_min_ea()
                e_ea = idaapi.inf_get_max_ea()
            if hasattr(idaapi, "auto_mark_range"):
                idaapi.auto_mark_range(s_ea, e_ea, idaapi.AU_FINAL)
                idaapi.auto_wait()
                return {"ok": True, "start": hex(s_ea), "end": hex(e_ea)}
            return make_error(MCPError.NOT_IMPLEMENTED, "auto_mark_range not available")

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
