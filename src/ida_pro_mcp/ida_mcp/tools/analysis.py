try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import contextlib
import hashlib
import json
import os
import tempfile
import time

import ida_ida
import ida_loader
import ida_segment
import ida_entry

# ============================================================================
# ANALYSIS - Loader/processor options and reanalysis
# ============================================================================

@tool
@idawrite
def analysis(
    action: Annotated[Literal["get_options", "set_options", "set_processor", "set_loader_options", "set_architecture", "reanalyze", "run", "analyze", "state", "set_gp", "save_idb", "make_code", "undefine", "get_af", "set_af", "force_offset"],
                      "Action: get_options|set_options|set_processor|set_loader_options|set_architecture|reanalyze|analyze|state|set_gp|save_idb|make_code|undefine|get_af|set_af|force_offset"],
    options: Annotated[Optional[dict], "Options dict for set_options"] = None,
    processor: Annotated[Optional[str], "Processor name for set_processor"] = None,
    flags: Annotated[Optional[int], "Processor flags (idaapi.SETPROC_*)"] = None,
    loader: Annotated[Optional[str], "Loader name (for set_loader_options)"] = None,
    value: Annotated[Optional[Union[str, dict]], "Loader options string or dict (for set_loader_options)"] = None,
    bitness: Annotated[Optional[int], "Target bitness (16/32/64) for set_architecture"] = None,
    endian: Annotated[Optional[str], "Target endian: le|be for set_architecture"] = None,
    start: Annotated[Optional[str], "Start address for reanalysis or make_code/undefine/force_offset range start"] = None,
    end: Annotated[Optional[str], "End address for reanalysis or make_code/undefine range end (optional)"] = None,
    gp: Annotated[Optional[str], "RISC-V global pointer value as hex string (for set_gp action), e.g. '0x2556f0'"] = None,
    addr: Annotated[Optional[str], "Target address for make_code, undefine, force_offset (hex string)"] = None,
    size: Annotated[Optional[int], "Number of bytes for make_code/undefine/force_offset (default: auto)"] = None,
    af_flag: Annotated[Optional[str], "Analysis flag name (AF_* constant name) for get_af/set_af, e.g. 'AF_MARKCODE'"] = None,
    af_value: Annotated[Optional[bool], "Flag value (true/false) for set_af"] = None,
    path: Annotated[Optional[str], "IDB save path for save_idb (default: current IDB path)"] = None,
    **kwargs
) -> dict:
    """
    Control analysis options, reanalysis, and on-the-fly IDB management.

    Actions:
    - get_options: Return key analysis/processor settings.
    - set_options: Set select info options (baseaddr, start_ea, min_ea, max_ea).
    - set_processor: Switch processor type.
    - set_loader_options: Apply loader-specific options string.
    - set_architecture: Update processor/bitness/endian settings.
    - reanalyze: Re-run auto-analysis over a range (add blocking=true to wait).
    - state: Check analysis progress (non-blocking).
    - set_gp: RISC-V only. Set the global pointer (GP / x3) value so the processor
        plugin resolves GP-relative data references and creates correct xrefs.
        Params: gp (REQUIRED, hex string e.g. "0x2556f0"). Triggers reanalysis.
    - save_idb: Save the current IDB to disk. Use path= to save to a specific file.
        Without path= saves in place (equivalent to Ctrl+W in IDA GUI).
    - make_code: Force bytes at addr to be disassembled as code. Deletes any existing
        data item first, then creates an instruction. Optionally reanalyzes the
        function containing addr. Use when IDA marked an address as data or UNK
        but you know it is code (missed entry point, tail call, obfuscated branch).
        Params: addr (REQUIRED), size (optional, default auto-detect from disasm).
    - undefine: Undefine (turn to raw bytes) a range starting at addr. Removes
        code/data annotations so the area can be reinterpreted.
        Params: addr (REQUIRED), size (optional, default: item size at addr).
    - get_af: Read one or all IDA analysis flags (AF_*). Use af_flag= to read a
        specific flag (e.g. "AF_MARKCODE"), or omit to get all flags and their values.
    - set_af: Enable or disable a specific IDA analysis flag. Triggers no reanalysis
        by itself — combine with reanalyze if needed.
        Params: af_flag (REQUIRED, e.g. "AF_TRACING"), af_value (REQUIRED, bool).
    - force_offset: Tell IDA a value at addr is a pointer/offset (creates xref).
        Params: addr (REQUIRED), size optional (4 or 8 bytes, default: address size).
    """
    try:
        inf = None
        try:
            if hasattr(idaapi, "get_inf_structure"):
                inf = idaapi.get_inf_structure()
        except Exception:
            inf = None

        def _get_app_bitness():
            if hasattr(ida_ida, "inf_get_app_bitness"):
                try:
                    return int(ida_ida.inf_get_app_bitness())
                except Exception:
                    pass
            return 64 if _inf_is_64bit() else 32

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
            procname = _inf_procname()
            filetype = _inf_filetype_id()
            is_64bit = _inf_bitness() == 64
            is_be = _inf_is_be()
            app_bitness = _get_app_bitness()
            loader_name = _get_loader_name()

            # Resolve the effective file type — same logic as idb_meta() so both tools agree.
            ft_name = _filetype_name(filetype)
            ft_effective = ft_name
            ft_note = None
            return {
                "ok": True,
                "procname": procname,
                "processor": procname,
                "file_type_info": {
                    "loader": ft_name,
                    "loader_id": filetype,
                    "effective": ft_effective,
                    "note": ft_note,
                },
                "is_64bit": is_64bit,
                "is_be": is_be,
                "app_bitness": app_bitness,
                "bitness": app_bitness,
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
            requested_baseaddr = None
            # Snapshot the current base BEFORE mutating any attribute. The
            # rebase delta must be computed against the pre-change state:
            # setting INF_BASEADDR first would make delta always 0, so the
            # segments would stay at the old base while INF_BASEADDR claimed
            # the new one — a silent desync of every address in the database.
            current_baseaddr = None
            if mapping.get("baseaddr") is not None:
                try:
                    if hasattr(idc, "get_inf_attr"):
                        current_baseaddr = int(idc.get_inf_attr(mapping["baseaddr"]))
                except Exception:
                    current_baseaddr = None
                if current_baseaddr is None:
                    try:
                        if hasattr(ida_ida, "inf_get_baseaddr"):
                            current_baseaddr = int(ida_ida.inf_get_baseaddr() or 0)
                    except Exception:
                        current_baseaddr = None

            for key, val in options.items():
                if key not in mapping or mapping[key] is None:
                    continue
                try:
                    cast_val = int(val, 0) if isinstance(val, str) else int(val)
                except (TypeError, ValueError):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"invalid value for {key}",
                        details={"key": key, "value": val},
                    )
                if key == "baseaddr":
                    # Handled below: rebase_program moves segments and updates
                    # INF_BASEADDR itself. Setting the attribute first would
                    # corrupt the delta computation.
                    requested_baseaddr = cast_val
                    continue
                try:
                    idc.set_inf_attr(mapping[key], cast_val)
                except Exception as e:
                    return make_error(
                        MCPError.IDA_ERROR,
                        str(e),
                        details={"key": key, "value": cast_val},
                    )
                applied[key] = cast_val

            if requested_baseaddr is not None:
                current_base = current_baseaddr if current_baseaddr is not None else 0
                delta = requested_baseaddr - int(current_base or 0)
                if delta != 0:
                    # rebase_program refuses non-page-aligned deltas (it
                    # returns 0 / throws). Surface the constraint up front
                    # instead of returning a generic "failed to rebase".
                    if delta % 0x1000:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "Failed to rebase program: the baseaddr delta must be page-aligned (multiple of 0x1000)",
                            details={
                                "requested_baseaddr": hex(requested_baseaddr),
                                "current_baseaddr": hex(int(current_base or 0)),
                                "delta": delta,
                            },
                        )
                    rebased = False
                    rebase_errors = []
                    for rebase_fn in (
                        getattr(idc, "rebase_program", None),
                        getattr(idaapi, "rebase_program", None),
                        getattr(ida_segment, "rebase_program", None),
                    ):
                        if not callable(rebase_fn):
                            continue
                        for flags in (
                            0,
                            getattr(idc, "MSF_FIXONCE", 0) | getattr(idc, "MSF_SILENT", 0),
                        ):
                            try:
                                result = rebase_fn(delta, flags)
                                rebased = bool(result) or result is None
                                if rebased:
                                    break
                            except Exception as e:
                                rebase_errors.append(str(e))
                        if rebased:
                            break
                    if not rebased:
                        return make_error(
                            MCPError.IDA_ERROR,
                            "Failed to rebase program to requested baseaddr",
                            details={
                                "requested_baseaddr": hex(requested_baseaddr),
                                "current_baseaddr": hex(int(current_base or 0)),
                                "delta": delta,
                                "errors": rebase_errors[:3],
                            },
                        )
                applied["baseaddr"] = requested_baseaddr
            return {"ok": True, "applied": applied}

        if action == "set_processor":
            if not processor:
                return make_error(MCPError.INVALID_ARGS, "processor required")
            proc_flags = flags if flags is not None else getattr(
                idaapi, "SETPROC_LOADER_NON_FATAL", idaapi.SETPROC_LOADER
            )
            inf = None
            try:
                if hasattr(idaapi, "get_inf_structure"):
                    inf = idaapi.get_inf_structure()
            except Exception:
                inf = None
            prev = ""
            with contextlib.suppress(Exception):
                prev = getattr(inf, "procname", "") if inf else ""
            if prev == processor:
                return {
                    "ok": True,
                    "processor": processor,
                    "previous": prev,
                    "result": True,
                    "note": "already set",
                }
            try:
                ok = idaapi.set_processor_type(processor, proc_flags)
            except RuntimeError as e:
                return make_error(
                    MCPError.IDA_ERROR,
                    str(e),
                    hint="Processor changes must be compatible with the loaded file. For mismatched architectures, use a raw binary or select the processor before loading.",
                    details={"processor": processor, "flags": proc_flags, "previous": prev},
                )
            return {"ok": True, "processor": processor, "previous": prev, "result": ok}

        if action == "set_gp":
            if not gp:
                return make_error(MCPError.INVALID_ARGS, "gp parameter required (e.g. gp='0x2556f0')")
            if not is_riscv_family():
                return make_error(
                    MCPError.INVALID_ARGS,
                    "set_gp is only valid for RISC-V targets",
                    details={"processor": _inf_procname()},
                    hint="Check the current processor with analysis(action='get_options').",
                )
            try:
                gp_int = int(str(gp).strip(), 16) if str(gp).startswith("0x") else int(str(gp).strip(), 0)
            except ValueError:
                return make_error(MCPError.INVALID_ARGS, f"invalid gp value: {gp!r} — expected hex string like '0x2556f0'")
            try:
                from ida_pro_mcp.ida_mcp.support.arch_utils import set_riscv_gp
            except ImportError:
                from arch_utils import set_riscv_gp  # type: ignore[import-not-found]
            return set_riscv_gp(gp_int)

        if action == "set_loader_options":
            if value is None:
                return make_error(MCPError.INVALID_ARGS, "value required")
            loader_name = loader or _get_loader_name()
            if not loader_name:
                return make_error(MCPError.INVALID_ARGS, "loader required (could not determine current loader)")
            opts = value
            if isinstance(value, dict):
                opts = ";".join([f"{k}={v}" for k, v in value.items()])
            if not hasattr(ida_loader, "set_loader_options"):
                # Soft fallback: persist the requested loader options in runtime metadata.
                cache_root = os.environ.get("IDA_MCP_CACHE_DIR") or tempfile.gettempdir()
                fallback_dir = os.path.join(cache_root, "analysis_fallback")
                os.makedirs(fallback_dir, exist_ok=True)
                key_src = f"{loader_name}|{opts}|{idaapi.get_input_file_path() if hasattr(idaapi, 'get_input_file_path') else ''}"
                key = hashlib.sha1(key_src.encode("utf-8", errors="ignore")).hexdigest()[:10]
                out_path = os.path.join(fallback_dir, f"loader_options_{key}.json")
                payload = {
                    "loader": loader_name,
                    "value": opts,
                    "time": time.time(),
                    "input_file": idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else None,
                }
                try:
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)
                except Exception:
                    out_path = None
                return {
                    "ok": True,
                    "loader": loader_name,
                    "result": False,
                    "fallback": "soft_saved",
                    "fallback_path": out_path,
                    "note": "Loader options API unavailable; saved requested options for host/runtime replay.",
                }
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
            warnings_list = []
            prev = ""
            with contextlib.suppress(Exception):
                prev = getattr(inf, "procname", "") if inf else ""
            if processor:
                proc_flags = flags if flags is not None else getattr(
                    idaapi, "SETPROC_LOADER_NON_FATAL", idaapi.SETPROC_LOADER
                )
                if prev == processor:
                    applied["processor"] = {
                        "value": processor,
                        "previous": prev,
                        "result": True,
                        "note": "already set",
                    }
                else:
                    try:
                        result = idaapi.set_processor_type(processor, proc_flags)
                    except RuntimeError as e:
                        return make_error(
                            MCPError.IDA_ERROR,
                            str(e),
                            hint="Processor changes must be compatible with the loaded file. For mismatched architectures, use a raw binary or select the processor before loading.",
                            details={"processor": processor, "flags": proc_flags, "previous": prev},
                        )
                    applied["processor"] = {"value": processor, "previous": prev, "result": result}
            if bitness is not None:
                if int(bitness) not in (16, 32, 64):
                    return make_error(MCPError.INVALID_ARGS, "bitness must be 16, 32, or 64")
                current_bitness = _get_app_bitness()
                if current_bitness == int(bitness):
                    applied["bitness"] = {"value": int(bitness), "note": "already set"}
                elif hasattr(ida_ida, "inf_set_app_bitness"):
                    try:
                        max_ea = ida_ida.inf_get_max_ea()
                    except Exception:
                        max_ea = None
                    if max_ea is not None:
                        max_allowed = (1 << int(bitness)) - 1
                        if max_ea > max_allowed:
                            warnings_list.append(
                                f"bitness {bitness} may truncate addresses (max_ea={hex(max_ea)} > {hex(max_allowed)})"
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
                    if warnings_list:
                        applied["bitness_warnings"] = warnings_list
                else:
                    applied["bitness_requested"] = int(bitness)
                    applied["bitness_applied"] = False
                    applied["bitness_note"] = "inf_set_app_bitness unavailable in this IDA build"
            if endian:
                if hasattr(ida_ida, "inf_set_be"):
                    be = str(endian).lower() in ("be", "big", "big_endian", "big-endian", "bigendian", "1", "true")
                    le = str(endian).lower() in ("le", "little", "little_endian", "little-endian", "littleendian", "0", "false")
                    if not (be or le):
                        return make_error(MCPError.INVALID_ARGS, "endian must be le|be|little|big")
                    current_be = None
                    with contextlib.suppress(Exception):
                        current_be = ida_ida.inf_is_be() if hasattr(ida_ida, "inf_is_be") else None
                    if current_be is not None and current_be == be:
                        applied["endian"] = {"value": "be" if be else "le", "note": "already set"}
                    else:
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
                    applied["endian_requested"] = str(endian)
                    applied["endian_applied"] = False
                    applied["endian_note"] = "inf_set_be unavailable in this IDA build"
            # Auto-configure arch-aware tool defaults
            arch_hints = {}
            proc_lower = str(applied.get("processor", {}).get("value", "") if isinstance(applied.get("processor"), dict) else applied.get("processor", "")).lower()
            if "arm" in proc_lower or "thumb" in proc_lower:
                arch_hints["disasm_note"] = "ARM/Thumb: use annotate_branches=true for branch target resolution. Thumb mode detected by IDA automatically."
                arch_hints["default_int_width"] = 4
                arch_hints["ptr_size"] = 4
            elif "mips" in proc_lower:
                arch_hints["disasm_note"] = "MIPS: branch delay slots are normal. Use annotate_branches=true for jump targets."
                arch_hints["default_int_width"] = 4
                arch_hints["ptr_size"] = 4
            elif "x86" in proc_lower and "64" in str(bitness or _get_app_bitness()):
                arch_hints["ptr_size"] = 8
                arch_hints["default_int_width"] = 4
            elif "x86" in proc_lower:
                arch_hints["ptr_size"] = 4
                arch_hints["default_int_width"] = 4
            elif "ppc" in proc_lower or "power" in proc_lower:
                arch_hints["disasm_note"] = "PowerPC: use annotate_branches=true. Conditional branches use CR fields."
                arch_hints["ptr_size"] = 4
            if arch_hints:
                applied["arch_hints"] = arch_hints
            return {"ok": True, "applied": applied}

        if action in ("reanalyze", "run", "analyze"):
            # start without end (or vice versa) silently fell through to a
            # whole-image reanalysis and reported success — reject it.
            if bool(start) != bool(end):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "start and end must be provided together for reanalyze (or both omitted for whole-image)",
                )
            if start and end:
                s_ea, err = validate_addr(start)
                if err: return err
                e_ea, err = validate_addr(end)
                if err: return err
            else:
                s_ea = idaapi.inf_get_min_ea()
                e_ea = idaapi.inf_get_max_ea()


            # Schedule analysis (non-blocking by default). Use plan_range or
            # auto_mark_range (fire-and-forget) so IDA's idle loop picks up the
            # work after this RPC call returns.
            #
            # When the caller does NOT supply an explicit range, we route
            # through _auto_reanalyze_text_segments() instead of blindly
            # scheduling plan_range(min_ea, max_ea). The whole-image default
            # is a no-op on stripped ARM64 ELF binaries: the loader creates
            # 8-byte PLT stubs for the dynamic symbols but never enqueues
            # analysis for .text, so plan_range over the full range returns
            # immediately with the queue empty and coverage stays 0%.
            mode = "none"
            range_label = None
            if start and end:
                import ida_auto as _ida_auto
                if hasattr(_ida_auto, "plan_range"):
                    _ida_auto.plan_range(s_ea, e_ea)
                    mode = "plan_range"
                elif hasattr(_ida_auto, "auto_mark_range"):
                    _ida_auto.auto_mark_range(s_ea, e_ea, _ida_auto.AU_FINAL)
                    mode = "auto_mark_range"
                elif hasattr(idaapi, "auto_mark_range"):
                    idaapi.auto_mark_range(s_ea, e_ea, idaapi.AU_FINAL)
                    mode = "idaapi.auto_mark_range"
                range_label = "explicit"
            # `pump` is accepted in TOOL_ARG_SCHEMAS as a blocking alias; honor it.
            blocking = kwargs.get("blocking") or kwargs.get("wait") or kwargs.get("pump") or False
            poll_timeout = 10.0
            if "poll_timeout" in kwargs and kwargs["poll_timeout"] is not None:
                poll_timeout = float(kwargs["poll_timeout"] or 0.0)
            # The poll budget must fit safely inside the host RPC recv
            # deadline (IDA_MCP_RPC_TIMEOUT, default 30s).
            poll_timeout = max(0.0, min(poll_timeout, 25.0))
            waited = 0.0
            rean = None
            if blocking and not start:
                # Whole-image reanalyze: use the smarter helper that targets
                # only the eligible executable segments (skips PLT/INIT/FINI
                # and the tiny LOAD trampolines) and waits for the auto
                # analyzer to actually drain.
                rean = _auto_reanalyze_text_segments(
                    wait_seconds=max(poll_timeout, 0.5)
                )
                # Ensure JNI / ELF exports become functions even if the
                # auto-analyzer failed to trace into them.
                ep = _ensure_entry_point_functions()
                waited = float(rean.get("waited_seconds") or 0.0)
                mode = "auto_reanalyze_text_segments"
                range_label = "eligible_text"
                if ep.get("created"):
                    rean["entry_point_funcs_created"] = ep
            elif blocking:
                # Explicit range: poll auto_is_ok() for the budget.
                start_time = time.time()
                import ida_auto as _ida_auto
                if hasattr(idaapi, "auto_is_ok") and bool(idaapi.auto_is_ok()):
                    waited = time.time() - start_time
                elif hasattr(_ida_auto, "auto_wait"):
                    _ida_auto.auto_wait()
                    waited = time.time() - start_time
                else:
                    while time.time() - start_time < poll_timeout:
                        analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else True
                        if analysis_ok:
                            break
                        time.sleep(0.2)
                        waited += 0.2
            try:
                func_count = sum(1 for _ in idautils.Functions())
            except Exception:
                func_count = 0
            boot = {"seeded_entries": 0}
            # Only seed entry points for raw blobs (no known file format).
            # ELF/PE/Mach-O loaders handle this themselves.
            _is_raw = False
            try:
                if hasattr(idaapi, "get_inf_structure"):
                    _is_raw = idaapi.get_inf_structure().filetype in (
                        getattr(idaapi, "f_BIN", 0), getattr(idaapi, "f_BINARY", 0)
                    )
            except Exception:
                _is_raw = False
            if func_count == 0 and _is_raw:
                boot = _bootstrap_raw_entry_points(s_ea, e_ea)
            analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else False
            try:
                func_count = sum(1 for _ in idautils.Functions())
            except Exception:
                func_count = 0
            result = {
                "ok": True,
                "start": hex(s_ea),
                "end": hex(e_ea),
                "mode": mode,
                "range_source": range_label,
                "analysis_complete": analysis_ok,
                "functions": func_count,
                "note": "Analysis scheduled (non-blocking). Check session(action='status') for analysis state.",
                **boot,
            }
            if blocking:
                if rean is not None and isinstance(rean, dict):
                    result["reanalyze"] = rean
                result["blocking_waited"] = round(waited, 2)
                result["note"] = "Analysis ran blocking. Ready to query."
            return result

        if action == "state":
            # Lightweight read-only check of analysis progress.
            analysis_ok = True
            try:
                if hasattr(idaapi, "get_auto_state"):
                    analysis_ok = int(idaapi.get_auto_state()) == int(
                        getattr(idaapi, "AU_NONE", 0)
                    )
                elif hasattr(idaapi, "auto_is_ok"):
                    analysis_ok = bool(idaapi.auto_is_ok())
            except Exception:
                analysis_ok = True
            func_count = -1
            try:
                func_count = idaapi.get_func_qty() if hasattr(idaapi, "get_func_qty") else -1
            except Exception:
                pass
            return {
                "ok": True,
                "analysis_complete": analysis_ok,
                "functions": func_count,
                "note": "Analysis complete." if analysis_ok else "Analysis still running.",
            }

        if action == "save_idb":
            import ida_loader as _ida_loader
            save_path = path or ""
            try:
                _ida_loader.save_database(save_path, 0)
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"save_database failed: {e}")
            actual_path = save_path or (idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else "")
            return {"ok": True, "saved_to": actual_path or "<current idb>"}

        if action == "make_code":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            import ida_bytes as _ida_bytes
            import ida_ua as _ida_ua
            import ida_funcs as _ida_funcs
            # Undefine whatever is sitting at the address.
            item_sz = max(1, idc.get_item_size(ea) if hasattr(idc, "get_item_size") else 1)
            clear_sz = size if size and size > 0 else item_sz
            try:
                _ida_bytes.del_items(ea, _ida_bytes.DELIT_SIMPLE, clear_sz)
            except Exception:
                pass
            # Create instruction.
            insn_len = 0
            try:
                insn_len = _ida_ua.create_insn(ea)
            except Exception:
                pass
            if insn_len == 0:
                try:
                    insn_len = idc.create_insn(ea)
                except Exception:
                    pass
            if insn_len == 0:
                return make_error(MCPError.IDA_ERROR, f"create_insn failed at {hex(ea)} — processor may not recognize bytes as a valid instruction")
            # If the address is inside a function, requeue that function for analysis.
            func = _ida_funcs.get_func(ea) if hasattr(_ida_funcs, "get_func") else None
            requeued = False
            if func:
                try:
                    import ida_auto as _ida_auto
                    _ida_auto.auto_mark_range(func.start_ea, func.end_ea, _ida_auto.AU_FINAL)
                    requeued = True
                except Exception:
                    pass
            return {
                "ok": True,
                "addr": hex(ea),
                "insn_len": insn_len,
                "requeued_func": requeued,
                "note": "Instruction created. If no function contains this address, consider funcs(action='create', addr=...) next.",
            }

        if action == "undefine":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            import ida_bytes as _ida_bytes
            item_sz = max(1, idc.get_item_size(ea) if hasattr(idc, "get_item_size") else 1)
            clear_sz = size if size and size > 0 else item_sz
            try:
                _ida_bytes.del_items(ea, _ida_bytes.DELIT_SIMPLE, clear_sz)
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"del_items failed: {e}")
            return {"ok": True, "addr": hex(ea), "cleared_bytes": clear_sz}

        if action == "get_af":
            # Collect all IDA AF_* constants and their current values.
            # IDA 7.x stores analysis flags in inf.af / inf.af2.
            # IDA 9.x exposes ida_ida.inf_get_af() and inf_get_af2().
            af_names: dict[str, int] = {}
            for name in dir(idc):
                if name.startswith(("AF_", "AF2_")):
                    val = getattr(idc, name, None)
                    if isinstance(val, int):
                        af_names[name] = val
            if not af_names:
                for name in dir(idaapi):
                    if name.startswith(("AF_", "AF2_")):
                        val = getattr(idaapi, name, None)
                        if isinstance(val, int):
                            af_names[name] = val

            def _get_current_af() -> int:
                for fn_name in ("inf_get_af",):
                    fn = getattr(idaapi, fn_name, None) or getattr(__import__("ida_ida", fromlist=[fn_name]), fn_name, None)
                    if callable(fn):
                        try:
                            return int(fn())
                        except Exception:
                            pass
                try:
                    _inf = idaapi.get_inf_structure()
                    if _inf and hasattr(_inf, "af"):
                        return int(_inf.af)
                except Exception:
                    pass
                return 0

            def _get_current_af2() -> int:
                for fn_name in ("inf_get_af2",):
                    fn = getattr(idaapi, fn_name, None)
                    if fn is None:
                        try:
                            fn = getattr(__import__("ida_ida", fromlist=[fn_name]), fn_name, None)
                        except Exception:
                            fn = None
                    if callable(fn):
                        try:
                            return int(fn())
                        except Exception:
                            pass
                try:
                    _inf = idaapi.get_inf_structure()
                    if _inf and hasattr(_inf, "af2"):
                        return int(_inf.af2)
                except Exception:
                    pass
                return 0

            current_af = _get_current_af()
            current_af2 = _get_current_af2()

            if af_flag:
                flag_upper = af_flag.upper()
                flag_val = af_names.get(flag_upper) or af_names.get(flag_upper.replace("IDA_", ""))
                if flag_val is None:
                    return make_error(MCPError.INVALID_ARGS, f"Unknown AF flag: {af_flag!r}. Use get_af without af_flag= to list all known flags.")
                is_af2 = flag_upper.startswith("AF2_")
                current_bits = current_af2 if is_af2 else current_af
                return {
                    "ok": True,
                    "flag": flag_upper,
                    "bit": hex(flag_val),
                    "enabled": bool(current_bits & flag_val),
                }

            # Return all flags with current state.
            result_flags: dict[str, dict] = {}
            for name, bit in sorted(af_names.items()):
                is_af2 = name.startswith("AF2_")
                current_bits = current_af2 if is_af2 else current_af
                result_flags[name] = {"bit": hex(bit), "enabled": bool(current_bits & bit)}
            return {
                "ok": True,
                "af_raw": hex(current_af),
                "af2_raw": hex(current_af2),
                "flags": result_flags,
            }

        if action == "set_af":
            if not af_flag:
                return make_error(MCPError.INVALID_ARGS, "af_flag required (e.g. 'AF_MARKCODE')")
            if af_value is None:
                return make_error(MCPError.INVALID_ARGS, "af_value required (true or false)")
            flag_upper = af_flag.upper()
            bit = None
            for ns in (idc, idaapi):
                candidate = getattr(ns, flag_upper, None)
                if isinstance(candidate, int):
                    bit = candidate
                    break
            if bit is None:
                return make_error(MCPError.INVALID_ARGS, f"Unknown AF flag: {af_flag!r}. Use get_af to list known flags.")
            is_af2 = flag_upper.startswith("AF2_")

            def _get_af_raw(af2: bool) -> int:
                attr = "af2" if af2 else "af"
                fn_name = "inf_get_af2" if af2 else "inf_get_af"
                for ns in (idaapi, __import__("ida_ida")):
                    fn = getattr(ns, fn_name, None)
                    if callable(fn):
                        try:
                            return int(fn())
                        except Exception:
                            pass
                try:
                    _inf = idaapi.get_inf_structure()
                    if _inf and hasattr(_inf, attr):
                        return int(getattr(_inf, attr))
                except Exception:
                    pass
                return 0

            def _set_af_raw(af2: bool, new_val: int) -> bool:
                fn_name = "inf_set_af2" if af2 else "inf_set_af"
                attr = "af2" if af2 else "af"
                for ns in (idaapi, __import__("ida_ida")):
                    fn = getattr(ns, fn_name, None)
                    if callable(fn):
                        try:
                            fn(new_val)
                            return True
                        except Exception:
                            pass
                try:
                    _inf = idaapi.get_inf_structure()
                    if _inf and hasattr(_inf, attr):
                        setattr(_inf, attr, new_val)
                        return True
                except Exception:
                    pass
                return False

            old_bits = _get_af_raw(is_af2)
            if af_value:
                new_bits = old_bits | bit
            else:
                new_bits = old_bits & ~bit
            ok = _set_af_raw(is_af2, new_bits)
            if not ok:
                return make_error(MCPError.IDA_ERROR, f"Could not set {flag_upper} — inf_set_af not available in this IDA build")
            return {
                "ok": True,
                "flag": flag_upper,
                "bit": hex(bit),
                "previous": bool(old_bits & bit),
                "current": bool(new_bits & bit),
                "note": "Flag set. Use analysis(action='reanalyze') if you want to re-run analysis with the new setting.",
            }

        if action == "force_offset":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            import ida_bytes as _ida_bytes
            # Determine pointer size: 8 for 64-bit IDBs, 4 for 32-bit.
            ptr_size = size if size in (4, 8) else (8 if _inf_is_64bit() else 4)
            # op_offset creates a cross-reference and reformats the operand as an offset.
            # idc.op_plain_offset(ea, n, base) for IDA < 7.5 compat; op_offset for newer.
            applied = False
            for fn_name, fn_args in [
                ("op_offset", (ea, 0, idaapi.REF_OFF32 if ptr_size == 4 else idaapi.REF_OFF64, idaapi.BADADDR, 0, 0)),
                ("op_plain_offset", (ea, 0, 0)),
            ]:
                fn = getattr(idc, fn_name, None)
                if callable(fn):
                    try:
                        fn(*fn_args)
                        applied = True
                        break
                    except Exception:
                        continue
            if not applied:
                return make_error(MCPError.IDA_ERROR, "op_offset/op_plain_offset not available in this IDA build")
            return {
                "ok": True,
                "addr": hex(ea),
                "ptr_size": ptr_size,
                "note": "IDA will now treat the value at this address as an offset/pointer and create an xref.",
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _bootstrap_raw_entry_points(start_ea: int, end_ea: int) -> dict:
    """
    Best-effort entry seeding for raw blobs when auto-analysis finds 0 functions.
    Uses deterministic vector-table style pointer extraction near image start.
    Sets Thumb mode and uses ida_ua.create_insn for IDA 9.x compatibility.
    """
    seeded = 0
    scan_size = min(max(0, end_ea - start_ea), 0x800)
    if scan_size < 8:
        return {"seeded_entries": 0}
    data = ida_bytes.get_bytes(start_ea, scan_size) or b""
    if len(data) < 8:
        return {"seeded_entries": 0}
    import struct
    candidates = []
    for i in range(4, len(data) - 3, 4):
        raw = struct.unpack_from("<I", data, i)[0]
        target = raw & ~1
        if raw == 0:
            continue
        if start_ea <= target < end_ea:
            candidates.append(target)
        else:
            base = raw & 0xFFFF0000
            off = target - base
            if 0 <= off < (end_ea - start_ea):
                candidates.append(start_ea + off)
    seen = set()
    for ea in candidates[:64]:
        if ea in seen:
            continue
        seen.add(ea)
        try:
            if idaapi.get_func(ea):
                seeded += 1
                continue
            # Use ida_ua.create_insn first (IDA 9.x), fall back to idc
            created = 0
            try:
                import ida_ua
                created = ida_ua.create_insn(ea)
            except Exception:
                pass
            if created == 0:
                created = idc.create_insn(ea)
            if created == 0:
                continue
            if ida_funcs.add_func(ea) or ida_funcs.add_func(ea, min(ea + 256, end_ea)):
                seeded += 1
        except Exception:
            continue
    return {"seeded_entries": seeded}


_SKIP_SEGMENT_NAMES = {
    ".plt", ".plt.got", ".plt.sec", ".plt.bnd",
    ".init", ".fini", ".init_array", ".fini_array",
    ".plt_indirect", ".plt_resolve",
    ".got", ".got.plt", ".got.off", ".got.sec",
}


def _segment_code_score(seg) -> tuple[int, int, int]:
    """Return (defined_code_bytes, total_code_bytes, code_head_count) for a segment.

    The score is used by the auto-reanalysis logic to detect "loader finished but
    never analyzed the code" failures — a typical symptom on stripped ARM64 ELF
    binaries (e.g. Android NDK ``libidmservicemgr.so``) where IDA's loader creates
    8-byte PLT stubs for the dynamic symbols but never enqueues work for ``.text``.
    """
    import idc as _idc
    defined = 0
    total = 0
    heads = 0
    if seg is None:
        return 0, 0, 0
    try:
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            return 0, 0, 0
    except Exception:
        return 0, 0, 0
    total = int(seg.end_ea) - int(seg.start_ea)
    if total <= 0:
        return 0, 0, 0
    head = int(seg.start_ea)
    end_ea = int(seg.end_ea)
    while head < end_ea:
        try:
            flags = ida_bytes.get_flags(head)
        except Exception:
            break
        try:
            if ida_bytes.is_code(flags):
                defined += int(_idc.get_item_size(head))
                heads += 1
        except Exception:
            pass
        try:
            nxt = _idc.next_head(head, end_ea)
        except Exception:
            break
        if nxt == idaapi.BADADDR or nxt <= head:
            break
        head = int(nxt)
    return defined, total, heads


def _find_text_segments() -> list[tuple[int, int, str]]:
    """Return [(start, end, name), ...] for segments that should be re-analyzed.

    Skips PLT/INIT/FINI/GOT style segments and the tiny ``LOAD`` trampolines
    that some ELF linkers emit (e.g. ``LOAD 0x0-0x35070`` is the read-only file
    header view; ``LOAD 0x35eb0-0x35ec0`` is a 16-byte trampoline). The result
    is sorted by start address and de-duplicated.
    """
    out: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        try:
            if not (seg.perm & idaapi.SEGPERM_EXEC):
                continue
        except Exception:
            continue
        s = int(seg.start_ea)
        e = int(seg.end_ea)
        if e - s < 0x100:
            continue
        name = ""
        try:
            name = ida_segment.get_segm_name(seg)
        except Exception:
            name = ""
        if name in _SKIP_SEGMENT_NAMES:
            continue
        key = (s, e)
        if key in seen:
            continue
        seen.add(key)
        out.append((s, e, name))
    out.sort(key=lambda t: t[0])
    return out


def _auto_reanalyze_text_segments(
    wait_seconds: float = 60.0,
) -> dict:
    """Best-effort: schedule ``ida_auto.plan_range`` over all eligible
    executable segments and wait (bounded by ``wait_seconds``) for the
    auto-analyzer to drain. Use as a fallback when the initial
    auto-analysis left the code section unanalyzed (e.g. the ELF loader
    created 8-byte PLT stubs but never created any real functions in
    ``.text``).

    Returns a dict with coverage before/after, number of functions
    created, ranges scheduled, and the wall-clock time spent waiting.
    Caller is responsible for saving the IDB if it wants persistence.
    """
    import ida_auto as _ida_auto

    ranges = _find_text_segments()
    before_funcs = 0
    before_defined = 0
    before_total = 0
    try:
        before_funcs = int(idaapi.get_func_qty())
    except Exception:
        pass
    for s, _e, _name in ranges:
        try:
            d, t, _h = _segment_code_score(idaapi.getseg(s))
            before_defined += d
            before_total += t
        except Exception:
            pass
    scheduled = 0
    for s, e, _name in ranges:
        try:
            if hasattr(_ida_auto, "plan_range"):
                _ida_auto.plan_range(s, e)
            elif hasattr(_ida_auto, "auto_mark_range"):
                _ida_auto.auto_mark_range(s, e, _ida_auto.AU_FINAL)
            elif hasattr(idaapi, "auto_mark_range"):
                idaapi.auto_mark_range(s, e, idaapi.AU_FINAL)
            else:
                continue
            scheduled += 1
        except Exception:
            continue
    waited = 0.0
    started = time.time()
    if scheduled > 0 and wait_seconds > 0:
        try:
            if hasattr(idaapi, "auto_is_ok") and bool(idaapi.auto_is_ok()):
                pass  # analyzer already drained; don't block at all
            elif hasattr(_ida_auto, "auto_wait"):
                # Pump the analyzer once; auto_wait() drains the queue and
                # returns (it has no timeout, so only call it when work is
                # actually pending — otherwise it defeats the poll budget).
                _ida_auto.auto_wait()
            else:
                # No auto_wait binding: poll auto_is_ok() bounded by the
                # caller's budget instead of blocking indefinitely.
                while time.time() - started < wait_seconds:
                    if hasattr(idaapi, "auto_is_ok") and bool(idaapi.auto_is_ok()):
                        break
                    time.sleep(0.2)
        except Exception:
            pass
        waited = time.time() - started
    after_funcs = 0
    after_defined = 0
    after_total = 0
    after_heads = 0
    try:
        after_funcs = int(idaapi.get_func_qty())
    except Exception:
        pass
    for s, _e, _name in ranges:
        try:
            d, t, h = _segment_code_score(idaapi.getseg(s))
            after_defined += d
            after_total += t
            after_heads += h
        except Exception:
            pass
    coverage_before = (
        round(before_defined / before_total * 100, 2) if before_total else 0.0
    )
    coverage_after = (
        round(after_defined / after_total * 100, 2) if after_total else 0.0
    )
    eligible = [
        {"start": hex(s), "end": hex(e), "name": name}
        for s, e, name in ranges
    ]
    return {
        "eligible_ranges": eligible,
        "scheduled": scheduled,
        "functions_before": before_funcs,
        "functions_after": after_funcs,
        "functions_added": max(0, after_funcs - before_funcs),
        "defined_code_bytes_before": before_defined,
        "defined_code_bytes_after": after_defined,
        "total_code_bytes": after_total,
        "code_heads_after": after_heads,
        "coverage_pct_before": coverage_before,
        "coverage_pct_after": coverage_after,
        "waited_seconds": round(waited, 2),
        "reanalysis_triggered": (
            after_funcs > before_funcs or after_defined > before_defined
        ),
    }


def _entry_point_addrs() -> list[int]:
    """Return deduped, sorted list of entry-point EAs (JNI exports, ELF
    entry, etc.) that should always have a function created, even if
    IDA's auto-analysis missed them."""
    out: set[int] = set()
    try:
        qty = int(ida_entry.get_entry_qty())
        for i in range(qty):
            ord_val = ida_entry.get_entry_ordinal(i)
            ea = int(ida_entry.get_entry(ord_val))
            if ea and ea != idaapi.BADADDR:
                out.add(ea)
    except Exception:
        pass
    return sorted(out)


def _ensure_entry_point_functions() -> dict:
    """Create functions for any entry point that doesn't have one yet.
    Useful when the auto-analyzer didn't trace into JNI exports because
    they were stripped or the loader didn't enqueue them."""
    import ida_funcs
    created = []
    skipped = []
    failed = []
    for ea in _entry_point_addrs():
        try:
            if idaapi.get_func(ea):
                skipped.append(hex(ea))
                continue
            ok = False
            try:
                ok = bool(ida_funcs.add_func(ea))
            except Exception:
                ok = False
            if ok:
                created.append(hex(ea))
            else:
                failed.append(hex(ea))
        except Exception:
            failed.append(hex(ea))
    return {
        "entry_points_total": len(created) + len(skipped) + len(failed),
        "created": created,
        "skipped_already_func": skipped,
        "failed": failed,
    }
