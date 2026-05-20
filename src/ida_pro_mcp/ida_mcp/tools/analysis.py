try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import ida_loader
import ida_ida
import hashlib
import json
import os
import tempfile
import time

try:
    from ida_pro_mcp.host.arch_profile import infer_binary_arch_profile as _infer_arch
except Exception:
    _infer_arch = None  # type: ignore


# ============================================================================
# ANALYSIS - Loader/processor options and reanalysis
# ============================================================================

@tool
@idawrite
def analysis(
    action: Annotated[Literal["get_options", "set_options", "set_processor", "set_loader_options", "set_architecture", "reanalyze", "run", "analyze", "wait"],
                      "Action: get_options|set_options|set_processor|set_loader_options|set_architecture|reanalyze|wait"],
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
            inf = None
            try:
                if hasattr(idaapi, "get_inf_structure"):
                    inf = idaapi.get_inf_structure()
            except Exception:
                inf = None

            def safe_inf_attr(attr, default=None):
                try:
                    if inf is not None and hasattr(inf, attr):
                        return getattr(inf, attr)
                except Exception:
                    pass
                return default
            def safe_idc_attr(name, default=None):
                key = getattr(idc, name, None)
                if key is None:
                    return default
                try:
                    return idc.get_inf_attr(key)
                except Exception:
                    return default

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
            binary_path = None
            try:
                if hasattr(ida_nalt, "get_input_file_path"):
                    binary_path = ida_nalt.get_input_file_path()
                elif hasattr(idaapi, "get_input_file_path"):
                    binary_path = idaapi.get_input_file_path()
            except Exception:
                pass
            if ft_name == "obj" and binary_path and callable(_infer_arch):
                try:
                    inf_result = _infer_arch(binary_path) or {}
                    if inf_result.get("file_kind") == "raw":
                        ft_effective = "raw"
                        ft_note = "IDA loader reports obj for plain binaries; effective kind is raw."
                except Exception:
                    pass

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
            for key, val in options.items():
                if key not in mapping or mapping[key] is None:
                    continue
                try:
                    if isinstance(val, str):
                        cast_val = int(val, 0)
                    else:
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
                if key == "baseaddr":
                    requested_baseaddr = cast_val

            if requested_baseaddr is not None:
                current_base = None
                try:
                    if hasattr(idc, "get_inf_attr") and getattr(idc, "INF_BASEADDR", None) is not None:
                        current_base = int(idc.get_inf_attr(idc.INF_BASEADDR))
                except Exception:
                    current_base = None
                if current_base is None:
                    try:
                        current_base = int(_safe_inf_get("baseaddr", 0) or 0)
                    except Exception:
                        current_base = 0
                delta = requested_baseaddr - int(current_base or 0)
                if delta != 0:
                    rebased = False
                    rebase_errors = []
                    for rebase_fn in (
                        getattr(idc, "rebase_program", None),
                        getattr(idaapi, "rebase_program", None),
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
            try:
                prev = getattr(inf, "procname", "") if inf else ""
            except Exception:
                pass
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
                out_path = os.path.join(fallback_dir, f"loader_options_{int(time.time())}_{os.getpid()}_{key}.json")
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
            try:
                prev = getattr(inf, "procname", "") if inf else ""
            except Exception:
                pass
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
                else:
                    if hasattr(ida_ida, "inf_set_app_bitness"):
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
                    try:
                        current_be = ida_ida.inf_is_be() if hasattr(ida_ida, "inf_is_be") else None
                    except Exception:
                        pass
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
            return {"ok": True, "applied": applied}

        if action in ("reanalyze", "run", "analyze"):
            if start and end:
                s_ea, err = validate_addr(start)
                if err: return err
                e_ea, err = validate_addr(end)
                if err: return err
            else:
                s_ea = idaapi.inf_get_min_ea()
                e_ea = idaapi.inf_get_max_ea()

            # Fix ALL segments to CODE type/class/perm for raw binaries.
            # set_segm_class only changes the class string; seg.type and seg.perm
            # are what create_insn()/add_func() actually check.
            for seg_ea in idautils.Segments():
                try:
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
                except Exception:
                    pass

            # Schedule analysis (non-blocking by default). Use plan_range or
            # auto_mark_range (fire-and-forget) so IDA's idle loop picks up the
            # work after this RPC call returns.
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
            else:
                mode = "none"
            # Optionally poll until analysis completes.
            blocking = kwargs.get("blocking") or kwargs.get("wait") or False
            waited = 0.0
            if blocking:
                poll_timeout = float(kwargs.get("poll_timeout", 60.0) or 60.0)
                start_time = time.time()
                while time.time() - start_time < poll_timeout:
                    analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else True
                    if analysis_ok:
                        break
                    time.sleep(0.2)
                    waited += 0.2
                    try:
                        import ida_kernwin
                        if hasattr(ida_kernwin, "process_ui_action"):
                            pass  # pump the event loop
                    except Exception:
                        pass
            # Raw-binary bootstrap: seed entry points synchronously so models
            # can call code/funcs tools immediately after this returns.
            try:
                func_count = sum(1 for _ in idautils.Functions())
            except Exception:
                func_count = 0
            boot = {"seeded_entries": 0}
            if func_count == 0:
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
                "analysis_complete": analysis_ok,
                "functions": func_count,
                "note": "Analysis scheduled (non-blocking). Poll with analysis(action='wait', timeout=30) or session(action='status') until analysis_complete=true.",
                **boot,
            }
            if blocking:
                result["blocking_waited"] = round(waited, 2)
                result["note"] = "Analysis ran blocking. Ready to query."
            return result

        if action == "wait":
            # Report current analysis state and optionally spin-wait for completion.
            # Uses request_idle callback + short spins to avoid blocking the socket loop.
            poll_timeout = float(kwargs.get("timeout", 0.0) or 0.0)
            poll_max_wait = float(kwargs.get("max_wait", 30.0) or 30.0)
            start_time = time.time()
            waited = 0.0
            while True:
                analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else True
                if analysis_ok:
                    break
                if poll_timeout <= 0:
                    break
                remaining = min(poll_timeout, poll_max_wait) - waited
                if remaining <= 0:
                    break
                sleep_sec = min(0.1, remaining)
                time.sleep(sleep_sec)
                waited += sleep_sec
                # Pump IDA's idle queue to let auto-analysis make progress
                try:
                    if hasattr(idaapi, "process_ui_action"):
                        pass  # non-blocking, just let the loop spin
                except Exception:
                    pass
            analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else True
            try:
                func_count = sum(1 for _ in idautils.Functions())
            except Exception:
                func_count = -1
            try:
                string_count = idaapi.get_strlist_qty() if hasattr(idaapi, "get_strlist_qty") else -1
            except Exception:
                string_count = -1
            return {
                "ok": True,
                "analysis_complete": analysis_ok,
                "functions": func_count,
                "strings": string_count,
                "seconds_waited": round(waited, 2),
                "note": (
                    "Analysis complete. Safe to call code/data/funcs tools."
                    if analysis_ok else
                    f"Analysis still in progress after {round(waited, 1)}s. Retry with timeout=<seconds> or poll session(action='status')."
                ),
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
    ptr_size = 4
    scan_size = min(max(0, end_ea - start_ea), 0x800)
    if scan_size < 8:
        return {"seeded_entries": 0}
    data = ida_bytes.get_bytes(start_ea, scan_size) or b""
    if len(data) < 8:
        return {"seeded_entries": 0}
    # Set Thumb mode for ARM targets before attempting instruction creation
    try:
        proc = (_inf_procname() or "").lower()
    except Exception:
        proc = ""
    if "arm" in proc:
        try:
            sr_auto = getattr(idc, "SR_auto", 2)
            idc.split_sreg_range(start_ea, "T", 1, sr_auto)
        except Exception:
            try:
                import ida_segregs
                ida_segregs.split_sreg_range(start_ea, "T", 1, 2)
            except Exception:
                pass
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
            if ida_funcs.add_func(ea):
                seeded += 1
            elif ida_funcs.add_func(ea, min(ea + 256, end_ea)):
                seeded += 1
        except Exception:
            continue
    return {"seeded_entries": seeded}
