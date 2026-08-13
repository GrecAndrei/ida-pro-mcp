from ._common import (
    Annotated,
    Literal,
    MCPError,
    Optional,
    Union,
    _filetype_name,
    _inf_bitness,
    _inf_filetype_id,
    _inf_is_64bit,
    _inf_is_be,
    _inf_procname,
    get_arch,
    handle_error,
    ida_bytes,
    ida_funcs,
    ida_nalt,
    ida_segment,
    idaapi,
    idautils,
    idawrite,
    idc,
    is_arm_family,
    is_riscv_family,
    make_error,
    public_arg,
    tool,
    validate_addr
)

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
from .. import compat as _compat

import contextlib
import hashlib
import json
import os
import tempfile
import time

import ida_ida
import ida_loader
import ida_entry

# ============================================================================
# ANALYSIS - Loader/processor options and reanalysis
# ============================================================================

@tool
@idawrite
def analysis(
    action: Annotated[Literal["get_options", "set_options", "set_processor", "set_loader_options", "set_architecture", "reanalyze", "run", "analyze", "state", "set_gp", "save_idb", "make_code", "undefine", "get_af", "set_af", "force_offset", "add_entry", "snapshot", "restore_snapshot", "auto_wait"],
                      "Action: get_options|set_options|set_processor|set_loader_options|set_architecture|reanalyze|analyze|state|set_gp|save_idb|make_code|undefine|get_af|set_af|force_offset|add_entry|snapshot|restore_snapshot|auto_wait"],
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
    ordinal: Annotated[Optional[int], "Entry ordinal for add_entry"] = None,
    name: Annotated[Optional[str], "Entry name for add_entry (optional)"] = None,
    snapshot_name: Annotated[Optional[str], "Snapshot name for snapshot/restore_snapshot"] = None,
    snapshot_id: Annotated[Optional[str], "Snapshot id/name for restore_snapshot (public-surface spelling)"] = None,
    timeout_ms: Annotated[Optional[int], "Bounded wait budget in milliseconds for auto_wait (default 15000)"] = None,
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
    - add_entry: Register a real entry point at addr under ordinal. Use for a
        bootstrapped reset-vector / ISR candidate on raw firmware.
        Params: addr (REQUIRED), ordinal (optional, auto-derived), name (optional).
    - snapshot: Save an ida_loader snapshot of the current database under
        snapshot_name so an experiment (reanalysis, patching, types) can be
        rolled back before publishing findings.
        Params: snapshot_name (REQUIRED).
    - restore_snapshot: Roll the live database back to a previously saved
        ida_loader snapshot. Params: snapshot_name (REQUIRED).
    - auto_wait: Bounded wait for auto-analysis to drain. Pumps the analyzer in
        50ms slices up to timeout_ms (default 15000) instead of calling the
        unbounded ida_auto.auto_wait(), which has no timeout and would blow the
        host RPC recv deadline. Never raises on timeout — returns
        still-running with timed_out=true. Use for deterministic patch→verify
        loops before querying fresh results.
        Params: timeout_ms (optional, default 15000; 0 = single pump, no wait).
    """
    try:
        # Public MCP names stay on the wire; accept them beside legacy aliases.
        addr = public_arg(kwargs, 'address', addr)
        if action in ('snapshot', 'restore_snapshot'):
            snapshot_name = snapshot_name or snapshot_id or name
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
            warnings = []
            if ft_name == "raw" or filetype in (
                getattr(idaapi, "f_BIN", -1), getattr(idaapi, "f_BINARY", -1),
            ):
                warnings.append(
                    "raw blob; arch unverified — bytes (e.g. RISC-V) will misdecode under "
                    "the current processor. Run analysis(action='set_architecture', ...) to "
                    "set processor/bitness/endian before trusting disassembly."
                )
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
                "warnings": warnings,
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
            if not ok:
                # set_processor_type returns success; a False return means the
                # processor was NOT switched — report an error instead of a
                # false-success envelope the agent would act on.
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Failed to set processor to {processor!r}",
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
            from ..support.arch_utils import set_riscv_gp
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
            if not ok:
                # set_loader_options returns success; a False return means the
                # options were NOT applied — surface it instead of a
                # false-success envelope.
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Failed to apply loader options for {loader_name!r}",
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
                    if not result:
                        return make_error(
                            MCPError.IDA_ERROR,
                            f"Failed to set processor to {processor!r}",
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
            elif "riscv" in proc_lower or proc_lower.startswith("rv"):
                rv_bits = int(bitness) if bitness is not None else _get_app_bitness()
                arch_hints["ptr_size"] = 8 if rv_bits == 64 else 4
                arch_hints["default_int_width"] = 4
                arch_hints["riscv_note"] = (
                    "RISC-V: GP (x3) unresolved? run analysis(action='set_gp', gp=...) "
                    "so GP-relative xrefs resolve; confirm 2-byte alignment for compressed "
                    "c.* instructions and the load base for raw blobs."
                )
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
                # Explicit range: wait for the analyzer bounded by
                # poll_timeout. auto_wait() drains the whole queue with no
                # timeout, so on a large range it can block for minutes past
                # the budget and blow the host RPC recv deadline. Pump
                # incrementally with auto_make_step() inside a bounded poll
                # loop so the analyzer makes progress without hanging the RPC;
                # if the budget runs out, analysis_complete=False tells the
                # caller to poll session status instead.
                start_time = time.time()
                import ida_auto as _ida_auto
                while time.time() - start_time < poll_timeout:
                    analysis_ok = bool(idaapi.auto_is_ok()) if hasattr(idaapi, "auto_is_ok") else True
                    if analysis_ok:
                        break
                    if hasattr(_ida_auto, "auto_make_step"):
                        try:
                            _ida_auto.auto_make_step(s_ea, e_ea)
                        except Exception:
                            pass
                    time.sleep(0.1)
                    waited += 0.1
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
            # Lightweight read-only check of analysis progress. The default is
            # deliberately conservative: safe mode may be lifted ONLY on a
            # confirmed live "auto analysis idle" verdict, so a probe exception
            # or an unavailable API must never report complete (the h02 probe
            # contract — D1-F6).
            analysis_ok = False
            try:
                if hasattr(idaapi, "get_auto_state"):
                    analysis_ok = int(idaapi.get_auto_state()) == int(
                        getattr(idaapi, "AU_NONE", 0)
                    )
                elif hasattr(idaapi, "auto_is_ok"):
                    analysis_ok = bool(idaapi.auto_is_ok())
            except Exception:
                analysis_ok = False
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
            save_path = path or None
            try:
                # save_database(outfile=None) saves to the current DB path.
                # An empty STRING is NOT None: passing "" makes IDA try to
                # write to a file named "" and report failure (verified on
                # 9.3/9.4 under both idat and idalib).
                saved_ok = _ida_loader.save_database(save_path, 0)
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"save_database failed: {e}")
            if not saved_ok:
                # save_database returns success; a False return means the save
                # did not happen — report it instead of claiming success.
                return make_error(
                    MCPError.IDA_ERROR,
                    "save_database reported failure",
                    details={"path": save_path or "<in-place>"},
                )
            actual_path = save_path
            if not actual_path:
                # Report the real database file (foo.i64 / foo.idb), not the
                # loaded input binary, when saving in place.
                if hasattr(idc, "get_idb_path"):
                    actual_path = idc.get_idb_path() or ""
                elif hasattr(idaapi, "get_idb_path"):
                    actual_path = idaapi.get_idb_path() or ""
            return {"ok": True, "saved_to": actual_path or "<current idb>"}

        if action == "make_code":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            import ida_bytes as _ida_bytes
            import ida_ua as _ida_ua
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
            func = _compat.get_func_info(ea)
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

        if action == "add_entry":
            # Register a real entry point (Edit → Segments → Add entry point)
            # for a bootstrapped reset-vector / ISR candidate. Raw blobs (RISC-V
            # etc.) have no format loader, so _bootstrap_raw_entry_points() finds
            # candidates in the image head; this action promotes one to a real
            # entry so IDA keeps analyzing and exposing it.
            if addr is None or addr == "":
                return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err:
                return err
            if ordinal is None:
                # Public surface (ida_add_entry) has no ordinal: derive the
                # next free ordinal instead of requiring callers to track them.
                try:
                    ordinal = int(ida_entry.get_entry_qty())
                except Exception:
                    return make_error(MCPError.INVALID_ARGS, "ordinal required")
            try:
                ord_int = int(ordinal)
            except (TypeError, ValueError):
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"ordinal must be an integer, got {ordinal!r}",
                    details={"ordinal": ordinal},
                )
            entry_name = name or ""
            added = False
            try:
                # add_entry(ordinal, ea, name, is_manual) is the IDA 7.x+ form;
                # a handful of builds only take the 3-arg form.
                added = bool(ida_entry.add_entry(ord_int, ea, entry_name, True))
            except TypeError:
                try:
                    added = bool(ida_entry.add_entry(ord_int, ea, entry_name))
                except Exception as e:
                    return make_error(MCPError.IDA_ERROR, f"add_entry failed: {e}")
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"add_entry failed: {e}")
            if not added:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"ida_entry.add_entry failed for ordinal {ord_int} at {hex(ea)}",
                    details={"ordinal": ord_int, "addr": hex(ea), "name": entry_name},
                )
            return {
                "ok": True,
                "ordinal": ord_int,
                "addr": hex(ea),
                "name": entry_name or None,
                "result": True,
                "note": "Registered as a real entry point.",
            }

        if action == "snapshot":
            # ida_loader.save_snapshot(name, dbflags) — snapshot the current
            # database under a name so a reversible experiment (reanalysis,
            # patching, type fixes) can be rolled back with restore_snapshot
            # before publishing findings. Pass DBFL_SNAPSHOT when the build
            # exposes it, else 0; fall back to the 1-arg form.
            # idalib (IDA_MCP_RUNTIME=idalib) does NOT expose the loader
            # snapshot API — it maps to the ida_undo checkpoint surface
            # instead (create_undo_point + perform_undo, verified live on
            # 9.4): undo points are enabled per session by the worker's
            # open_database(enable_history=True).
            if not snapshot_name:
                return make_error(MCPError.INVALID_ARGS, "snapshot_name required")
            saved = False
            mechanism = "ida_loader"
            try:
                if hasattr(ida_loader, "save_snapshot"):
                    flags = getattr(ida_loader, "DBFL_SNAPSHOT", 0)
                    try:
                        saved = bool(ida_loader.save_snapshot(snapshot_name, flags))
                    except TypeError:
                        saved = bool(ida_loader.save_snapshot(snapshot_name))
                else:
                    import ida_undo as _ida_undo
                    saved = bool(
                        _ida_undo.create_undo_point("ida_mcp_snapshot", snapshot_name)
                    )
                    mechanism = "ida_undo"
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"save_snapshot failed: {e}")
            if not saved:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"save_snapshot failed for {snapshot_name!r}",
                    details={"snapshot_name": snapshot_name},
                )
            return {
                "ok": True,
                "snapshot_name": snapshot_name,
                "result": True,
                "mechanism": mechanism,
            }

        if action == "restore_snapshot":
            # Roll the live DB back to a previously saved ida_loader snapshot.
            # restore_snapshot replaces the current database with the snapshot,
            # so any experiment done after snapshot() is discarded.
            # idalib fallback: perform_undo() rolls back the most recent undo
            # point (LIFO — the standard snapshot→experiment→restore flow
            # restores the last saved snapshot). The point name is recorded
            # at snapshot time; the Python binding exposes no point
            # enumeration, so the restore is by LIFO position, not by name.
            # Accepts the public surface spellings: snapshot_name (legacy),
            # snapshot_id (public op), or ordinal (0 = most recent undo point).
            key = snapshot_name or snapshot_id
            if not key and ordinal is None:
                return make_error(MCPError.INVALID_ARGS, "snapshot_name required")
            restored = False
            mechanism = "ida_loader"
            try:
                if hasattr(ida_loader, "restore_snapshot"):
                    if key:
                        restored = bool(ida_loader.restore_snapshot(key))
                    else:
                        return make_error(
                            MCPError.INVALID_ARGS,
                            "ordinal restore requires the undo-based snapshot mechanism "
                            "(not available in this IDA build)",
                        )
                else:
                    import ida_undo as _ida_undo
                    mechanism = "ida_undo"
                    steps = 1 if key else int(ordinal) + 1
                    # perform_undo pops the most recent point each call; an
                    # ordinal n rolls back n+1 points (0 = most recent).
                    for _ in range(max(1, min(steps, 64))):
                        restored = bool(_ida_undo.perform_undo())
                        if not restored:
                            break
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"restore_snapshot failed: {e}")
            if not restored:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"restore_snapshot failed for {key or ordinal!r} — snapshot may not exist",
                    details={"snapshot_name": key or None, "ordinal": ordinal},
                )
            return {
                "ok": True,
                "snapshot_name": key,
                "ordinal": ordinal,
                "result": True,
                "mechanism": mechanism,
            }

        if action == "auto_wait":
            # Bounded wait for auto-analysis to drain. The unbounded
            # ida_auto.auto_wait() drains the whole queue with no timeout and
            # would blow the host RPC recv deadline on a large binary (see the
            # reanalyze / _auto_reanalyze_text_segments notes), so pump the
            # analyzer one unit per 50ms slice via auto_make_step() and poll
            # auto_is_ok() up to the bound. Never raises on timeout.
            import ida_auto as _ida_auto
            import time as _time
            budget_ms = 15000
            if timeout_ms is not None:
                try:
                    budget_ms = int(timeout_ms)
                except (TypeError, ValueError):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"timeout_ms must be a non-negative integer, got {timeout_ms!r}",
                        details={"timeout_ms": timeout_ms},
                    )
            budget_ms = max(0, budget_ms)
            deadline = _time.time() + (budget_ms / 1000.0)
            timed_out = False
            drained = 0

            def _auto_done() -> bool:
                if hasattr(_ida_auto, "auto_is_ok"):
                    return bool(_ida_auto.auto_is_ok())
                if hasattr(idaapi, "auto_is_ok"):
                    return bool(idaapi.auto_is_ok())
                return True

            while not _auto_done():
                # Pump one queued unit. Prefer the 2-arg (s, e) form (IDA 9)
                # and fall back to the no-arg form for builds that take none.
                try:
                    _ida_auto.auto_make_step()
                    drained += 1
                except TypeError:
                    try:
                        _ida_auto.auto_make_step(idaapi.BADADDR, idaapi.BADADDR)
                        drained += 1
                    except Exception:
                        break
                except Exception:
                    break
                if budget_ms <= 0:
                    timed_out = True
                    break
                if _time.time() >= deadline:
                    timed_out = True
                    break
                _time.sleep(0.05)
            analysis_done = _auto_done()
            return {
                "ok": True,
                "analysis_done": analysis_done,
                # IDA exposes no direct queue-size API; report the number of
                # analyzer units drained as a lower-bound proxy for depth (0
                # when the queue is already idle).
                "queue_depth": 0 if analysis_done else drained,
                "timed_out": timed_out,
                "note": (
                    "Auto-analysis still running; poll again or check session(action='status')."
                    if (timed_out and not analysis_done)
                    else "Auto-analysis idle."
                ),
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


def _bootstrap_raw_entry_points(start_ea: int, end_ea: int) -> dict:
    """
    Best-effort entry seeding for raw blobs when auto-analysis finds 0 functions.

    Arch-aware scan of the image head:
      * RISC-V: reset ``j``/``jal`` (and ``auipc``+``jalr``) branches plus ISR
        pointer tables read as LE u32, BE u32, or LE u16 (compressed c.j) — a
        headerless .bin has no vector table, so both the direct branch at the
        image head and pointer-like tables are candidates.
      * ARM/Thumb: LE u32 vector-table pointers (existing path).
      * Unknown: default LE u32 pointer-table scan.

    Found targets are converted to code, wrapped in functions, and registered
    via ida_entry.add_entry so IDA keeps analyzing/exposing them.
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
    arch = get_arch()
    is_rv = is_riscv_family(arch)
    is_arm = is_arm_family(arch)

    def _scan_le32_table() -> None:
        """LE u32 vector/ISR table scan (shared by ARM and unknown arches)."""
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

    if is_rv:
        # Reset branch at the image head: `j`/`jal` target, or auipc+jalr long
        # branch.  Raw RISC-V firmware commonly starts at the reset vector.
        try:
            first_mnem = (idc.print_insn_mnem(start_ea) or "").lower()
        except Exception:
            first_mnem = ""
        if first_mnem in ("j", "jal"):
            try:
                tgt = int(idc.get_operand_value(start_ea, 0))
                if tgt not in (idaapi.BADADDR, 0) and start_ea <= tgt < end_ea:
                    candidates.append(tgt)
            except Exception:
                pass
        elif first_mnem == "auipc":
            # auipc ra, imm20 ; jalr ra, imm12(ra)  ->  target = PC + (imm20<<12) + imm12
            try:
                imm = int(idc.get_operand_value(start_ea, 1))
                if imm & 0x80000:
                    imm -= 0x100000
                ra = start_ea + (imm << 12)
                ea2 = idc.next_head(start_ea, end_ea)
                if ea2 != idaapi.BADADDR and (idc.print_insn_mnem(ea2) or "").lower() == "jalr":
                    imm12 = int(idc.get_operand_value(ea2, 2))
                    if imm12 & 0x800:
                        imm12 -= 0x1000
                    tgt = (ra + imm12) & 0xFFFFFFFFFFFFFFFF
                    if start_ea <= tgt < end_ea:
                        candidates.append(tgt)
            except Exception:
                pass
        # ISR pointer tables: LE/BE u32, then LE u16 (compressed c.j targets).
        for i in range(4, len(data) - 3, 4):
            for raw in (struct.unpack_from("<I", data, i)[0],
                        struct.unpack_from(">I", data, i)[0]):
                if raw == 0:
                    continue
                target = raw & ~1
                if start_ea <= target < end_ea:
                    candidates.append(target)
                else:
                    base = raw & 0xFFFF0000
                    off = target - base
                    if 0 <= off < (end_ea - start_ea):
                        candidates.append(start_ea + off)
        for i in range(0, len(data) - 1, 2):
            raw16 = struct.unpack_from("<H", data, i)[0]
            target16 = raw16 & ~1
            if raw16 == 0 or target16 < 0x100:
                continue
            if start_ea <= target16 < end_ea:
                candidates.append(target16)
    elif is_arm:
        # Thumb vector-table pointers (LE u32; bit 0 selects Thumb).
        _scan_le32_table()
    else:
        _scan_le32_table()

    seen = set()
    for ea in candidates[:64]:
        if ea in seen:
            continue
        seen.add(ea)
        try:
            if _compat.get_func_start(ea) is not None:
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
            # Register as an entry point so IDA keeps analyzing/exposing it.
            try:
                ord_val = ida_entry.get_entry_qty() + 1
                ida_entry.add_entry(ord_val, ea, "", 0)
            except Exception:
                pass
        except Exception:
            continue
    return {"seeded_entries": seeded}


_SKIP_SEGMENT_NAMES = {
    ".plt", ".plt.got", ".plt.sec", ".plt.bnd",
    ".init", ".fini", ".init_array", ".fini_array",
    ".plt_indirect", ".plt_resolve",
    ".got", ".got.plt", ".got.off", ".got.sec",
}


def _is_raw_bin_filetype() -> bool:
    """True when the loaded file is a raw/headerless binary (f_BIN / f_BINARY).

    Uses only the ``idaapi``/``idc`` module globals so the auto-reanalysis
    helpers stay self-contained (they are also executed standalone by the host
    test harness, where ``_common`` re-exports are absent).
    """
    try:
        f_bin = getattr(idaapi, "f_BIN", 0)
        f_binary = getattr(idaapi, "f_BINARY", f_bin)
        ft = None
        inf_getter = getattr(idaapi, "inf_get_filetype", None)
        if callable(inf_getter):
            ft = int(inf_getter())
        else:
            inf_attr = getattr(idc, "get_inf_attr", None)
            if callable(inf_attr):
                v = inf_attr(getattr(idc, "INF_FILETYPE", -1))
                if v is not None:
                    ft = int(v)
            else:
                inf = idaapi.get_inf_structure() if callable(getattr(idaapi, "get_inf_structure", None)) else None
                if inf is not None:
                    v = getattr(inf, "filetype", None)
                    if v is not None:
                        ft = int(v)
        if ft is not None:
            return ft in (f_bin, f_binary)
    except Exception:
        pass
    return False


def _raw_mapped_range():
    """Return (min_ea, max_ea) of the whole mapped database, or None."""
    try:
        import ida_ida as _ida_ida
        if hasattr(_ida_ida, "inf_get_min_ea") and hasattr(_ida_ida, "inf_get_max_ea"):
            mn = int(_ida_ida.inf_get_min_ea())
            mx = int(_ida_ida.inf_get_max_ea())
            if mn < mx:
                return (mn, mx)
    except Exception:
        pass
    try:
        inf = idaapi.get_inf_structure() if callable(getattr(idaapi, "get_inf_structure", None)) else None
        if inf is not None:
            mn = getattr(inf, "min_ea", None)
            mx = getattr(inf, "max_ea", None)
            if mn is not None and mx is not None and mn < mx:
                return (int(mn), int(mx))
    except Exception:
        pass
    try:
        inf_attr = getattr(idc, "get_inf_attr", None)
        if callable(inf_attr):
            mn = inf_attr(getattr(idc, "INF_MIN_EA", -1))
            mx = inf_attr(getattr(idc, "INF_MAX_EA", -1))
            if mn is not None and mx is not None and mn < mx:
                return (int(mn), int(mx))
    except Exception:
        pass
    return None


def _segment_code_score(seg_ea: int) -> tuple[int, int, int]:
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
    seg = _compat.get_segment(seg_ea)
    if seg is None:
        return 0, 0, 0
    try:
        if not (_compat.get_segment_perm(seg_ea) & idaapi.SEGPERM_EXEC):
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
        seg = _compat.get_segment(seg_ea)
        if not seg:
            continue
        try:
            if not (_compat.get_segment_perm(seg_ea) & idaapi.SEGPERM_EXEC):
                continue
        except Exception:
            continue
        s = int(seg.start_ea)
        e = int(seg.end_ea)
        if e - s < 0x100:
            continue
        name = ""
        try:
            name = _compat.get_segment_name(seg_ea)
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
    # Raw blobs (f_BIN) frequently load with NO executable segment — the bin
    # loader creates a single R/W segment with perms that analysis tools then
    # treat as data-only.  Refusing to schedule anything leaves the agent with
    # a silent no-op, so fall back to the whole mapped range (the <0x100-byte
    # skip is kept).  The caller (_auto_reanalyze_text_segments) reports the
    # "no executable segments" warning.
    if not out and _is_raw_bin_filetype():
        mrange = _raw_mapped_range()
        if mrange is not None:
            s, e = mrange
            if e - s >= 0x100:
                out = [(s, e, "<raw-mapped>")]
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
    # Open-time entry seeding for opaque raw blobs (f_BIN): this helper runs on
    # every fresh load via server_script.py after auto_wait(), so a headerless
    # .bin gets reset/ISR targets seeded even before any agent calls
    # analysis(action='reanalyze').  Guarded so the host test namespace (no
    # _bootstrap_raw_entry_points in scope) short-circuits on the non-raw path.
    if _is_raw_bin_filetype():
        mrange = _raw_mapped_range()
        if mrange is not None:
            try:
                boot = _bootstrap_raw_entry_points(*mrange)
                if boot.get("seeded_entries") and not ranges:
                    ranges = [(*mrange, "<raw-mapped>")]
            except Exception:
                pass
    warning = None
    if ranges and ranges[0][2] == "<raw-mapped>":
        warning = (
            "no executable segments; set perms with segments(action='set_perms', ...) "
            "— fell back to the whole mapped range for analysis"
        )
    before_funcs = 0
    before_defined = 0
    before_total = 0
    try:
        before_funcs = int(idaapi.get_func_qty())
    except Exception:
        pass
    for s, _e, _name in ranges:
        try:
            d, t, _h = _segment_code_score(s)
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
            # Drain the planned text ranges with auto_wait_range(s, e) — the
            # SDK primitive that analyzes exactly the requested span and returns
            # once it is done. It is far more efficient than stepping one
            # address at a time: the previous spin-pump (auto_make_step in a
            # 0.1s loop until auto_is_ok()) took ~46s to drain a ~1KB .text on
            # IDA 9.3, because auto_is_ok() only flips after the whole queue
            # drains while each auto_make_step call advances a single address.
            # auto_wait() is avoided deliberately (it drains the ENTIRE queue
            # with no timeout — a whole-image reanalyze of a large binary could
            # block for minutes and blow the host RPC recv deadline), but
            # auto_wait_range is scoped to the span we just planned. Bounding:
            # per-range calls are skipped once the caller's budget is spent, and
            # each call is wrapped so a stuck analyzer degrades to the legacy
            # auto_make_step pump rather than hanging startup.
            have_wait_range = hasattr(_ida_auto, "auto_wait_range")
            have_step = hasattr(_ida_auto, "auto_make_step")
            wait_range_ok = have_wait_range
            if have_wait_range:
                for s, e, _n in ranges:
                    if time.time() - started >= wait_seconds:
                        break
                    try:
                        _ida_auto.auto_wait_range(s, e)
                    except Exception:
                        # Range drain failed; fall through to the step pump so
                        # the caller's reanalysis still makes best-effort
                        # progress instead of silently doing nothing.
                        wait_range_ok = False
                        break
            # Belt-and-braces: if auto_wait_range is unavailable or errored,
            # fall back to the legacy incremental pump until auto_is_ok() or
            # the budget is spent.
            if not wait_range_ok and have_step:
                while time.time() - started < wait_seconds:
                    if hasattr(idaapi, "auto_is_ok") and bool(idaapi.auto_is_ok()):
                        break
                    try:
                        for s, e, _n in ranges:
                            _ida_auto.auto_make_step(s, e)
                    except Exception:
                        pass
                    time.sleep(0.1)
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
            d, t, h = _segment_code_score(s)
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
    result = {
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
    if warning:
        result["warning"] = warning
    return result


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
            if _compat.get_func_start(ea) is not None:
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
