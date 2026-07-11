"""EXPORT — write IDB content to real on-disk artifacts.

Formats: listing, html, idc, json, sarif, binexport, headers, redact, vtable.
Each action either writes a file and returns its path, or returns a structured
error. No silent "plugin ran" without verifying the artifact exists.
"""

from __future__ import annotations

import json as json_module
import os
import re
import tempfile
from typing import Any, Optional

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# Redaction (pure — testable without IDA)
# ---------------------------------------------------------------------------

_REDACTION_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "EMAIL"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP"),
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "MD5"),
    (re.compile(r"\b[a-fA-F0-9]{40}\b"), "SHA1"),
    (re.compile(r"\b[a-fA-F0-9]{64}\b"), "SHA256"),
    (re.compile(r"\bhttps?://[^\s\"']+"), "URL"),
]


def redact_text(content: str, patterns: list | None = None) -> tuple[str, list[str]]:
    """Redact sensitive-looking tokens. Returns (redacted, labels)."""
    patterns = patterns or _REDACTION_PATTERNS
    redacted = content
    redactions: list[str] = []
    for pattern, label in patterns:
        matches = pattern.findall(redacted)
        for match in matches:
            sample = match if isinstance(match, str) else str(match)
            redactions.append(f"{label}: {sample[:40]}")
        redacted = pattern.sub(f"[{label}_REDACTED]", redacted)
    return redacted, redactions


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _escape_idc_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _ensure_parent_dir(p: str) -> None:
    parent = os.path.dirname(p)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def _is_writable_dir(d: str) -> bool:
    if not d:
        return False
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return False
    return os.path.isdir(d) and os.access(d, os.W_OK)


def _default_export_path(ext: str) -> str:
    input_path = ""
    try:
        input_path = idaapi.get_input_file_path() or ""
    except Exception:
        input_path = ""
    base_name = os.path.basename(input_path) if input_path else "ida_export.bin"
    stem = os.path.splitext(base_name)[0] or "ida_export"
    candidate_dirs = [
        os.path.dirname(input_path) if input_path else "",
        os.environ.get("IDA_MCP_CACHE_DIR", ""),
        os.path.join(tempfile.gettempdir(), "ida_mcp_exports"),
        os.getcwd(),
    ]
    for d in candidate_dirs:
        if _is_writable_dir(d):
            return os.path.join(d, f"{stem}{ext}")
    return os.path.join(tempfile.gettempdir(), f"{stem}{ext}")


def _clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _print_tinfo_c(tif) -> str:
    """Best-effort C declaration string for a tinfo_t."""
    name = str(tif.get_type_name() or "")
    # IDA 7.x/9.x: print_tinfo / _print / str(tif)
    printers = []
    if hasattr(ida_typeinf, "print_tinfo"):
        printers.append(
            lambda: ida_typeinf.print_tinfo(
                "",  # prefix
                0,
                0,
                ida_typeinf.PRTYPE_1LINE | getattr(ida_typeinf, "PRTYPE_TYPE", 0),
                tif,
                name,
                "",
            )
        )
    if hasattr(tif, "_print"):
        printers.append(lambda: tif._print(name or None))
    printers.append(lambda: str(tif))
    for fn in printers:
        try:
            out = fn()
            if out and str(out).strip():
                text = str(out).strip()
                if not text.endswith(";") and not text.endswith("}"):
                    text = text + ";"
                return text
        except Exception:
            continue
    return f"/* unresolved type {name} */"


def _export_headers_text(max_types: int = 500) -> tuple[str, int]:
    """Emit C-like type declarations from the local type library."""
    lines = [
        "// Type definitions exported from IDA",
        f"// Source: {idaapi.get_input_file_path() or ''}",
        "",
    ]
    til = ida_typeinf.get_idati()
    if not til:
        return "\n".join(lines) + "\n// No type library loaded\n", 0

    qty_func = getattr(ida_typeinf, "get_ordinal_qty", None) or getattr(
        ida_typeinf, "get_ordinal_count", None
    )
    count = int(qty_func(til) or 0) if qty_func else 0
    type_count = 0
    for ordinal in range(1, count + 1):
        if type_count >= max_types:
            break
        tif = ida_typeinf.tinfo_t()
        try:
            ok = tif.get_numbered_type(til, ordinal)
        except Exception:
            ok = False
        if not ok:
            continue
        tname = tif.get_type_name()
        if not tname:
            continue
        decl = _print_tinfo_c(tif)
        lines.append(f"// ordinal {ordinal}: {tname}")
        lines.append(decl)
        lines.append("")
        type_count += 1
    return "\n".join(lines), type_count


def _try_binexport_binary(path: str) -> tuple[bool, str]:
    """Invoke BinExport with an explicit output path.

    Prefer IDC ``BinExportBinary("path")`` (Google BinExport), then plugin names.
    Returns (ok, detail).
    """
    abs_path = os.path.abspath(path)
    _ensure_parent_dir(abs_path)

    # 1) Named IDC function registered by the plugin (controls output path).
    idc_cmds = [
        f'BinExportBinary("{_escape_idc_string(abs_path)}");',
        f'BinExport2Binary("{_escape_idc_string(abs_path)}");',
    ]
    for cmd in idc_cmds:
        try:
            if hasattr(idc, "eval_idc"):
                idc.eval_idc(cmd)
            elif hasattr(idaapi, "ida_expr") and hasattr(idaapi.ida_expr, "eval_idc_expr"):
                import ida_idaapi

                idaapi.ida_expr.eval_idc_expr(None, ida_idaapi.BADADDR, cmd)
            else:
                continue
            if os.path.isfile(abs_path) and os.path.getsize(abs_path) > 0:
                return True, f"idc:{cmd.split('(')[0]}"
        except Exception as e:
            str(e)
            continue

    # 2) load_and_run_plugin with common plugin basenames (path not controllable).
    #    If a file appears next to the IDB with .BinExport, rename/copy to target.
    plugin_names = (
        "binexport12_ida",
        "binexport11_ida",
        "binexport10_ida",
        "binexport",
        "zynamics_binexport_9",
    )
    import ida_loader

    idb_dir = ""
    try:
        idb_path = idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
        idb_dir = os.path.dirname(idb_path) if idb_path else ""
    except Exception:
        idb_dir = ""
    before = set()
    if idb_dir and os.path.isdir(idb_dir):
        before = {f for f in os.listdir(idb_dir) if f.lower().endswith(".binexport")}

    for name in plugin_names:
        try:
            # arg 2 == kBinary in recent BinExport
            ida_loader.load_and_run_plugin(name, 2)
        except Exception:
            try:
                ida_loader.load_and_run_plugin(name, 0)
            except Exception:
                continue
        if os.path.isfile(abs_path) and os.path.getsize(abs_path) > 0:
            return True, f"plugin:{name}"
        if idb_dir:
            after = {f for f in os.listdir(idb_dir) if f.lower().endswith(".binexport")}
            new = after - before
            candidates = list(new) or sorted(after, key=lambda f: os.path.getmtime(os.path.join(idb_dir, f)), reverse=True)[:1]
            for fname in candidates:
                src = os.path.join(idb_dir, fname)
                if os.path.isfile(src) and os.path.getsize(src) > 0:
                    try:
                        import shutil

                        shutil.copy2(src, abs_path)
                        if os.path.isfile(abs_path) and os.path.getsize(abs_path) > 0:
                            return True, f"plugin:{name}->copy"
                    except OSError:
                        continue
    return False, "BinExport plugin not available or produced no file"


def _write_binexport_fallback(path: str, max_funcs: int = 5000) -> dict:
    """Structured JSON fallback when BinExport plugin is missing.

    Not a .BinExport protobuf — labeled clearly so callers do not confuse it.
    """
    fallback_path = path if path.endswith(".json") else f"{path}.fallback.json"
    _ensure_parent_dir(fallback_path)
    functions = []
    for fea in idautils.Functions():
        fn = ida_funcs.get_func(fea)
        functions.append(
            {
                "addr": hex(fea),
                "name": idc.get_func_name(fea) or "",
                "size": (fn.end_ea - fn.start_ea) if fn else 0,
            }
        )
        if len(functions) >= max_funcs:
            break
    payload = {
        "format": "binexport-fallback-json",
        "compatible_with": "bindiff(action='snapshot') fingerprints, not Google BinDiff UI",
        "source_file": idaapi.get_input_file_path() or "",
        "imagebase": hex(idaapi.get_imagebase()),
        "function_count": len(functions),
        "functions": functions,
    }
    with open(fallback_path, "w", encoding="utf-8") as f:
        json_module.dump(payload, f, indent=2)
    return {
        "ok": True,
        "exported": False,
        "fallback": True,
        "binexport_available": False,
        "path": fallback_path,
        "function_count": len(functions),
        "note": (
            "BinExport plugin unavailable. Wrote structured JSON fallback. "
            "Install Google BinExport for real .BinExport files, or use "
            "bindiff(action='snapshot', path=...) for cross-version diffs."
        ),
    }


# ---------------------------------------------------------------------------
# Tool entry
# ---------------------------------------------------------------------------

@tool
@idaread
def export(
    action: Annotated[
        Literal[listing, html, idc, json, sarif, binexport, headers, redact, vtable],
        "Action: listing|html|idc|json|sarif|binexport|headers|redact|vtable",
    ],
    path: Annotated[Optional[str], "Output file path (or text for redact if text= omitted)"] = None,
    addr: Annotated[Optional[str], "Address or start:end range for partial listing"] = None,
    include_decompile: Annotated[bool, "Include decompiled pseudocode in json (expensive)"] = False,
    text: Annotated[Optional[str], "Text to redact (redact action)"] = None,
    limit: Annotated[Optional[int], "Max items for list-like exports"] = None,
    max_functions: Annotated[Optional[int], "Cap function rows in json/html/listing"] = None,
    query: Annotated[Optional[str], "Filter pattern for vtable names"] = None,
    **kwargs,
) -> dict:
    """
    Export IDB data to real files.

    listing  — assembly listing (.lst)
    html     — simple navigable HTML report
    idc      — IDC script recreating names/functions/comments/types
    json     — structured metadata (functions, strings, imports, exports, types, comments)
    sarif    — SARIF 2.1 from blackboard vuln findings only (no invented noise)
    binexport— Google BinExport binary format when plugin installed; else explicit JSON fallback
    headers  — C declarations from local type library
    redact   — redact IPs/emails/hashes/URLs from text= or binary strings
    vtable   — dump C++ vtables matching query into JSON
    """
    try:
        if path and action != "redact":
            path, err = validate_path_safe(path)
            if err:
                return err

        max_funcs = _clamp_int(
            max_functions if max_functions is not None else kwargs.get("max_functions"),
            5000,
            1,
            100000,
        )
        item_limit = _clamp_int(limit if limit is not None else kwargs.get("limit"), 1000, 1, 100000)

        if action == "listing":
            if not path:
                path = _default_export_path(".lst")
            _ensure_parent_dir(path)

            if addr:
                if ":" in str(addr):
                    start_s, end_s = str(addr).split(":", 1)
                    start_ea = parse_address(start_s)
                    end_ea = parse_address(end_s)
                else:
                    ea = parse_address(addr)
                    func = ida_funcs.get_func(ea)
                    if func:
                        start_ea, end_ea = func.start_ea, func.end_ea
                    else:
                        start_ea, end_ea = ea, ea + 0x100
            else:
                segs = list(idautils.Segments())
                if not segs:
                    return make_error(MCPError.IDA_ERROR, "No segments found")
                seg = ida_segment.getseg(segs[0])
                start_ea = seg.start_ea
                end_ea = min(seg.end_ea, start_ea + 0x10000)

            lines = []
            current = start_ea
            while current < end_ea and len(lines) < max_funcs:
                disasm = idc.generate_disasm_line(current, 0)
                if disasm:
                    lines.append(f"{hex(current)}: {ida_lines.tag_remove(disasm)}")
                current = idc.next_head(current)
                if current == idaapi.BADADDR:
                    break

            with open(path, "w", encoding="utf-8") as f:
                f.write("; IDA Pro Listing\n")
                f.write(f"; File: {idaapi.get_input_file_path()}\n")
                f.write(f"; Range: {hex(start_ea)} - {hex(end_ea)}\n\n")
                f.write("\n".join(lines))
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "lines": len(lines),
                "start": hex(start_ea),
                "end": hex(end_ea),
            }

        if action == "html":
            if not path:
                path = _default_export_path(".html")
            _ensure_parent_dir(path)
            parts = [
                "<!DOCTYPE html><html><head>",
                "<meta charset='utf-8'/>",
                "<title>IDA Analysis Report</title>",
                "<style>body{font-family:monospace} .func,.str{margin:4px 0} .addr{color:#06c}</style>",
                "</head><body>",
                f"<h1>Analysis: {os.path.basename(idaapi.get_input_file_path() or '')}</h1>",
                "<h2>Functions</h2>",
            ]
            func_count = 0
            for func_ea in idautils.Functions():
                if func_count >= max_funcs:
                    break
                name = idc.get_func_name(func_ea) or ""
                parts.append(
                    f'<div class="func"><span class="addr">{hex(func_ea)}</span> {name}</div>'
                )
                func_count += 1
            parts.append("<h2>Strings</h2>")
            str_count = 0
            for s in idautils.Strings():
                if str_count >= item_limit:
                    break
                parts.append(
                    f'<div class="str"><span class="addr">{hex(s.ea)}</span> {str(s)[:200]}</div>'
                )
                str_count += 1
            parts.append("</body></html>")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(parts))
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "functions": func_count,
                "strings": str_count,
            }

        if action == "idc":
            if not path:
                path = _default_export_path(".idc")
            _ensure_parent_dir(path)
            commands = [
                "// IDC script generated by ida-pro-mcp",
                "#include <idc.idc>",
                "static main() {",
            ]
            rename_count = 0
            for ea, nm in idautils.Names():
                if not nm:
                    continue
                commands.append(f'  MakeName({hex(ea)}, "{_escape_idc_string(str(nm))}");')
                rename_count += 1
                if rename_count >= 100000:
                    break
            func_count = 0
            for fea in idautils.Functions():
                fn = ida_funcs.get_func(fea)
                if not fn:
                    continue
                commands.append(f"  MakeFunction({hex(fn.start_ea)}, {hex(fn.end_ea)});")
                func_count += 1
                if func_count >= 100000:
                    break
            comment_count = 0
            for seg_ea in idautils.Segments():
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    c0 = idc.get_cmt(head, 0)
                    c1 = idc.get_cmt(head, 1)
                    if c0:
                        commands.append(
                            f'  MakeComm({hex(head)}, "{_escape_idc_string(str(c0))}");'
                        )
                        comment_count += 1
                    if c1:
                        commands.append(
                            f'  MakeRptCmt({hex(head)}, "{_escape_idc_string(str(c1))}");'
                        )
                        comment_count += 1
                    if comment_count >= 50000:
                        break
                if comment_count >= 50000:
                    break
            type_count = 0
            for ea, _nm in idautils.Names():
                t = idc.get_type(ea)
                if not t:
                    continue
                commands.append(f'  SetType({hex(ea)}, "{_escape_idc_string(str(t))}");')
                type_count += 1
                if type_count >= 50000:
                    break
            commands.append("}")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(commands))
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "commands": len(commands),
                "renames": rename_count,
                "functions": func_count,
                "comments": comment_count,
                "types": type_count,
            }

        if action == "json":
            if not path:
                path = _default_export_path("_export.json")
            _ensure_parent_dir(path)
            md5 = None
            try:
                digest = idaapi.retrieve_input_file_md5()
                if digest:
                    md5 = digest.hex() if hasattr(digest, "hex") else str(digest)
            except Exception:
                md5 = None
            data: dict[str, Any] = {
                "binary_metadata": {
                    "file": idaapi.get_input_file_path(),
                    "md5": md5,
                    "imagebase": hex(idaapi.get_imagebase()),
                    "ida_version": getattr(idaapi, "get_kernel_version", lambda: "unknown")(),
                },
                "functions": [],
                "strings": [],
                "imports": [],
                "exports": [],
                "types": [],
                "comments": [],
            }
            for func_ea in idautils.Functions():
                if len(data["functions"]) >= max_funcs:
                    break
                func = ida_funcs.get_func(func_ea)
                row = {
                    "addr": hex(func_ea),
                    "name": idc.get_func_name(func_ea) or "",
                    "size": (func.end_ea - func.start_ea) if func else 0,
                }
                if include_decompile:
                    try:
                        import ida_hexrays

                        cfunc = ida_hexrays.decompile(func_ea)
                        if cfunc:
                            row["decompile"] = str(cfunc)[:8000]
                    except Exception:
                        pass
                data["functions"].append(row)
            for s in idautils.Strings():
                if len(data["strings"]) >= item_limit:
                    break
                data["strings"].append({"addr": hex(s.ea), "value": str(s)[:500]})
            try:
                for i in range(idaapi.get_import_module_qty()):
                    mod_name = idaapi.get_import_module_name(i) or f"mod_{i}"

                    def _cb(ea, name, ord_, _mod=mod_name):
                        data["imports"].append(
                            {
                                "module": _mod,
                                "addr": hex(ea),
                                "name": name or "",
                                "ordinal": int(ord_ or 0),
                            }
                        )
                        return True

                    idaapi.enum_import_names(i, _cb)
            except Exception:
                pass
            try:
                for idx, ord_, ea, nm in idautils.Entries():
                    data["exports"].append(
                        {
                            "index": int(idx),
                            "ordinal": int(ord_),
                            "addr": hex(ea),
                            "name": nm or "",
                        }
                    )
            except Exception:
                pass
            try:
                til = ida_typeinf.get_idati()
                qty_func = getattr(ida_typeinf, "get_ordinal_qty", None) or getattr(
                    ida_typeinf, "get_ordinal_count", None
                )
                qty = int(qty_func(til) or 0) if qty_func and til else 0
                for ord_ in range(1, qty + 1):
                    tif = ida_typeinf.tinfo_t()
                    if tif.get_numbered_type(til, ord_):
                        n = str(tif.get_type_name() or "")
                        if n:
                            data["types"].append(
                                {"ordinal": ord_, "name": n, "decl": _print_tinfo_c(tif)}
                            )
                    if len(data["types"]) >= item_limit:
                        break
            except Exception:
                pass
            for seg_ea in idautils.Segments():
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    c = idc.get_cmt(head, 0) or idc.get_cmt(head, 1)
                    if c:
                        data["comments"].append({"addr": hex(head), "comment": str(c)[:500]})
                    if len(data["comments"]) >= item_limit:
                        break
                if len(data["comments"]) >= item_limit:
                    break

            with open(path, "w", encoding="utf-8") as f:
                json_module.dump(data, f, indent=2)
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "functions": len(data["functions"]),
                "strings": len(data["strings"]),
                "imports": len(data["imports"]),
                "exports": len(data["exports"]),
                "types": len(data["types"]),
                "comments": len(data["comments"]),
            }

        if action == "sarif":
            if not path:
                path = _default_export_path(".sarif.json")
            _ensure_parent_dir(path)
            # Only real findings — never invent a result per function.
            findings = []
            try:
                try:
                    from .blackboard import BlackboardStore  # type: ignore
                except ImportError:
                    from blackboard import BlackboardStore  # type: ignore

                bb = BlackboardStore()
                for cat in ("vuln", "finding", "security", "ioc"):
                    try:
                        findings.extend(
                            bb.list(category=cat, include_resolved=False, limit=500) or []
                        )
                    except Exception:
                        continue
            except Exception:
                findings = []

            results = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                a = str(f.get("addr") or "")
                msg = str(f.get("title") or f.get("content") or "").strip()
                if not msg:
                    continue
                level = "warning"
                conf = f.get("confidence")
                try:
                    if conf is not None and float(conf) >= 0.85:
                        level = "error"
                except (TypeError, ValueError):
                    pass
                results.append(
                    {
                        "ruleId": "ida.blackboard.finding",
                        "level": level,
                        "message": {"text": msg[:2000]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": idaapi.get_input_file_path() or ""
                                    },
                                    "region": {"startLine": 1},
                                    "address": {"absoluteAddress": a or "0x0"},
                                }
                            }
                        ],
                    }
                )
                if len(results) >= item_limit:
                    break

            sarif = {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "ida-pro-mcp",
                                "rules": [
                                    {
                                        "id": "ida.blackboard.finding",
                                        "name": "BlackboardFinding",
                                        "shortDescription": {
                                            "text": "Finding persisted on the analysis blackboard"
                                        },
                                    }
                                ],
                            }
                        },
                        "results": results,
                    }
                ],
            }
            with open(path, "w", encoding="utf-8") as f:
                json_module.dump(sarif, f, indent=2)
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "results": len(results),
                "note": (
                    "SARIF contains blackboard findings only. "
                    "Write findings with blackboard(action='write') first; "
                    "empty results means no findings stored."
                ),
            }

        if action == "binexport":
            if not path:
                path = _default_export_path(".BinExport")
            _ensure_parent_dir(path)
            ok, detail = _try_binexport_binary(path)
            if ok and os.path.isfile(path) and os.path.getsize(path) > 0:
                return {
                    "ok": True,
                    "exported": True,
                    "path": os.path.abspath(path),
                    "size_bytes": os.path.getsize(path),
                    "binexport_available": True,
                    "method": detail,
                }
            return _write_binexport_fallback(path, max_funcs=max_funcs)

        if action == "headers":
            if not path:
                path = _default_export_path(".h")
            _ensure_parent_dir(path)
            body, type_count = _export_headers_text(max_types=max_funcs)
            with open(path, "w", encoding="utf-8") as f:
                f.write(body)
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "types_count": type_count,
                "bytes": len(body.encode("utf-8")),
            }

        if action == "redact":
            content = text if text is not None else None
            if content is None and path and not os.path.exists(str(path)):
                # Back-compat: path used as inline text when not a filesystem path
                content = str(path)
            if content is None and path and os.path.isfile(str(path)):
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            if content is None:
                strings = []
                for s in idautils.Strings():
                    if len(strings) >= item_limit:
                        break
                    val = str(s)
                    if val and len(val) > 3:
                        strings.append(val)
                content = "\n".join(strings)
            redacted, redactions = redact_text(content)
            out_path = kwargs.get("out_path") or kwargs.get("output")
            result = {
                "ok": True,
                "original_length": len(content),
                "redacted_length": len(redacted),
                "redactions": redactions[:100],
                "count": len(redactions),
                "redacted": redacted[:50000],
            }
            if out_path:
                out_path, err = validate_path_safe(str(out_path))
                if err:
                    return err
                _ensure_parent_dir(out_path)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(redacted)
                result["path"] = out_path
                result["exported"] = True
            return result

        if action == "vtable":
            if not path:
                path = _default_export_path("_vtables.json")
            _ensure_parent_dir(path)
            q = query or kwargs.get("query")
            matcher = compile_smart_pattern(q, case_sensitive=False) if q else None
            ptr_size = 8 if _inf_is_64bit() else 4
            import struct as _struct

            vtables = []
            for ea, name in idautils.Names():
                if matcher and not matcher(name):
                    continue
                lname = (name or "").lower()
                if "_ztv" not in lname and "vtable" not in lname:
                    # Also accept RTTI-ish patterns
                    if "vftable" not in lname:
                        continue
                entries = []
                cur = ea
                for idx in range(64):
                    raw = ida_bytes.get_bytes(cur, ptr_size)
                    if not raw or len(raw) < ptr_size:
                        break
                    fmt = "<Q" if ptr_size == 8 else "<I"
                    target = _struct.unpack(fmt, raw)[0]
                    if target == 0 or not ida_bytes.is_loaded(target):
                        break
                    func_name = idc.get_name(target) or ""
                    entries.append(
                        {"index": idx, "addr": hex(target), "name": func_name}
                    )
                    cur += ptr_size
                if entries:
                    vtables.append(
                        {
                            "vtable_addr": hex(ea),
                            "name": name,
                            "entries": entries,
                            "count": len(entries),
                        }
                    )
                if len(vtables) >= item_limit:
                    break
            with open(path, "w", encoding="utf-8") as f:
                json_module.dump(
                    {"vtables": vtables, "count": len(vtables)}, f, indent=2
                )
            return {
                "ok": True,
                "exported": True,
                "path": path,
                "count": len(vtables),
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
