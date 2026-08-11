#!/usr/bin/env python3
"""Host-side radare2/Rizin subprocess engine (Architecture A, Phase 1).

Optional, default-off: every op is a per-call stateless one-shot
(``rz -q -c`` / ``r2 -q -c``) over the raw binary path. The engine never
writes the IDB, never runs in-process, never inherits the host environment
(``IDA_MCP_SESSION_TOKEN`` and every other secret are scrubbed), and never
shell-interpolates the target path — the path travels as an argv element.

It works while IDA is mid-auto-analysis (safe_mode) and when IDA is down:
it only needs the raw file plus an optional arch/bitness/base context.

Phase 1 ops (all return the standard host envelope via ``make_error`` /
``is_error_result``):

  * status                 — engine availability feature-test (rz -v / r2 -v)
  * bininfo                — rz-bin -I / rabin2 -I metadata (filetype/arch/endian/bits/entries)
  * load_hints             — bininfo + host-side raw-arch heuristics (processor/bitness/base)
  * disassemble_hypothesis — rv32/rv64/thumb/metapc over one window, with disagreement offsets
  * vxrefs                 — raw pointer-width little/big-endian word scan for a target value
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any

from .config import R2_BIN, R2_BININFO_BIN, R2_TIMEOUT_SECONDS
from .errors import MCPError, is_error_result, make_error

# r2/rz colorize disassembly output; strip ANSI escapes before parsing.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Disassembly line: 0xADDR <hex bytes>  <mnemonic ...>
# The byte column is a run of 2-hex-digit tokens, contiguous ("1300") or
# single-space separated ("13 00") depending on the r2/rz version.
_DISASM_LINE_RE = re.compile(
    r"^\s*0x([0-9a-fA-F]{1,16})\s+([0-9a-fA-F]{2}(?:\s?[0-9a-fA-F]{2})*)\s+(.+)$"
)

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][0-9a-zA-Z.]+)?)")

# The four Phase-1 decoder hypotheses. ``endian_var`` is False for RISC-V:
# radare2's riscv module hard-codes little-endian and rejects `e asm.endian`.
_HYPOTHESES: dict[str, dict[str, Any]] = {
    "rv32": {"asm_arch": "riscv", "bits": 32, "endian_var": False},
    "rv64": {"asm_arch": "riscv", "bits": 64, "endian_var": False},
    "thumb": {"asm_arch": "arm", "bits": 16, "endian_var": True},
    "metapc": {"asm_arch": "x86", "bits": 32, "endian_var": True},
}


def _r2_env() -> dict[str, str]:
    """Minimal, scrubbed environment for the r2/rz child.

    The child must never inherit ``IDA_MCP_SESSION_TOKEN`` or any other host
    secret. It only needs PATH (to resolve its own binary/plugins) and HOME
    (r2/rz write config caches there). ``R2_NOPLUGINS`` keeps plugin loading
    off — the one hardening flag that is portable across radare2 and Rizin.
    """
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "R2_NOPLUGINS": "1",
    }


def _extract_json_object(text: str) -> dict | None:
    """Parse the first balanced JSON object found in *text*.

    Some rz-bin/rabin2 builds print a leading diagnostic line to stdout; the
    JSON object itself is the only thing we need. Returns None when no valid
    object can be recovered.
    """
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        payload = json.loads(text[start : end + 1])
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _decode_stdout(result: dict) -> str:
    stdout = result.get("stdout")
    if isinstance(stdout, bytes):
        return stdout.decode("utf-8", errors="replace")
    return str(stdout or "")


def _decode_stderr(result: dict) -> str:
    stderr = result.get("stderr")
    if isinstance(stderr, bytes):
        return stderr.decode("utf-8", errors="replace")
    return str(stderr or "")


def _scan_words(data: bytes, target: int, width: int, endian: str) -> list[dict]:
    """Find every offset in *data* holding a *width*-byte word equal to target.

    Uses ``bytes.find`` (memchr-class scan) so even unaligned occurrences are
    found efficiently on large files.
    """
    if width not in (4, 8):
        return []
    try:
        packed = target.to_bytes(width, endian)
    except OverflowError:
        return []
    matches: list[dict] = []
    start = 0
    while True:
        idx = data.find(packed, start)
        if idx < 0:
            break
        matches.append(
            {"offset": idx, "width": width, "endian": endian, "word": target}
        )
        start = idx + 1
    return matches


def _compute_disagreements(results: list[dict]) -> list[dict]:
    """Cross-decoder disagreement offsets for disassemble_hypothesis.

    At every offset where at least two hypotheses decoded an instruction, an
    offset is a *disagreement* when the interpretations differ (mnemonic or
    instruction size). Different ISAs decodating the same bytes is exactly the
    "likely mis-decode" signal the op exists to surface.
    """
    by_offset: dict[int, list[dict]] = {}
    for res in results:
        if res.get("error"):
            continue
        arch = res.get("arch")
        bits = res.get("bits")
        for ins in res.get("instructions", []):
            off = int(ins.get("offset", 0))
            text = str(ins.get("text") or "")
            mnemonic = text.split(None, 1)[0] if text else ""
            by_offset.setdefault(off, []).append(
                {
                    "arch": arch,
                    "bits": bits,
                    "size": int(ins.get("size", 0)),
                    "bytes": str(ins.get("bytes") or ""),
                    "mnemonic": mnemonic,
                }
            )
    disagreements: list[dict] = []
    for off in sorted(by_offset):
        interpretations = by_offset[off]
        if len(interpretations) < 2:
            continue
        distinct = {(i["mnemonic"], i["size"]) for i in interpretations}
        if len(distinct) > 1:
            disagreements.append(
                {"offset": off, "interpretations": interpretations}
            )
    return disagreements


class R2Engine:
    """Per-call stateless one-shot driver for the r2/Rizin subprocess engine."""

    def __init__(
        self,
        bin_path: str | None = None,
        bininfo_bin: str | None = None,
        timeout: float | None = None,
        allowed_root: str | None = None,
    ) -> None:
        self.bin_path = str(bin_path or R2_BIN)
        self.bininfo_bin = str(bininfo_bin or R2_BININFO_BIN)
        self.timeout = float(timeout) if timeout is not None else float(R2_TIMEOUT_SECONDS)
        self.allowed_root = allowed_root

    # ------------------------------------------------------------------
    # Target canonicalization (mirrors the memory-tool allow-root logic)
    # ------------------------------------------------------------------
    @staticmethod
    def canonicalize_target(
        path: Any, allowed_root: str | None = None
    ) -> tuple[str | None, dict | None]:
        """Resolve *path* to a canonical absolute file path.

        Mirrors the memory tool's allow-root rules: ``realpath`` resolution,
        containment inside the allowed root, and rejection of symlink
        components. Returns ``(canonical_path, None)`` on success or
        ``(None, error_envelope)`` on failure.
        """
        if not isinstance(path, str) or not path.strip():
            return None, make_error(
                MCPError.INVALID_ARGS, "r2: binary_path is required"
            )
        try:
            canonical = os.path.realpath(
                os.path.abspath(os.path.expanduser(path.strip()))
            )
        except Exception:
            return None, make_error(
                MCPError.INVALID_ARGS, "r2: invalid binary path"
            )
        if not os.path.isfile(canonical):
            return None, make_error(
                MCPError.R2_BINARY_NOT_FOUND,
                f"r2: target binary not found: {canonical}",
                hint=(
                    "The target file does not exist. Verify the path, and "
                    "confirm the engine binary via IDA_MCP_R2_BIN."
                ),
                details={"path": canonical},
            )
        if allowed_root:
            try:
                root = os.path.realpath(
                    os.path.abspath(os.path.expanduser(allowed_root))
                )
            except Exception:
                root = ""
            if root:
                try:
                    common = os.path.commonpath([root, canonical])
                except ValueError:
                    common = ""
                if common != root:
                    return None, make_error(
                        MCPError.INVALID_ARGS,
                        "r2: binary path escapes the allowed root",
                    )
                rel = os.path.relpath(canonical, root)
                current = root
                for part in rel.split(os.sep):
                    if not part:
                        continue
                    current = os.path.join(current, part)
                    if os.path.islink(current):
                        return None, make_error(
                            MCPError.INVALID_ARGS,
                            "r2: symbolic links are not allowed in the target path",
                        )
        return canonical, None

    # ------------------------------------------------------------------
    # Subprocess plumbing
    # ------------------------------------------------------------------
    @staticmethod
    def _restricted_cwd(path: str | None = None) -> str:
        """A restricted working directory for the child.

        Never the server's cwd. When a target file is known, the child runs in
        the target's own directory (a location the caller already controls);
        otherwise a throwaway system temp dir.
        """
        if path:
            d = os.path.dirname(os.path.abspath(path))
            if os.path.isdir(d):
                return d
        return tempfile.gettempdir()

    def _one_shot(
        self, argv: list[str], *, cwd: str | None = None
    ) -> dict[str, Any]:
        """Run one stateless r2/rz subprocess with hardened args.

        Returns a success envelope ``{ok, argv, returncode, stdout, stderr}``
        or a ``make_error`` payload. A negative returncode means the process
        was killed by a signal (R2_PROCESS_DIED); a non-zero exit with no
        stdout surfaces as R2_ENGINE_START_FAILED so op-level parsers can
        still tolerate non-zero exits that carry usable output.
        """
        try:
            proc = subprocess.run(
                [str(a) for a in argv],
                env=_r2_env(),
                cwd=cwd if cwd is not None else self._restricted_cwd(),
                capture_output=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return make_error(
                MCPError.R2_ENGINE_START_FAILED,
                f"r2 engine binary not found: {argv[0] if argv else ''}",
                recoverable=True,
                hint=(
                    "Set IDA_MCP_R2_BIN to the rz/r2 executable, or install "
                    "the engine (installer --with-r2)."
                ),
            )
        except subprocess.TimeoutExpired:
            return make_error(
                MCPError.R2_TIMEOUT,
                "r2 engine subprocess exceeded its wall-clock cap",
                recoverable=False,
                details={"timeout_seconds": self.timeout, "argv": [str(a) for a in argv]},
            )
        except OSError as exc:
            return make_error(
                MCPError.R2_ENGINE_START_FAILED,
                f"r2 engine failed to start: {exc}",
                recoverable=True,
            )
        returncode = proc.returncode
        if returncode is not None and returncode < 0:
            return make_error(
                MCPError.R2_PROCESS_DIED,
                "r2 engine subprocess died before returning a result",
                recoverable=True,
                details={"returncode": returncode, "argv": [str(a) for a in argv]},
            )
        if returncode not in (0, None) and not proc.stdout:
            return make_error(
                MCPError.R2_ENGINE_START_FAILED,
                f"r2 engine exited with code {returncode}",
                recoverable=True,
                details={
                    "returncode": returncode,
                    "stderr": proc.stderr.decode("utf-8", errors="replace")[:500],
                },
            )
        return {
            "ok": True,
            "argv": [str(a) for a in argv],
            "returncode": returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        """Feature-test engine availability via ``rz -v`` / ``r2 -v``.

        Unlike the other ops this always returns ``{ok: true, available: ...}``
        — an absent engine is an expected, default-off state, not a failure.
        """
        result = self._one_shot([self.bin_path, "-v"])
        if is_error_result(result):
            code = result.get("code")
            if code == MCPError.R2_ENGINE_START_FAILED:
                return {
                    "ok": True,
                    "available": False,
                    "bin": self.bin_path,
                    "reason": result.get("message") or "engine unavailable",
                    "hint": result.get("hint"),
                }
            # Genuine failure (timeout / died) stays an error envelope.
            return result
        text = _decode_stdout(result)
        first_line = next(
            (ln.strip() for ln in text.splitlines() if ln.strip()), ""
        )
        lowered = text.lower()
        variant = (
            "rizin"
            if "rizin" in lowered
            else ("radare2" if "radare2" in lowered else "unknown")
        )
        version: str | None = None
        m = _VERSION_RE.search(first_line)
        if m:
            version = m.group(1)
        return {
            "ok": True,
            "available": True,
            "bin": self.bin_path,
            "variant": variant,
            "version": version,
            "first_line": first_line,
        }

    # ------------------------------------------------------------------
    # bininfo
    # ------------------------------------------------------------------
    def _run_bininfo_json(self, flags: list[str], path: str) -> dict[str, Any]:
        """Run ``<rz-bin|rabin2> <flags> <path>`` and parse the JSON object."""
        argv = [self.bininfo_bin, *flags, path]
        result = self._one_shot(argv)
        if is_error_result(result):
            return result
        payload = _extract_json_object(_decode_stdout(result))
        if payload is None:
            return make_error(
                MCPError.R2_ENGINE_START_FAILED,
                "r2 bininfo output was not valid JSON",
                recoverable=True,
                details={
                    "stderr": _decode_stderr(result)[:500],
                    "stdout": _decode_stdout(result)[:500],
                },
            )
        return payload

    def bininfo(self, binary_path: str) -> dict[str, Any]:
        """Metadata for a raw binary via ``rz-bin -I`` / ``rabin2 -I``."""
        canonical, err = self.canonicalize_target(binary_path, self.allowed_root)
        if err:
            return err
        info_result = self._run_bininfo_json(["-Ij"], canonical)
        if is_error_result(info_result):
            return info_result
        info = dict(info_result.get("info") or {})
        entries: list[dict[str, Any]] = []
        entries_result = self._run_bininfo_json(["-ej"], canonical)
        if not is_error_result(entries_result):
            raw_entries = entries_result.get("entries") or []
            if isinstance(raw_entries, list):
                entries = [
                    e for e in raw_entries if isinstance(e, dict)
                ]
        return {
            "ok": True,
            "file": canonical,
            "filetype": (
                info.get("bintype") or info.get("class") or info.get("type")
                or "unknown"
            ),
            "arch": info.get("arch") or None,
            "endian": info.get("endian") or None,
            "bits": info.get("bits") or None,
            "machine": info.get("machine") or None,
            "os": info.get("os") or None,
            "class": info.get("class") or None,
            "entries": entries,
            "raw": info,
        }

    # ------------------------------------------------------------------
    # load_hints
    # ------------------------------------------------------------------
    def load_hints(
        self,
        binary_path: str,
        arch_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compute load hints: bininfo + host-side raw-arch heuristics.

        Explicit caller context (from a session's analysis_options or bare
        ``processor``/``bitness``/``baseaddr`` args) always wins over r2's
        guesses — the paper's "r2 proposes, IDA disposes" rule.
        """
        canonical, err = self.canonicalize_target(binary_path, self.allowed_root)
        if err:
            return err
        ctx = dict(arch_context or {})
        bin_res = self.bininfo(canonical)
        info: dict[str, Any] = {}
        if not is_error_result(bin_res):
            info = dict(bin_res.get("raw") or {})

        inference: dict[str, Any] = {}
        try:
            from .analysis.arch_profile import infer_binary_arch_profile
            inference = dict(infer_binary_arch_profile(canonical))
        except Exception as exc:  # heuristics are advisory
            inference = {"reason": f"host-side inference unavailable: {exc}"}

        def _pick(caller_val: Any, bininfo_val: Any, infer_val: Any) -> Any:
            for candidate in (caller_val, bininfo_val, infer_val):
                if candidate not in (None, "", 0):
                    return candidate
            return None

        processor = _pick(ctx.get("processor"), info.get("arch"), inference.get("processor"))
        bitness = _pick(ctx.get("bitness"), info.get("bits"), inference.get("bitness"))
        endian = _pick(ctx.get("endian"), info.get("endian"), inference.get("endian"))
        base_candidate = _pick(
            ctx.get("baseaddr"),
            ctx.get("load_base"),
            inference.get("load_base"),
        )
        caller_explicit = any(
            ctx.get(k) not in (None, "") for k in ("processor", "bitness", "endian", "baseaddr", "load_base")
        )
        return {
            "ok": True,
            "file": canonical,
            "filetype": (
                info.get("bintype") or inference.get("file_kind") or "unknown"
            ),
            "processor": processor,
            "bitness": bitness,
            "endian": endian,
            "base_candidate": base_candidate,
            "load_hints": {
                "processor": processor,
                "bitness": bitness,
                "endian": endian,
                "baseaddr": base_candidate,
            },
            "confidence": inference.get("confidence"),
            "reason": inference.get("reason"),
            "warning": inference.get("warning"),
            "candidates": inference.get("candidates") or [],
            "ambiguous": bool(inference.get("ambiguous")),
            "arch_context_applied": bool(caller_explicit),
            "bininfo": bin_res if not is_error_result(bin_res) else None,
        }

    # ------------------------------------------------------------------
    # disassemble_hypothesis
    # ------------------------------------------------------------------
    def _decode_window(
        self,
        path: str,
        offset: int,
        size: int,
        base: int,
        name: str,
        cfg: dict[str, Any],
    ) -> dict[str, Any]:
        """Disassemble one window under one arch hypothesis."""
        arch = cfg.get("asm_arch", "x86")
        bits = int(cfg.get("bits") or 32)
        commands = [f"e asm.arch={arch}", f"e asm.bits={bits}"]
        if cfg.get("endian_var"):
            commands.append("e asm.endian=little")
        commands.append(f"s 0x{base + offset:X}")
        commands.append(f"pD {size}")
        argv = [self.bin_path, "-q"]
        if base:
            argv += ["-m", f"0x{base:X}"]
        argv += ["-c", "; ".join(commands), path]
        result = self._one_shot(argv)
        if is_error_result(result):
            return {
                "arch": name,
                "bits": bits,
                "decode_error": result,
                "instructions": [],
            }
        text = _ANSI_RE.sub("", _decode_stdout(result))
        instructions: list[dict[str, Any]] = []
        for line in text.splitlines():
            m = _DISASM_LINE_RE.match(line)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16) - base
            except ValueError:
                continue
            if addr < 0:
                continue
            bytes_hex = m.group(2).replace(" ", "").replace("\t", "")
            ins_text = m.group(3).strip()
            if not ins_text or ins_text.lower().startswith("invalid"):
                continue
            instructions.append(
                {
                    "offset": addr,
                    "size": len(bytes_hex) // 2,
                    "bytes": bytes_hex,
                    "text": ins_text,
                }
            )
        return {
            "arch": name,
            "bits": bits,
            "decode_error": None,
            "instructions": instructions,
        }

    def disassemble_hypothesis(
        self,
        binary_path: str,
        offset: int = 0,
        size: int = 64,
        base: int = 0,
        hypotheses: list[str] | None = None,
        arch_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Try rv32/rv64/thumb/metapc on one window and report disagreements.

        *offset* is a file offset; *base* is the virtual address of file
        offset 0 (default 0). ``arch_context`` may carry an explicit
        processor/bitness that narrows the default hypothesis set.
        """
        canonical, err = self.canonicalize_target(binary_path, self.allowed_root)
        if err:
            return err
        try:
            file_size = os.path.getsize(canonical)
        except OSError as exc:
            return make_error(
                MCPError.IO_ERROR, f"cannot stat r2 target: {exc}"
            )
        if offset < 0 or offset >= file_size:
            return make_error(
                MCPError.ADDRESS_INVALID,
                f"r2 disassemble_hypothesis offset 0x{offset:X} is outside the file (size 0x{file_size:X})",
                details={"offset": offset, "file_size": file_size},
            )
        size = max(1, min(int(size), file_size - offset))
        base = max(0, int(base))

        chosen = [h for h in (hypotheses or []) if h in _HYPOTHESES]
        if not chosen:
            # Narrow the default set from arch_context when it is decisive.
            proc = str((arch_context or {}).get("processor") or "").lower()
            bits = (arch_context or {}).get("bitness")
            if proc in ("riscv",) and bits in (64, "64"):
                chosen = ["rv64"]
            elif proc in ("riscv",):
                chosen = ["rv32"]
            elif proc == "arm":
                chosen = ["thumb"]
            elif proc in ("metapc", "x86", "i386", "i686"):
                chosen = ["metapc"]
            else:
                chosen = list(_HYPOTHESES)
        if not chosen:
            return make_error(
                MCPError.INVALID_ARGS,
                f"r2 disassemble_hypothesis: no valid hypotheses in {hypotheses!r}",
            )

        results = []
        for name in chosen:
            results.append(
                self._decode_window(
                    canonical, offset, size, base, name, _HYPOTHESES[name]
                )
            )
        return {
            "ok": True,
            "file": canonical,
            "window": {"offset": offset, "size": size, "base": base},
            "hypotheses": results,
            "disagreements": _compute_disagreements(results),
        }

    # ------------------------------------------------------------------
    # vxrefs
    # ------------------------------------------------------------------
    def vxrefs(
        self,
        binary_path: str,
        target: Any,
        pointer_width: int | str | None = None,
        endian: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Scan a raw file for pointer-width LE/BE words equal to *target*.

        The pre-IDA analogue of ``search(data_value)`` on an analyzed IDB —
        finds dispatch/vector/function-pointer table entries that IDA never
        created data xrefs for because the blob was loaded raw.
        """
        canonical, err = self.canonicalize_target(binary_path, self.allowed_root)
        if err:
            return err
        try:
            target_val = int(str(target), 0)
        except (ValueError, TypeError):
            return make_error(
                MCPError.INVALID_ARGS,
                "r2 vxrefs: target must be an integer address",
            )
        if target_val < 0:
            return make_error(
                MCPError.INVALID_ARGS,
                "r2 vxrefs: target must be non-negative",
            )
        try:
            with open(canonical, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            return make_error(
                MCPError.IO_ERROR, f"cannot read r2 target: {exc}"
            )

        widths = [int(pointer_width)] if pointer_width else [4, 8]
        widths = [w for w in widths if w in (4, 8)]
        if not widths:
            widths = [4, 8]
        endians = [endian] if endian else ["little", "big"]
        endians = [e for e in endians if e in ("little", "big")]
        if not endians:
            endians = ["little", "big"]

        matches: list[dict[str, Any]] = []
        for width in widths:
            for end in endians:
                matches.extend(_scan_words(data, target_val, width, end))

        if not pointer_width and len(widths) > 1:
            # Auto width: prefer the width with more hits (ties → narrower).
            count4 = sum(1 for m in matches if m["width"] == 4)
            count8 = sum(1 for m in matches if m["width"] == 8)
            if count4 or count8:
                keep = 4 if count4 >= count8 else 8
                matches = [m for m in matches if m["width"] == keep]

        matches.sort(key=lambda m: (m["offset"], m["endian"], m["width"]))
        total = len(matches)
        if limit is not None:
            matches = matches[: max(0, int(limit))]
        return {
            "ok": True,
            "file": canonical,
            "target": target_val,
            "pointer_width": matches[0]["width"] if matches else (widths[0] if pointer_width else 4),
            "endian": (matches[0]["endian"] if matches else (endian or "auto")),
            "count": len(matches),
            "total": total,
            "matches": matches,
        }
