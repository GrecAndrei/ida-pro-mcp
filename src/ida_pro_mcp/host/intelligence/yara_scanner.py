"""
YARA scanner — wraps yara-python to compile signature-base rules and scan
IDB memory or binary files for known malware/APT indicators.

Uses yara-python (already a runtime dependency). Compiles all ``.yar`` /
``.yara`` files under a rules directory into a single ruleset, caches the
compiled output under CACHE_DIR, and exposes scan helpers for both raw
bytes and (via callback) IDA memory ranges.

The scanner is decoupled from the IDA layer: callers pass a ``read_bytes``
callback that knows how to read a (start, size) range from wherever the
target data lives (IDB memory, file, network buffer, etc.). This keeps the
module pure-Python and unit-testable without an IDA instance.

The pe-module caveat: signature-base rules with ``import "pe"`` and
``uint16(0) == 0x5a4d and filesize < X`` only match when scanning a real
PE file. When scanning IDB memory, those conditions evaluate to false but
string matches still fire. Callers should treat matches as "candidate
indicators" and verify with the original binary when the pe condition is
non-trivial.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import CACHE_DIR
from ..errors import MCPError, make_error

__all__ = [
    "YaraScanner",
    "YaraRuleMatch",
    "YaraStringHit",
    "is_yara_available",
    "yara_version",
    "default_rules_dir",
    "default_compiled_path",
    "compile_rules",
    "compile_text",
    "load_compiled_rules",
]

logger = logging.getLogger(__name__)

_COMPILED_FILENAME = "signature_base_compiled.bin"
_COMPILED_VERSION = 1
_MAX_SCAN_BYTES = 16 * 1024 * 1024
_MAX_MATCHES_PER_SCAN = 5000
_MAX_STRING_DATA_PER_MATCH = 256
_MAX_RULE_FILES = 5000
_SCAN_CHUNK_SIZE = 256 * 1024


@dataclass
class YaraStringHit:
    identifier: str
    offset: int
    data: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "offset": self.offset,
            "data": self.data,
        }


@dataclass
class YaraRuleMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[YaraStringHit] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": list(self.tags),
            "meta": dict(self.meta),
            "strings": [s.to_dict() for s in self.strings],
            "string_count": len(self.strings),
        }


def is_yara_available() -> bool:
    try:
        import yara  # noqa: F401

        return True
    except Exception:
        return False


def yara_version() -> str:
    try:
        import yara

        return str(getattr(yara, "__version__", "unknown"))
    except Exception:
        return "unavailable"


def default_rules_dir() -> str:
    return os.path.join(CACHE_DIR, "signature-base", "yara")


def default_compiled_path() -> str:
    return os.path.join(CACHE_DIR, _COMPILED_FILENAME)


def _safe_meta_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return str(value)
    except Exception:
        return None


def _iter_rule_files(rules_dir: str) -> list[tuple[str, str]]:
    if not rules_dir or not os.path.isdir(rules_dir):
        return []
    out: list[tuple[str, str]] = []
    for root_dir, _dirs, files in os.walk(rules_dir):
        for fname in sorted(files):
            if not (fname.endswith((".yar", ".yara"))):
                continue
            full = os.path.join(root_dir, fname)
            try:
                if os.path.getsize(full) > 2_000_000:
                    continue
            except OSError:
                continue
            namespace = os.path.splitext(fname)[0]
            out.append((namespace, full))
            if len(out) >= _MAX_RULE_FILES:
                return out
    return out


def compile_rules(
    rules_dir: str,
    output_path: str | None = None,
    externals: dict[str, Any] | None = None,
) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]]]:
    """Compile every ``.yar``/``.yara`` file under ``rules_dir`` into a single
    ruleset using yara-python. Returns (rules, file_errors, compile_errors).

    - file_errors: per-file I/O issues (read failure, oversize)
    - compile_errors: yara-python SyntaxError / other compile-time failures

    signature-base rules reference undeclared external variables like
    ``filepath`` and ``filename`` (intended for LOKI/THOR scanners). Pass
    them via ``externals`` so compilation succeeds; the variables can be
    overridden per-scan via the yara-python ``externals`` kwarg on match.
    """
    if not is_yara_available():
        return (
            None,
            [],
            [make_error(MCPError.YARA_DISABLED, "yara-python not available",
                        details={"path": rules_dir})],
        )
    import yara

    if externals is None:
        externals = {
            "filepath": "",
            "filename": "",
            "extension": "",
            "filetype": "",
            "owner": "",
            "category": "",
            "tlevel": "0",
            "t1": "0",
            "t2": "0",
            "t3": "0",
            "t4": "0",
            "rule_type": "",
            "severity": "0",
            "review": "",
            "rev": "",
            "year": "2024",
        }
    file_errors: list[dict[str, Any]] = []
    filepaths: dict[str, str] = {}
    for namespace, full in _iter_rule_files(rules_dir):
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                f.read(2048)
        except OSError as e:
            file_errors.append(
                make_error(
                    MCPError.FILE_NOT_FOUND,
                    str(e),
                    details={"namespace": namespace, "path": full,
                             "errno": e.errno, "exception_type": type(e).__name__},
                )
            )
            continue
        filepaths[namespace] = full
    if not filepaths:
        return (
            None,
            file_errors,
            [make_error(MCPError.NO_RESULTS, "no rule files found",
                        details={"path": rules_dir})],
        )
    compile_errors: list[dict[str, Any]] = []
    rules: Any | None = None
    try:
        rules = yara.compile(filepaths=filepaths, externals=externals)
    except yara.SyntaxError as e:
        compile_errors.append(
            make_error(MCPError.YARA_COMPILE_ERROR, str(e),
                       details={"path": rules_dir})
        )
    except Exception as e:
        compile_errors.append(
            make_error(
                MCPError.YARA_SCAN_ERROR,
                f"{type(e).__name__}: {e}",
                details={"path": rules_dir, "exception_type": type(e).__name__},
            )
        )
    if rules is not None and output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            rules.save(output_path)
        except Exception as e:
            compile_errors.append(
                make_error(
                    MCPError.IO_ERROR,
                    f"save failed: {e}",
                    details={"path": output_path, "exception_type": type(e).__name__},
                )
            )
    return rules, file_errors, compile_errors


def load_compiled_rules(path: str) -> Any | None:
    if not path or not os.path.isfile(path):
        return None
    if not is_yara_available():
        return None
    import yara

    try:
        return yara.load(path)
    except Exception as e:
        logger.warning("yara load failed: %s", e)
        return None


def compile_text(source: str) -> Any | None:
    """Compile a single YARA rule source string. Returns the compiled
    rules object on success or ``None`` on any error (including
    ``yara-python`` not being installed or the source being invalid).

    Use this for ad-hoc single-rule scans; for a directory of rule
    files prefer :func:`compile_rules`, which caches the result on
    disk and reports per-file errors.
    """
    if not source or not is_yara_available():
        return None
    import yara

    try:
        return yara.compile(source=source)
    except Exception as e:
        logger.warning("yara compile_text failed: %s", e)
        return None


def _match_to_rule_match(m: Any, base_offset: int = 0) -> YaraRuleMatch:
    tags: list[str] = []
    try:
        for t in (m.tags or []):
            tags.append(str(t))
    except Exception:
        pass
    meta: dict[str, Any] = {}
    try:
        for k, v in (m.meta or {}).items():
            meta[str(k)] = _safe_meta_value(v)
    except Exception:
        pass
    strings: list[YaraStringHit] = []
    try:
        for s in (m.strings or []):
            try:
                instances = s.instances
            except Exception:
                instances = ()
            if not instances:
                continue
            for inst in instances:
                try:
                    matched = inst.matched_data
                except Exception:
                    matched = b""
                if isinstance(matched, (bytes, bytearray)):
                    try:
                        text = matched[:_MAX_STRING_DATA_PER_MATCH].decode("utf-8", errors="replace")
                    except Exception:
                        text = repr(matched[:_MAX_STRING_DATA_PER_MATCH])
                else:
                    text = str(matched)[:_MAX_STRING_DATA_PER_MATCH]
                try:
                    offset = int(inst.offset)
                except Exception:
                    offset = 0
                strings.append(
                    YaraStringHit(
                        identifier=str(s.identifier),
                        offset=base_offset + offset,
                        data=text,
                    )
                )
    except Exception:
        pass
    return YaraRuleMatch(
        rule=str(m.rule),
        namespace=str(getattr(m, "namespace", "") or ""),
        tags=tags,
        meta=meta,
        strings=strings,
    )


def scan_bytes(rules: Any, data: bytes, base_offset: int = 0) -> list[YaraRuleMatch]:
    """Run compiled rules against a bytes buffer. Returns a list of
    ``YaraRuleMatch``. Yields at most ``_MAX_MATCHES_PER_SCAN`` matches."""
    if rules is None or not data:
        return []
    out: list[YaraRuleMatch] = []
    try:
        iterator = rules.match(data=data)
    except Exception as e:
        logger.warning("yara scan failed: %s", e)
        return out
    for m in iterator:
        out.append(_match_to_rule_match(m, base_offset=base_offset))
        if len(out) >= _MAX_MATCHES_PER_SCAN:
            break
    return out


def scan_file(rules: Any, path: str) -> list[YaraRuleMatch]:
    if rules is None or not path or not os.path.isfile(path):
        return []
    out: list[YaraRuleMatch] = []
    try:
        iterator = rules.match(filepath=path)
    except Exception as e:
        logger.warning("yara file scan failed: %s", e)
        return out
    for m in iterator:
        out.append(_match_to_rule_match(m))
        if len(out) >= _MAX_MATCHES_PER_SCAN:
            break
    return out


ReadBytesFn = Callable[[int, int], bytes | None]


def scan_address_range(
    rules: Any,
    read_bytes: ReadBytesFn,
    start: int,
    end: int,
    chunk_size: int = _SCAN_CHUNK_SIZE,
    max_bytes: int = _MAX_SCAN_BYTES,
) -> list[YaraRuleMatch]:
    """Scan an inclusive ``[start, end)`` byte range. Caller supplies
    ``read_bytes(start_addr, size) -> bytes | None``. Returns aggregated
    matches across all chunks. The ``YaraStringHit.offset`` is the
    address-relative offset reported by yara-python; for IDB callers,
    pass the segment base as ``start`` so the returned offsets map
    directly to addresses."""
    if rules is None or not read_bytes or end <= start:
        return []
    if chunk_size <= 0:
        chunk_size = _SCAN_CHUNK_SIZE
    out: list[YaraRuleMatch] = []
    cursor = start
    total = 0
    while cursor < end and total < max_bytes:
        size = min(chunk_size, end - cursor, max_bytes - total)
        try:
            buf = read_bytes(cursor, size)
        except Exception:
            buf = None
        if not buf:
            cursor += size
            total += size
            continue
        for m in scan_bytes(rules, buf, base_offset=cursor):
            out.append(m)
            if len(out) >= _MAX_MATCHES_PER_SCAN:
                return out
        cursor += size
        total += size
    return out


class YaraScanner:
    """High-level wrapper around yara-python with a small caching layer."""

    def __init__(
        self,
        rules_dir: str | None = None,
        compiled_path: str | None = None,
    ) -> None:
        self._rules_dir = rules_dir or default_rules_dir()
        self._compiled_path = compiled_path or default_compiled_path()
        self._rules: Any | None = None
        self._file_errors: list[dict[str, Any]] = []
        self._compile_errors: list[dict[str, Any]] = []
        self._loaded_at: float = 0.0
        self._loaded_from: str = ""

    @property
    def rules_dir(self) -> str:
        return self._rules_dir

    @property
    def compiled_path(self) -> str:
        return self._compiled_path

    def is_loaded(self) -> bool:
        return self._rules is not None

    def available(self) -> bool:
        return is_yara_available()

    def load(self, force_recompile: bool = False) -> dict[str, Any]:
        if not is_yara_available():
            return {
                "loaded": False,
                "reason": "yara-python not available",
                "rules_dir": self._rules_dir,
                "compiled_path": self._compiled_path,
            }
        if not force_recompile and os.path.isfile(self._compiled_path):
            rules = load_compiled_rules(self._compiled_path)
            if rules is not None:
                self._rules = rules
                self._loaded_at = time.time()
                self._loaded_from = "compiled_cache"
                return {
                    "loaded": True,
                    "from_cache": True,
                    "rules_dir": self._rules_dir,
                    "compiled_path": self._compiled_path,
                }
        if not os.path.isdir(self._rules_dir):
            return {
                "loaded": False,
                "reason": f"rules dir not found: {self._rules_dir}",
                "rules_dir": self._rules_dir,
                "compiled_path": self._compiled_path,
            }
        rules, file_errors, compile_errors = compile_rules(
            self._rules_dir, self._compiled_path
        )
        self._file_errors = file_errors
        self._compile_errors = compile_errors
        if rules is None:
            return {
                "loaded": False,
                "reason": "compile failed",
                "file_errors": file_errors[:5],
                "compile_errors": compile_errors[:5],
                "rules_dir": self._rules_dir,
                "compiled_path": self._compiled_path,
            }
        self._rules = rules
        self._loaded_at = time.time()
        self._loaded_from = "fresh_compile"
        return {
            "loaded": True,
            "from_cache": False,
            "rules_dir": self._rules_dir,
            "compiled_path": self._compiled_path,
            "file_errors": len(file_errors),
            "compile_errors": len(compile_errors),
        }

    def unload(self) -> None:
        self._rules = None
        self._loaded_at = 0.0
        self._loaded_from = ""

    def stats(self) -> dict[str, Any]:
        return {
            "loaded": self.is_loaded(),
            "loaded_from": self._loaded_from,
            "loaded_at": self._loaded_at,
            "rules_dir": self._rules_dir,
            "compiled_path": self._compiled_path,
            "rules_dir_exists": os.path.isdir(self._rules_dir),
            "compiled_exists": os.path.isfile(self._compiled_path),
            "file_errors": len(self._file_errors),
            "compile_errors": len(self._compile_errors),
            "yara_version": yara_version(),
        }

    def scan_bytes(self, data: bytes, base_offset: int = 0) -> list[YaraRuleMatch]:
        return scan_bytes(self._rules, data, base_offset=base_offset)

    def scan_file(self, path: str) -> list[YaraRuleMatch]:
        return scan_file(self._rules, path)

    def scan_address_range(
        self,
        read_bytes: ReadBytesFn,
        start: int,
        end: int,
        chunk_size: int = _SCAN_CHUNK_SIZE,
    ) -> list[YaraRuleMatch]:
        return scan_address_range(
            self._rules, read_bytes, start, end, chunk_size=chunk_size
        )
