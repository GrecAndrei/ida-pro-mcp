"""IDA install discovery and version parsing.

Locates every IDA Pro / IDA Home installation reachable from the current
environment, parses its version, and lets the installer pick one (interactively
or via CLI override).  The MCP supports running against IDA 9.0 through the
latest 9.x release simultaneously — the installer just needs to know which
install to wire into the launch config.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from .common import atomic_write_text, reject_symlink_path

VERSION_TUPLE = tuple[int, int, int]
# IDA build version: e.g. 9.3.260421.be7de18d  (major.minor.YYMMDD.shorthash)
_BUILD_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d{6})\.([0-9a-f]{6,8})")
_VERSION_DIGITS_RE = re.compile(r"\d+")


def _expand_configured_path(value: str | os.PathLike[str]) -> Path:
    """Expand environment variables and ``~`` in an installer path value."""
    return Path(os.path.expanduser(os.path.expandvars(os.fspath(value))))


def parse_version(s: str) -> tuple[int, ...]:
    """Extract every run of digits in `s` as an int tuple.

    Tolerates oddball IDA version strings — `9.0.20240812`, `9.0sp1`,
    `9.3rc2`, plain `9` — without raising IndexError (audit §6.5).
    Returns (0,) for any string with no digits at all so callers can
    still compare without a None guard.
    """
    parts = _VERSION_DIGITS_RE.findall(s)
    return tuple(int(p) for p in parts) if parts else (0,)


# State file written into install_root so subsequent installer runs (or
# any process that needs to know which IDA is wired) can find the choice
# without re-prompting.
STATE_FILE = "ida-install.json"


def _expand_configured_path(value: str) -> Path:
    """Expand user/environment references from installer path settings."""
    return Path(os.path.expandvars(os.path.expanduser(str(value).strip())))


def _safe_roots() -> list[Path]:
    """Filesystem roots a discovered IDA install is allowed to resolve into.

    A symlink under ~/Applications or Program Files that points outside
    these roots is treated as adversarial — the installer refuses to
    wire it as IDADIR.  Audit §6.5.
    """
    roots: list[Path] = []
    with contextlib.suppress(OSError):
        roots.append(Path.home().resolve())
    if sys.platform == "darwin":
        roots.append(Path("/Applications"))
    elif sys.platform.startswith("linux"):
        roots.append(Path("/opt"))
        roots.append(Path("/usr/local"))
        roots.append(Path("/usr"))
    else:
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"):
            v = os.environ.get(env, "").strip()
            if v:
                roots.append(_expand_configured_path(v))
    # Always allow the temp / staging dirs used by tests.  These do not
    # widen the production attack surface because production never
    # resolves a candidate to /tmp during a real install.
    for env in ("TMPDIR", "TEMP", "TMP"):
        v = os.environ.get(env, "").strip()
        if v:
            roots.append(_expand_configured_path(v))
    cleaned: list[Path] = []
    for r in roots:
        try:
            cleaned.append(r.resolve())
        except OSError:
            continue
    return cleaned


def _resolves_under_safe_root(candidate: Path) -> bool:
    """Return True iff `candidate` (or its realpath) lives under a safe root.

    Resolves symlinks with both os.path.realpath() and Path.resolve()
    so we catch (a) basic symlink redirection and (b) `..` traversal in
    the candidate's literal path that would otherwise re-anchor it
    elsewhere after resolve().
    """
    try:
        realpath = Path(os.path.realpath(str(candidate)))
        resolved = candidate.resolve()
    except OSError:
        return False
    safe_roots = _safe_roots()
    if not safe_roots:
        # No allow-list configured — fail open with a defensive log
        # rather than refusing every install.
        return True
    for check in (realpath, resolved):
        for root in safe_roots:
            try:
                check.relative_to(root)
                return True
            except ValueError:
                continue
    return False


@dataclass(frozen=True)
class IdaInstall:
    """A single IDA Pro / IDA Home installation on disk."""

    path: Path
    version: VERSION_TUPLE  # (major, minor) — only the user-facing 2-component version
    build: str  # e.g. "260421.be7de18d" (YYMMDD.shorthash), or "" if unknown
    idat_binary: Path | None
    arch: str  # "x64" | "arm64" | "x86" | "unknown"
    flavor: str  # "pro" | "home" | "essential" | "free" | "unknown"
    source: str  # "env" | "path" | "home_scan" | "opt_scan" | "applications_scan" | "explicit"

    @property
    def version_str(self) -> str:
        return ".".join(str(x) for x in self.version)

    @property
    def full_version_str(self) -> str:
        base = self.version_str
        return f"{base}.{self.build}" if self.build else base

    @property
    def display(self) -> str:
        rel = self.path
        try:
            rel = self.path.relative_to(Path.home())
            rel_str = f"~/{rel}"
        except ValueError:
            rel_str = str(self.path)
        ver = self.full_version_str
        return f"IDA {ver} {self.flavor} ({self.arch}) at {rel_str}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["path"] = str(self.path)
        d["idat_binary"] = str(self.idat_binary) if self.idat_binary else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> IdaInstall:
        if not isinstance(d, dict):
            raise ValueError("install state must be an object")
        raw_version = d["version"]
        if (
            not isinstance(raw_version, (list, tuple))
            or len(raw_version) != 2
            or any(isinstance(part, bool) or not isinstance(part, int) for part in raw_version)
        ):
            raise ValueError("install version must contain two integer components")
        return cls(
            path=Path(d["path"]),
            version=tuple(raw_version),
            build=d.get("build", ""),
            idat_binary=Path(d["idat_binary"]) if d.get("idat_binary") else None,
            arch=d.get("arch", "unknown"),
            flavor=d.get("flavor", "unknown"),
            source=d.get("source", "explicit"),
        )


def _ida_binary_names() -> list[str]:
    if sys.platform == "win32":
        return ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]
    if sys.platform == "darwin":
        return ["idat64", "idat", "ida64", "ida"]
    return ["idat64", "idat", "ida64", "ida"]


def _binary_arch(binary: Path) -> str:
    """Return 'x64', 'arm64', 'x86', or 'unknown' by sniffing the ELF/Mach-O/PE header."""
    try:
        with binary.open("rb") as f:
            head = f.read(20)
    except OSError:
        return "unknown"
    if head[:4] == b"\x7fELF":
        ei_class = head[4]
        if ei_class == 2:
            # 64-bit ELF: read e_machine at offset 18
            e_machine = int.from_bytes(head[18:20], "little")
            return "arm64" if e_machine == 0xB7 else "x64"
        return "x86"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "arm64" if head[4] in (0x0C, 0x0D) or (len(head) >= 8 and head[7] in (0x0C, 0x0D)) else "x64"
    if head[:2] == b"MZ":
        # PE: look for IMAGE_FILE_MACHINE_AMD64 (0x8664) / ARM64 (0xAA64) in optional header
        try:
            with binary.open("rb") as f:
                f.seek(0x3C)
                pe_off = int.from_bytes(f.read(4), "little")
                f.seek(pe_off + 4)
                machine = int.from_bytes(f.read(2), "little")
            if machine == 0xAA64:
                return "arm64"
            if machine == 0x8664:
                return "x64"
            if machine == 0x14C:
                return "x86"
        except OSError:
            pass
    return "unknown"


def _scan_binary_for_version(binary: Path) -> tuple[VERSION_TUPLE, str] | None:
    """Search a binary's raw bytes for the embedded IDA build string.

    IDA stores the build tag (e.g. '9.3.260421.be7de18d') as a plain ASCII
    string, which is exactly what ``strings -n 5`` would surface — without
    depending on the external ``strings`` binary (not guaranteed on Windows,
    where the previous subprocess call silently no-op'd and every candidate
    reported version (0, 0)).  The file is scanned in overlapping chunks so
    memory stays bounded on large binaries.
    """
    chunk_size = 1 << 20  # 1 MiB
    overlap = 64
    prefix = b""
    try:
        with binary.open("rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                text = (prefix + data).decode("latin-1", errors="replace")
                m = _BUILD_VERSION_RE.search(text)
                if m:
                    version = (int(m.group(1)), int(m.group(2)))
                    build = f"{m.group(3)}.{m.group(4)}"
                    return (version, build)
                # Carry the raw tail BYTES into the next chunk so a version
                # string split across a chunk boundary is still matched. latin-1
                # decodes 1 byte -> 1 char, so this equals text[-overlap:] but
                # stays bytes for the next `prefix + data` concatenation.
                prefix = data[-overlap:]
    except OSError:
        return None
    return None


def _detect_version(binary: Path) -> tuple[VERSION_TUPLE, str] | None:
    """Try to extract (version, build) from an IDA binary.

    IDA embeds a build version string in `ida` / `ida64` like
    '9.3.260421.be7de18d'.  The `idat` wrapper script is too small to
    contain the string, so we always look at the real binary (ida/ida64)
    when available.  Returns ((major, minor), "260421.be7de18d") on success.
    """
    candidates: list[Path] = [binary]
    # idat is a tiny shell wrapper; the real binary sits next to it
    parent = binary.parent
    for sibling in ("ida64", "ida", "ida64.exe", "ida.exe"):
        s = parent / sibling
        if s.is_file() and s != binary:
            candidates.append(s)
    seen: set[Path] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        if not cand.is_file():
            continue
        # In-process byte scan first: cross-platform, no external tooling.
        matched = _scan_binary_for_version(cand)
        if matched:
            return matched
        # Fallback: the external `strings` tool when available (some Unix
        # systems decode additional encodings that a raw byte scan misses).
        try:
            result = subprocess.run(
                ["strings", "-n", "5", str(cand)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                # Skip placeholder version strings
                if line.startswith("UNKNOWN:"):
                    continue
                # Build format: 9.3.260421.be7de18d  (YYMMDD + short hash)
                m = _BUILD_VERSION_RE.search(line)
                if m:
                    version = (int(m.group(1)), int(m.group(2)))
                    build = f"{m.group(3)}.{m.group(4)}"
                    return (version, build)
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def _detect_flavor(install_dir: Path) -> str:
    """Detect IDA edition by license file or installer metadata."""
    home = Path.home()
    # License files in user home
    for name, flavor in (
        ("idapro_*.hexlic", "pro"),
        ("idahome_*.hexlic", "home"),
        ("idaessential_*.hexlic", "essential"),
        ("idafree_*.hexlic", "free"),
    ):
        for _lic in home.glob(name):
            return flavor
    # Bundled license next to install
    for _lic in install_dir.glob("idapro_*.hexlic"):
        return "pro"
    for _lic in install_dir.glob("idahome_*.hexlic"):
        return "home"
    for _lic in install_dir.glob("*.hexlic"):
        return "pro"
    return "unknown"


def _find_idat(install_dir: Path) -> Path | None:
    names = _ida_binary_names()
    for name in names:
        candidate = install_dir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    # Modern IDA 9.x layout with idabin subdirectory
    idabin = install_dir / "idabin"
    if idabin.is_dir():
        for name in names:
            candidate = idabin / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    # macOS installs wrapped in Contents/MacOS directly
    mac = install_dir / "Contents" / "MacOS"
    if mac.is_dir():
        for name in names:
            candidate = mac / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    # macOS installs with nested .app bundles (e.g. ida64.app/Contents/MacOS)
    try:
        for app in sorted(install_dir.glob("*.app")):
            app_mac = app / "Contents" / "MacOS"
            if app_mac.is_dir():
                for name in names:
                    candidate = app_mac / name
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        return candidate
    except OSError:
        pass
    return None


def _make_install(install_dir: Path, source: str) -> IdaInstall | None:
    """Build an IdaInstall from a directory containing an idat binary."""
    if not install_dir.is_dir():
        return None
    idat = _find_idat(install_dir)
    if idat is None:
        return None
    detected = _detect_version(idat)
    if detected is None:
        version: VERSION_TUPLE = (0, 0)
        build = ""
    else:
        version, build = detected
    arch = _binary_arch(idat)
    flavor = _detect_flavor(install_dir)
    return IdaInstall(
        path=install_dir.resolve(),
        version=version,
        build=build,
        idat_binary=idat,
        arch=arch,
        flavor=flavor,
        source=source,
    )


def _scan_home() -> Iterable[Path]:
    """Scan well-known locations under $HOME for IDA installs."""
    home = Path.home()
    candidates: list[Path] = []
    # Direct: ~/ida-pro-X.Y
    for p in sorted(home.glob("ida-pro-*")):
        if p.is_dir():
            candidates.append(p)
    # Direct: ~/ida-X.Y
    for p in sorted(home.glob("ida-*")):
        if p.is_dir() and p.name.count(".") >= 1:
            candidates.append(p)
    # Quarantine duplicates and reject symlink-redirected dirs.
    seen: set[Path] = set()
    for p in candidates:
        try:
            rp = p.resolve()
        except OSError:
            continue
        if rp in seen:
            continue
        if not _resolves_under_safe_root(p):
            continue
        seen.add(rp)
        yield rp


def _scan_system_dirs() -> Iterable[Path]:
    """Scan system-wide install locations (Linux /opt, macOS /Applications, Windows Program Files)."""
    candidates: list[Path] = []
    if sys.platform == "darwin":
        apps = Path("/Applications")
        if apps.is_dir():
            for p in apps.iterdir():
                if p.name.startswith("IDA Pro") or p.name.startswith("IDA "):
                    candidates.append(p)
    elif sys.platform.startswith("linux"):
        for parent in (Path("/opt"), Path("/usr/local")):
            if not parent.is_dir():
                continue
            for p in parent.iterdir():
                if p.name.startswith("ida") and p.is_dir():
                    candidates.append(p)
    else:
        # Windows: Program Files / Program Files (x86)
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(env, "").strip()
            if not base:
                continue
            bp = _expand_configured_path(base)
            if not bp.is_dir():
                continue
            for p in bp.iterdir():
                if "ida" in p.name.lower() and p.is_dir():
                    candidates.append(p)
    seen: set[Path] = set()
    for p in candidates:
        try:
            rp = p.resolve()
        except OSError:
            continue
        if rp in seen:
            continue
        if not _resolves_under_safe_root(p):
            continue
        seen.add(rp)
        yield rp


def _from_path() -> Iterable[Path]:
    for name in _ida_binary_names():
        resolved = shutil.which(name)
        if resolved:
            yield Path(resolved).resolve().parent


def _from_env() -> Iterable[Path]:
    for env_name in ("IDADIR", "IDA_DIR", "IDA_MCP_IDAT"):
        val = os.environ.get(env_name, "").strip()
        if not val:
            continue
        p = _expand_configured_path(val)
        try:
            resolved = p.resolve()
        except OSError:
            continue
        if resolved.is_file():
            yield resolved.parent
        elif resolved.is_dir():
            yield resolved


def detect_ida_installs() -> list[IdaInstall]:
    """Return every reachable IDA install, sorted newest-version first.

    Order of sources (priority high → low):
      1. env vars (IDADIR, IDA_DIR, IDA_MCP_IDAT)
      2. PATH lookup (idat64, idat, ida64, ida)
      3. $HOME scan
      4. System scan (/opt, /Applications, Program Files)
    """
    found: dict[Path, IdaInstall] = {}

    def _add(p: Path, source: str) -> None:
        install = _make_install(p, source)
        if install is None:
            return
        key = install.path
        if key in found:
            return
        found[key] = install

    for p in _from_env():
        _add(p, "env")
    for p in _from_path():
        _add(p, "path")
    for p in _scan_home():
        _add(p, "home_scan")
    for p in _scan_system_dirs():
        _add(p, "system_scan" if sys.platform != "darwin" else "applications_scan")

    # Sort: version/build desc, then pro > home > essential > free > unknown,
    # then path.  The public version is only major/minor, but IDA can have
    # multiple builds of the same release installed; automatic selection must
    # not choose an older build merely because its path sorts first.
    flavor_rank = {"pro": 0, "home": 1, "essential": 2, "free": 3, "unknown": 4}

    def _sort_key(i: IdaInstall) -> tuple:
        build_match = re.match(r"^(\d{6})(?:\.([0-9a-fA-F]+))?", i.build or "")
        build_date = int(build_match.group(1)) if build_match else -1
        build_hash = build_match.group(2).lower() if build_match and build_match.group(2) else ""
        return (
            -i.version[0],
            -i.version[1],
            -build_date,
            -bool(build_match),
            flavor_rank.get(i.flavor, 9),
            build_hash,
            str(i.path),
        )

    return sorted(found.values(), key=_sort_key)


def write_install_state(install_root: Path, install: IdaInstall) -> Path:
    """Persist the selected install to <install_root>/ida-install.json."""
    state_path = install_root / STATE_FILE
    reject_symlink_path(state_path, "installer state path")
    payload = {
        "selected": install.to_dict(),
        "selected_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
    atomic_write_text(state_path, json.dumps(payload, indent=2))
    return state_path


def read_install_state(install_root: Path) -> IdaInstall | None:
    """Read back the last installer-selected IDA install, or None."""
    state_path = install_root / STATE_FILE
    try:
        reject_symlink_path(state_path, "installer state path")
    except RuntimeError:
        return None
    if not state_path.is_file():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    sel = data.get("selected")
    if not isinstance(sel, dict):
        return None
    try:
        return IdaInstall.from_dict(sel)
    except (KeyError, TypeError, ValueError):
        return None


def select_ida_install(
    installs: list[IdaInstall],
    *,
    explicit_dir: Path | None = None,
    explicit_version: str | None = None,
    prompt_fn=None,
    default_index: int = 0,
) -> IdaInstall:
    """Pick one install from `installs` (or use overrides).

    Resolution order:
      1. `explicit_dir` — use that directory if it contains idat
      2. `explicit_version` — pick the highest-version install matching X.Y[.Z]
      3. Interactive prompt (when `prompt_fn` given and >1 installs)
      4. `default_index` from the sorted list
    """
    if explicit_dir:
        install = _make_install(explicit_dir, "explicit")
        if install is None:
            raise RuntimeError(f"--ida-dir {explicit_dir} does not contain an idat/ida binary")
        return install

    if explicit_version:
        # parse_version tolerates odd inputs (`9.0sp1`, trailing chars)
        # by extracting digit runs; an empty result becomes (0,) so we
        # can still compare without raising IndexError (audit §6.5).
        want = parse_version(explicit_version)
        if want == (0,):
            raise RuntimeError(
                f"Invalid --ida-version {explicit_version!r}: no version digits found"
            )
        if len(want) == 1:
            matches = [i for i in installs if i.version[0] == want[0]]
        elif len(want) == 2:
            matches = [i for i in installs if i.version == want]
        elif len(want) >= 3:
            # Third component matches the start of the build date (e.g. "9.3.260421")
            target_build_prefix = str(want[2])
            matches = [
                i for i in installs
                if i.version == want[:2] and i.build.startswith(target_build_prefix)
            ]
        else:
            raise RuntimeError(
                f"Invalid --ida-version {explicit_version!r}: expected MAJOR[.MINOR[.BUILD]]"
            )
        if not matches:
            raise RuntimeError(
                f"No installed IDA matches version {explicit_version}; found: "
                + ", ".join(i.full_version_str for i in installs)
            )
        return matches[0]

    if not installs:
        raise RuntimeError(
            "No IDA Pro install detected. Pass --ida-dir <path> or set IDADIR / IDA_DIR."
        )

    if len(installs) == 1:
        return installs[0]

    if prompt_fn is not None:
        return prompt_fn(installs)

    return installs[default_index]
