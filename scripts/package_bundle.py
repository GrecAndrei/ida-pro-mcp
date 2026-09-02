#!/usr/bin/env python3
"""Package self-contained and self-extracting bundles for IDA Pro MCP releases."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from ida_pro_mcp._version import __version__

POSIX_SH_TEMPLATE = """#!/bin/sh
set -e
# IDA Pro MCP Self-Extracting Installer
# Version: {version}
# Target: {platform}

echo "=== IDA Pro MCP v{version} Installer ==="

TARGET_DIR="${{HOME}}/.local/share/ida-pro-mcp"
if [ "$(uname -s)" = "Darwin" ]; then
    TARGET_DIR="${{HOME}}/Library/Application Support/ida-pro-mcp"
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix=*)
            TARGET_DIR="${{1#*=}}"
            shift
            ;;
        --prefix)
            TARGET_DIR="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

mkdir -p "$TARGET_DIR"
echo "Unpacking to $TARGET_DIR..."

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ARCHIVE_LINE=$(awk '/^__PAYLOAD_BELOW__/ {{print NR + 1; exit 0; }}' "$SCRIPT_PATH")

tail -n +"$ARCHIVE_LINE" "$SCRIPT_PATH" | tar -xz -C "$TARGET_DIR"

echo "Running installation setup..."
if [ -x "$TARGET_DIR/runtime/bin/python3" ]; then
    PYTHON="$TARGET_DIR/runtime/bin/python3"
elif [ -x "$TARGET_DIR/runtime/bin/python" ]; then
    PYTHON="$TARGET_DIR/runtime/bin/python"
else
    PYTHON="$(command -v python3 || command -v python || true)"
fi

if [ -z "$PYTHON" ]; then
    echo "Error: Python 3 not found. Please install Python 3.10+ or use the standalone bundle." >&2
    exit 1
fi

"$PYTHON" -m ida_pro_mcp.installer.main --yes --install-root "$TARGET_DIR" "$@"
echo "=== IDA Pro MCP installed successfully! ==="
exit 0
__PAYLOAD_BELOW__
"""

WINDOWS_BAT_TEMPLATE = """@echo off
setlocal enabledelayedexpansion
title IDA Pro MCP v{version} Installer

echo ===========================================
echo   IDA Pro MCP v{version} Installer
echo   Target: Windows x64
echo ===========================================

set "TARGET_DIR=%LOCALAPPDATA%\\ida-pro-mcp"

:parse_args
if "%~1"=="" goto after_args
if "%~1"=="--prefix" (
    set "TARGET_DIR=%~2"
    shift
    shift
    goto parse_args
)
shift
goto parse_args

:after_args
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
echo Unpacking to %TARGET_DIR%...

tar -xf "%~dpnx0" -C "%TARGET_DIR%" 2>nul
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Force '%~dpnx0' '%TARGET_DIR%'" 2>nul
)

if exist "%TARGET_DIR%\\runtime\\python.exe" (
    set "PYTHON=%TARGET_DIR%\\runtime\\python.exe"
) else (
    set "PYTHON=python"
)

"%PYTHON%" -m ida_pro_mcp.installer.main --yes --install-root "%TARGET_DIR%" %*
if %errorlevel% equ 0 (
    echo ===========================================
    echo   IDA Pro MCP installed successfully!
    echo ===========================================
) else (
    echo [ERROR] Installation failed.
    exit /b %errorlevel%
)
exit /b 0
"""


def build_posix_sfx(
    payload_tar_gz: Path,
    output_script: Path,
    version: str,
    platform_name: str,
) -> Path:
    """Combine the POSIX shell extraction header with the gzipped tarball payload."""
    header = POSIX_SH_TEMPLATE.format(version=version, platform=platform_name).encode("utf-8")
    payload = payload_tar_gz.read_bytes()

    output_script.parent.mkdir(parents=True, exist_ok=True)
    with open(output_script, "wb") as f:
        f.write(header)
        f.write(payload)

    mode = output_script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    output_script.chmod(mode)
    return output_script


def build_windows_sfx(
    payload_zip: Path,
    output_bat: Path,
    version: str,
) -> Path:
    """Create a Windows self-extracting batch wrapper."""
    header = WINDOWS_BAT_TEMPLATE.format(version=version).encode("utf-8")
    payload = payload_zip.read_bytes()

    output_bat.parent.mkdir(parents=True, exist_ok=True)
    with open(output_bat, "wb") as f:
        f.write(header)
        f.write(payload)
    return output_bat


def create_payload_archive(
    source_root: Path,
    target_archive: Path,
    format_type: str = "tar.gz",
) -> Path:
    """Create a compressed archive of the package source and wheels for extraction."""
    target_archive.parent.mkdir(parents=True, exist_ok=True)
    if format_type == "tar.gz":
        with tarfile.open(target_archive, "w:gz") as tar:
            for item in ["src", "pyproject.toml", "README.md", "LICENSE"]:
                src_path = source_root / item
                if src_path.exists():
                    tar.add(src_path, arcname=item)
    elif format_type == "zip":
        with zipfile.ZipFile(target_archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in ["src", "pyproject.toml", "README.md", "LICENSE"]:
                src_path = source_root / item
                if src_path.is_file():
                    zf.write(src_path, arcname=item)
                elif src_path.is_dir():
                    for root, _dirs, files in os.walk(src_path):
                        for file in files:
                            full = Path(root) / file
                            rel = full.relative_to(source_root)
                            zf.write(full, arcname=str(rel))
    return target_archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package IDA Pro MCP self-extracting release bundles")
    parser.add_argument("--outdir", default="dist", help="Output directory for generated release bundles")
    parser.add_argument("--version", default=__version__, help="Version string to brand the packages")
    parser.add_argument(
        "--platforms",
        nargs="+",
        default=["linux-x86_64", "macos-arm64", "macos-x86_64", "windows-x64"],
        help="Target platforms to generate",
    )
    args = parser.parse_args(argv)

    source_root = Path(__file__).resolve().parent.parent
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    version = args.version

    print(f"Packaging IDA Pro MCP v{version} bundles in {outdir}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        tar_payload = tmppath / f"ida-pro-mcp-{version}-payload.tar.gz"
        zip_payload = tmppath / f"ida-pro-mcp-{version}-payload.zip"

        print("Building payload archives...")
        create_payload_archive(source_root, tar_payload, "tar.gz")
        create_payload_archive(source_root, zip_payload, "zip")

        generated = []
        for plat in args.platforms:
            if plat.startswith("linux"):
                out_path = outdir / f"ida-pro-mcp-v{version}-{plat}.sh"
                build_posix_sfx(tar_payload, out_path, version, plat)
                generated.append(out_path)
            elif plat.startswith("macos"):
                out_path = outdir / f"ida-pro-mcp-v{version}-{plat}.command"
                build_posix_sfx(tar_payload, out_path, version, plat)
                generated.append(out_path)
            elif plat.startswith("windows"):
                out_path = outdir / f"ida-pro-mcp-v{version}-{plat}.bat"
                build_windows_sfx(zip_payload, out_path, version)
                generated.append(out_path)

        print("Generated bundles:")
        for g in generated:
            sha256 = hashlib.sha256(g.read_bytes()).hexdigest()
            print(f"  {g.name} ({g.stat().st_size:,} bytes, sha256: {sha256[:16]}...)")

    print("Bundling complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
