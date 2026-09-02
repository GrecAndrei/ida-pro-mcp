from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ida_pro_mcp.installer.common import InstallReport, find_ida_sig_dir
from ida_pro_mcp.installer.runtime import (
    _copy_file_atomically,
    _normalise_sha256,
    _profile_download_url,
    _read_response_limited,
    _sha256_file,
    _validate_https_host,
    activate_idalib,
    detect_ida_install_dir,
    find_idalib_python_dir,
    get_install_root,
    kill_ida_processes,
    resolve_r2_binary,
    run_checked,
    stage_sigs,
)


def test_sha256_helpers(tmp_path: Path) -> None:
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    assert _sha256_file(str(f)) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    assert _normalise_sha256("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9") == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert _normalise_sha256("invalid_hash") == ""
    assert _normalise_sha256(None) == ""


def test_validate_https_host() -> None:
    _validate_https_host("https://huggingface.co/models/123", "huggingface.co")
    _validate_https_host("https://github.com/owner/repo/releases", "github.com", path_prefix="/owner/repo")

    with pytest.raises(RuntimeError, match="Refusing untrusted download URL"):
        _validate_https_host("http://huggingface.co/insecure", "huggingface.co")

    with pytest.raises(RuntimeError, match="Refusing untrusted download URL"):
        _validate_https_host("https://malicious.com/payload", "huggingface.co")

    with pytest.raises(RuntimeError, match="Refusing untrusted download URL"):
        _validate_https_host("https://github.com/other/repo", "github.com", path_prefix="/owner/repo")


def test_profile_download_url() -> None:
    class DummyProfile:
        download_url = "https://huggingface.co/repo/resolve/main/model.gguf"
        download_revision = "a" * 40

    url = _profile_download_url(DummyProfile())
    assert f"/resolve/{'a'*40}/" in url

    class BadProfile:
        download_url = "https://huggingface.co/repo/resolve/main/model.gguf"
        download_revision = "short_hash"

    assert _profile_download_url(BadProfile()) == ""


def test_read_response_limited() -> None:
    resp = io.BytesIO(b"short response")
    res = _read_response_limited(resp, max_bytes=100, label="metadata")
    assert res == b"short response"

    resp_long = io.BytesIO(b"A" * 200)
    with pytest.raises(RuntimeError, match="metadata exceeds the 100 byte safety limit"):
        _read_response_limited(resp_long, max_bytes=100, label="metadata")


def test_copy_file_atomically(tmp_path: Path) -> None:
    src = tmp_path / "source.txt"
    src.write_text("content", encoding="utf-8")
    dst = tmp_path / "dest.txt"

    _copy_file_atomically(src, dst, overwrite=True)
    assert dst.read_text(encoding="utf-8") == "content"

    # Overwrite False with existing file
    with pytest.raises(OSError):
        _copy_file_atomically(src, dst, overwrite=False)


def test_run_checked_success_and_failure() -> None:
    res = run_checked([sys.executable, "-c", "print('stdout test')"])
    assert "stdout test" in res.stdout

    with pytest.raises(RuntimeError, match="failed"):
        run_checked([sys.executable, "-c", "import sys; sys.exit(1)"])

    with pytest.raises(RuntimeError, match="timed out"):
        run_checked([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)


def test_kill_ida_processes() -> None:
    ok = kill_ida_processes(binary_path=None)
    assert isinstance(ok, bool)


def test_resolve_r2_binary(tmp_path: Path) -> None:
    fake_rz = tmp_path / ("rz.exe" if sys.platform == "win32" else "rz")
    fake_rz.write_bytes(b"")
    fake_rz.chmod(0o755)

    with patch("shutil.which", return_value=str(fake_rz)), patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=[str(fake_rz), "-v"], returncode=0, stdout="rizin 0.7.0"
        ),
    ):
        bin_path, ver = resolve_r2_binary()
        assert bin_path == str(fake_rz)
        assert ver == "rizin 0.7.0"


def test_stage_sigs(tmp_path: Path) -> None:
    sigs_src = tmp_path / "sig_pack"
    sigs_src.mkdir()
    (sigs_src / "riscv.sig").write_text("RISCV_SIG", encoding="utf-8")
    (sigs_src / "arm.sig.gz").write_text("ARM_SIG", encoding="utf-8")
    (sigs_src / "ignore.txt").write_text("IGNORE", encoding="utf-8")

    ida_dir = tmp_path / "ida_install"
    sig_dir = find_ida_sig_dir(ida_dir)

    report = InstallReport()
    manifest = stage_sigs(sigs_src, sig_dir, dry_run=False, report=report)
    assert manifest.count == 2
    assert (ida_dir / "sig" / "riscv.sig").is_file()
    assert (ida_dir / "sig" / "arm.sig.gz").is_file()
    assert not (ida_dir / "sig" / "ignore.txt").exists()


def test_activate_idalib_flow(tmp_path: Path) -> None:
    ida_dir = tmp_path / "ida_93"
    ida_dir.mkdir()
    idalib_whl = ida_dir / "idalib-9.3.0-py3-none-any.whl"
    idalib_whl.write_bytes(b"PK\x03\x04")

    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="Activated")):
        ok, msg = activate_idalib(str(ida_dir))
        assert isinstance(ok, bool)
