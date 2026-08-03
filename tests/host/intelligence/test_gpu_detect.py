"""Tests for GPU device auto-detection in the embedding server launch."""
from __future__ import annotations

from unittest import mock

from ida_pro_mcp.host.intelligence import core
import sys


def _EXE():
    return sys.executable


def _fake_run(stdout: str = "", rc: int = 0):
    proc = mock.Mock()
    proc.stdout = stdout
    proc.returncode = rc
    return proc


def test_detects_first_vulkan_device():
    proc = _fake_run(
        "Available devices:\n"
        "  Vulkan0: Intel(R) UHD Graphics 620 (WHL GT2) (11845 MiB, 6483 MiB free)\n"
    )
    with mock.patch.object(core.subprocess, "run", return_value=proc) as run:
        assert core._detect_gpu_device(_EXE()) == "Vulkan0"
        run.assert_called_once()


def test_multiple_vulkan_devices_prefers_first():
    proc = _fake_run(
        "  Vulkan0: Intel iGPU (1024 MiB)\n"
        "  Vulkan1: NVIDIA RTX (8192 MiB)\n"
    )
    with mock.patch.object(core.subprocess, "run", return_value=proc):
        assert core._detect_gpu_device(_EXE()) == "Vulkan0"


def test_cpu_only_build_returns_empty():
    proc = _fake_run("Available devices:\n")
    with mock.patch.object(core.subprocess, "run", return_value=proc):
        assert core._detect_gpu_device(_EXE()) == ""


def test_probe_failure_returns_empty():
    with mock.patch.object(
        core.subprocess, "run", side_effect=OSError("no such binary")
    ):
        assert core._detect_gpu_device("/nonexistent/llama-server") == ""


def test_missing_binary_returns_empty_without_probing():
    with mock.patch.object(core.subprocess, "run") as run:
        assert core._detect_gpu_device("/nonexistent/llama-server") == ""
        run.assert_not_called()
