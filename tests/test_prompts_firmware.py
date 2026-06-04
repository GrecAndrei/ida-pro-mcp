import os
import sys
import types

if "rpc" not in sys.modules:
    _rpc = types.ModuleType("rpc")
    _rpc.prompt = lambda f: f
    sys.modules["rpc"] = _rpc

from tests._isolated_repo_loader import load_ida_module

prompts_mod = load_ida_module("prompts")


def test_quickref_mentions_firmware_triage_snapshot():
    text = prompts_mod.QUICKREF_TEXT
    assert "firmware_view(action=\"triage_snapshot\")" in text


def test_firmware_workflow_starts_with_triage_snapshot():
    text = prompts_mod.WORKFLOW_FIRMWARE
    assert "One-Shot Orientation" in text
    assert "firmware_view(action=\"triage_snapshot\")" in text
