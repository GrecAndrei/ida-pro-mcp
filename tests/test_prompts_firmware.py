import os
import sys
import importlib.util
import types

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

_PROMPTS_PATH = os.path.join(SRC, "ida_pro_mcp", "ida_mcp", "prompts.py")
if "rpc" not in sys.modules:
    _rpc = types.ModuleType("rpc")
    _rpc.prompt = lambda f: f
    sys.modules["rpc"] = _rpc
_SPEC = importlib.util.spec_from_file_location("_prompts_mod", _PROMPTS_PATH)
prompts_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prompts_mod)


def test_quickref_mentions_firmware_triage_snapshot():
    text = prompts_mod.QUICKREF_TEXT
    assert "firmware_view(action=\"triage_snapshot\")" in text


def test_firmware_workflow_starts_with_triage_snapshot():
    text = prompts_mod.WORKFLOW_FIRMWARE
    assert "One-Shot Orientation" in text
    assert "firmware_view(action=\"triage_snapshot\")" in text
