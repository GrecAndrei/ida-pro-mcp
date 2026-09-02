"""Unit tests for scripts/report_tools_list_occupancy.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ida_pro_mcp.host.server.server import IDAMCPServer
from scripts import report_tools_list_occupancy as rtlo


def test_measure_payload():
    server = IDAMCPServer()
    res_full = rtlo.measure_payload(server, "full")
    assert res_full["mode"] == "full"
    assert res_full["tool_count"] > 0
    assert res_full["response_tokens"] > 0
    assert res_full["response_chars"] > 0
    assert res_full["tool_desc_tokens"] > 0
    assert res_full["schema_tokens"] > 0

    res_lean = rtlo.measure_payload(server, "lean")
    assert res_lean["mode"] == "lean"
    assert res_lean["tool_count"] > 0

    res_ultra = rtlo.measure_payload(server, "ultra")
    assert res_ultra["mode"] == "ultra"
    assert res_ultra["tool_count"] > 0


def test_main_execution(tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "scripts" / "tools_list_occupancy.json"
    monkeypatch.setattr(rtlo, "ROOT", tmp_path)
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)

    rc = rtlo.main()
    assert rc == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["encoding"] == "cl100k_base"
    assert len(data["modes"]) == 3
    assert data["modes"][0]["mode"] == "full"

    captured = capsys.readouterr()
    assert "tools/list payload occupancy" in captured.out
    assert "full" in captured.out
    assert "lean" in captured.out
    assert "ultra" in captured.out
