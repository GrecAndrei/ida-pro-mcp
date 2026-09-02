"""Unit tests for scripts/report_tool_description_occupancy.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import report_tool_description_occupancy as rtdo


def test_load_tool_descriptions():
    descriptions = rtdo.load_tool_descriptions()
    assert isinstance(descriptions, dict)
    assert len(descriptions) > 0
    assert "session" in descriptions
    assert "analysis" in descriptions


def test_load_tool_descriptions_missing(tmp_path, monkeypatch):
    dummy_file = tmp_path / "dummy_schemas.py"
    dummy_file.write_text("FOO = 1\n", encoding="utf-8")
    monkeypatch.setattr(rtdo, "SCHEMAS_PATH", dummy_file)

    with pytest.raises(RuntimeError, match="TOOL_DESCRIPTIONS not found"):
        rtdo.load_tool_descriptions()


def test_main_execution(tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "scripts" / "tool_description_occupancy.json"
    monkeypatch.setattr(rtdo, "ROOT", tmp_path)
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)

    rc = rtdo.main()
    assert rc == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["encoding"] == "cl100k_base"
    assert data["tool_count"] > 0
    assert data["total_chars"] > 0
    assert data["total_tokens"] > 0
    assert isinstance(data["tools"], list)

    captured = capsys.readouterr()
    assert "Tool descriptions:" in captured.out
    assert "Total tokens (cl100k_base):" in captured.out
    assert "Top 15 by token count:" in captured.out
