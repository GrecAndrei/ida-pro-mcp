from __future__ import annotations

from pathlib import Path


def test_project_drops_legacy_file_and_session_actions():
    src = Path("src/ida_pro_mcp/ida_mcp/tools/project.py").read_text(encoding="utf-8")
    assert '"read"' not in src.split("action: Annotated[Literal[", 1)[1].split("],", 1)[0]
    assert '"write"' not in src.split("action: Annotated[Literal[", 1)[1].split("],", 1)[0]
    assert '"sessions"' not in src.split("action: Annotated[Literal[", 1)[1].split("],", 1)[0]
    assert '"batch"' not in src.split("action: Annotated[Literal[", 1)[1].split("],", 1)[0]
    assert 'action == "read"' not in src
    assert 'action == "write"' not in src
    assert 'action == "sessions"' not in src
    assert 'action == "batch"' not in src
