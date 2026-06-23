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


def test_project_description_stays_aligned_with_removed_legacy_actions():
    src = Path("src/ida_pro_mcp/host/schemas_data.py").read_text(encoding="utf-8")
    project_line = [line for line in src.splitlines() if line.strip().startswith('"project": "Project I/O')][0]
    assert " read," not in project_line
    assert " write," not in project_line
    assert " sessions," not in project_line
    assert " batch," not in project_line

