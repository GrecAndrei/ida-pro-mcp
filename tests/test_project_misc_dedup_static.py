from __future__ import annotations

from pathlib import Path


def test_project_read_write_delegate_to_misc_file_impls():
    src = Path("src/ida_pro_mcp/ida_mcp/tools/project.py").read_text(encoding="utf-8")
    assert "from .misc import read_file_impl, write_file_impl" in src
    assert "out = read_file_impl(path, encoding=\"utf-8\")" in src
    assert "out = write_file_impl(path, str(content), encoding=\"utf-8\")" in src
