"""Contract tests for the version shipped in release artifacts."""

import re
from pathlib import Path


def test_current_release_version_is_consistent():
    version_source = Path(__file__).parents[1] / "src" / "ida_pro_mcp" / "_version.py"
    match = re.search(
        r'^__version__ = "([^"]+)"$', version_source.read_text(), re.MULTILINE
    )
    assert match is not None
    assert match.group(1) == "1.0.0a3"
