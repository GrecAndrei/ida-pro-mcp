"""Contract tests for the version shipped in release artifacts."""

from ida_pro_mcp import __version__


def test_current_release_version_is_consistent():
    assert __version__ == "1.0.0a2"
