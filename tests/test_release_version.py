"""Contract tests for the version shipped in release artifacts."""

import json
import re
from pathlib import Path


def test_current_release_version_is_consistent():
    repo_root = Path(__file__).parents[1]
    version_source = repo_root / "src" / "ida_pro_mcp" / "_version.py"
    match = re.search(
        r'^__version__ = "([^"]+)"$', version_source.read_text(), re.MULTILINE
    )
    assert match is not None
    version = match.group(1)
    assert re.fullmatch(r"\d+\.\d+\.\d+a\d+", version)

    plugin_manifest = json.loads((repo_root / "ida-plugin.json").read_text())
    assert plugin_manifest["plugin"]["version"] == version

    installer_sh = (repo_root / "scripts" / "install.sh").read_text()
    installer_bat = (repo_root / "scripts" / "install.bat").read_text()
    assert f"IDA_PRO_MCP_VERSION:-{version}" in installer_sh
    assert f'set "VERSION={version}"' in installer_bat
    assert f'set "TAG=v{version}"' in installer_bat
