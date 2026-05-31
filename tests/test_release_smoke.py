from pathlib import Path


def test_package_version_matches_pyproject():
    import tomllib
    import ida_pro_mcp

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert ida_pro_mcp.__version__ == pyproject["project"]["version"]


def test_tool_registry_counts_are_consistent():
    from ida_pro_mcp.host.schemas_data import ADVERTISED_TOOLS, TOOLS

    assert len(TOOLS) == 73
    assert set(ADVERTISED_TOOLS).issubset(set(TOOLS))
    assert len(TOOLS) == len(set(TOOLS))
    assert len(ADVERTISED_TOOLS) == len(set(ADVERTISED_TOOLS))


def test_generated_tool_docs_manifest_matches_registry():
    readme = Path(".agents/tool-docs/README.md")
    if not readme.exists():
        return
    content = readme.read_text(encoding="utf-8")
    assert "`73` docs" in content
    assert "src/ida_pro_mcp/host/schemas_data.py" in content


def test_security_docs_exist():
    assert Path("SECURITY.md").exists()
    assert Path("docs/SAFETY_MODEL.md").exists()
