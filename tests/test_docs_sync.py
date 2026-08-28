"""Generated public-operation docs must stay aligned with the MCP contract."""

from __future__ import annotations

import re
from pathlib import Path

from ida_pro_mcp.host.agent_operations import list_agent_operations, render_agent_operations_markdown

REPO_ROOT = Path(__file__).resolve().parents[1]

# Meta-docs that describe the product surface and must not name operations or
# tools that no longer exist. These are hand-edited prose (unlike the
# generated TOOLS_REFERENCE / SKILL.md).
META_DOCS = (
    "CONTRIBUTING.md",
    "docs/guide/use-cases.md",
    "docs/guide/architecture.md",
)

# Legacy tool-surface identifiers that have been removed or never existed.
# Prose must not name them as current tools. (agent/query/summarize are
# deliberately excluded: they are ordinary English words, not stable tool IDs.)
DEAD_TOOL_NAMES = ("firmware_view", "binary_info", "data_ops", "packer")


def _meta_doc_texts():
    for name in META_DOCS:
        path = REPO_ROOT / name
        assert path.is_file(), f"meta-doc {name} missing"
        yield name, path.read_text(encoding="utf-8")


def _operation_names() -> set[str]:
    return {operation.name for operation in list_agent_operations()}


# `ida_mcp` / `ida_pro_mcp` are the Python package names, not operations; the
# meta-docs legitimately reference module paths like src/ida_pro_mcp/...
_PACKAGE_IDENTIFIERS = {"ida_mcp", "ida_pro_mcp"}


def _ida_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"\bida_[a-z0-9_]+\b", text)
        if token not in _PACKAGE_IDENTIFIERS
    }


def test_readme_describes_the_agent_operation_surface():
    """The README must document the real surface, not a fixed sentence.

    This previously asserted one exact marketing phrase, so rewording the
    intro broke it while dropping every operation from the page would not.
    Bind it to the registry instead.
    """
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "ida_help" in text

    names = [operation.name for operation in list_agent_operations()]
    entry_points = {"ida_open_binary", "ida_decompile", "ida_find", "ida_write_finding"}
    missing = sorted(name for name in entry_points if name not in text)
    assert not missing, f"README does not mention core operations: {missing}"

    # The README summarises rather than enumerates, but it should cover a
    # real share of the surface so it cannot drift into describing nothing.
    mentioned = [name for name in names if name.removeprefix("ida_") in text]
    assert len(mentioned) >= len(names) // 2, (
        f"README mentions only {len(mentioned)} of {len(names)} operations"
    )

    # The operations table must enumerate every operation exactly once, so
    # adding an operation cannot silently leave the README behind.
    table = re.search(
        r"\| \*\*Session\*\*.*?\| \*\*Workflow\*\*.*?\|\n", text, flags=re.S
    )
    assert table is not None, "README operations table not found"
    listed = {
        op
        for row in table.group(0).splitlines()
        for cell in row.split("|")[1:-1]
        for op in re.findall(r"`([a-z0-9_]+)`", cell)
    }
    expected = {name.removeprefix("ida_") for name in names}
    assert listed == expected, (
        f"README operations table out of sync: "
        f"missing {sorted(expected - listed)}, extra {sorted(listed - expected)}"
    )


def test_readme_operation_count_matches_the_registry():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    count = len(list_agent_operations())
    assert f"{count} exact-schema operations" in text


def test_tools_reference_is_generated_from_the_public_operation_contract():
    reference = REPO_ROOT / "docs" / "TOOLS_REFERENCE.md"
    generated = reference.read_text(encoding="utf-8")
    assert generated.replace("<!-- GENERATED: scripts/generate_tool_skills.py -->\n", "") == render_agent_operations_markdown()


def test_skill_markdown_is_generated_from_the_public_operation_contract():
    from ida_pro_mcp.host.agent_operations import render_agent_skill_markdown

    skill = REPO_ROOT / ".agents" / "skills" / "ida-pro-mcp" / "SKILL.md"
    generated = skill.read_text(encoding="utf-8")
    assert generated.replace("<!-- GENERATED: scripts/generate_tool_skills.py -->\n", "") == render_agent_skill_markdown()


def test_every_public_operation_is_documented_once():
    text = (REPO_ROOT / "docs" / "TOOLS_REFERENCE.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## `(ida_[a-z0-9_]+)`$", text, flags=re.MULTILINE)
    names = [operation.name for operation in list_agent_operations()]
    assert headings == names
    assert len(headings) == len(set(headings))


def test_meta_docs_reference_only_real_operations():
    """CONTRIBUTING / USE_CASES / ARCHITECTURE must not name ida_* operations
    that are absent from the current operation catalog."""
    names = _operation_names()
    for doc_name, text in _meta_doc_texts():
        unknown = sorted(_ida_tokens(text) - names)
        assert not unknown, (
            f"{doc_name} references operations absent from the catalog: {unknown}"
        )


def test_meta_docs_avoid_dead_legacy_tool_names():
    """None of the meta-docs may present removed tools as current surface."""
    pattern = re.compile(
        r"\b(?:{})\b".format("|".join(re.escape(name) for name in DEAD_TOOL_NAMES))
    )
    for doc_name, text in _meta_doc_texts():
        hits = sorted(set(pattern.findall(text)))
        assert not hits, (
            f"{doc_name} names tools that no longer exist on the surface: {hits}"
        )


def test_contributing_recommends_real_pytest_entrypoints():
    """CONTRIBUTING must point at pytest entrypoints that exist, not at
    unittest modules that were removed."""
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "pytest" in text
    assert "--basetemp=.pytest_tmp" in text
    assert "python -m unittest" not in text
    for stale in ("test_host_wiki_and_hardening", "test_linux_support", "test_session_features"):
        assert stale not in text, f"CONTRIBUTING.md still references removed module {stale}"


def test_arch_surface_policy_matches_current_tiering():
    """ARCHITECTURE must describe the default agent catalog and scope the
    Tier A/B/C model to the legacy surface."""
    text = (REPO_ROOT / "docs/guide/architecture.md").read_text(encoding="utf-8")
    section = text.split("## Product surface policy", 1)[1].split("## ", 1)[0]
    # Default surface is the full ida_* catalog, not a hidden Tier A subset.
    assert "list_agent_operations" in section
    assert "no hidden default subset" in section
    # Tier A (ADVERTISED_TOOLS) applies only to the legacy backend.
    assert "IDA_MCP_TOOL_SURFACE=legacy" in section
    assert "ADVERTISED_TOOLS" in section
    assert "HIDDEN_TOOLS_IN_LIST" in section
    assert "ADVERTISED_ACTIONS" in section
