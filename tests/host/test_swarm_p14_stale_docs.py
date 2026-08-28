"""Meta-doc staleness regression (paper section 10.2 item 12).

CONTRIBUTING.md / docs/guide/use-cases.md / docs/guide/architecture.md are hand-edited prose and
drifted from the current surface (removed unittest modules, a stale Tier A
claim, and no coverage of the raw-blob/RISC-V path).  This pins the rebuilt
behavior:

- the meta-docs contain no ``ida_*`` operation or legacy tool name that is
  absent from the current surface;
- CONTRIBUTING.md points at real pytest entrypoints (per-dir layouts,
  ``--basetemp=.pytest_tmp``);
- docs/guide/architecture.md scopes the Tier A/B/C model to the legacy surface and
  describes the default agent catalog;
- docs/guide/use-cases.md documents the opaque raw-blob / RISC-V path with real
  operations (fw shaping + r2 sidecar + raw value scan + GP sreg fix);
- the local Claude Code allow-list names only tools that exist in ``TOOLS``.

Host-only: reads repo files and queries host-side registries
(``agent_operations``, ``schemas_data``).  No live IDA is required — nothing
here imports IDA modules, and the docs under test describe the host-side
surface.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ida_pro_mcp.host.agent_operations import list_agent_operations
from ida_pro_mcp.host.schemas_data import TOOLS

REPO_ROOT = Path(__file__).resolve().parents[2]

META_DOCS = (
    "CONTRIBUTING.md",
    "docs/guide/use-cases.md",
    "docs/guide/architecture.md",
)

# Legacy tool-surface identifiers that have been removed or never existed.
# (agent/query/summarize are deliberately excluded: they are ordinary English
# words, not stable tool IDs, so absence-asserting them would be brittle.)
DEAD_TOOL_NAMES = ("firmware_view", "binary_info", "data_ops", "packer")


def _doc_text(name: str) -> str:
    path = REPO_ROOT / name
    assert path.is_file(), f"meta-doc {name} missing"
    return path.read_text(encoding="utf-8")


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


def test_meta_docs_contain_no_unknown_operation_names():
    """The three meta-docs must not name ida_* operations absent from the
    current catalog (regression: USE_CASES/ARCHITECTURE drifted)."""
    names = _operation_names()
    for doc in META_DOCS:
        text = _doc_text(doc)
        unknown = sorted(_ida_tokens(text) - names)
        assert not unknown, (
            f"{doc} names operations absent from the current surface: {unknown}"
        )


def test_meta_docs_contain_no_removed_legacy_tools():
    """None of the meta-docs may present removed tools as current surface."""
    pattern = re.compile(
        r"\b(?:{})\b".format("|".join(re.escape(name) for name in DEAD_TOOL_NAMES))
    )
    for doc in META_DOCS:
        text = _doc_text(doc)
        hits = sorted(set(pattern.findall(text)))
        assert not hits, f"{doc} references removed tools: {hits}"


def test_contributing_points_at_pytest_not_removed_unittest_modules():
    """CONTRIBUTING must recommend pytest entrypoints that exist, not the
    unittest modules that were removed (test_host_wiki_and_hardening,
    test_linux_support, test_session_features)."""
    text = _doc_text("CONTRIBUTING.md")
    assert "pytest" in text
    assert "--basetemp=.pytest_tmp" in text
    assert "python -m unittest" not in text
    for stale in (
        "test_host_wiki_and_hardening",
        "test_linux_support",
        "test_session_features",
    ):
        assert stale not in text, f"CONTRIBUTING.md still references removed module {stale}"


def test_arch_tiering_is_scoped_to_legacy_surface():
    """ARCHITECTURE must describe the default agent catalog and scope the
    Tier A/B/C model to the legacy surface."""
    text = _doc_text("docs/guide/architecture.md")
    section = text.split("## Product surface policy", 1)[1].split("## ", 1)[0]
    assert "list_agent_operations" in section
    assert "no hidden default subset" in section
    assert "IDA_MCP_TOOL_SURFACE=legacy" in section
    assert "ADVERTISED_TOOLS" in section
    assert "HIDDEN_TOOLS_IN_LIST" in section
    assert "ADVERTISED_ACTIONS" in section


def test_use_cases_document_opaque_raw_blob_riscv_path():
    """Opaque raw-blob / RISC-V scenario: a headerless blob has no symbols and
    no IDA xrefs, so the doc must route through the raw path — fw shaping,
    the default-off r2 sidecar, a raw pointer-word/value scan, and the RISC-V
    GP segment-register fix — using only real operation names."""
    text = _doc_text("docs/guide/use-cases.md")
    names = _operation_names()

    def require(tokens):
        unknown = sorted(t for t in tokens if t not in names)
        assert not unknown, f"raw-blob/RISC-V scenario references unknown ops: {unknown}"
        missing = sorted(t for t in tokens if t not in text)
        assert not missing, f"raw-blob/RISC-V scenario missing operations: {missing}"

    # Opening a headerless blob as raw bytes.
    require({"ida_open_binary", "ida_open_background"})
    assert "input_format='bin'" in text
    # Pre-IDA r2 sidecar (subprocess, default-off).
    require({"ida_r2_bininfo", "ida_r2_load_hints", "ida_r2_vxrefs"})
    # Firmware shaping of the carved region.
    require({"ida_fw_detect_vector_table", "ida_fw_detect_load_base", "ida_fw_carve"})
    # Raw pointer-word/value scan where IDA xrefs do not exist yet.
    require({"ida_search_data_value", "ida_create_data"})
    # RISC-V GP-relative xref resolution via the segment-register seam.
    require({"ida_sreg_set", "ida_sreg_get"})
    # Reversibility primitives for experiment-driven shaping.
    require(
        {
            "ida_undo_begin",
            "ida_undo_end",
            "ida_idb_snapshot",
            "ida_idb_restore_snapshot",
        }
    )


def test_settings_local_whitelist_matches_current_tools():
    """The local Claude Code allow-list must not name tools absent from
    current TOOLS (regression: binary_info/agent/query/summarize/packer/
    data_ops were stale).  The file is local-only (.gitignored) and optional."""
    settings = REPO_ROOT / ".claude" / "settings.local.json"
    if not settings.is_file():
        pytest.skip("settings.local.json not present (local-only file)")
    data = json.loads(settings.read_text(encoding="utf-8"))
    allow = data.get("permissions", {}).get("allow", [])
    prefix = "mcp__ida-pro-mcp__"
    tools = set(TOOLS)
    stale = sorted(
        entry[len(prefix):]
        for entry in allow
        if entry.startswith(prefix) and entry[len(prefix):] not in tools
    )
    assert not stale, f"allow-list names tools absent from current TOOLS: {stale}"
