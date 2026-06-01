"""Tests for the intelligence_context consolidation.

The old code had two files:
  - intelligence_context.py: ContextAssembler class with __init__ only,
    inheriting from ContextAssemblerStateMixin
  - intelligence_context_state.py: a 1844-line module containing
    ContextAssemblerStateMixin with every method of the assembler

That split was purely organizational and made the class harder to read.
This merge brings the methods back into intelligence_context.py and
deletes the state module.

Coverage:
  - intelligence_context.py is now self-contained
  - intelligence_context_state.py is gone
  - no other module imports the old state module
  - public surface preserved (get_assembler, ContextAssembler,
    _intel_profile_enabled, _shutdown_intelligence_singleton, atexit)
  - class is no longer a mixin
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOST_DIR = REPO_ROOT / "src" / "ida_pro_mcp" / "host"
CONTEXT_PY = HOST_DIR / "intelligence_context.py"
STATE_PY = HOST_DIR / "intelligence_context_state.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_state_module_deleted():
    """The old intelligence_context_state.py must be gone after the merge."""
    assert not STATE_PY.exists(), (
        f"{STATE_PY} still exists — the merge should have deleted it"
    )


def test_no_other_module_imports_old_state_module():
    """No code should still import from intelligence_context_state.

    The mixin used to be imported by name in intelligence_context.py
    and in any docs/comments. After the merge, intelligence_context.py
    must not mention it either.
    """
    offenders: list[tuple[Path, int, str]] = []
    for path in HOST_DIR.rglob("*.py"):
        for ln, line in enumerate(_read(path).splitlines(), 1):
            if re.search(
                r"(from\s+(\.|host\.)?intelligence_context_state\b|"
                r"import\s+intelligence_context_state\b)",
                line,
            ):
                offenders.append((path, ln, line.strip()))
    assert not offenders, (
        "stale imports of intelligence_context_state found:\n"
        + "\n".join(f"{p}:{ln}: {l}" for p, ln, l in offenders)
    )


def test_context_module_no_longer_uses_state_mixin():
    """intelligence_context.py must not reference the deleted mixin."""
    src = _read(CONTEXT_PY)
    assert "ContextAssemblerStateMixin" not in src, (
        "intelligence_context.py still references the deleted mixin"
    )


def test_context_class_extends_only_remaining_mixins():
    """The class header should only extend the two surviving mixins."""
    src = _read(CONTEXT_PY)
    m = re.search(r"^class\s+ContextAssembler\s*\(([^)]*)\)\s*:", src, re.MULTILINE)
    assert m is not None, "ContextAssembler class not found"
    bases = m.group(1)
    assert "ContextAssemblerSemanticMixin" in bases
    assert "ContextAssemblerPolicyMixin" in bases


def test_context_module_defines_init_and_assemble():
    """The class body must define __init__ and assemble in this file."""
    src = _read(CONTEXT_PY)
    assert re.search(r"^    def\s+__init__\(self\)\s*:", src, re.MULTILINE), (
        "ContextAssembler.__init__ must be defined in this module"
    )
    assert re.search(r"^    def\s+assemble\(", src, re.MULTILINE), (
        "ContextAssembler.assemble must be defined in this module"
    )


def test_key_methods_live_in_module():
    """Smoke-check that key methods are defined as part of the merged
    class body in intelligence_context.py."""
    src = _read(CONTEXT_PY)
    expected = [
        "def __init__(",
        "def assemble(",
        "def bulk_index(",
        "def stop(",
        "def status(",
        "def record_call(",
        "def check_stuck(",
        "def suggest_next_targets(",
        # blackboard helpers
        "def _get_bb_entries(",
        "def _merge_related_findings(",
        # LLM-first payloads
        "def _build_llm_action_card(",
        "def _build_llm_uncertainty(",
        "def _llm_query_intent(",
        # decompile enrichment
        "def _enrich_decompile(",
        "def _enrich_address_list(",
    ]
    for needle in expected:
        assert needle in src, f"{needle!r} not found in intelligence_context.py"


def test_module_level_helpers_present():
    """_intel_profile_enabled and _shutdown_intelligence_singleton must
    be defined at module level in intelligence_context.py."""
    src = _read(CONTEXT_PY)
    assert re.search(r"^def\s+_intel_profile_enabled\b", src, re.MULTILINE)
    assert re.search(r"^def\s+_shutdown_intelligence_singleton\b", src, re.MULTILINE)


def test_singleton_factory_present():
    """get_assembler() and the atexit shutdown hook must be present."""
    src = _read(CONTEXT_PY)
    assert re.search(r"^def\s+get_assembler\b", src, re.MULTILINE)
    assert "atexit.register" in src


def test_class_lines_increased_after_merge():
    """The merged file should be substantially larger than the old
    skinny stub. The pre-merge stub was ~135 lines. After merging the
    1844-line state file, the result should be at least 1500 lines."""
    n = len(_read(CONTEXT_PY).splitlines())
    assert n >= 1500, (
        f"intelligence_context.py is only {n} lines — expected the "
        f"merged state body to bring it up. Merge may be incomplete."
    )


def test_unused_imports_dropped():
    """The merged module should not import the helpers it doesn't use.

    Pre-merge imports included `compact_policy_blob`, `derive_focus_candidates`,
    `prune_policy_store` (helpers used by the policy mixin, not this file),
    and many stdlib modules (math, struct, subprocess, urllib, uuid, sys,
    re) that the merged class never touches.
    """
    src = _read(CONTEXT_PY)
    # The policy mixin uses these, not the base class body.
    assert "from .intelligence_helpers import" not in src
    # Stdlib modules that the merged class doesn't need.
    for dead in ("import math", "import struct", "import subprocess",
                 "import urllib", "import uuid", "import sys", "import re"):
        assert dead not in src, f"unused stdlib import: {dead}"
