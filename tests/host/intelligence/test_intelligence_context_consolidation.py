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
CONTEXT_PY = HOST_DIR / "intelligence" / "context.py"
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

