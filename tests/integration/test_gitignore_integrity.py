"""Ensure .gitignore covers all generated/cache artifacts.

This file SHOULD stay up to date as new tooling is added.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GITIGNORE_PATH = REPO_ROOT / ".gitignore"


def _gitignore_entries() -> set[str]:
    lines = GITIGNORE_PATH.read_text(encoding="utf-8").splitlines()
    entries: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.add(line)
    return entries


IGNORED_PATTERNS = {
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    "*.egg-info/",
    "dist/",
    "build/",
    ".eggs/",
    ".venv/",
    "venv/",
    "env/",
    ".python-version",
    ".pytest_cache/",
    ".ruff_cache/",
    ".coverage",
    "htmlcov/",
    "*.cover",
    ".idea/",
    ".vscode/",
    ".DS_Store",
    "Thumbs.db",
    ".agents/",
    "embedder.json",
    "ida-install.json",
    "ORIGINAL_REQUEST.md",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    "*.bak",
    "*.orig",
    "*.swp",
    "ida_mcp_cache/",
    ".claude/",
    ".commandcode/",
}


class TestGitignoreIntegrity:
    def test_gitignore_exists(self):
        assert GITIGNORE_PATH.is_file(), f".gitignore not found at {GITIGNORE_PATH}"

    def test_pycache_ignored(self):
        entries = _gitignore_entries()
        assert "__pycache__/" in entries

    def test_ruff_cache_ignored(self):
        entries = _gitignore_entries()
        assert ".ruff_cache/" in entries, (
            ".ruff_cache/ must be in .gitignore — ruff generates it"
        )

    def test_pytest_cache_ignored(self):
        entries = _gitignore_entries()
        assert ".pytest_cache/" in entries

    def test_venv_ignored(self):
        entries = _gitignore_entries()
        assert ".venv/" in entries

    def test_agents_ignored(self):
        entries = _gitignore_entries()
        assert ".agents/" in entries

    def test_embedder_json_ignored(self):
        entries = _gitignore_entries()
        assert "embedder.json" in entries

    def test_key_generated_patterns_covered(self):
        """Fail if any expected pattern is missing."""
        entries = _gitignore_entries()
        missing = IGNORED_PATTERNS - entries
        assert not missing, (
            f"{len(missing)} expected .gitignore patterns missing: "
            + ", ".join(sorted(missing))
        )
