"""Regression tests for t11_intel_tools audit fixes.

Covers the `function_families` ``mark_examined`` path in the intelligence
tool: the bare `from blackboard import BlackboardStore` flat import fails in
the package/editable-install layout (no top-level ``blackboard`` module),
silently disabling ``mark_examined``. The fix resolves the store through the
package-relative ``.blackboard`` module with a flat fallback, so
``mark_examined=True`` records examinations instead of dropping into
``mark_examined_error``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

# Imported at module level (rather than inside the fixture) on purpose: the
# conftest evicts-and-restores sys.modules between tests, and numpy's C
# extension cannot be loaded more than once per process — so any module that
# transitively imports numpy must be imported before the first test's snapshot
# is taken, or the second test dies on re-import.
from _isolated_repo_loader import install_common_stub, load_tool_module  # noqa: E402

import ida_pro_mcp.host.intelligence.families as _FAMILIES_MOD  # noqa: E402
import ida_pro_mcp.services  # noqa: E402

# Load the tool modules once at collection time so they survive the per-test
# sys.modules restore.
install_common_stub()
_INTELLIGENCE = load_tool_module("intelligence")
_BLACKBOARD = load_tool_module("blackboard")


# ---------------------------------------------------------------------------
# Fixtures: run the real `intelligence` dispatch with fake services
# ---------------------------------------------------------------------------

class _FakeEmbedder:
    backend = "fake"

    def ensure_ready(self):
        return True


class _FakeIndex:
    def __init__(self, *args, **kwargs):
        self.size = 3
        self._db = "/tmp/fake.idb.embeddings.db"

    def search(self, *args, **kwargs):
        return []

    def metadata(self):
        return {"count": self.size}


class _FakeStore:
    """Stand-in for BlackboardStore that only records examination calls."""

    def __init__(self):
        self.examined = []

    def record_examination(self, **kwargs):
        self.examined.append(kwargs)


@pytest.fixture
def function_families_env(monkeypatch):
    """Wire a fake services stack so intelligence's function_families runs."""
    # Register the stub ida_* modules first so `import idaapi` below resolves
    # to the stub, not the real IDA shim that sits on sys.path via conftest.
    install_common_stub()
    import idaapi

    # _index_for_current_idb reads the active IDB path from idaapi.
    monkeypatch.setattr(idaapi, "PATH_TYPE_IDB", 1, raising=False)
    monkeypatch.setattr(idaapi, "get_path", lambda _t: "/tmp/fake.idb", raising=False)

    monkeypatch.setattr(ida_pro_mcp.services, "BgeCodeEmbedder", _FakeEmbedder)
    monkeypatch.setattr(ida_pro_mcp.services, "FunctionEmbeddingIndex", _FakeIndex)

    # compute_function_families: one family, two members.
    def _fake_families(*args, **kwargs):
        return {
            "families": [
                {
                    "summary": "lookalike group",
                    "members": [
                        {"ea": 0x1000, "name": "sub_1000"},
                        {"ea": 0x2000, "name": "sub_2000"},
                    ],
                }
            ]
        }

    monkeypatch.setattr(_FAMILIES_MOD, "compute_function_families", _fake_families)

    # Replace BlackboardStore on the package module with a recording fake so
    # no real blackboard DB is created; this is the module the fixed
    # `from .blackboard import BlackboardStore` resolves to.
    store = _FakeStore()
    # The conftest purges ida_mcp.tools.* submodules after every test, so the
    # collection-time _BLACKBOARD object is stale by the time this test runs.
    # Re-resolve the module the tool's `from .blackboard import BlackboardStore`
    # will read from sys.modules and patch THAT object (blackboard imports only
    # stdlib, so a fresh import is safe and numpy can be loaded once only).
    import importlib
    import sys

    _blk = sys.modules.get("ida_pro_mcp.ida_mcp.tools.blackboard")
    if _blk is None:
        _blk = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")
    monkeypatch.setattr(_blk, "BlackboardStore", lambda: store)

    return _INTELLIGENCE, store


# ---------------------------------------------------------------------------
# mark_examined — records through the package-relative blackboard import
# ---------------------------------------------------------------------------

def test_function_families_mark_examined_records_via_package_import(function_families_env):
    intelligence_mod, store = function_families_env

    resp = intelligence_mod.intelligence(
        action="function_families",
        mark_examined=True,
        verdict="interesting",
        min_similarity=0.8,
    )

    assert resp["ok"] is True
    # The package-relative import resolved, so every member got recorded.
    assert resp.get("marked_examined") == 2
    assert "mark_examined_error" not in resp
    assert len(store.examined) == 2
    # ea is an int in the families result; the tool str()s it before handing
    # to the store, which normalizes via normalize_addr.
    assert store.examined[0]["addr"] == "4096"
    assert store.examined[0]["verdict"] == "interesting"
    assert store.examined[0]["name"] == "sub_1000"


def test_function_families_without_mark_examined_skips_store(function_families_env):
    intelligence_mod, store = function_families_env

    resp = intelligence_mod.intelligence(action="function_families", min_similarity=0.8)

    assert resp["ok"] is True
    assert "marked_examined" not in resp
    assert "mark_examined_error" not in resp
    assert store.examined == []


# ---------------------------------------------------------------------------
# The flat top-level import must not be the resolution path anymore
# ---------------------------------------------------------------------------

def test_function_families_does_not_use_flat_blackboard_import():
    """The bare `from blackboard import BlackboardStore` fails in the package
    layout; guard the fixed source only uses it as a guarded fallback."""
    src = Path(__file__).resolve().parents[2] / "src"
    path = src / "ida_pro_mcp" / "ida_mcp" / "tools" / "intelligence.py"
    text = path.read_text(encoding="utf-8")

    # The package-relative import must be present, and the flat import must
    # only appear as the guarded fallback (not as the primary resolution).
    assert "from .blackboard import BlackboardStore" in text
    flat_idx = text.find("from blackboard import BlackboardStore")
    assert flat_idx != -1
    assert text.rfind("except ImportError:", 0, flat_idx) < flat_idx
