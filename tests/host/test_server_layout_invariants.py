"""`host/server/` must stay organized and documented in step with itself.

Two failures are guarded here, both of which happened during the `server_*`
prefix removal:

1. ``pyproject.toml`` carried a ``per-file-ignores`` entry keyed to
   ``server_runtime.py``. Renaming the file silently dropped the ignore and
   four pre-existing ``SIM115`` findings failed the lint, which reads as "you
   broke something" rather than "you moved something".
2. A test imported the module as ``runtime`` while the test body also used
   ``runtime`` as a local test double, so a module attribute resolved to the
   double.

The first is checked by requiring every ``per-file-ignores`` path under
``host/server/`` to exist. The second is a lint concern and is covered by
running ruff, so this test focuses on the structural invariants: the directory
carries no redundant ``server_`` prefix, the module map in
``docs/guide/architecture.md`` names only files that exist, and the two session
modules stay distinguishable by name.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = REPO_ROOT / "src" / "ida_pro_mcp" / "host" / "server"
ARCHITECTURE = REPO_ROOT / "docs" / "guide" / "architecture.md"


def _server_modules() -> list[Path]:
    return sorted(p for p in SERVER_DIR.glob("*.py") if p.name != "__init__.py")


def test_server_directory_exists_and_is_populated():
    assert SERVER_DIR.is_dir()
    assert len(_server_modules()) >= 20, f"only {len(_server_modules())} modules in server/"


def test_no_module_carries_a_redundant_server_prefix():
    # server/server_blackboard.py stutters; the directory already says "server".
    offenders = [p.name for p in _server_modules() if p.name.startswith("server_")]
    assert not offenders, f"redundant server_ prefix inside server/: {offenders}"


def test_session_modules_remain_distinguishable():
    # session.py holds the Session/SessionManager data classes; the dispatch
    # helpers were once server_session.py. Renaming the latter to session.py
    # would silently shadow the former, so the dispatch module keeps its own
    # name.
    names = {p.name for p in _server_modules()}
    assert "session.py" in names, "session.py (Session/SessionManager) is missing"
    assert "session_dispatch.py" in names, (
        "session_dispatch.py is missing; renaming it to session.py would shadow "
        "the Session data classes"
    )


def test_every_per_file_ignore_path_still_exists():
    # A per-file-ignore keyed to a renamed path fails open: the ignore silently
    # stops applying and unrelated pre-existing findings break the lint.
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ignores = config.get("tool", {}).get("ruff", {}).get("lint", {}).get("per-file-ignores", {})
    missing = [
        pattern
        for pattern in ignores
        if "*" not in pattern and not (REPO_ROOT / pattern).exists()
    ]
    assert not missing, f"per-file-ignores reference paths that no longer exist: {missing}"


def _documented_server_modules() -> set[str]:
    """Module names documented in the guide's ``host/server/`` section.

    The guide itemises the directory with bare filenames (`` `dispatch.py` ``)
    but also cites fully-qualified paths elsewhere, so both forms are read and
    only the directory section is considered.
    """
    text = ARCHITECTURE.read_text(encoding="utf-8")
    start = text.find("src/ida_pro_mcp/host/server/")
    assert start != -1, "the architecture guide has no host/server/ section"
    # The section runs until the next top-level bullet at column 0.
    rest = text[start:]
    end = rest.find("\n- `", 1)
    section = rest if end == -1 else rest[:end]
    return set(re.findall(r"`([a-z_]+\.py)`", section)) | set(
        re.findall(r"src/ida_pro_mcp/host/server/([a-z_]+\.py)", text)
    )


def test_architecture_module_map_names_only_existing_files():
    referenced = sorted(_documented_server_modules())
    assert referenced, "the architecture guide names no host/server modules"
    missing = [name for name in referenced if not (SERVER_DIR / name).is_file()]
    assert not missing, f"architecture guide references missing modules: {missing}"


def test_architecture_module_map_covers_every_server_module():
    # The reverse direction: a new module must be documented, so the map cannot
    # quietly fall behind the directory it describes.
    referenced = _documented_server_modules()
    undocumented = [p.name for p in _server_modules() if p.name not in referenced]
    assert not undocumented, f"host/server modules absent from the architecture map: {undocumented}"
