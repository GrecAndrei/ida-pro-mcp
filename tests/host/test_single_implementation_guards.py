"""Invariants: shared helpers must have exactly one implementation.

Several helpers in this package were originally copy-pasted into more than one
module. The symlink guard in particular existed three times, which meant a
path-traversal fix had to be applied three times and a single miss left a hole.
These tests assert identity so a future copy cannot be reintroduced silently.
"""

from __future__ import annotations

from ida_pro_mcp.host.server.blackboard_legacy import path_has_symlink
from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin
from ida_pro_mcp.host.server.server_dispatch import ServerDispatchMixin
from ida_pro_mcp.host.server.server_session import _sess_coerce_tag, _sess_coerce_untag


def test_symlink_guard_has_a_single_implementation():
    # All three public names must be the same function object, not copies.
    # Class access unwraps the staticmethod descriptor.
    assert ServerBlackboardMixin._bb_path_has_symlink is path_has_symlink
    assert ServerDispatchMixin._memory_path_has_symlink is path_has_symlink


def test_session_tag_coercion_has_a_single_implementation():
    # untag and tag validate identically; untag must be the same function.
    assert _sess_coerce_untag is _sess_coerce_tag


def test_symlink_guard_rejects_escapes_and_accepts_real_paths(tmp_path):
    root = tmp_path / "root"
    (root / "real").mkdir(parents=True)
    (root / "real" / "file.json").write_text("{}", encoding="utf-8")
    link = root / "link"
    try:
        link.symlink_to(root / "real")
    except (OSError, NotImplementedError):  # pragma: no cover - platform without symlinks
        return

    assert path_has_symlink(str(root / "real" / "file.json"), str(root)) is False
    assert path_has_symlink(str(link / "file.json"), str(root)) is True
    assert path_has_symlink(str(tmp_path / "outside"), str(root)) is True
    # Empty inputs fail closed rather than permitting the path.
    assert path_has_symlink("", str(root)) is True
    assert path_has_symlink(str(root), "") is True
