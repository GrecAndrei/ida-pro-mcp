"""The standalone test loader must not rely on deprecated import behavior.

``ida_mcp`` modules are loaded standalone so tests can exercise them without the
IDA SDK. The loader previously registered each module under a top-level
``sys.modules`` key and then hand-pinned ``__package__`` to the real package.
That leaves ``__package__ != __spec__.parent``, which the import system reports
as deprecated: it warns today, and the fallback that keeps ``from .rpc import
...`` resolving is slated for removal. Thirty-six tests depended on that
fallback, so the suite only passed because warnings were not surfaced.

These tests pin the corrected behavior so a future loader change cannot
reintroduce the skew behind a passing suite.
"""

from __future__ import annotations

import sys
import types
import warnings

import pytest

from tests._isolated_repo_loader import (
    IDA_MCP_ROOT,
    load_standalone_package_module,
    register_ida_mcp_package,
)


def test_stub_package_points_at_the_real_source():
    sub = register_ida_mcp_package()
    assert sub.__path__ == [str(IDA_MCP_ROOT)]
    assert sys.modules["ida_pro_mcp.ida_mcp"] is sub


def test_standalone_module_is_registered_inside_its_package():
    mod = load_standalone_package_module("error_handling", "t_loader_pkg_ut")
    # Registered under a key inside the package, not a flat top-level name.
    assert sys.modules["ida_pro_mcp.ida_mcp.t_loader_pkg_ut"] is mod
    assert "t_loader_pkg_ut" not in sys.modules
    # The whole point: the import system's own consistency check holds.
    assert mod.__package__ == mod.__spec__.parent == "ida_pro_mcp.ida_mcp"
    assert mod.__name__ == "ida_pro_mcp.ida_mcp.t_loader_pkg_ut"


def test_standalone_load_raises_no_deprecation_warning():
    # error_handling has a relative `from . import compat`, which is exactly the
    # statement the skewed __package__ used to make the import system warn on.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_standalone_package_module("error_handling", "t_loader_warn_ut")
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert not deprecations, [str(w.message) for w in deprecations]


def test_each_load_gets_an_independent_module_object():
    # Isolation must survive the key change: two loads of the same source are
    # distinct objects under distinct keys, so module state cannot leak.
    first = load_standalone_package_module("error_handling", "t_loader_iso_a")
    second = load_standalone_package_module("error_handling", "t_loader_iso_b")
    assert first is not second
    first.__dict__["_loader_probe"] = True
    assert "_loader_probe" not in second.__dict__


def test_unknown_relpath_raises_rather_than_registering_a_broken_module():
    with pytest.raises((FileNotFoundError, OSError)):
        load_standalone_package_module("definitely_not_a_real_module_xyz", "t_loader_bad")
    assert "ida_pro_mcp.ida_mcp.t_loader_bad" not in sys.modules


def test_loader_helpers_return_modules():
    mod = load_standalone_package_module("error_handling", "t_loader_type_ut")
    assert isinstance(mod, types.ModuleType)
    assert hasattr(mod, "make_error")
