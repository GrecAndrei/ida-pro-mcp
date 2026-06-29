"""Runtime feature-detection shim for IDA SDK capabilities added in 9.3.

Each helper returns a boolean by introspecting the running IDA environment
(idaapi attributes, imported modules, kernel version).  Tools that want to
opt-in to a 9.3 feature call the helper and gracefully degrade on older
versions — no hard version forks in the call sites.

Tested against:
  - 9.0 — all helpers return False (or "unknown")
  - 9.2 — all helpers return False for 9.3-specific features
  - 9.3 — all helpers return True for added-in-9.3 features
"""
from __future__ import annotations

import importlib
import logging
from typing import Any, Tuple

logger = logging.getLogger(__name__)


_MAJOR = 0
_MINOR = 0
_PATCH = 0
_version_loaded = False


def _load_version() -> None:
    """Resolve the running IDA version once at module import.

    Falls back to (0, 0, 0) if the SDK isn't present (e.g. when this module
    is imported by the host for argument-validation, not by idat).
    """
    global _MAJOR, _MINOR, _PATCH, _version_loaded
    if _version_loaded:
        return
    _version_loaded = True
    try:
        import idaapi  # type: ignore[import-not-found]
    except ImportError:
        return
    getter = getattr(idaapi, "get_kernel_version", None)
    if not callable(getter):
        return
    try:
        raw = str(getter())
    except Exception:  # pragma: no cover - defensive
        return
    parts = raw.split(".")
    nums: list[int] = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            break
    if not nums:
        return
    _MAJOR = nums[0]
    _MINOR = nums[1] if len(nums) > 1 else 0
    _PATCH = nums[2] if len(nums) > 2 else 0


def ida_version() -> Tuple[int, int, int]:
    """Return (major, minor, patch) of the running IDA, or (0,0,0) outside IDA."""
    _load_version()
    return (_MAJOR, _MINOR, _PATCH)


def ida_version_str() -> str:
    """Return the running IDA kernel version as a string, or 'unknown'."""
    try:
        import idaapi  # type: ignore[import-not-found]

        return str(idaapi.get_kernel_version())
    except Exception:
        return "unknown"


def at_least(major: int, minor: int = 0) -> bool:
    """True if the running IDA is >= major.minor."""
    cur = ida_version()
    if cur == (0, 0, 0):
        # Outside IDA, conservatively assume newer to allow tools that gate
        # on feature detection (which we still do) to load.  Tool callers
        # should call has_feature() for hard guards.
        return True
    return (cur[0], cur[1]) >= (major, minor)


# ============================================================================
# Feature probes
#
# Each probe is cached after first call.  If the SDK attribute changes during
# a session (it won't, but for tests), call reset_probe_cache() to re-check.
# ============================================================================
_PROBE_CACHE: dict[str, bool] = {}


def _probe(name: str, predicate) -> bool:
    cached = _PROBE_CACHE.get(name)
    if cached is not None:
        return cached
    try:
        result = bool(predicate())
    except Exception as exc:
        logger.debug("Feature probe %r failed: %s", name, exc)
        result = False
    _PROBE_CACHE[name] = result
    return result


def reset_probe_cache() -> None:
    """Clear the feature-probe cache.  Used by tests and live-reload scenarios."""
    _PROBE_CACHE.clear()


# ----- 9.3 capabilities -----

def has_cfunc_serialize() -> bool:
    """9.3: cfunc_t.serialize() / deserialize() for persisting decompilation."""
    return _probe(
        "cfunc_serialize",
        lambda: at_least(9, 3) and _has_idaapi_attr("cfunc_t", "serialize"),
    )


def has_ida_lumina() -> bool:
    """9.3: ida_lumina Python module for direct Lumina API access."""
    return _probe(
        "ida_lumina",
        lambda: at_least(9, 3) and _module_importable("ida_lumina"),
    )


def has_forbid_noprop() -> bool:
    """9.3: vdui_t.ui_noprop_lvar() for fine-grained assignment-propagation control."""
    return _probe(
        "forbid_noprop",
        lambda: at_least(9, 3) and _has_idaapi_attr("vdui_t", "ui_noprop_lvar"),
    )


def has_microcode_assertions() -> bool:
    """9.3: ability to insert/remove microcode assertions (was read-only in 9.2)."""
    return _probe(
        "microcode_assertions",
        lambda: at_least(9, 3),
    )


def has_mte_intrinsics() -> bool:
    """9.3: ARM64 MTE decompiler intrinsics (__arm_mte_create_random_tag, etc.)."""
    return _probe(
        "mte_intrinsics",
        lambda: at_least(9, 3),
    )


def has_neon_crypto_intrinsics() -> bool:
    """9.3: ARM64 NEON AES/SHA256/SHA512 intrinsics in decompiler output."""
    return _probe(
        "neon_crypto_intrinsics",
        lambda: at_least(9, 3),
    )


def has_cssc_intrinsics() -> bool:
    """9.3: ARMv8.7 CSSC (CTZ/CNT/ABS/SMAX/...) decompiler intrinsics."""
    return _probe(
        "cssc_intrinsics",
        lambda: at_least(9, 3),
    )


def has_v850_decompiler() -> bool:
    """9.3: V850 decompiler (new in 9.3)."""
    return _probe(
        "v850_decompiler",
        lambda: at_least(9, 3),
    )


def has_nds32_processor() -> bool:
    """9.3: Andes NDS32 processor module (PLFM_NDS32 = 76)."""
    return _probe(
        "nds32_processor",
        lambda: at_least(9, 3) and _idaapi_const("PLFM_NDS32") == 76,
    )


def has_objc_parser() -> bool:
    """9.3: Objective-C header parser (clang-backed)."""
    return _probe(
        "objc_parser",
        lambda: at_least(9, 3) and _idaapi_const("SRCLANG_OBJCPP") is not None,
    )


def has_xref_tree_widget() -> bool:
    """9.3: BWN_XREF_TREE widget replaces legacy BWN_CALLS in 9.3."""
    return _probe(
        "xref_tree_widget",
        lambda: at_least(9, 3) and _idaapi_const("BWN_XREF_TREE") is not None,
    )


def has_qset_qmap_headers() -> bool:
    """9.3: new qset.hpp / qmap.hpp headers in SDK."""
    # There's no runtime introspection; we rely on version gate plus a
    # try/import of one of the container headers via a probe module.  Since
    # C++ headers aren't introspectable from Python, we just version-gate.
    return _probe("qset_qmap_headers", lambda: at_least(9, 3))


def has_golang_type_folders() -> bool:
    """9.3: Hierarchical package-path organization for recovered Go types."""
    return _probe("golang_type_folders", lambda: at_least(9, 3))


def has_dart_classifier() -> bool:
    """Whether the BehaviorClassifier knows about Dart/Flutter patterns.

    This is an MCP-side feature flag, not a 9.3 SDK one — exposed here so
    tool code has one place to consult.
    """
    return _probe(
        "dart_classifier",
        lambda: _module_attr("ida_pro_mcp.ida_mcp.tools.search", "intelligence", "DART_ANCHORS")
        is not None,
    )


# ----- Generic helpers -----


def _module_importable(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


def _module_attr(*names: str) -> Any:
    """Resolve a dotted attribute path; return None if any link is missing."""
    obj: Any = None
    try:
        for n in names:
            if obj is None:
                obj = importlib.import_module(n)
            else:
                obj = getattr(obj, n, None)
                if obj is None:
                    return None
    except Exception:
        return None
    return obj


def _has_idaapi_attr(*path: str) -> bool:
    try:
        import idaapi  # type: ignore[import-not-found]
    except ImportError:
        return False
    obj: Any = idaapi
    for name in path:
        obj = getattr(obj, name, None)
        if obj is None:
            return False
    return True


def _idaapi_const(name: str) -> Any:
    try:
        import idaapi  # type: ignore[import-not-found]
    except ImportError:
        return None
    return getattr(idaapi, name, None)
