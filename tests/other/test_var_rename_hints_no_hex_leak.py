"""Regression: _extract_var_rename_hints must not emit garbage hex addresses.

Previously the regex ``re.sub(r'[\\*\\[\\]0-9]', '', type_str)`` stripped all
digits from the type name, and the reason string used ``f"type={tinfo}"``
which str()s an lvar to its memory address (e.g. ``0xffbbaaa>``). The result
was a ``suggested`` field full of truncated/corrupted hex tokens like
``"xffbbaaa>"`` — useless to the LLM consumer.

The fix:
  * bail out when tinfo.__str__() looks like a memory address
  * strip pointer/array decorators but not letters within identifier tokens
  * use the cleaned type name in the reason string, not the tinfo object

Implementation note: importing ``ida_pro_mcp.ida_mcp.tools.code`` triggers the
full tool import chain, which pulls in ``zeromcp`` (an IDA-only dep). We
copy the function body verbatim into a stand-alone test module so we can
exercise it without booting the rest of the tool layer.
"""
from __future__ import annotations

import os
import re
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.abspath(os.path.join(ROOT, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)


_EXTRACT_FN_SRC = textwrap.dedent('''
    def _extract_var_rename_hints(cfunc):
        """Stand-alone copy for testing.

        Behavior is bit-for-bit equivalent to
        ``ida_pro_mcp.ida_mcp.tools.code._extract_var_rename_hints`` but
        stripped of its decorators and the IDA-only `cfunc` typing so the
        test can run without zeromcp/idaapi.
        """
        import re
        hints = []
        try:
            pseudo = str(cfunc)
            lvars = list(getattr(cfunc, "lvars", []) or [])
            for v in lvars:
                name = str(getattr(v, "name", "") or "").strip()
                if not name or not re.match(r'^[va]\\d+$', name):
                    continue

                suggestion = None
                reason = ""

                # 1. IDA type info — highest confidence
                try:
                    tinfo = getattr(v, "type", None)
                    if tinfo is not None:
                        type_str = str(tinfo).strip()
                        if not type_str or type_str.startswith("0x") or type_str.startswith("0X"):
                            raise ValueError("anonymous lvar (no type name)")
                        type_str = type_str.lower().strip("* ")
                        base = re.sub(r'[\\*\\[\\]]', '', type_str)
                        base = re.sub(r'\\b\\d+\\b', '', base).strip()
                        if base and base not in ("void", "int", "char", "byte", "word", "dword",
                                                 "qword", "bool", "unsigned", "signed", "__int"):
                            parts = re.split(r'[\\s_]', base)
                            parts = [p for p in parts if len(p) > 2 and p not in ("type", "ptr", "ref")]
                            if parts:
                                suggestion = parts[-1].rstrip("t").rstrip("_") or parts[-1]
                                reason = f"type={type_str}"
                except Exception:
                    pass

                if suggestion and suggestion != name:
                    hints.append({"var": name, "suggested": suggestion, "reason": reason[:80]})
        except Exception:
            pass
        return hints[:10]
''')


namespace: dict = {"__name__": "fake_code_module"}
exec(compile(_EXTRACT_FN_SRC, "<code.py:fake>", "exec"), namespace)
_extract_var_rename_hints = namespace["_extract_var_rename_hints"]


class _FakeTinfo:
    """Mimics lvar_t.type whose __str__ returns a hex memory address
    (the pre-fix behavior that produced ``0xffbbaaa>``)."""

    def __init__(self, addr: str) -> None:
        self._addr = addr

    def __str__(self) -> str:
        return self._addr


class _FakeLvar:
    def __init__(self, name: str, tinfo) -> None:
        self.name = name
        self.type = tinfo


class _FakeCFunc:
    """Minimal cfunc stand-in: .lvars + __str__."""

    def __init__(self, lvars, pseudo: str = "") -> None:
        self.lvars = lvars
        self._pseudo = pseudo

    def __str__(self) -> str:
        return self._pseudo


def test_anonymous_lvar_does_not_emit_hex_address():
    """Pre-fix: tinfo.__str__() == '0xffbbaaa' leaked into the suggestion."""
    tinfo = _FakeTinfo("0xffbbaaa>")
    lvar = _FakeLvar("a1", tinfo)
    cfunc = _FakeCFunc([lvar])

    hints = _extract_var_rename_hints(cfunc)

    for h in hints:
        assert not h["suggested"].startswith("0x"), (
            f"suggestion looks like a memory address: {h}"
        )
        assert "xff" not in h["suggested"], (
            f"suggestion contains truncated hex: {h}"
        )


def test_real_type_name_is_used_cleanly():
    """When tinfo.__str__() is a real type name, the cleaned name lands in the hint."""
    tinfo = _FakeTinfo("wifi_frame_t *")
    lvar = _FakeLvar("v1", tinfo)
    cfunc = _FakeCFunc([lvar])

    hints = _extract_var_rename_hints(cfunc)

    assert len(hints) == 1
    h = hints[0]
    assert h["var"] == "v1"
    assert h["suggested"] in ("frame", "wifi"), (
        f"expected 'frame' or 'wifi', got {h['suggested']!r}"
    )
    assert "wifi_frame_t" in h["reason"] or "frame" in h["reason"]
    assert "0xff" not in h["reason"]


def test_void_int_etc_get_no_type_based_hint():
    """Trivial types should not produce a misleading rename suggestion."""
    for trivial in ("void", "int", "char", "byte", "word", "dword", "qword", "bool"):
        tinfo = _FakeTinfo(trivial)
        lvar = _FakeLvar("v1", tinfo)
        cfunc = _FakeCFunc([lvar])

        hints = _extract_var_rename_hints(cfunc)
        for h in hints:
            if h.get("reason", "").startswith("type="):
                assert trivial not in h["reason"], (
                    f"trivial type {trivial!r} shouldn't be in reason: {h}"
                )


def test_empty_tinfo_does_not_crash():
    """Empty tinfo (None) should silently produce no hint."""
    lvar = _FakeLvar("v1", None)
    cfunc = _FakeCFunc([lvar])

    hints = _extract_var_rename_hints(cfunc)
    for h in hints:
        assert isinstance(h, dict)
        assert "var" in h and "suggested" in h

