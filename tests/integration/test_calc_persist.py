"""
Unit tests for the opt-in calc(persist=True) path.

The new `_calc_persist_capture` function (in `calc.py`) writes both the
LLM's question AND the result to the blackboard. The previous always-on
auto-capture was broken: it captured answers but lost questions, skipped
`eval` entirely, and used the wrong response key for `chain`. These tests
verify the new path actually does what the design intent says.

`_calc_persist_capture` lives in a 950-line module that pulls in the
full IDA SDK at the top. We extract the function by source-slicing and
exec it in a controlled namespace with a fake BlackboardStore.
"""
from __future__ import annotations

import json
import os
import sys
import types
import unittest


def _load_persist_fn():
    """Extract _calc_persist_capture from calc.py by source slicing.

    Strategy: copy the function source into a fresh namespace where
    `BlackboardStore` is a fake that records every write and returns
    `False` for every `exists_similar` call. Inject a `json` symbol into
    the namespace so the function can use it.
    """
    src_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "src", "ida_pro_mcp", "ida_mcp", "tools", "calc.py",
    )
    src_path = os.path.normpath(src_path)
    with open(src_path, encoding="utf-8") as f:
        text = f.read()
    lines = text.split("\n")

    start = None
    for i, line in enumerate(lines):
        if line.startswith("def _calc_persist_capture("):
            start = i
            break
    if start is None:
        raise RuntimeError("_calc_persist_capture not found in calc.py")

    def_indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= def_indent:
            end = i
            break

    func_src = "\n".join(lines[start:end])

    captured_writes: list = []
    exists_calls: list = []

    class FakeStore:
        def __init__(self, *a, **kw):
            pass

        def exists_similar(self, addr, category, title):
            exists_calls.append((addr, category, title))
            return False

        def write(self, **kw):
            captured_writes.append(kw)
            return "fake-id-" + str(len(captured_writes))

    # Strip the `from .blackboard import BlackboardStore` block — we
    # inject the symbol directly into the namespace so the test can
    # substitute a fake.
    src_lines = func_src.split("\n")
    cleaned: list = []
    i = 0
    while i < len(src_lines):
        line = src_lines[i]
        if "from .blackboard import BlackboardStore" in line:
            # skip this line and any except/import branches for it
            i += 1
            while i < len(src_lines):
                nxt = src_lines[i].strip()
                if nxt.startswith("except") or nxt.startswith("try:"):
                    i += 1
                    continue
                if nxt.startswith("from blackboard") or nxt.startswith("return"):
                    i += 1
                    continue
                break
            continue
        cleaned.append(line)
        i += 1
    func_src = "\n".join(cleaned)

    func_globals = {
        "__builtins__": __builtins__,
        "BlackboardStore": FakeStore,
        "json": json,
    }
    exec(compile(func_src, "<calc._calc_persist_capture>", "exec"),
         func_globals)
    return func_globals["_calc_persist_capture"], captured_writes, exists_calls


# Module-level state so the FakeStore is per-test (each test creates fresh
# lists). The function is loaded once at import time and bound to a fresh
# FakeStore via the closure variables.
_fn, _W, _E = _load_persist_fn()


def _reset():
    """Return the function and reset the captured lists for a fresh test."""
    _W.clear()
    _E.clear()
    return _fn


class TestPersistEval(unittest.TestCase):
    """The action the old auto-capture silently skipped."""

    def test_eval_writes_question_and_answer(self):
        fn = _reset()
        fn(
            input_summary={"action": "eval", "expr": "0x401000 + 0x100"},
            result={"ok": True, "expr": "0x401000 + 0x100", "value": 0x401100},
            action="eval",
        )
        self.assertEqual(len(_W), 1)
        w = _W[0]
        self.assertIn("0x401000 + 0x100", w["title"])
        self.assertIn("0x401100", w["title"])
        self.assertEqual(w["category"], "calc_eval")
        self.assertIn("calc", w["tags"])
        self.assertIn("persist", w["tags"])
        content = json.loads(w["content"])
        self.assertEqual(content["expr"], "0x401000 + 0x100")
        self.assertEqual(content["value"], 0x401100)

    def test_eval_no_question_no_write(self):
        fn = _reset()
        fn(
            input_summary={"action": "eval", "expr": None},
            result={"ok": True, "value": 0x401100},
            action="eval",
        )
        self.assertEqual(_W, [])

    def test_eval_no_answer_no_write(self):
        fn = _reset()
        fn(
            input_summary={"action": "eval", "expr": "0x401000+0x100"},
            result={"ok": True, "value": None},
            action="eval",
        )
        self.assertEqual(_W, [])


class TestPersistResolve(unittest.TestCase):
    """The action the old auto-capture mangled by losing the offset suffix."""

    def test_resolve_writes_question_and_answer(self):
        fn = _reset()
        fn(
            input_summary={
                "action": "resolve",
                "addr": "0x401000+0x1234",
            },
            result={
                "ok": True,
                "va": "0x401234",
                "file_offset": "0x1234",
                "segment": ".text",
                "direction": "va_to_file_offset",
            },
            action="resolve",
        )
        self.assertEqual(len(_W), 1)
        w = _W[0]
        self.assertIn("0x401000+0x1234", w["title"])
        self.assertIn("0x401234", w["title"])
        self.assertEqual(w["addr"], "0x401234")
        content = json.loads(w["content"])
        self.assertEqual(content["addr"], "0x401000+0x1234")
        self.assertEqual(content["va"], "0x401234")

    def test_resolve_falls_back_to_value_arg(self):
        fn = _reset()
        fn(
            input_summary={"action": "resolve", "value": "0x500000"},
            result={"ok": True, "va": "0x401000", "file_offset": "0x1000",
                    "segment": ".text", "direction": "va_to_file_offset"},
            action="resolve",
        )
        self.assertEqual(len(_W), 1)
        self.assertIn("0x500000", _W[0]["title"])


class TestPersistDeref(unittest.TestCase):
    """The one action the old auto-capture actually got right."""

    def test_deref_writes_question_and_answer(self):
        fn = _reset()
        fn(
            input_summary={"action": "deref", "addr": "0x401000"},
            result={"ok": True, "addr": "0x401000", "type": "u32", "value": 0x500000,
                    "value_hex": "0x500000", "depth": 1},
            action="deref",
        )
        self.assertEqual(len(_W), 1)
        w = _W[0]
        self.assertIn("0x401000", w["title"])
        self.assertIn("0x500000", w["title"])
        self.assertEqual(w["addr"], "0x401000")
        content = json.loads(w["content"])
        self.assertEqual(content["addr"], "0x401000")
        self.assertEqual(content["value"], 0x500000)


class TestPersistChain(unittest.TestCase):
    """The action the old auto-capture completely missed (wrong key)."""

    def test_chain_writes_question_and_answer_with_steps(self):
        fn = _reset()
        fn(
            input_summary={
                "action": "chain",
                "addr": "0x401000",
                "offsets": ["0x10", "0x20"],
            },
            result={
                "ok": True,
                "base": "0x401000",
                "offsets": [0x10, 0x20],
                "steps": [
                    {"ptr": "0x500000", "offset": 0x10, "addr": "0x500010"},
                    {"ptr": "0x600000", "offset": 0x20, "addr": "0x600020"},
                ],
                "final": "0x600020",
            },
            action="chain",
        )
        self.assertEqual(len(_W), 1)
        w = _W[0]
        self.assertIn("0x401000", w["title"])
        self.assertIn("0x600020", w["title"])
        content = json.loads(w["content"])
        self.assertEqual(content["addr"], "0x401000")
        self.assertEqual(content["offsets"], ["0x10", "0x20"])
        self.assertEqual(len(content["steps"]), 2)
        self.assertEqual(content["final"], "0x600020")

    def test_chain_handles_string_offsets(self):
        fn = _reset()
        fn(
            input_summary={
                "action": "chain",
                "addr": "0x401000",
                "offsets": "0x10,0x20,0x30",
            },
            result={
                "ok": True,
                "base": "0x401000",
                "offsets": [0x10, 0x20, 0x30],
                "steps": [
                    {"ptr": "0x500000", "offset": 0x10, "addr": "0x500010"},
                    {"ptr": "0x600000", "offset": 0x20, "addr": "0x600020"},
                    {"ptr": "0x700000", "offset": 0x30, "addr": "0x700030"},
                ],
                "final": "0x700030",
            },
            action="chain",
        )
        self.assertEqual(len(_W), 1)
        w = _W[0]
        self.assertIn("0x10", w["title"])
        self.assertIn("0x20", w["title"])
        self.assertIn("0x30", w["title"])


class TestPersistSanity(unittest.TestCase):
    def test_not_ok_no_write(self):
        fn = _reset()
        fn(
            input_summary={"action": "deref", "addr": "0x401000"},
            result={"ok": False, "error": "bad addr"},
            action="deref",
        )
        self.assertEqual(_W, [])

    def test_unknown_action_no_write(self):
        fn = _reset()
        fn(
            input_summary={"action": "bitops", "value": 1, "target": 2, "bit_op": "xor"},
            result={"ok": True, "result": 3},
            action="bitops",
        )
        self.assertEqual(_W, [])

    def test_dedup_calls_exists_similar_before_write(self):
        fn = _reset()
        fn(
            input_summary={"action": "deref", "addr": "0x401000"},
            result={"ok": True, "addr": "0x401000", "value": 0x500000},
            action="deref",
        )
        self.assertEqual(len(_E), 1)
        self.assertEqual(_E[0][0], "0x401000")
        self.assertEqual(_E[0][1], "calc_deref")
        self.assertEqual(len(_W), 1)

    def test_question_preserved_verbatim(self):
        fn = _reset()
        weird_inputs = [
            "0x401000+0x1234",
            "0x401000 - 0x1000",
            "0x401000",
            "main+0x20",
        ]
        for q in weird_inputs:
            fn(
                input_summary={"action": "resolve", "addr": q},
                result={"ok": True, "va": "0x401000", "file_offset": "0x0",
                        "segment": ".text", "direction": "va_to_file_offset"},
                action="resolve",
            )
        self.assertEqual(len(_W), 4)
        titles = [w["title"] for w in _W]
        for q in weird_inputs:
            self.assertTrue(
                any(q in t for t in titles),
                f"question {q!r} lost in titles {titles}",
            )


if __name__ == "__main__":
    unittest.main()
