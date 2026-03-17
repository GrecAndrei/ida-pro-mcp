#!/usr/bin/env python3
"""
Regression tests for funcs tool sync-mode routing.
"""

import ast
import unittest
from pathlib import Path


FUNCS_TOOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "tools"
    / "funcs.py"
)


def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class TestFuncsSyncRouting(unittest.TestCase):
    def setUp(self):
        self.module = ast.parse(FUNCS_TOOL_PATH.read_text(encoding="utf-8"))

    def test_funcs_has_read_and_write_dispatch_helpers(self):
        read_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "_funcs_read_dispatch"),
            None,
        )
        write_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "_funcs_write_dispatch"),
            None,
        )
        self.assertIsNotNone(read_fn)
        self.assertIsNotNone(write_fn)
        self.assertIn("idaread", {_decorator_name(d) for d in read_fn.decorator_list})
        self.assertIn("idawrite", {_decorator_name(d) for d in write_fn.decorator_list})
        for fn in (read_fn, write_fn):
            self.assertEqual(len(fn.body), 1)
            self.assertIsInstance(fn.body[0], ast.Return)
            call = fn.body[0].value
            self.assertIsInstance(call, ast.Call)
            self.assertIsInstance(call.func, ast.Name)
            self.assertEqual(call.func.id, "_funcs_impl")
            self.assertTrue(any(kw.arg is None for kw in call.keywords))

    def test_funcs_routes_list_and_info_to_read_dispatch(self):
        funcs_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "funcs"),
            None,
        )
        self.assertIsNotNone(funcs_fn)
        decorators = {_decorator_name(d) for d in funcs_fn.decorator_list}
        self.assertIn("tool", decorators)
        self.assertNotIn("idawrite", decorators)

        if_stmt = next(
            (
                n
                for n in funcs_fn.body
                if isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name)
                and n.test.left.id == "normalized_action"
                and len(n.test.ops) == 1
                and isinstance(n.test.ops[0], ast.In)
            ),
            None,
        )
        self.assertIsNotNone(if_stmt)

        test_expr = if_stmt.test
        self.assertIsInstance(test_expr, ast.Compare)
        self.assertIsInstance(test_expr.left, ast.Name)
        self.assertEqual(test_expr.left.id, "normalized_action")
        self.assertEqual(len(test_expr.ops), 1)
        self.assertIsInstance(test_expr.ops[0], ast.In)
        self.assertEqual(len(test_expr.comparators), 1)
        self.assertIsInstance(test_expr.comparators[0], ast.Tuple)
        values = [
            elt.value
            for elt in test_expr.comparators[0].elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
        self.assertEqual(values, ["list", "info"])

        self.assertEqual(len(if_stmt.body), 1)
        self.assertIsInstance(if_stmt.body[0], ast.Return)
        self.assertIsInstance(if_stmt.body[0].value, ast.Call)
        self.assertIsInstance(if_stmt.body[0].value.func, ast.Name)
        self.assertEqual(if_stmt.body[0].value.func.id, "_funcs_read_dispatch")
        self.assertTrue(any(kw.arg is None for kw in if_stmt.body[0].value.keywords))

        trailing_return = funcs_fn.body[-1]
        self.assertIsInstance(trailing_return, ast.Return)
        self.assertIsInstance(trailing_return.value, ast.Call)
        self.assertIsInstance(trailing_return.value.func, ast.Name)
        self.assertEqual(trailing_return.value.func.id, "_funcs_write_dispatch")
        self.assertTrue(any(kw.arg is None for kw in trailing_return.value.keywords))


if __name__ == "__main__":
    unittest.main()
