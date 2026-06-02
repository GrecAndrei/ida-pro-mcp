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

    def test_funcs_no_longer_has_read_and_write_dispatch_helpers(self):
        """Step 7: the read/write dispatch helpers were removed; the
        `funcs` tool now calls `_funcs_impl` directly."""
        names = {
            n.name
            for n in self.module.body
            if isinstance(n, ast.FunctionDef)
        }
        self.assertNotIn("_funcs_read_dispatch", names)
        self.assertNotIn("_funcs_write_dispatch", names)
        # And `_funcs_impl` is still the implementation backbone.
        self.assertIn("_funcs_impl", names)

    def test_funcs_calls_impl_directly(self):
        """The `funcs` tool body ends with a single direct call to
        `_funcs_impl`, with no read/write routing."""
        funcs_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "funcs"),
            None,
        )
        self.assertIsNotNone(funcs_fn)
        decorators = {_decorator_name(d) for d in funcs_fn.decorator_list}
        self.assertIn("tool", decorators)
        # The trailing return is a direct call to _funcs_impl.
        trailing = funcs_fn.body[-1]
        self.assertIsInstance(trailing, ast.Return)
        self.assertIsInstance(trailing.value, ast.Call)
        self.assertIsInstance(trailing.value.func, ast.Name)
        self.assertEqual(trailing.value.func.id, "_funcs_impl")
        # No `if normalized_action in (...)` routing remains.
        for n in funcs_fn.body:
            self.assertFalse(
                isinstance(n, ast.If)
                and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name)
                and n.test.left.id == "normalized_action",
                "funcs() still has a normalized_action routing block",
            )

    def test_funcs_no_longer_owns_rename_comment_or_list_actions(self):
        """The four write/lookup actions previously living on `funcs`
        were migrated to their canonical homes:
          - set_name, rename  -> modify(action="rename")
          - add_comment       -> modify(action="comment")
          - list              -> data(action="functions")
        Both the public `funcs` tool and the internal `_funcs_impl`
        Literal must reflect the smaller surface, and the action
        branches must be gone from the implementation."""
        funcs_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "funcs"),
            None,
        )
        impl_fn = next(
            (n for n in self.module.body if isinstance(n, ast.FunctionDef) and n.name == "_funcs_impl"),
            None,
        )
        self.assertIsNotNone(funcs_fn)
        self.assertIsNotNone(impl_fn)

        def _literal_values(fn: ast.FunctionDef) -> set[str]:
            """Find the Literal[...] annotation on the first parameter and
            return the set of allowed string values."""
            for arg in fn.args.args:
                if arg.annotation is None:
                    continue
                ann = arg.annotation
                # PEP 604 union: Literal | None, etc. — collect all Subscript
                # nodes whose value is a Name('Literal').
                values: set[str] = set()
                for node in ast.walk(ann):
                    if (
                        isinstance(node, ast.Subscript)
                        and isinstance(node.value, ast.Name)
                        and node.value.id == "Literal"
                        and isinstance(node.slice, ast.Tuple)
                    ):
                        for elt in node.slice.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                values.add(elt.value)
                if values:
                    return values
            return set()

        outer = _literal_values(funcs_fn)
        inner = _literal_values(impl_fn)
        for removed in ("set_name", "rename", "add_comment", "list"):
            self.assertNotIn(removed, outer, f"funcs Literal still allows {removed!r}")
            self.assertNotIn(removed, inner, f"_funcs_impl Literal still allows {removed!r}")

        # The action branches for the removed actions must not appear in
        # the implementation as `elif action == "<removed>":`.
        removed_branches: set[str] = set()
        for node in ast.walk(impl_fn):
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Eq)
                and isinstance(node.left, ast.Name)
                and node.left.id == "action"
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and isinstance(node.comparators[0].value, str)
            ):
                removed_branches.add(node.comparators[0].value)
        for removed in ("set_name", "add_comment", "list"):
            self.assertNotIn(
                removed,
                removed_branches,
                f"_funcs_impl still has an `action == {removed!r}` branch",
            )


if __name__ == "__main__":
    unittest.main()
