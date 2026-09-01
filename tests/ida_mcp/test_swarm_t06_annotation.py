"""Regression tests for the t06 annotation audit fixes.

Covers (each maps to a confirmed finding in the t06 audit):
- dry_run is honored by every comment-management action (set_structured,
  bulk_set, import_md) — previously it wrote to the IDB unconditionally.
- The governance engine now intercepts every annotation write path, so PII
  in auto-generated comments (referenced strings, bulk text, imported
  markdown) is redacted before it touches the IDB instead of only being
  surfaced by the advisory `validate` action.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_tool_module

PII_TEXT = "C2 at 192.168.1.1"
REDACTED_TEXT = "C2 at [IP_REDACTED]"


def _install_comment_mocks():
    """Point the shared idc mock at recording comment writers."""
    idc = sys.modules["idc"]
    writes = []
    idc.get_cmt = lambda *a, **kw: ""
    idc.set_cmt = lambda *a, **kw: writes.append(("set_cmt", a))
    idc.get_func_cmt = lambda *a, **kw: ""
    idc.set_func_cmt = lambda *a, **kw: writes.append(("set_func_cmt", a))
    return writes


class TestGovernCommentHelper(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("annotation")

    def test_redacts_pii(self):
        self.assertEqual(self.mod._govern_comment(PII_TEXT), REDACTED_TEXT)

    def test_passes_plain_text_through(self):
        self.assertEqual(self.mod._govern_comment("ordinary comment"), "ordinary comment")

    def test_returns_none_when_blocked(self):
        orig = self.mod.evaluate_operation
        try:
            self.mod.evaluate_operation = lambda *a, **kw: {"approved": False}
            self.assertIsNone(self.mod._govern_comment("anything"))
        finally:
            self.mod.evaluate_operation = orig


class TestBulkSetDryRunAndGovernance(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("annotation")
        self.mod.MCPError.ANNOTATION_ERROR = "ANNOTATION_ERROR"
        self.writes = _install_comment_mocks()

    def test_dry_run_does_not_write(self):
        r = self.mod.annotation(
            action="bulk_set",
            items='[{"addr":"0x401000","text":"hello"},{"addr":"0x401010","text":"world"}]',
            dry_run=True,
        )
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["set_count"], 2)
        self.assertTrue(r["dry_run"])
        self.assertEqual(self.writes, [])

    def test_real_write_redacts_pii(self):
        r = self.mod.annotation(
            action="bulk_set",
            items=(
                f'[{{"addr":"0x401000","text":"{PII_TEXT}"}},'
                f'{{"addr":"0x401010","text":"clean"}}]'
            ),
            dry_run=False,
        )
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["set_count"], 2)
        written = {a[1][0]: a[1][1] for a in self.writes}
        self.assertEqual(written[0x401000], REDACTED_TEXT)
        self.assertEqual(written[0x401010], "clean")
        self.assertNotIn("192.168.1.1", " ".join(written.values()))

    def test_repeatable_and_func_types(self):
        self.mod.annotation(
            action="bulk_set",
            items='[{"addr":"0x401000","text":"r","type":"repeatable"},'
                  '{"addr":"0x401100","text":"f","type":"func"}]',
            dry_run=False,
        )
        self.assertEqual(self.writes, [
            ("set_cmt", (0x401000, "r", 1)),
            ("set_func_cmt", (0x401100, "f", 0)),
        ])

    def test_rejected_write_is_reported_per_item(self):
        self.mod.idc.set_cmt = lambda *a, **kw: False
        r = self.mod.annotation(
            action="bulk_set",
            items='[{"addr":"0x401000","text":"hello"}]',
            dry_run=False,
        )
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["set_count"], 0)
        self.assertEqual(r["error_count"], 1)
        self.assertEqual(r["errors"][0]["error"], "IDA rejected comment write")


class TestSetStructuredDryRunAndGovernance(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("annotation")
        self.mod.MCPError.ANNOTATION_ERROR = "ANNOTATION_ERROR"
        self.writes = _install_comment_mocks()

    def test_dry_run_does_not_write(self):
        r = self.mod.annotation(
            action="set_structured", addr="0x401000", text="note", dry_run=True,
        )
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["dry_run"])
        self.assertEqual(self.writes, [])

    def test_real_write_redacts_pii(self):
        r = self.mod.annotation(
            action="set_structured", addr="0x401000", text=f"note {PII_TEXT}",
            dry_run=False,
        )
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.writes[0][1][1], f"note {REDACTED_TEXT}")

    def test_rejected_write_returns_annotation_error(self):
        self.mod.idc.set_cmt = lambda *a, **kw: False
        r = self.mod.annotation(
            action="set_structured", addr="0x401000", text="note", dry_run=False,
        )
        self.assertTrue(r["error"], r)
        self.assertEqual(r["code"], "ANNOTATION_ERROR")


class TestImportMdDryRunAndGovernance(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module(
            "annotation",
            common_overrides={"validate_path_safe": lambda p, *a, **kw: (p, None)},
        )
        self.mod.MCPError.ANNOTATION_ERROR = "ANNOTATION_ERROR"
        self.writes = _install_comment_mocks()

    def _run(self, dry_run):
        content = f"## f (`0x401000`)\n\n- `0x401000`: {PII_TEXT}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            return self.mod.annotation(action="import_md", path=path, dry_run=dry_run)
        finally:
            os.unlink(path)

    def test_dry_run_does_not_write(self):
        r = self._run(dry_run=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 1)
        self.assertTrue(r["dry_run"])
        self.assertEqual(self.writes, [])

    def test_real_import_redacts_pii(self):
        r = self._run(dry_run=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 1)
        self.assertEqual(self.writes[0][1][1], REDACTED_TEXT)
        self.assertNotIn("192.168.1.1", self.writes[0][1][1])

    def test_rejected_write_is_not_counted_as_imported(self):
        self.mod.idc.set_cmt = lambda *a, **kw: False
        r = self._run(dry_run=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 0)
        self.assertEqual(r["error_count"], 1)
        self.assertEqual(r["errors"][0]["error"], "IDA rejected comment write")


class TestAutoCommentGovernance(unittest.TestCase):
    def setUp(self):
        self.mod = load_tool_module("annotation")
        self.mod.MCPError.ANNOTATION_ERROR = "ANNOTATION_ERROR"
        self.writes = _install_comment_mocks()
        idc = sys.modules["idc"]
        idaapi = sys.modules["idaapi"]
        idautils = sys.modules["idautils"]
        idc.print_insn_mnem = lambda ea: "LEA"
        idc.get_str_type = lambda ea: 2
        idc.get_strlit_contents = lambda *a, **kw: PII_TEXT.encode()
        idc.get_operand_value = lambda ea, op: 0
        idc.get_func_name = lambda ea: ""
        idc.get_name = lambda ea: ""
        idautils.DataRefsFrom = lambda ea: [0x6000]
        idautils.CodeRefsFrom = lambda ea, f: iter([])
        idaapi.get_func = lambda ea: None

    def test_string_ref_pii_is_redacted_before_write(self):
        r = self.mod.annotation(action="auto_comment", addr="0x401000", dry_run=False)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["count"], 1)
        self.assertEqual(len(self.writes), 1)
        written = self.writes[0][1][1]
        self.assertIn("[IP_REDACTED]", written)
        self.assertNotIn("192.168.1.1", written)

    def test_dry_run_does_not_write(self):
        r = self.mod.annotation(action="auto_comment", addr="0x401000", dry_run=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.writes, [])

    def test_rejected_write_returns_annotation_error(self):
        self.mod.idc.set_cmt = lambda *a, **kw: False
        r = self.mod.annotation(action="auto_comment", addr="0x401000", dry_run=False)
        self.assertTrue(r["error"], r)
        self.assertEqual(r["code"], "ANNOTATION_ERROR")


if __name__ == "__main__":
    unittest.main()
