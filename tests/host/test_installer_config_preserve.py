"""Regression tests for installer config-update silent-wipe.

Before the fix, when a user's MCP config file contained comments (// or /* */),
trailing commas, or any other JSONC/JSON5 syntax, the installer's
``_load_json_config`` would raise ``JSONDecodeError`` and silently fall back to
``{}``. The subsequent ``path.write_text`` call then overwrote the user's
config with only the new server entry, destroying every other setting.

These tests assert the new contract:

  * Permissive JSONC/JSON5 syntax is accepted and preserved on write-back.
  * Truly unparseable files cause the update to return ``False``, leave the
    file untouched, and log a clear error on the ``InstallReport``.
  * URLs and other "looks like a comment" content inside JSON strings is not
    treated as a comment.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from ida_pro_mcp.installer.clients import (
    ConfigParseError,
    _load_json_config,
    _strip_jsonc_comments,
    update_json_config,
    update_toml_config,
)
from ida_pro_mcp.installer.common import InstallReport


class TestStripJsoncComments(unittest.TestCase):
    def test_line_comments_removed(self):
        out = _strip_jsonc_comments('// hi\n{"a": 1}\n// bye')
        self.assertEqual(out, '\n{"a": 1}\n')

    def test_block_comments_removed(self):
        out = _strip_jsonc_comments('/* hi */ {"a": /* mid */ 1} /* tail */')
        self.assertEqual(out, ' {"a":  1} ')

    def test_trailing_commas_removed(self):
        out = _strip_jsonc_comments('{"a": [1, 2, 3,], "b": {"c": 1,},}')
        self.assertEqual(out, '{"a": [1, 2, 3], "b": {"c": 1}}')

    def test_slash_inside_string_preserved(self):
        out = _strip_jsonc_comments('{"url": "https://example.com/x"}')
        self.assertIn('https://example.com/x', out)
        # And round-trips through json.loads.
        import json
        self.assertEqual(json.loads(out), {"url": "https://example.com/x"})

    def test_block_comment_marker_inside_string_preserved(self):
        out = _strip_jsonc_comments('{"msg": "use /* not a comment */ here"}')
        import json
        self.assertEqual(json.loads(out), {"msg": "use /* not a comment */ here"})

    def test_escaped_quote_does_not_close_string(self):
        out = _strip_jsonc_comments(r'{"msg": "he said \"// not a comment\""}')
        import json
        self.assertEqual(json.loads(out), {"msg": 'he said "// not a comment"'})

    def test_single_quoted_strings_handled(self):
        out = _strip_jsonc_comments("{'a': 1, 'b': 2,}")
        import json
        # json.loads does not support single quotes; this stays invalid JSON
        # but the stripper must not corrupt the structure.
        self.assertIn("'a'", out)


class TestLoadJsonConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file_returns_empty(self):
        self.assertEqual(_load_json_config(self.tmp / "nope.json"), {})

    def test_empty_file_returns_empty(self):
        p = self.tmp / "empty.json"
        p.write_text("")
        self.assertEqual(_load_json_config(p), {})

    def test_strict_json(self):
        p = self.tmp / "ok.json"
        p.write_text('{"a": 1, "b": [2, 3]}')
        self.assertEqual(_load_json_config(p), {"a": 1, "b": [2, 3]})

    def test_jsonc_with_line_comment(self):
        p = self.tmp / "jsonc.json"
        p.write_text('// header\n{"a": 1, /* mid */ "b": 2}\n// trailer\n')
        self.assertEqual(_load_json_config(p), {"a": 1, "b": 2})

    def test_jsonc_with_trailing_comma(self):
        p = self.tmp / "tc.json"
        p.write_text('{"a": 1, "b": [1, 2,],}')
        self.assertEqual(_load_json_config(p), {"a": 1, "b": [1, 2]})

    def test_truly_broken_raises(self):
        p = self.tmp / "broken.json"
        p.write_text('{"a": 1, broken"\n}')
        with self.assertRaises(ConfigParseError) as ctx:
            _load_json_config(p)
        self.assertIn("Could not parse", str(ctx.exception))
        self.assertIn("Fix the syntax", str(ctx.exception))

    def test_scalar_top_level_is_rejected(self):
        p = self.tmp / "scalar.json"
        p.write_text("[]")
        with self.assertRaises(ConfigParseError) as ctx:
            _load_json_config(p)
        self.assertIn("top-level JSON object", str(ctx.exception))


class TestUpdateJsonConfigPreservesUserData(unittest.TestCase):
    """The original bug: installer wiped user config when JSONC syntax was present."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_report(self):
        return InstallReport()

    def test_preserves_existing_keys_with_line_comment(self):
        p = self.tmp / "user.json"
        p.write_text(
            '// my MCP config\n'
            '{\n'
            '  // top-level settings\n'
            '  "theme": "dark",\n'
            '  "mcpServers": {\n'
            '    "other-server": {"command": "x"}\n'
            '  }\n'
            '}\n'
        )
        original = p.read_text()
        report = self._make_report()
        ok = update_json_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertTrue(ok)
        self.assertEqual(report.errors, [])
        new = p.read_text()
        # Existing top-level key preserved.
        self.assertIn('"theme": "dark"', new)
        # Existing sibling server preserved.
        self.assertIn('"other-server"', new)
        # New server added.
        self.assertIn('"ida-pro-mcp"', new)
        # Ensure the original file would have been wiped before the fix.
        self.assertNotEqual(original, new)

    def test_preserves_existing_keys_with_trailing_comma(self):
        p = self.tmp / "user.json"
        p.write_text(
            '{\n'
            '  "theme": "dark",\n'
            '  "mcpServers": {\n'
            '    "other": {"command": "x"},\n'
            '  },\n'
            '}\n'
        )
        report = self._make_report()
        ok = update_json_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertTrue(ok)
        new = p.read_text()
        self.assertIn('"theme": "dark"', new)
        self.assertIn('"other"', new)
        self.assertIn('"ida-pro-mcp"', new)

    def test_preserves_url_inside_string(self):
        p = self.tmp / "user.json"
        p.write_text('{"url": "https://x/y", "theme": "dark"}')
        report = self._make_report()
        ok = update_json_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertTrue(ok)
        self.assertIn("https://x/y", p.read_text())

    def test_unparseable_file_left_untouched(self):
        p = self.tmp / "broken.json"
        original = '{\n  "theme": "dark,\n  broken"\n}\n'
        p.write_text(original)
        report = self._make_report()
        ok = update_json_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertFalse(ok)
        # File must NOT be modified.
        self.assertEqual(p.read_text(), original)
        # Error must be reported.
        self.assertEqual(len(report.errors), 1)
        self.assertIn("Could not parse", report.errors[0])
        # modified_files must NOT include this path.
        self.assertNotIn(str(p), report.modified_files)

    def test_wrong_server_container_type_left_untouched(self):
        for value in ("[]", "null"):
            p = self.tmp / f"wrong-container-{value[:2]}.json"
            original = f'{{"theme": "dark", "mcpServers": {value}}}\n'
            p.write_text(original)
            report = self._make_report()

            ok = update_json_config(
                p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
            )

            self.assertFalse(ok)
            self.assertEqual(p.read_text(), original)
            self.assertEqual(len(report.errors), 1)
            self.assertIn("must be an object", report.errors[0])
            self.assertNotIn(str(p), report.modified_files)


class TestUpdateTomlConfigPreservesUserData(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_preserves_existing_sections(self):
        p = self.tmp / "user.toml"
        p.write_text(
            'theme = "dark"\n\n'
            '[mcp_servers]\n'
            'other = { command = "x" }\n\n'
            '[user]\n'
            'key = "val"\n'
        )
        report = InstallReport()
        ok = update_toml_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertTrue(ok)
        new = p.read_text()
        self.assertIn('theme = "dark"', new)
        self.assertIn("[mcp_servers.other]", new)
        self.assertIn("[user]", new)
        self.assertIn("[mcp_servers.ida-pro-mcp]", new)

    def test_unparseable_file_left_untouched(self):
        p = self.tmp / "broken.toml"
        original = 'theme = "dark\nmcp_servers = { invalid = }\n'
        p.write_text(original)
        report = InstallReport()
        ok = update_toml_config(
            p, "ida-pro-mcp", {"command": "y"}, report, dry_run=False
        )
        self.assertFalse(ok)
        self.assertEqual(p.read_text(), original)
        self.assertEqual(len(report.errors), 1)
        self.assertIn("Could not parse", report.errors[0])
        self.assertNotIn(str(p), report.modified_files)


if __name__ == "__main__":
    unittest.main()
