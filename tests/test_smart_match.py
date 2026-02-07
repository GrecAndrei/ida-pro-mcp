#!/usr/bin/env python3
"""
Unit tests for _is_regex, smart_match, compile_smart_pattern, and pattern_filter.
Also tests regex-aware SessionManager and BookmarkManager filtering.

These tests run standalone without IDA Pro.
"""
import os
import sys
import json
import re
import fnmatch
import tempfile
import shutil
import unittest

# ---- Inline the functions under test (they are pure-Python, no IDA deps) ----

def _is_regex(pattern: str) -> bool:
    if not pattern:
        return False
    if pattern.startswith("/") and pattern.count("/") >= 2:
        return True
    _REGEX_INDICATORS = (
        r"\d", r"\w", r"\s", r"\b", r"\D", r"\W", r"\S", r"\B",
        r"\A", r"\Z",
    )
    for ind in _REGEX_INDICATORS:
        if ind in pattern:
            return True
    if re.search(r"\\[.^$*+?{}()|[\]\\]", pattern):
        return True
    _REGEX_META = set("^$+{}()|")
    if _REGEX_META.intersection(pattern):
        return True
    if re.search(r"\[.+\]", pattern):
        return True
    if re.search(r".\{[0-9]", pattern):
        return True
    return False


def compile_smart_pattern(pattern, case_sensitive=False):
    if not pattern:
        return lambda _text: True
    regex = None
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1:]
        flags = 0
        for ch in flag_str:
            if ch == "i": flags |= re.IGNORECASE
            elif ch == "m": flags |= re.MULTILINE
            elif ch == "s": flags |= re.DOTALL
        try:
            regex = re.compile(body, flags or (0 if case_sensitive else re.IGNORECASE))
        except re.error:
            regex = None
    elif _is_regex(pattern):
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error:
            regex = None
    if regex is not None:
        return lambda _text, _re=regex: bool(_re.search(_text))
    if "*" in pattern or "?" in pattern:
        pat_lower = pattern.lower()
        return lambda _text, _p=pat_lower: fnmatch.fnmatch(_text.lower(), _p)
    if case_sensitive:
        return lambda _text, _p=pattern: _p in _text
    else:
        pat_lower = pattern.lower()
        return lambda _text, _p=pat_lower: _p in _text.lower()


def smart_match(pattern, text, case_sensitive=False):
    return compile_smart_pattern(pattern, case_sensitive)(text)


def pattern_filter(data, pattern, key):
    if not pattern:
        return data
    matcher = compile_smart_pattern(pattern)
    def get_value(item):
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)
    return [item for item in data if matcher(get_value(item))]


# ---- Import session/bookmark managers (no IDA deps) ----
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ida_mcp_stdio import SessionManager, BookmarkManager


class TestIsRegex(unittest.TestCase):
    """Test _is_regex detection."""

    def test_plain_strings_not_regex(self):
        self.assertFalse(_is_regex(""))
        self.assertFalse(_is_regex("hello"))
        self.assertFalse(_is_regex("malloc"))
        self.assertFalse(_is_regex("some_function_name"))
        self.assertFalse(_is_regex("CreateFileW"))

    def test_glob_only_not_regex(self):
        # Glob wildcards alone should not be detected as regex
        self.assertFalse(_is_regex("*alloc*"))
        self.assertFalse(_is_regex("sub_*"))
        self.assertFalse(_is_regex("func?"))

    def test_explicit_regex_syntax(self):
        self.assertTrue(_is_regex("/pattern/"))
        self.assertTrue(_is_regex("/hello.*/i"))
        self.assertTrue(_is_regex("/^start/"))

    def test_auto_detect_backslash_sequences(self):
        self.assertTrue(_is_regex(r"\d+"))
        self.assertTrue(_is_regex(r"\w+alloc"))
        self.assertTrue(_is_regex(r"foo\s+bar"))
        self.assertTrue(_is_regex(r"\bword\b"))

    def test_auto_detect_anchors(self):
        self.assertTrue(_is_regex("^start"))
        self.assertTrue(_is_regex("end$"))
        self.assertTrue(_is_regex("^exact$"))

    def test_auto_detect_quantifiers(self):
        self.assertTrue(_is_regex("a+"))
        self.assertTrue(_is_regex("(foo|bar)"))
        self.assertTrue(_is_regex("a{2,4}"))

    def test_auto_detect_alternation(self):
        self.assertTrue(_is_regex("malloc|calloc"))
        self.assertTrue(_is_regex("(read|write)"))

    def test_auto_detect_character_class(self):
        self.assertTrue(_is_regex("[a-z]"))
        self.assertTrue(_is_regex("[0-9A-F]+"))

    def test_auto_detect_escaped_metachar(self):
        self.assertTrue(_is_regex(r"\.exe"))
        self.assertTrue(_is_regex(r"foo\.bar"))
        self.assertTrue(_is_regex(r"\(test\)"))


class TestSmartMatch(unittest.TestCase):
    """Test smart_match with various patterns."""

    def test_plain_substring(self):
        self.assertTrue(smart_match("hello", "say hello world"))
        self.assertFalse(smart_match("hello", "say GOODBYE"))

    def test_plain_substring_case_insensitive(self):
        self.assertTrue(smart_match("hello", "say HELLO world"))
        self.assertFalse(smart_match("hello", "say HELLO world", case_sensitive=True))

    def test_glob_matching(self):
        self.assertTrue(smart_match("*alloc*", "my_malloc_wrapper"))
        self.assertTrue(smart_match("sub_*", "sub_12345"))
        self.assertFalse(smart_match("sub_*", "main"))

    def test_regex_anchors(self):
        self.assertTrue(smart_match("^init", "init_module"))
        self.assertFalse(smart_match("^init", "module_init"))

    def test_regex_alternation(self):
        self.assertTrue(smart_match("malloc|calloc", "uses malloc here"))
        self.assertTrue(smart_match("malloc|calloc", "uses calloc here"))
        self.assertFalse(smart_match("malloc|calloc", "uses realloc here"))

    def test_regex_backslash_sequences(self):
        self.assertTrue(smart_match(r"\d+", "func_123"))
        self.assertFalse(smart_match(r"\d+", "no_digits"))

    def test_explicit_regex_syntax(self):
        self.assertTrue(smart_match("/^func/", "func_main"))
        self.assertFalse(smart_match("/^func/", "main_func"))

    def test_explicit_regex_with_flags(self):
        self.assertTrue(smart_match("/HELLO/i", "hello world"))
        # /HELLO/ with no flags defaults to case-insensitive in our implementation
        self.assertTrue(smart_match("/HELLO/", "hello world"))

    def test_empty_pattern_matches_all(self):
        self.assertTrue(smart_match("", "anything"))

    def test_invalid_regex_falls_back(self):
        # Invalid regex should fall back to substring matching
        self.assertTrue(smart_match("[invalid", "has [invalid bracket"))
        self.assertFalse(smart_match("[invalid", "no match here"))


class TestCompileSmartPattern(unittest.TestCase):
    """Test compile_smart_pattern returns a reusable callable."""

    def test_callable_reuse(self):
        matcher = compile_smart_pattern("^init")
        self.assertTrue(matcher("init_module"))
        self.assertTrue(matcher("init_system"))
        self.assertFalse(matcher("module_init"))

    def test_empty_pattern(self):
        matcher = compile_smart_pattern("")
        self.assertTrue(matcher("anything"))

    def test_case_sensitive(self):
        matcher = compile_smart_pattern("Hello", case_sensitive=True)
        self.assertTrue(matcher("Hello World"))
        self.assertFalse(matcher("hello world"))


class TestPatternFilter(unittest.TestCase):
    """Test pattern_filter on list of dicts."""

    def test_no_pattern_returns_all(self):
        data = [{"name": "a"}, {"name": "b"}]
        self.assertEqual(pattern_filter(data, "", "name"), data)

    def test_substring_filter(self):
        data = [{"name": "malloc"}, {"name": "calloc"}, {"name": "free"}]
        result = pattern_filter(data, "alloc", "name")
        self.assertEqual(len(result), 2)

    def test_regex_filter(self):
        data = [{"name": "init_a"}, {"name": "init_b"}, {"name": "a_init"}]
        result = pattern_filter(data, "^init", "name")
        self.assertEqual(len(result), 2)

    def test_glob_filter(self):
        data = [{"name": "sub_123"}, {"name": "main"}, {"name": "sub_abc"}]
        result = pattern_filter(data, "sub_*", "name")
        self.assertEqual(len(result), 2)


class TestSessionManagerFiltering(unittest.TestCase):
    """Test SessionManager.discover_sessions with query filtering."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        # Create some test sessions (requires a file to exist for binary_path validation,
        # but SessionManager.create_session doesn't check)
        self.mgr.create_session("/tmp/test/binary_alpha.exe")
        self.mgr.create_session("/tmp/test/binary_beta.dll")
        self.mgr.create_session("/tmp/test/malware_sample.bin")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_query_returns_all(self):
        result = self.mgr.discover_sessions()
        self.assertEqual(len(result), 3)

    def test_substring_filter(self):
        result = self.mgr.discover_sessions(query="binary")
        self.assertEqual(len(result), 2)

    def test_regex_filter(self):
        result = self.mgr.discover_sessions(query=r"\.exe")
        self.assertEqual(len(result), 1)
        self.assertIn("alpha", result[0].binary_path)

    def test_glob_filter(self):
        result = self.mgr.discover_sessions(query="*malware*")
        self.assertEqual(len(result), 1)


class TestBookmarkManagerRegex(unittest.TestCase):
    """Test BookmarkManager.find and list with regex-aware queries."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmpdir, "sessions"), exist_ok=True)
        self.bm = BookmarkManager(os.path.join(self.tmpdir, "sessions"))
        self.sid = "TEST1234"
        # Add some bookmarks
        self.bm.add(self.sid, {
            "addr": "0x401000",
            "name": "malloc_wrapper",
            "notes": "Custom allocator",
            "category": "memory",
            "tags": ["alloc", "heap"],
        })
        self.bm.add(self.sid, {
            "addr": "0x402000",
            "name": "init_crypto",
            "notes": "AES initialization routine",
            "category": "crypto",
            "tags": ["aes", "init"],
        })
        self.bm.add(self.sid, {
            "addr": "0x403000",
            "name": "parse_input",
            "notes": "User input parser, potential buffer overflow",
            "category": "vulnerability",
            "tags": ["input", "overflow"],
        })

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_plain_substring(self):
        result = self.bm.find(self.sid, "alloc")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)

    def test_find_regex(self):
        result = self.bm.find(self.sid, "^init")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["name"], "init_crypto")

    def test_find_alternation(self):
        result = self.bm.find(self.sid, "malloc|crypto")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)

    def test_find_by_addr_regex(self):
        result = self.bm.find(self.sid, "0x40[12]000")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)

    def test_find_by_notes(self):
        result = self.bm.find(self.sid, "buffer overflow")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)

    def test_list_with_category_regex(self):
        result = self.bm.list(self.sid, {"category": "^mem"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)

    def test_list_with_tag_regex(self):
        result = self.bm.list(self.sid, {"tag": "init|alloc"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)

    def test_list_with_query(self):
        result = self.bm.list(self.sid, {"query": "^parse"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)


if __name__ == "__main__":
    unittest.main()
