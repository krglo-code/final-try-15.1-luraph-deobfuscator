import tempfile
import unittest
from pathlib import Path

import static_review


class StaticReviewTests(unittest.TestCase):
    def test_ignores_markers_in_comments_and_strings(self):
        src = '''
-- Luraph Obfuscator v15.1
local banner = "LPH_ENCSTR2"
--[=[ loadstring("x") _bsdata0 ]=]
local x = 1
'''
        code = static_review.code_only(src)
        self.assertNotRegex(code, r"LPH_ENCSTR2|_bsdata0|loadstring")
        self.assertEqual(static_review.readable_strings(src), ["LPH_ENCSTR2"])

    def test_detects_real_code_marker(self):
        src = 'local value = LPH_ENCSTR2("opaque")\n'
        code = static_review.code_only(src)
        self.assertEqual(len(__import__("re").findall(
            static_review.PATTERNS["luraph_encrypted_strings_v2"], code,
            __import__("re").IGNORECASE)), 1)

    def test_long_bracket_string_and_escape(self):
        src = r'''local a = [==[hello\nworld]==] local b = "line\\nnext"'''
        strings = static_review.readable_strings(src)
        self.assertEqual(strings[0], r"hello\nworld")
        self.assertEqual(strings[1], "line\\nnext")

    def test_report_is_json_serializable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.lua"
            path.write_text('local x = LPH_ENCSTR2("hello")', encoding="utf-8")
            report = static_review.analyze(path)
            self.assertEqual(report["file"], "sample.lua")
            self.assertTrue(report["indicators"])
            self.assertIn("No target code was executed;", " ".join(report["limitations"]))


if __name__ == "__main__":
    unittest.main()
