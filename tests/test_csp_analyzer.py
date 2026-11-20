"""Tests for csp_analyzer.py.

Run with:  python3 tests/run_tests.py
(or: python3 -m pytest tests/ -q, if pytest is installed)

The mock tests need no network. The live test audits github.com and
is skipped automatically when the network is unreachable.
"""

import json
import os
import subprocess
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from csp_analyzer import (  # noqa: E402
    analyze_csp,
    fetch_csp,
    format_report,
    grade_for,
    parse_csp,
)

STRICT = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
    "frame-ancestors 'none'; form-action 'self'; "
    "upgrade-insecure-requests; report-to csp-endpoint"
)
LOOSE = "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; object-src *"


class TestParseCsp(unittest.TestCase):
    def test_empty_header(self):
        self.assertEqual(parse_csp(None), {})
        self.assertEqual(parse_csp(""), {})

    def test_directives_lowercased(self):
        parsed = parse_csp("Default-Src 'self'; SCRIPT-SRC 'none'")
        self.assertEqual(parsed["default-src"], ["'self'"])
        self.assertEqual(parsed["script-src"], ["'none'"])

    def test_value_less_directive(self):
        parsed = parse_csp("upgrade-insecure-requests; default-src 'self'")
        self.assertEqual(parsed["upgrade-insecure-requests"], [])

    def test_trailing_semicolon_and_spaces(self):
        parsed = parse_csp("default-src 'self' ;  img-src 'self' data: ;")
        self.assertEqual(parsed["default-src"], ["'self'"])
        self.assertEqual(parsed["img-src"], ["'self'", "data:"])


class TestGrades(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(grade_for(100), "A")
        self.assertEqual(grade_for(90), "A")
        self.assertEqual(grade_for(89), "B")
        self.assertEqual(grade_for(75), "B")
        self.assertEqual(grade_for(74), "C")
        self.assertEqual(grade_for(60), "C")
        self.assertEqual(grade_for(59), "D")
        self.assertEqual(grade_for(40), "D")
        self.assertEqual(grade_for(39), "F")
        self.assertEqual(grade_for(0), "F")


class TestAnalyzeCsp(unittest.TestCase):
    def test_strict_policy_scores_100(self):
        report = analyze_csp(STRICT)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.findings, [])

    def test_missing_header_is_high(self):
        report = analyze_csp(None)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "high")
        self.assertEqual(report.score, 75)
        self.assertEqual(report.grade, "B")

    def test_unsafe_inline_and_eval_are_high(self):
        report = analyze_csp(LOOSE)
        directives = {f.directive for f in report.findings
                      if f.severity == "high"}
        self.assertIn("script-src", directives)
        self.assertTrue(any("'unsafe-inline'" in f.message
                            for f in report.findings))
        self.assertTrue(any("'unsafe-eval'" in f.message
                            for f in report.findings))

    def test_wildcard_script_src_is_high(self):
        report = analyze_csp("script-src *; default-src 'self'")
        self.assertTrue(any(f.severity == "high" and "*" in f.message
                            for f in report.findings))

    def test_data_in_script_src_is_high(self):
        report = analyze_csp("script-src 'self' data:; default-src 'self'")
        self.assertTrue(any(f.severity == "high" and "data:" in f.message
                            for f in report.findings))

    def test_missing_directives_flagged(self):
        # base-uri, frame-ancestors and form-action do NOT fall back
        # to default-src, so they are still flagged when absent.
        report = analyze_csp("default-src 'self'; script-src 'self'")
        missing = {f.directive for f in report.findings}
        self.assertIn("frame-ancestors", missing)
        self.assertIn("base-uri", missing)
        self.assertIn("form-action", missing)
        # But object-src DOES fall back to default-src 'self', so it
        # is covered and not flagged here.
        self.assertNotIn("object-src", missing)

    def test_strict_default_src_covers_object_src(self):
        # object-src falls back to default-src, so default-src 'none'
        # already locks plugins down; no object-src finding is due.
        report = analyze_csp(
            "default-src 'none'; script-src 'self'; base-uri 'self'; "
            "frame-ancestors 'self'; form-action 'self'; "
            "upgrade-insecure-requests; report-to x")
        self.assertFalse(any(f.directive == "object-src"
                             for f in report.findings))

    def test_strict_dynamic_nonce_downgrades_unsafe_inline(self):
        # Modern browsers ignore 'unsafe-inline' when 'strict-dynamic'
        # and a nonce are present, so it is low, not high.
        report = analyze_csp(
            "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' "
            "'unsafe-eval' https: http:; object-src 'none'; "
            "base-uri 'self'; report-uri https://example.com/csp")
        inline = [f for f in report.findings
                  if f.directive == "script-src"
                  and "'unsafe-inline'" in f.message]
        self.assertEqual(len(inline), 1)
        self.assertEqual(inline[0].severity, "low")
        # 'unsafe-eval' is NOT neutralised by strict-dynamic: still high.
        self.assertTrue(any(f.severity == "high"
                            and "'unsafe-eval'" in f.message
                            for f in report.findings))

    def test_report_only_flagged(self):
        report = analyze_csp(STRICT, report_only=True)
        self.assertTrue(any(f.severity == "medium"
                            and "Report-Only" in f.directive
                            for f in report.findings))

    def test_nonce_policy_has_no_script_finding(self):
        report = analyze_csp(
            "default-src 'self'; script-src 'self' 'nonce-abc123'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; "
            "form-action 'self'; upgrade-insecure-requests; report-to x")
        self.assertFalse(any(f.directive == "script-src"
                             for f in report.findings))

    def test_style_unsafe_inline_is_medium_not_high(self):
        report = analyze_csp(
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'self'; form-action 'self'; "
            "upgrade-insecure-requests; report-to x")
        style = [f for f in report.findings if f.directive == "style-src"]
        self.assertEqual(len(style), 1)
        self.assertEqual(style[0].severity, "medium")

    def test_findings_sorted_high_first(self):
        report = analyze_csp(LOOSE)
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(
            severities, key={"high": 0, "medium": 1, "low": 2}.get))

    def test_json_round_trip(self):
        report = analyze_csp(LOOSE)
        data = json.loads(json.dumps(report.as_dict()))
        self.assertEqual(data["score"], report.score)
        self.assertEqual(data["grade"], report.grade)
        self.assertEqual(len(data["findings"]), len(report.findings))
        self.assertIn("fix", data["findings"][0])

    def test_text_report_mentions_score_and_grade(self):
        text = format_report(analyze_csp(STRICT))
        self.assertIn("100/100", text)
        self.assertIn("Grade: A", text)
        self.assertIn("No findings", text)


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "csp_analyzer.py")
        return subprocess.run([sys.executable, path, *args],
                              capture_output=True, text=True, timeout=60)

    def test_header_mode(self):
        result = self.run_cli("--header", STRICT)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score: 100/100", result.stdout)

    def test_header_mode_json(self):
        result = self.run_cli("--header", LOOSE, "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["grade"], "F")
        self.assertGreater(len(data["findings"]), 0)

    def test_fail_on_high_exits_1(self):
        result = self.run_cli("--header", LOOSE, "--fail-on", "high")
        self.assertEqual(result.returncode, 1)

    def test_fail_on_high_passes_strict(self):
        result = self.run_cli("--header", STRICT, "--fail-on", "high")
        self.assertEqual(result.returncode, 0)

    def test_bad_url_exits_2(self):
        result = self.run_cli("not-a-url")
        self.assertEqual(result.returncode, 2)

    def test_no_args_exits_2(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)


class TestLiveAudit(unittest.TestCase):
    def test_github_has_a_csp(self):
        try:
            url, status, header, report_only = fetch_csp("https://github.com")
        except (urllib.error.URLError, OSError) as exc:
            self.skipTest("network unreachable: %s" % exc)
        self.assertEqual(status, 200)
        self.assertIsNotNone(header, "github.com sent no CSP header")
        report = analyze_csp(header, url=url, report_only=report_only)
        # GitHub's policy is strict; it should not score below a B.
        self.assertGreaterEqual(report.score, 75)


if __name__ == "__main__":
    unittest.main(verbosity=2)
