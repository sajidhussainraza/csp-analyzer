#!/usr/bin/env python3
"""CSP Analyzer - audit a website's Content-Security-Policy header.

A small, dependency-free Python CLI that fetches a site's
Content-Security-Policy (CSP) header, checks it against the standard
hardening rules, and grades it A-F with plain-language findings and
fixes. It can also analyse a header value passed directly with
--header, which needs no network at all.

Standard library only (urllib, ssl, json, argparse). No third-party
packages, no telemetry, nothing is stored. The analyzer only sends
read-only GET requests and never logs in or submits data.

Usage:
    python3 csp_analyzer.py https://example.com
    python3 csp_analyzer.py https://example.com --json
    python3 csp_analyzer.py --header "default-src 'self'; script-src 'self'"
    python3 csp_analyzer.py https://example.com --fail-on high
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0.0"

DEDUCTIONS = {"high": 25, "medium": 10, "low": 3}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Sources that are only safe when paired with a nonce or hash.
UNSAFE_INLINE = "'unsafe-inline'"
UNSAFE_EVAL = "'unsafe-eval'"

# Directives whose absence is worth flagging, with the severity to use.
MISSING_DIRECTIVES = [
    ("default-src", "medium",
     "No default-src fallback, so any directive you forget falls back "
     "to loading from anywhere.",
     "Add default-src 'self' (or stricter) so every unlisted resource "
     "type defaults to same-origin only."),
    ("object-src", "medium",
     "No object-src, so plugins and embeds (<object>, <embed>) can "
     "load from anywhere.",
     "Add object-src 'none' unless the site genuinely embeds plugins."),
    ("base-uri", "low",
     "No base-uri, so an injected <base> tag can redirect every "
     "relative URL on the page.",
     "Add base-uri 'self' (or 'none' if the page uses no relative URLs)."),
    ("frame-ancestors", "medium",
     "No frame-ancestors, so the page can be framed by any site "
     "(clickjacking).",
     "Add frame-ancestors 'self' (or 'none' if the page must never be "
     "framed)."),
    ("form-action", "low",
     "No form-action, so forms can submit credentials to any origin.",
     "Add form-action 'self' unless a form genuinely posts elsewhere."),
]

# Wildcard and scheme sources that defeat a directive.
DANGEROUS_SOURCES = {
    "*": "a wildcard that allows the resource from any origin",
    "http:": "plain-HTTP sources that can be intercepted or downgraded",
    "https:": "any HTTPS origin, which is barely a restriction at all",
    "data:": "inline data: URLs that can carry attacker-controlled content",
}


@dataclass
class Finding:
    severity: str
    directive: str
    message: str
    fix: str

    def as_dict(self):
        return {
            "severity": self.severity,
            "directive": self.directive,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass
class Report:
    url: str | None
    header: str | None
    report_only: bool = False
    findings: list = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    status: int | None = None

    def as_dict(self):
        return {
            "url": self.url,
            "status": self.status,
            "header": self.header,
            "report_only": self.report_only,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.as_dict() for f in self.findings],
        }


def parse_csp(header):
    """Parse a CSP header value into {directive: [sources]}.

    Directive names are lower-cased. A directive with no value (such
    as upgrade-insecure-requests) maps to an empty list. Returns an
    empty dict for a missing or blank header.
    """
    directives = {}
    if not header:
        return directives
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _fallback_covers(default_sources):
    """True when default-src restricts object-src on its own.

    object-src is a fetch directive, so it falls back to default-src.
    A default-src of 'none' or 'self' (or named hosts) already locks
    plugins down; a wildcard or scheme source does not.
    """
    if not default_sources:
        return False
    return not any(s in ("*", "http:", "https:", "data:", "blob:")
                   for s in default_sources)


def _check_script_sources(directives, findings):
    """Flag dangerous sources in the directives that run code."""
    effective = directives.get("script-src") or directives.get("default-src") or []
    # With 'strict-dynamic' plus a nonce, modern browsers ignore
    # 'unsafe-inline' entirely, so it is a footnote, not a hole.
    modern_nonce = ("'strict-dynamic'" in effective and any(
        s.startswith("'nonce-") for s in effective))
    for source in effective:
        if source in ("'unsafe-inline'", "'unsafe-eval'"):
            if source == "'unsafe-inline'":
                if modern_nonce:
                    findings.append(Finding(
                        "low", "script-src",
                        "script-src allows 'unsafe-inline', but modern "
                        "browsers ignore it when 'strict-dynamic' and a "
                        "nonce are present; old browsers still honour it.",
                        "Drop 'unsafe-inline' if no legacy browser must "
                        "be supported."))
                else:
                    findings.append(Finding(
                        "high", "script-src",
                        "script-src allows 'unsafe-inline', so any injected "
                        "<script> or inline event handler runs.",
                        "Remove 'unsafe-inline' and move inline scripts to "
                        "external files, or protect them with a nonce or hash."))
            else:
                findings.append(Finding(
                    "high", "script-src",
                    "script-src allows 'unsafe-eval', so eval() and "
                    "friends can run attacker-controlled strings as code.",
                    "Remove 'unsafe-eval'; rewrite the code that needs "
                    "eval() instead."))
        elif source in DANGEROUS_SOURCES:
            severity = "high" if source in ("*", "data:") else "medium"
            findings.append(Finding(
                severity, "script-src",
                "script-src allows %s, which is %s."
                % (source, DANGEROUS_SOURCES[source]),
                "List the exact hosts the site needs instead of %s."
                % source))
    # unsafe-inline in style-src is less severe: it enables style
    # injection, not code execution. style-src falls back to
    # default-src, so an 'unsafe-inline' there counts too.
    style = directives.get("style-src") or directives.get("default-src") or []
    if "'unsafe-inline'" in style:
        findings.append(Finding(
            "medium", "style-src",
            "style-src allows 'unsafe-inline', so injected styles can "
            "exfiltrate data or restyle the page.",
            "Move inline styles to external files, or protect them with "
            "a nonce or hash."))
    # A nonce or hash in script-src is a sign of a modern policy.
    if effective and any(s.startswith(("'nonce-", "'sha256-", "'sha384-",
                                       "'sha512-")) for s in effective):
        pass  # No finding; noted in the text report instead.


def _check_missing(directives, findings):
    for name, severity, message, fix in MISSING_DIRECTIVES:
        if name not in directives:
            # object-src falls back to default-src, so a strict
            # default-src already covers it.
            if name == "object-src" and _fallback_covers(
                    directives.get("default-src")):
                continue
            findings.append(Finding(severity, name, message, fix))


def _check_extras(directives, findings):
    if "upgrade-insecure-requests" not in directives:
        findings.append(Finding(
            "low", "upgrade-insecure-requests",
            "No upgrade-insecure-requests, so a stray http:// resource "
            "on the page still loads over plain HTTP.",
            "Add upgrade-insecure-requests so browsers upgrade insecure "
            "subresources automatically."))
    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(Finding(
            "low", "report-uri",
            "No report-uri or report-to, so CSP violations are never "
            "reported back and a broken policy goes unnoticed.",
            "Add report-to (or report-uri) pointing at an endpoint that "
            "collects violation reports."))
    if "report-uri" in directives and "report-to" not in directives:
        findings.append(Finding(
            "low", "report-uri",
            "report-uri is deprecated; modern browsers prefer report-to.",
            "Add a report-to directive alongside report-uri for modern "
            "browsers."))
    # worker-src / connect-src widening the policy silently.
    for name in ("worker-src", "connect-src", "img-src", "media-src"):
        sources = directives.get(name) or []
        if "*" in sources:
            findings.append(Finding(
                "low", name,
                "%s allows '*', so that resource type loads from any "
                "origin." % name,
                "List the exact hosts the site needs for %s." % name))


def analyze_csp(header, url=None, report_only=False):
    """Analyse one CSP header value and return a Report."""
    report = Report(url=url, header=header, report_only=report_only)
    if not header:
        report.findings.append(Finding(
            "high", "Content-Security-Policy",
            "No Content-Security-Policy header was sent, so the browser "
            "has no allow-list for scripts, styles or embeds and a "
            "single XSS flaw runs attacker code directly.",
            "Send a Content-Security-Policy header, starting with "
            "default-src 'self'; script-src 'self' and object-src "
            "'none' as a minimum."))
        report.score = 100 - DEDUCTIONS["high"]
        report.grade = grade_for(report.score)
        return report

    if report_only:
        report.findings.append(Finding(
            "medium", "Content-Security-Policy-Report-Only",
            "Only a Content-Security-Policy-Report-Only header was sent, "
            "so violations are logged but nothing is actually blocked.",
            "Move the policy to an enforcing Content-Security-Policy "
            "header once the report-only run shows no false positives."))

    directives = parse_csp(header)
    _check_script_sources(directives, report.findings)
    _check_missing(directives, report.findings)
    _check_extras(directives, report.findings)

    report.score = max(
        0, 100 - sum(DEDUCTIONS[f.severity] for f in report.findings))
    report.grade = grade_for(report.score)
    report.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return report


def fetch_csp(url, timeout=15):
    """GET a URL and return (final_url, status, header, report_only).

    urllib follows redirects itself, so the header audited is the one
    from the final page. Raises ValueError for a bad URL and
    URLError/OSError when the site cannot be reached.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("URL must start with http:// or https://")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url, headers={"User-Agent": "csp-analyzer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:
            headers = resp.headers
            header = headers.get("Content-Security-Policy")
            report_only = False
            if header is None:
                header = headers.get("Content-Security-Policy-Report-Only")
                report_only = header is not None
            return resp.url, resp.status, header, report_only
    except urllib.error.HTTPError as exc:
        # An error page can still carry a CSP header worth auditing.
        headers = exc.headers
        header = headers.get("Content-Security-Policy")
        report_only = False
        if header is None:
            header = headers.get("Content-Security-Policy-Report-Only")
            report_only = header is not None
        return exc.url, exc.code, header, report_only


def format_report(report):
    """Render a Report as plain text."""
    lines = []
    title = report.url or "CSP header analysis"
    lines.append("CSP report: %s" % title)
    lines.append("Score: %d/100  Grade: %s" % (report.score, report.grade))
    lines.append("")
    if report.header:
        lines.append("  Policy: %s" % report.header)
        if report.report_only:
            lines.append("  (Report-Only: violations are logged, not blocked)")
    else:
        lines.append("  Policy: none sent")
    directives = parse_csp(report.header)
    if directives.get("script-src") or directives.get("default-src"):
        effective = directives.get("script-src") or directives.get("default-src")
        if any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
               for s in effective):
            lines.append("  Note: script-src uses a nonce or hash, a modern "
                         "policy.")
    if report.findings:
        lines.append("")
        lines.append("Findings (%d):" % len(report.findings))
        for finding in report.findings:
            lines.append("  [%s] %s: %s"
                         % (finding.severity.upper(), finding.directive,
                            finding.message))
            lines.append("        Fix: %s" % finding.fix)
    else:
        lines.append("")
        lines.append("No findings: this policy blocks inline scripts, "
                     "plugins and framing, and restricts every resource "
                     "type to named origins.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit a website's Content-Security-Policy header.")
    parser.add_argument("url", nargs="?",
                        help="Website URL to audit (https://example.com).")
    parser.add_argument("--header",
                        help="Analyse a CSP header value directly "
                             "(no network needed).")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON.")
    parser.add_argument("--fail-on",
                        choices=["high", "medium", "low", "none"],
                        default="none",
                        help="Exit 1 when findings at or above this "
                             "severity are found (default: none).")
    args = parser.parse_args(argv)

    if args.header and args.url:
        parser.error("--header and a URL cannot be used together.")
    if not args.header and not args.url:
        parser.error("Give a URL to audit or a header with --header.")

    try:
        if args.header:
            report = analyze_csp(args.header)
        else:
            final_url, status, header, report_only = fetch_csp(args.url)
            report = analyze_csp(header, url=final_url,
                                 report_only=report_only)
            report.status = status
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError) as exc:
        print("Error: could not reach the site (%s)" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(format_report(report))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold
               for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
