# CSP Analyzer

A small, dependency-free Python CLI that audits a website's
Content-Security-Policy (CSP) header against the standard hardening
rules. It grades the policy A-F and explains each finding in plain
language with a fix, so students and small teams can see exactly
where a policy lets an XSS flaw run code and how to close it.

Standard library only (`urllib`, `ssl`, `json`, `argparse`). No
third-party packages, no telemetry, nothing is stored. The analyzer
only sends read-only GET requests and never logs in or submits data.
It can also analyse a header value passed directly with `--header`,
which needs no network at all.

## What it checks

| Check | What a good result looks like |
| --- | --- |
| Header present | An enforcing Content-Security-Policy header is sent, not just a Report-Only one |
| script-src | No `'unsafe-inline'`, `'unsafe-eval'`, `*`, `http:`, `https:` or `data:`; a nonce or hash where inline scripts are needed |
| style-src | No `'unsafe-inline'` |
| default-src | A fallback such as `'self'` or `'none'` so forgotten directives do not default to anywhere |
| object-src | `'none'`, or a strict default-src that covers it |
| base-uri | `'self'` or `'none'`, so an injected `<base>` tag cannot redirect relative URLs |
| frame-ancestors | `'self'` or `'none'`, so the page cannot be framed (clickjacking) |
| form-action | `'self'`, so forms cannot post credentials to any origin |
| upgrade-insecure-requests | Present, so stray `http://` resources upgrade automatically |
| Reporting | A `report-to` (or `report-uri`) endpoint collects violation reports |

Two subtleties are handled, not just pattern-matched:

- `object-src` falls back to `default-src`, so a strict
  `default-src 'none'` already locks plugins down and is not
  flagged. `base-uri`, `frame-ancestors` and `form-action` do not
  fall back, so they are always checked on their own.
- With `'strict-dynamic'` plus a nonce, modern browsers ignore
  `'unsafe-inline'`, so it drops from High to Low. `'unsafe-eval'`
  is never neutralised that way and stays High.

Findings are graded by severity:

| Severity | Examples |
| --- | --- |
| High | No CSP header at all, `'unsafe-inline'` / `'unsafe-eval'` in script-src, `*` or `data:` in script-src |
| Medium | Report-Only header only, `http:` / `https:` in script-src, `'unsafe-inline'` in style-src, missing default-src / object-src / frame-ancestors |
| Low | Missing base-uri / form-action / upgrade-insecure-requests / reporting, deprecated `report-uri` |

Score starts at 100 and deducts 25 / 10 / 3 per high / medium / low
finding: 90+ is A, 75+ B, 60+ C, 40+ D, below that F.

## Install

No installation needed. Python 3.8+ only, standard library only:

```bash
git clone https://github.com/sajidhussainraza/csp-analyzer.git
cd csp-analyzer
```

## Usage

Audit a website's CSP header:

```bash
python3 csp_analyzer.py https://example.com
```

Analyse a header value directly (no network needed):

```bash
python3 csp_analyzer.py --header "default-src 'self'; script-src 'self'"
```

Machine-readable output:

```bash
python3 csp_analyzer.py https://example.com --json
```

Use it as a CI gate (fail only on high-severity findings):

```bash
python3 csp_analyzer.py https://example.com --fail-on high
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at/above `--fail-on` |
| 1 | Findings at/above `--fail-on` were found |
| 2 | Usage error (bad URL, site unreachable) |

Note: the analyzer only reads the header a site sends on an
anonymous visit. It cannot audit a policy served only after login,
or one applied by JavaScript in the browser.

## Example

```
$ python3 csp_analyzer.py https://github.com
CSP report: https://github.com
Score: 87/100  Grade: B

  Policy: default-src 'none'; base-uri 'self'; ... (full policy in
  the saved output file)
  Note: script-src uses a nonce or hash, a modern policy.

Findings (2):
  [MEDIUM] style-src: style-src allows 'unsafe-inline', so injected
  styles can exfiltrate data or restyle the page.
        Fix: Move inline styles to external files, or protect them
        with a nonce or hash.
  [LOW] report-uri: No report-uri or report-to, so CSP violations
  are never reported back and a broken policy goes unnoticed.
        Fix: Add report-to (or report-uri) pointing at an endpoint
        that collects violation reports.
```

The full output of that run is saved in
`examples/sample-output-github.com.txt` (captured 19 November 2026).

Two more live audits from the same day: google.com scores 13/100,
Grade F, and example.com scores 75/100, Grade B (no header at all).
Google's F deserves a careful read rather than a laugh: its homepage
policy is Report-Only and nonce-based, so modern browsers do enforce
the nonce even though the header as sent is loose (`'unsafe-eval'`,
`https:` / `http:` fallbacks, no `frame-ancestors`). The score grades
the header as sent; the teaching point is that a Report-Only policy
blocks nothing, whatever its nonce says. Both full outputs are saved
in `examples/` (captured 19 November 2026).

## Teaching notes

This tool pairs well with a lesson on XSS defence in depth: run it
against a deliberately loose demo policy, then tighten one directive
at a time and watch the grade move. Good discussion points:

- Why CSP is the second line of defence after input validation: one
  missed sanitisation flaw still needs a policy that refuses to run
  the injected script.
- Why `'unsafe-inline'` is the directive that matters most: with it,
  an attacker does not need to host anything, the payload runs inline.
- Why nonces and hashes replaced `'unsafe-inline'`: they let a page
  keep its few inline scripts while refusing every script the server
  did not bless.
- Why `default-src` is the safety net: every directive you forget
  inherits it, so `'self'` there turns an oversight into a block.
- Why a Report-Only policy is a rehearsal, not a defence: it logs
  violations while letting the attack through, so it must graduate
  to an enforcing header.
- Why `frame-ancestors` replaced `X-Frame-Options`: it covers the
  same clickjacking case with a single CSP directive.

## Tests

```bash
python3 tests/run_tests.py   # 26 tests, including a live audit of github.com
```

The mock and CLI tests need no internet. The live test runs a real
audit against github.com and is skipped automatically when the
network is unreachable. (pytest is also supported if it is installed:
`python3 -m pytest tests/ -q`.)

## License

MIT
