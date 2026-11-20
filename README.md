![CSP Analyzer](docs/banner.png)

# CSP Analyzer

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests: 26/26 passing](https://img.shields.io/badge/tests-26%2F26%20passing-brightgreen.svg)](tests/)

**Audit any website's Content-Security-Policy header in seconds, get an A-F grade, and learn exactly how to fix it.**

CSP Analyzer is a small, dependency-free Python CLI that fetches a site's
Content-Security-Policy (CSP) header, checks it against the standard
hardening rules, and grades it A-F with plain-language findings and a fix
for each one. It shows students and small teams exactly where a policy
lets an XSS flaw run code, and how to close it.

Standard library only (`urllib`, `ssl`, `json`, `argparse`). No
third-party packages, no telemetry, nothing is stored. The analyzer only
sends read-only GET requests and never logs in or submits data. It can
also analyse a header value passed directly with `--header`, which needs
no network at all.

## Features

- **A-F grading** with a 0-100 score, so any policy can be compared at a glance
- **Plain-language findings** with a concrete fix for every issue found
- **Detects the dangerous patterns**: `'unsafe-inline'`, `'unsafe-eval'`, wildcard (`*`) sources, `http:`, `https:` and `data:` in `script-src`
- **Checks the directives that get forgotten**: `default-src`, `object-src`, `base-uri`, `frame-ancestors`, `form-action`, `upgrade-insecure-requests` and reporting
- **Report-Only aware**: tells you when a policy only logs violations instead of blocking them
- **Smart about modern policies**: understands `default-src` fallback for `object-src`, and that `'strict-dynamic'` with a nonce neutralises `'unsafe-inline'` in modern browsers
- **Offline mode**: audit any header string with `--header`, no network needed
- **CI ready**: `--json` for machine-readable output and `--fail-on` to fail a build on findings above a severity
- **Zero dependencies**: Python standard library only, nothing to install

## Installation

Python 3.10+ only, standard library only, no dependencies to install:

```bash
git clone https://github.com/sajidhussainraza/csp-analyzer.git
cd csp-analyzer
```

That is the whole install. There is nothing else to set up.

## Quick start

Audit a website's CSP header:

```bash
python3 csp_analyzer.py https://example.com
```

```
CSP report: https://example.com
Score: 75/100  Grade: B

  Policy: none sent

Findings (1):
  [HIGH] Content-Security-Policy: No Content-Security-Policy header was sent, so the browser
  has no allow-list for scripts, styles or embeds and a single XSS flaw runs attacker code directly.
        Fix: Send a Content-Security-Policy header, starting with default-src 'self';
        script-src 'self' and object-src 'none' as a minimum.
```

Analyse a header value directly (no network needed):

```bash
python3 csp_analyzer.py --header "default-src 'self'; script-src 'self'"
```

```
CSP report: CSP header analysis
Score: 78/100  Grade: B
```

Machine-readable output:

```bash
python3 csp_analyzer.py https://example.com --json
```

Use it as a CI gate (fail only on high-severity findings):

```bash
python3 csp_analyzer.py https://example.com --fail-on high
echo $?   # 1: a high-severity finding was found
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` were found |
| 2 | Usage error (bad URL, site unreachable) |

Note: the analyzer only reads the header a site sends on an anonymous
visit. It cannot audit a policy served only after login, or one applied
by JavaScript in the browser.

## Live results

Real audits, captured 19 November 2026 and re-checked 20 November 2026.
Full outputs are saved in [`examples/`](examples/).

| Site | Score | Grade | What stood out |
| --- | --- | --- | --- |
| [github.com](https://github.com) | 87/100 | B | Nonce-based `script-src`, but `'unsafe-inline'` in `style-src` and no reporting endpoint |
| [google.com](https://www.google.com) | 13/100 | F | Report-Only, nonce-based policy (see below) |
| [example.com](https://example.com) | 75/100 | B | No CSP header at all |

Google's F deserves a careful read rather than a laugh: its homepage
policy is Report-Only and nonce-based, so modern browsers do enforce
the nonce even though the header as sent is loose (`'unsafe-eval'`,
`https:` / `http:` fallbacks, no `frame-ancestors`). The score grades
the header as sent; the teaching point is that a Report-Only policy
blocks nothing, whatever its nonce says.

## How grading works

Score starts at 100 and deducts **25 / 10 / 3** per high / medium / low
finding:

| Score | Grade |
| --- | --- |
| 90-100 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

Findings are graded by severity:

| Severity | Examples |
| --- | --- |
| High | No CSP header at all, `'unsafe-inline'` / `'unsafe-eval'` in `script-src`, `*` or `data:` in `script-src` |
| Medium | Report-Only header only, `http:` / `https:` in `script-src`, `'unsafe-inline'` in `style-src`, missing `default-src` / `object-src` / `frame-ancestors` |
| Low | Missing `base-uri` / `form-action` / `upgrade-insecure-requests` / reporting, deprecated `report-uri` |

## What it checks

| Check | What a good result looks like |
| --- | --- |
| Header present | An enforcing Content-Security-Policy header is sent, not just a Report-Only one |
| `script-src` | No `'unsafe-inline'`, `'unsafe-eval'`, `*`, `http:`, `https:` or `data:`; a nonce or hash where inline scripts are needed |
| `style-src` | No `'unsafe-inline'` |
| `default-src` | A fallback such as `'self'` or `'none'` so forgotten directives do not default to anywhere |
| `object-src` | `'none'`, or a strict `default-src` that covers it |
| `base-uri` | `'self'` or `'none'`, so an injected `<base>` tag cannot redirect relative URLs |
| `frame-ancestors` | `'self'` or `'none'`, so the page cannot be framed (clickjacking) |
| `form-action` | `'self'`, so forms cannot post credentials to any origin |
| `upgrade-insecure-requests` | Present, so stray `http://` resources upgrade automatically |
| Reporting | A `report-to` (or `report-uri`) endpoint collects violation reports |

Two subtleties are handled, not just pattern-matched:

- `object-src` falls back to `default-src`, so a strict
  `default-src 'none'` already locks plugins down and is not
  flagged. `base-uri`, `frame-ancestors` and `form-action` do not
  fall back, so they are always checked on their own.
- With `'strict-dynamic'` plus a nonce, modern browsers ignore
  `'unsafe-inline'`, so it drops from High to Low. `'unsafe-eval'`
  is never neutralised that way and stays High.

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

26/26 tests pass. The mock and CLI tests need no internet. The live
test runs a real audit against github.com and is skipped automatically
when the network is unreachable. (pytest is also supported if it is
installed: `python3 -m pytest tests/ -q`.)

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository and create a branch for your change.
2. Keep the tool dependency-free (Python standard library only).
3. Add or update tests in `tests/` for any behaviour you change.
4. Run the full suite and make sure all 26 tests pass:
   `python3 tests/run_tests.py`
5. Open a pull request describing the change and why it helps.

Bug reports are welcome too: please include the command you ran, the
header or URL involved, and the output you got versus what you
expected.

## License

MIT. See [LICENSE](LICENSE) for the full text.

---

Built by [Cyber Legends](https://cyberlegends.org) — cybersecurity
trainings, services and solutions.
