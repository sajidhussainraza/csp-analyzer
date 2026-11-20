# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No (pre-release)   |

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security problem.**

Email the details to **info@cyberlegends.org** with the subject
`[csp-analyzer] Security report`. Include:

- What the issue is and what it affects
- Steps to reproduce it, if you have them
- The version or commit you tested against

You will get an acknowledgement within 7 days, and a fix or a plan for
one within 30 days for confirmed issues. Please do not disclose the
issue publicly until a fix is released.

## What This Tool Does (and Does Not Do)

- CSP Analyzer only sends anonymous, read-only HTTP GET requests to
  the URL you give it. It never logs in, never submits data, and never
  stores anything.
- It has no dependencies, no network calls besides the single audit
  request, and no telemetry.
- It reads only the `Content-Security-Policy` (and
  `Content-Security-Policy-Report-Only`) response headers. It does not
  execute JavaScript, follow login flows, or audit policies that only
  appear after authentication.
- A low score is a finding about a website's header, not a
  vulnerability in this tool. If a site's policy looks wrong, check
  with that site's owner before treating it as a live exploit.
