# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-20

### Added

- Dependency-free Python CLI that audits a site's
  Content-Security-Policy header and grades it A-F with a 0-100 score.
- Plain-language findings with a concrete fix for every issue:
  `unsafe-inline` / `unsafe-eval`, wildcard and scheme sources in
  `script-src`, missing `default-src` / `object-src` / `base-uri` /
  `frame-ancestors` / `form-action`, missing
  `upgrade-insecure-requests`, and missing or deprecated reporting.
- Report-Only awareness: a `Content-Security-Policy-Report-Only`
  header is flagged as logging only, not blocking.
- Modern-policy handling: `default-src` fallback covers `object-src`,
  and `'strict-dynamic'` with a nonce downgrades `'unsafe-inline'`
  from High to Low in modern browsers.
- Offline mode (`--header`), machine-readable output (`--json`), and
  a CI gate (`--fail-on {high,medium,low,none}`, default `none`).
- Exit codes 0 (pass), 1 (findings at or above `--fail-on`),
  2 (usage or network error).
- 27 tests (stdlib `unittest`, no pytest needed), including a live
  audit of github.com that skips when the network is unreachable.
- Full repository standard: README, CONTRIBUTING.md, Code of Conduct,
  Security policy, issue and pull request templates, CI workflow,
  `.gitignore`, `.editorconfig`, and original SVG banner and logo.

### Fixed

- `style-src` now respects the `default-src` fallback: an
  `'unsafe-inline'` in `default-src` is flagged as a medium
  `style-src` finding even when no `style-src` directive is present,
  matching how browsers actually apply the policy.

## [Unreleased]

- Nothing yet. See the [roadmap](README.md#roadmap) for what is planned.
