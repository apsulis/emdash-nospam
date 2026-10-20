# Changelog

## 0.1.1 — 2026-10-20

Release process only, no change in behaviour: versions are now staged on npm from GitHub Actions with provenance
and approved by a maintainer with two-factor authentication.

## 0.1.0 — 2026-10-20

First version of `@apsulis/emdash-nospam` for EmDash 1.3.x: `createNospam()` for form endpoints (honeypot, user
agent, signed timing token bound to the form and the browser, per-IP rate limit counted after the bot checks, content
checks: links, BBCode, hidden markup, blocked words, unexpected scripts), graded verdicts (`ok`, `silent`, `retry`,
`limit`; `flag` for borderline messages), English and French messages, browser helper (`/client`), administrator
dashboard widget (counts, reasons, last refusals, setup warnings). No runtime dependency.
