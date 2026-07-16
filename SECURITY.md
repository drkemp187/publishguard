# Security Policy

PublishGuard is a defensive security tool. We take its own integrity seriously.

## Design guarantees

- **Zero runtime dependencies.** The tool uses only the Node.js standard library.
- **Zero network access.** PublishGuard never makes network calls. All analysis
  is static and local.
- **No code execution.** PublishGuard reads package files as text; it never
  executes the package under analysis.

## Reporting a vulnerability

If you discover a security issue in PublishGuard itself (e.g. a detection bypass
or a way to make the tool execute untrusted input), please open a
[GitHub Security Advisory](https://github.com/drkemp187/publishguard/security/advisories/new)
or email the maintainer. Please do not open a public issue for undisclosed
vulnerabilities.

## Scope

PublishGuard detects a curated set of worm-spread behaviors. It is one layer of
defense, not a guarantee. Combine it with `npm audit`, provenance/attestations,
2FA on your npm account, and least-privilege publish tokens.
