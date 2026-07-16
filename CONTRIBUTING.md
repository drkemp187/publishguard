# Contributing to PublishGuard

Thanks for helping harden the npm supply chain! Contributions are welcome.

## Ground rules

- **Keep it dependency-free.** PublishGuard must never add a runtime dependency.
  A supply-chain tool that grows a supply chain is a contradiction.
- **Keep it offline.** No network calls, ever.
- **Every new detection needs a test** with both a true-positive fixture and a
  proof it does not fire on clean code (false-positive guard).

## Adding a detection signature

1. Add a signature to `lib/engine.js` (`SIGNATURES` array) with a stable
   `PGxxx` rule id, tight patterns, a clear message, and remediation.
2. Add a test in `test/test.js` covering a true positive and a clean-code case.
3. Run `npm test` — all tests must pass.
4. Document the rule in the README detection table.

## Running tests

```bash
npm test
```

## Reporting false positives

Open an issue with a minimal reproduction. Reducing false positives is a
first-class goal — security tools that cry wolf get uninstalled.
