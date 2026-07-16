# 🛡️ PublishGuard

**The last line of defense before your npm token spreads a worm.**

PublishGuard is a **pre-publish tripwire** for npm packages. It runs in your own
`prepublishOnly` hook or CI — *right before* `npm publish` — and **refuses to
publish** if it detects the behaviors that self-replicating supply-chain worms
(Shai-Hulud–class) use to spread from one compromised package into all the
others a maintainer owns.

Every other tool protects the people who **install** packages. PublishGuard
protects the **supply itself** — it stops *your* package from becoming the next
link in a worm's replication chain.

- 🔒 **Zero dependencies. Zero network calls.** Pure Node stdlib. A supply-chain
  tool should not itself be a supply-chain risk.
- 🧬 **Baseline-diff detection.** Flags lifecycle scripts (`postinstall`,
  `prepublish`, `prepare`, …) that appeared or changed since your last
  known-good commit — the #1 worm injection vector.
- 🕵️ **Behavioral static analysis.** Detects token theft (`~/.npmrc`,
  `NPM_TOKEN`, `NODE_AUTH_TOKEN`), credential harvesting, self-`npm publish`,
  and exfil beacons in what you're *about to ship*.
- 🚦 **Blocks the publish.** Exits non-zero so CI/`prepublishOnly` halts before
  a compromised artifact ever reaches the registry.
- 📤 **SARIF output.** Findings ingest natively into GitHub code scanning.

> PublishGuard is a **defensive** tool. It performs static analysis of your own
> package on your own machine/CI. It never executes package code and never
> contacts the network.

## Why "pre-publish" is the missing layer

| Layer | Tools | What they protect |
|-------|-------|-------------------|
| **Install-time** (consumer) | many scanners | People installing packages |
| **Publish-time** (maintainer) | **← PublishGuard** | The registry / the supply chain itself |

Worms like Shai-Hulud are exponential precisely because a single compromised
maintainer auto-publishes the worm into every package they control.
PublishGuard breaks that replication step.

## Quick start

```bash
npx publishguard check                 # scan the current package
npx publishguard baseline              # snapshot current lifecycle scripts as known-good
npx publishguard check --sarif out.sarif
```

Wire it into your package so a publish is **blocked** if anything looks wormy:

```json
{
  "scripts": {
    "prepublishOnly": "publishguard check --strict"
  }
}
```

Or drop the GitHub Action into `.github/workflows/` (see `examples/`).

## What it detects

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `PG001` lifecycle-script-added | CRITICAL | A new install/publish lifecycle script not in your baseline |
| `PG002` lifecycle-script-changed | HIGH | An existing lifecycle script whose body changed |
| `PG003` npm-token-access | CRITICAL | Code reading `.npmrc` / `NPM_TOKEN` / `NODE_AUTH_TOKEN` |
| `PG004` credential-harvest | HIGH | Reads of AWS/GCP/GitHub creds or bulk `process.env` dump |
| `PG005` self-publish | CRITICAL | Code invoking `npm publish` / registry publish API |
| `PG006` network-exfil | HIGH | Beacons to raw IPs, `webhook.site`, known C2 patterns |
| `PG007` obfuscated-payload | MEDIUM | `eval`/`Function`/base64-`Buffer` decode of remote strings |

## False positives & suppression

If a line must legitimately contain a flagged string (e.g. you're building
security tooling), append a suppression comment — the same idea as
`eslint-disable-line`:

```js
const pattern = /npm publish/; // publishguard-disable-line
```

PublishGuard eats its own dog food: its detection patterns use this marker, so
`publishguard check` on the PublishGuard repo itself is clean.

## License

MIT — use it anywhere, including commercially.
