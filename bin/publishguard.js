#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanPackage, writeBaseline, toSarif } = require('../lib/scanner');
const { worstSeverity, SEVERITY_RANK } = require('../lib/engine');
const pkg = require('../package.json');

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[91m', mag: '\x1b[95m', yel: '\x1b[93m', blu: '\x1b[94m', grn: '\x1b[92m',
};
const useColor = process.stdout.isTTY;
const c = (s, col) => (useColor ? col + s + C.reset : s);
const SEV_COLOR = { CRITICAL: C.mag, HIGH: C.red, MEDIUM: C.yel, LOW: C.blu };

function usage() {
  console.log(`PublishGuard v${pkg.version} — pre-publish worm tripwire for npm

Usage:
  publishguard check [--strict] [--sarif <file>] [--dir <path>]
  publishguard baseline [--dir <path>]

Commands:
  check       Scan the package about to be published. Exits non-zero on findings.
  baseline    Snapshot current lifecycle scripts as the known-good baseline.

Options:
  --strict         Fail on any finding (default: fail only on HIGH+ severity).
  --sarif <file>   Also write results as SARIF 2.1.0 (for GitHub code scanning).
  --dir <path>     Package root (default: current directory).
`);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--strict') args.strict = true;
    else if (a === '--sarif') args.sarif = argv[++i];
    else if (a === '--dir') args.dir = argv[++i];
    else if (a === '-h' || a === '--help') args.help = true;
    else args._.push(a);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  const root = path.resolve(args.dir || process.cwd());

  if (args.help || !cmd) { usage(); process.exit(cmd ? 0 : 1); }

  if (cmd === 'baseline') {
    const n = writeBaseline(root);
    console.log(c('✓', C.grn) + ` Baseline written (.publishguard-baseline.json) — captured ${n} lifecycle script(s).`);
    console.log(c('  Commit this file so future publishes are diffed against it.', C.dim));
    process.exit(0);
  }

  if (cmd !== 'check') { usage(); process.exit(1); }

  const { findings, pkgName, hadBaseline } = scanPackage(root);

  console.log(`\n${c('🛡️  PublishGuard', C.bold)} — scanning ${c(pkgName, C.bold)} before publish\n`);
  if (!hadBaseline) {
    console.log(c('  ⚠  No baseline found. Run `publishguard baseline` to enable', C.yel));
    console.log(c('     lifecycle-script drift detection (recommended).\n', C.yel));
  }

  if (findings.length === 0) {
    console.log(c('  ✓ No worm-spread indicators detected. Safe to publish.\n', C.grn));
    process.exit(0);
  }

  // Sort by severity, worst first
  findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  for (const f of findings) {
    const sc = SEV_COLOR[f.severity] || C.blu;
    console.log(`  ${c('[' + f.severity + ']', sc)} ${c(f.rule, C.bold)} ${f.name}`);
    console.log(`     ${f.message}`);
    console.log(c(`     file: ${f.file}`, C.dim));
    if (f.evidence) console.log(c(`     evidence: ${f.evidence}`, C.dim));
    console.log(c(`     fix: ${f.remediation}`, C.dim));
    console.log();
  }

  if (args.sarif) {
    fs.writeFileSync(args.sarif, JSON.stringify(toSarif(findings), null, 2));
    console.log(c(`  SARIF written to ${args.sarif}`, C.dim));
  }

  const worst = worstSeverity(findings);
  const shouldBlock = args.strict || SEVERITY_RANK[worst] >= SEVERITY_RANK.HIGH;
  if (shouldBlock) {
    console.log(c(`\n✗ PUBLISH BLOCKED — ${findings.length} indicator(s), worst severity ${worst}.`, C.red));
    console.log(c('  If this is a legitimate change, review carefully, then update your baseline.\n', C.dim));
    process.exit(1);
  }
  console.log(c(`\n⚠ ${findings.length} low-severity finding(s); publish allowed (use --strict to block).\n`, C.yel));
  process.exit(0);
}

main();
