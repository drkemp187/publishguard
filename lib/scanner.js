'use strict';

const fs = require('fs');
const path = require('path');
const { scanText, diffLifecycleScripts } = require('./engine');

const BASELINE_FILE = '.publishguard-baseline.json';

// Extensions we statically inspect for behavioral signatures.
// Markdown/docs are intentionally excluded: they are not executable and
// commonly describe the very patterns we detect (e.g. security tool READMEs).
const SCANNABLE = new Set(['.js', '.cjs', '.mjs', '.ts', '.json', '.sh']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.github']);

/**
 * Recursively collect scannable files under a directory.
 */
function collectFiles(dir, acc = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      collectFiles(path.join(dir, e.name), acc);
    } else if (e.isFile()) {
      if (SCANNABLE.has(path.extname(e.name))) acc.push(path.join(dir, e.name));
    }
  }
  return acc;
}

/**
 * Run a full pre-publish scan of the package at `root`.
 * Returns { findings, pkgName, hadBaseline }.
 */
function scanPackage(root) {
  const findings = [];
  const pkgPath = path.join(root, 'package.json');
  let pkg = {};
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch {
    return { findings: [{
      rule: 'PG000', name: 'no-package-json', severity: 'HIGH',
      message: 'No readable package.json found; cannot verify publish safety.',
      remediation: 'Run PublishGuard from your package root.', evidence: pkgPath,
      file: 'package.json',
    }], pkgName: '(unknown)', hadBaseline: false };
  }

  // 1. Lifecycle-script baseline diff
  let baseline = null;
  const baselinePath = path.join(root, BASELINE_FILE);
  if (fs.existsSync(baselinePath)) {
    try { baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')).scripts || {}; }
    catch { baseline = null; }
  }
  const diffFindings = diffLifecycleScripts(pkg.scripts, baseline);
  for (const f of diffFindings) { f.file = 'package.json'; findings.push(f); }

  // 2. Behavioral scan of package.json script bodies
  for (const [name, body] of Object.entries(pkg.scripts || {})) {
    if (typeof body !== 'string') continue;
    for (const f of scanText(body)) {
      findings.push({ ...f, file: `package.json (scripts.${name})` });
    }
  }

  // 3. Behavioral scan of shipped source files.
  //    If package.json declares a "files" allowlist, only scan what would
  //    actually be published (mirrors npm's own pack behavior), so local-only test
  //    fixtures and dev tooling don't produce noise.
  let scanRoots = [root];
  if (Array.isArray(pkg.files) && pkg.files.length > 0) {
    scanRoots = pkg.files
      .map(f => path.join(root, f))
      .filter(p => fs.existsSync(p));
    // package.json itself always ships and is always scanned.
  }
  const seen = new Set();
  for (const scanRoot of scanRoots) {
    const stat = fs.existsSync(scanRoot) ? fs.statSync(scanRoot) : null;
    const files = stat && stat.isDirectory() ? collectFiles(scanRoot) : (stat ? [scanRoot] : []);
    for (const file of files) {
      if (seen.has(file)) continue;
      seen.add(file);
      // Honor the scannable-extension allowlist even for direct file entries
      // (e.g. a "files": ["README.md"] entry must not be behavior-scanned).
      if (!SCANNABLE.has(path.extname(file))) continue;
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
      if (text.length > 2_000_000) continue; // skip huge minified bundles
      const rel = path.relative(root, file);
      for (const f of scanText(text)) {
        findings.push({ ...f, file: rel });
      }
    }
  }

  return { findings, pkgName: pkg.name || '(unnamed)', hadBaseline: baseline !== null };
}

/**
 * Snapshot current lifecycle scripts as the known-good baseline.
 */
function writeBaseline(root) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const { LIFECYCLE_SCRIPTS } = require('./engine');
  const scripts = {};
  for (const name of LIFECYCLE_SCRIPTS) {
    if (pkg.scripts && pkg.scripts[name] !== undefined) scripts[name] = pkg.scripts[name];
  }
  const out = { generatedAt: new Date().toISOString(), package: pkg.name, scripts };
  fs.writeFileSync(path.join(root, BASELINE_FILE), JSON.stringify(out, null, 2) + '\n');
  return Object.keys(scripts).length;
}

/**
 * Convert findings to a minimal, valid SARIF 2.1.0 document.
 */
function toSarif(findings) {
  const levelMap = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };
  const ruleIds = [...new Set(findings.map(f => f.rule))];
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: {
        name: 'PublishGuard',
        informationUri: 'https://github.com/drkemp187/publishguard',
        rules: ruleIds.map(id => ({ id })),
      }},
      results: findings.map(f => ({
        ruleId: f.rule,
        level: levelMap[f.severity] || 'warning',
        message: { text: `${f.message} (${f.remediation})` },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: f.file || 'package.json' },
        }}],
      })),
    }],
  };
}

module.exports = { scanPackage, writeBaseline, toSarif, BASELINE_FILE };
