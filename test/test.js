'use strict';

const assert = require('assert');
const path = require('path');
const { scanText, diffLifecycleScripts, worstSeverity } = require('../lib/engine');
const { scanPackage, toSarif } = require('../lib/scanner');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ✓ ' + name); }
  catch (e) { failed++; console.log('  ✗ ' + name + '\n      ' + e.message); }
}

console.log('\nPublishGuard tests\n');

// --- Behavioral signature scanning ---
test('detects npm token access (PG003)', () => {
  const f = scanText("const t = fs.readFileSync(HOME + '/.npmrc')");
  assert.ok(f.some(x => x.rule === 'PG003'));
});

test('detects self-publish (PG005)', () => {
  const f = scanText("execSync('npm publish --access public')");
  assert.ok(f.some(x => x.rule === 'PG005'));
});

test('detects exfil beacon (PG006)', () => {
  const f = scanText("post('https://webhook.site/abc')");
  assert.ok(f.some(x => x.rule === 'PG006'));
});

test('detects obfuscated eval payload (PG007)', () => {
  const f = scanText("eval(Buffer.from(x,'base64').toString())");
  assert.ok(f.some(x => x.rule === 'PG007'));
});

test('detects hardcoded secret (PG008)', () => {
  const f = scanText('const token = "AKIA1234567890ABCDEF";');
  assert.ok(f.some(x => x.rule === 'PG008'));
});

test('clean code produces no findings', () => {
  const f = scanText('function add(a,b){return a+b;}');
  assert.strictEqual(f.length, 0);
});

test('suppression marker excludes a line from scanning', () => {
  const f = scanText("const p = /npm publish/; // publishguard-disable-line");
  assert.strictEqual(f.length, 0);
});

// --- Lifecycle baseline diff ---
test('flags newly ADDED lifecycle script (PG001 CRITICAL)', () => {
  const f = diffLifecycleScripts({ postinstall: 'node evil.js' }, {});
  assert.ok(f.some(x => x.rule === 'PG001' && x.severity === 'CRITICAL'));
});

test('flags CHANGED lifecycle script (PG002)', () => {
  const f = diffLifecycleScripts({ prepare: 'node b.js' }, { prepare: 'node a.js' });
  assert.ok(f.some(x => x.rule === 'PG002'));
});

test('no diff finding when script unchanged', () => {
  const f = diffLifecycleScripts({ prepare: 'tsc' }, { prepare: 'tsc' });
  assert.strictEqual(f.length, 0);
});

// --- Full package scan (integration) ---
test('malicious fixture triggers CRITICAL and blocks', () => {
  const { findings } = scanPackage(path.join(__dirname, 'fixtures', 'malicious'));
  assert.ok(findings.length >= 3, 'expected several findings');
  assert.strictEqual(worstSeverity(findings), 'CRITICAL');
  const rules = new Set(findings.map(f => f.rule));
  assert.ok(rules.has('PG003'), 'token theft');
  assert.ok(rules.has('PG005'), 'self-publish');
});

test('secret fixture triggers PG008', () => {
  const { findings } = scanPackage(path.join(__dirname, 'fixtures', 'secret-leak'));
  assert.ok(findings.some(f => f.rule === 'PG008'), 'hardcoded secret should be flagged');
});

test('clean fixture produces zero findings', () => {
  const { findings } = scanPackage(path.join(__dirname, 'fixtures', 'clean'));
  assert.strictEqual(findings.length, 0);
});

test('files allowlist limits scan to publishable paths', () => {
  const fs = require('fs'); const os = require('os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-'));
  fs.writeFileSync(path.join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', files: ['lib'] }));
  fs.mkdirSync(path.join(dir, 'lib'));
  fs.writeFileSync(path.join(dir, 'lib', 'ok.js'), 'module.exports = 1;');
  fs.writeFileSync(path.join(dir, 'scratch.js'), "require('child_process').execSync('npm publish')");
  const { findings } = scanPackage(dir);
  assert.strictEqual(findings.length, 0, 'non-published file should not be scanned');
});

// --- SARIF output ---
test('SARIF output is valid shape', () => {
  const { findings } = scanPackage(path.join(__dirname, 'fixtures', 'malicious'));
  const sarif = toSarif(findings);
  assert.strictEqual(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs[0].results));
  assert.ok(sarif.runs[0].results.length > 0);
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
