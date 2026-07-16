'use strict';

/**
 * PublishGuard detection engine.
 *
 * Static, offline analysis of a package that is about to be published.
 * Detects the behaviors that self-replicating supply-chain worms
 * (Shai-Hulud class) use to spread. No code execution, no network.
 *
 * Zero runtime dependencies (Node stdlib only) by design: a supply-chain
 * defense tool must not itself enlarge the supply chain.
 */

const LIFECYCLE_SCRIPTS = [
  'preinstall', 'install', 'postinstall',
  'preprepare', 'prepare', 'postprepare',
  'prepublish', 'prepublishOnly', 'prepack', 'postpack',
];

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

/**
 * Behavioral signatures. Each is intentionally specific to reduce false
 * positives. `evidence` is the matched snippet shown to the user.
 */
const SIGNATURES = [
  {
    id: 'PG003',
    name: 'npm-token-access',
    severity: 'CRITICAL',
    // Reading the npm auth token is the worm's key to self-publish.
    patterns: [
      /\.npmrc\b/,             // publishguard-disable-line
      /\bNPM_TOKEN\b/,         // publishguard-disable-line
      /\bNODE_AUTH_TOKEN\b/,   // publishguard-disable-line
      /_authToken/i,           // publishguard-disable-line
    ],
    message: 'Accesses npm authentication token (the key a worm needs to self-publish).',
    remediation: 'Legitimate publish flows do not read the token from package code. Remove this access.',
  },
  {
    id: 'PG004',
    name: 'credential-harvest',
    severity: 'HIGH',
    patterns: [
      /\bAWS_ACCESS_KEY_ID\b/,          // publishguard-disable-line
      /\bAWS_SECRET_ACCESS_KEY\b/,      // publishguard-disable-line
      /\bGITHUB_TOKEN\b/,               // publishguard-disable-line
      /\bGH_TOKEN\b/,                   // publishguard-disable-line
      /process\.env\s*\)/,             // publishguard-disable-line
      /JSON\.stringify\(\s*process\.env/, // publishguard-disable-line
    ],
    message: 'Harvests cloud/CI credentials or dumps the entire process environment.',
    remediation: 'Remove environment credential access from published code.',
  },
  {
    id: 'PG005',
    name: 'self-publish',
    severity: 'CRITICAL',
    patterns: [
      /npm\s+publish/,                                          // publishguard-disable-line
      /['"`]publish['"`]\s*,/,                                  // publishguard-disable-line
      /registry\.npmjs\.org\/.+\/-\/.+\/publish/i,              // publishguard-disable-line
      /\bnpm-registry-fetch\b/,                                 // publishguard-disable-line
    ],
    message: 'Invokes an npm publish operation from within package code (self-propagation).', // publishguard-disable-line
    remediation: 'Package runtime/install code must never call `npm publish`. This is a worm hallmark.', // publishguard-disable-line
  },
  {
    id: 'PG006',
    name: 'network-exfil',
    severity: 'HIGH',
    patterns: [
      /webhook\.site/i,                                 // publishguard-disable-line
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // publishguard-disable-line
      /\bpipedream\.net\b/i,                            // publishguard-disable-line
      /\brequestbin\b/i,                                // publishguard-disable-line
      /\btrufflehog\b/i,                                // publishguard-disable-line
    ],
    message: 'Contains an exfiltration/beacon endpoint (raw IP, webhook.site, requestbin, etc.).', // publishguard-disable-line
    remediation: 'Remove hardcoded beacon/exfil endpoints.',
  },
  {
    id: 'PG007',
    name: 'obfuscated-payload',
    severity: 'MEDIUM',
    patterns: [
      /\beval\s*\(/,                                                        // publishguard-disable-line
      /new\s+Function\s*\(/,                                                // publishguard-disable-line
      /Buffer\.from\([^)]*,\s*['"]base64['"]\)\s*\.toString/,               // publishguard-disable-line
      /child_process[\s\S]{0,40}\beval/,                                    // publishguard-disable-line
    ],
    message: 'Dynamically evaluates code or decodes a base64 payload (obfuscation).',
    remediation: 'Avoid eval/Function/base64-decode-then-run in published packages.',
  },
];

/**
 * Lines containing this marker are excluded from scanning. This lets
 * legitimate tooling (including PublishGuard's own rule definitions, or a
 * security library that must reference these strings) opt out of a match,
 * the same way `eslint-disable-line` works. Use sparingly and honestly.
 */
const SUPPRESS_MARKER = 'publishguard-disable-line';

/**
 * Strip lines that carry the suppression marker, preserving line count so
 * evidence offsets stay sane. Returns the sanitized text.
 */
function stripSuppressed(text) {
  if (!text.includes(SUPPRESS_MARKER)) return text;
  return text
    .split('\n')
    .map(line => (line.includes(SUPPRESS_MARKER) ? '' : line))
    .join('\n');
}

/**
 * Scan a blob of source text for behavioral signatures.
 * Returns array of findings (without file context).
 */
function scanText(rawText) {
  const text = stripSuppressed(rawText);
  const findings = [];
  for (const sig of SIGNATURES) {
    for (const pat of sig.patterns) {
      const m = pat.exec(text);
      if (m) {
        findings.push({
          rule: sig.id,
          name: sig.name,
          severity: sig.severity,
          message: sig.message,
          remediation: sig.remediation,
          evidence: text.slice(Math.max(0, m.index - 20), m.index + 60).replace(/\s+/g, ' ').trim(),
        });
        break; // one hit per signature per blob is enough
      }
    }
  }
  return findings;
}

/**
 * Compare current package.json lifecycle scripts to a baseline snapshot.
 * Returns findings for added (PG001) and changed (PG002) scripts.
 */
function diffLifecycleScripts(currentScripts, baselineScripts) {
  const findings = [];
  currentScripts = currentScripts || {};
  baselineScripts = baselineScripts || null;

  for (const name of LIFECYCLE_SCRIPTS) {
    const cur = currentScripts[name];
    if (cur === undefined) continue;

    if (baselineScripts === null) {
      // No baseline yet: any lifecycle script is worth surfacing as info-level
      // via the normal behavioral scan, not as a diff finding.
      continue;
    }

    const base = baselineScripts[name];
    if (base === undefined) {
      findings.push({
        rule: 'PG001',
        name: 'lifecycle-script-added',
        severity: 'CRITICAL',
        message: `Lifecycle script '${name}' was ADDED since the known-good baseline. This is the primary worm-injection vector.`,
        remediation: `If you did not intentionally add '${name}', your package may be compromised. Investigate before publishing.`,
        evidence: `${name}: ${cur}`.slice(0, 120),
      });
    } else if (base !== cur) {
      findings.push({
        rule: 'PG002',
        name: 'lifecycle-script-changed',
        severity: 'HIGH',
        message: `Lifecycle script '${name}' CHANGED since the known-good baseline.`,
        remediation: `Review the change to '${name}'. Unexpected edits to install scripts are a worm hallmark.`,
        evidence: `was: ${base} | now: ${cur}`.slice(0, 160),
      });
    }
  }
  return findings;
}

function worstSeverity(findings) {
  let worst = null;
  for (const f of findings) {
    if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

module.exports = {
  LIFECYCLE_SCRIPTS,
  SIGNATURES,
  SEVERITY_RANK,
  SUPPRESS_MARKER,
  scanText,
  diffLifecycleScripts,
  worstSeverity,
};
