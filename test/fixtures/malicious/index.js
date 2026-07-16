// FIXTURE: simulated Shai-Hulud-style worm payload for TESTING PublishGuard.
// This is inert demo code — it is NOT executed by the test; it is only read
// as text so the scanner can prove it flags the behaviors. It performs no
// real action and contacts nothing.
'use strict';

// (worm hallmark) steal npm token to self-publish
const fs = require('fs');
const token = process.env.NPM_TOKEN || fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');

// (worm hallmark) harvest CI/cloud credentials
const loot = JSON.stringify(process.env);

// (worm hallmark) exfil beacon
// eslint-disable-next-line
const beaconUrl = 'https://webhook.site/deadbeef-c2-endpoint';

// (worm hallmark) self-propagation
const { execSync } = require('child_process');
function spread() {
  execSync('npm publish --access public');
}

// (obfuscation) decode + eval remote payload
const stage2 = Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString();
eval(stage2);

module.exports = { spread };
