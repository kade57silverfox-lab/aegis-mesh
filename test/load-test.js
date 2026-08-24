'use strict';

/**
 * Traffic simulator against your OWN local gateway, used to demonstrate the
 * self-optimizing behavior end-to-end:
 *   Phase 1 — normal, low-rate traffic for 15s (posture should stay NORMAL)
 *   Phase 2 — a concentrated burst for 20s (posture should escalate, then
 *             LOCKDOWN if the burst is sustained)
 *   Phase 3 — back to normal traffic for 20s (posture should de-escalate
 *             step by step back to NORMAL)
 *
 * This talks to the gateway's own HTTP fallback port by default (no certs
 * required to run this). Point it at the HTTPS port + `NODE_TLS_REJECT_UNAUTHORIZED=0`
 * if you generated certs and want to exercise the TLS path.
 */
const http = require('http');

const TARGET_HOST = process.env.GATEWAY_HOST || '127.0.0.1';
const TARGET_PORT = Number(process.env.GATEWAY_PORT || 8080);

function fireRequest(bodyOverride) {
  return new Promise((resolve) => {
    const body = bodyOverride || JSON.stringify({ hello: 'world', ts: Date.now() });
    const req = http.request(
      { host: TARGET_HOST, port: TARGET_PORT, path: '/api/ping', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }
    );
    req.on('error', () => resolve('ERR'));
    req.write(body);
    req.end();
  });
}

// low-entropy repeated junk payload, mimicking a crude flood attack
const ATTACK_PAYLOAD = 'A'.repeat(500);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Paces requests to hit an actual target rate: fires `requestsPerSecond`
 * requests once per second (in `concurrency`-sized parallel waves within
 * that second), for `seconds` seconds. This is what makes "5 req/s" and
 * "60 req/s" mean what they say, instead of just blasting as fast as
 * concurrency + upstream latency happen to allow.
 */
async function paced(seconds, requestsPerSecond, concurrency, payload) {
  const statusCounts = {};
  const record = (status) => { statusCounts[status] = (statusCounts[status] || 0) + 1; };

  for (let second = 0; second < seconds; second++) {
    const secondStart = Date.now();
    let launched = 0;
    const inFlightPromises = [];
    while (launched < requestsPerSecond) {
      const wave = [];
      for (let i = 0; i < concurrency && launched < requestsPerSecond; i++, launched++) {
        wave.push(fireRequest(payload).then(record));
      }
      inFlightPromises.push(...wave);
      await Promise.all(wave);
    }
    await Promise.all(inFlightPromises);
    const elapsed = Date.now() - secondStart;
    if (elapsed < 1000) await sleep(1000 - elapsed);
  }
  return statusCounts;
}

async function phase(label, seconds, requestsPerSecond, concurrency, payload) {
  console.log(`\n=== ${label} (${seconds}s @ ~${requestsPerSecond} req/s, concurrency=${concurrency}) ===`);
  const result = await paced(seconds, requestsPerSecond, concurrency, payload);
  console.log(`${label} results:`, result);
}

async function main() {
  console.log(`Load-testing gateway at http://${TARGET_HOST}:${TARGET_PORT}`);
  console.log('Watch the dashboard (http://localhost:8090) to see posture react live.\n');

  await phase('Phase 1: normal traffic', 15, 5, 3, null);
  await phase('Phase 2: attack burst', 20, 60, 40, ATTACK_PAYLOAD);
  await phase('Phase 3: recovery / normal traffic', 25, 5, 3, null);

  console.log('\nDone. Posture should have escalated during Phase 2 and stepped back down during Phase 3.');
}

main();
