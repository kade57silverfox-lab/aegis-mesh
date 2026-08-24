'use strict';

/**
 * Spins up several fake backend servers so the gateway has something real
 * to route traffic to. Each one has a different latency/failure profile so
 * the RoutingTable's "pick the fastest healthy upstream" logic has something
 * meaningful to react to.
 */
const http = require('http');

const PROFILES = [
  { port: 9001, name: 'upstream-1 (fast, reliable)', baseLatencyMs: 15, jitterMs: 15, failureRate: 0.01 },
  { port: 9002, name: 'upstream-2 (medium, occasional errors)', baseLatencyMs: 60, jitterMs: 40, failureRate: 0.05 },
  { port: 9003, name: 'upstream-3 (slow, flaky)', baseLatencyMs: 150, jitterMs: 100, failureRate: 0.10 },
];

function startUpstream({ port, name, baseLatencyMs, jitterMs, failureRate }) {
  const server = http.createServer((req, res) => {
    if (req.url === '/health') {
      // health checks stay fast/reliable regardless of profile so RoutingTable
      // latency comparisons reflect real traffic latency, not probe latency
      res.writeHead(200);
      res.end('ok');
      return;
    }

    const latency = baseLatencyMs + Math.random() * jitterMs;
    setTimeout(() => {
      if (Math.random() < failureRate) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'simulated upstream failure', server: name }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ server: name, path: req.url, latencyMs: Math.round(latency) }));
    }, latency);
  });

  server.listen(port, () => console.log(`[mock-upstream] ${name} listening on :${port}`));
}

PROFILES.forEach(startUpstream);
