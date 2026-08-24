'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { makeLogger } = require('../utils/logger');
const log = makeLogger('DashboardApi');

const DASHBOARD_DIR = path.join(__dirname, '..', '..', 'dashboard');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

/**
 * Small hand-rolled HTTP API (no Express — keeping the "zero runtime deps"
 * story consistent) that serves:
 *   GET /                -> the dashboard SPA
 *   GET /api/state       -> full JSON snapshot of everything the dashboard needs
 */
class DashboardApi {
  constructor(config, deps) {
    this.config = config;
    this.deps = deps; // { routingTable, rateLimiter, tlsFingerprint, anomalyDetector, postureManager, metricsStore }
  }

  start() {
    const server = http.createServer((req, res) => this._handle(req, res));
    server.listen(this.config.dashboard.port, () => {
      log.info(`dashboard + API listening on :${this.config.dashboard.port}`);
    });
    return server;
  }

  _handle(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.url === '/api/state') {
      const body = JSON.stringify(this._buildState());
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(body);
      return;
    }

    // static file serving for the dashboard SPA
    let filePath = req.url === '/' ? '/index.html' : req.url;
    filePath = path.join(DASHBOARD_DIR, filePath);
    if (!filePath.startsWith(DASHBOARD_DIR)) {
      res.writeHead(403);
      res.end('forbidden');
      return;
    }
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('not found');
        return;
      }
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    });
  }

  _buildState() {
    const { routingTable, rateLimiter, tlsFingerprint, anomalyDetector, postureManager, metricsStore } = this.deps;
    return {
      timestamp: Date.now(),
      posture: postureManager.snapshot(),
      routing: routingTable.snapshot(),
      rateLimiter: rateLimiter.snapshot(),
      fingerprints: tlsFingerprint.snapshot(),
      anomaly: anomalyDetector.snapshot(),
      latency: metricsStore.latencyStats(),
      latencySeries: metricsStore.series_('latencyMs', 120),
      attackScoreSeries: metricsStore.series_('attackScore', 120),
    };
  }
}

module.exports = { DashboardApi };
