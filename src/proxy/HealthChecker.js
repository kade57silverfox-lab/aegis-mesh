'use strict';

const http = require('http');
const { makeLogger } = require('../utils/logger');
const log = makeLogger('HealthChecker');

/**
 * Periodically probes every configured upstream's /health endpoint,
 * measuring round-trip latency and feeding both latency and up/down status
 * back into the RoutingTable. This is what makes the routing table "live"
 * instead of a static list.
 */
class HealthChecker {
  constructor(config, routingTable) {
    this.config = config;
    this.routingTable = routingTable;
    this.timer = null;
  }

  start() {
    const interval = this.config.routing.healthCheckIntervalMs;
    this.timer = setInterval(() => this._probeAll(), interval);
    this._probeAll(); // probe immediately on boot instead of waiting a full interval
    log.info(`health checks started, interval=${interval}ms`);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  _probeAll() {
    for (const u of this.config.upstreams) {
      this._probeOne(u);
    }
  }

  _probeOne(u) {
    const start = process.hrtime.bigint();
    const req = http.get(
      { host: u.host, port: u.port, path: '/health', timeout: this.config.routing.healthCheckTimeoutMs },
      (res) => {
        const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;
        res.resume(); // drain
        const success = res.statusCode >= 200 && res.statusCode < 300;
        this.routingTable.markProbeResult(u.id, success, latencyMs);
      }
    );
    req.on('timeout', () => {
      req.destroy();
      this.routingTable.markProbeResult(u.id, false, this.config.routing.healthCheckTimeoutMs);
    });
    req.on('error', () => {
      this.routingTable.markProbeResult(u.id, false, this.config.routing.healthCheckTimeoutMs);
    });
  }
}

module.exports = { HealthChecker };
