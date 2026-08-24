'use strict';

const config = require('../config');
const { makeLogger } = require('./utils/logger');
const { RoutingTable } = require('./proxy/RoutingTable');
const { HealthChecker } = require('./proxy/HealthChecker');
const { ProxyEngine } = require('./proxy/ProxyEngine');
const { RateLimiter } = require('./security/RateLimiter');
const { TlsFingerprint } = require('./security/TlsFingerprint');
const { AnomalyDetector } = require('./security/AnomalyDetector');
const { PostureManager } = require('./security/PostureManager');
const { MetricsStore } = require('./analytics/MetricsStore');
const { DashboardApi } = require('./analytics/DashboardApi');

const log = makeLogger('bootstrap');

function main() {
  const routingTable = new RoutingTable(config);
  const rateLimiter = new RateLimiter(config);
  const tlsFingerprint = new TlsFingerprint(config);
  const anomalyDetector = new AnomalyDetector(config);
  const metricsStore = new MetricsStore(config);

  const postureManager = new PostureManager(config, {
    anomalyDetector,
    tlsFingerprint,
    rateLimiter,
    routingTable,
    metricsStore,
  });

  const healthChecker = new HealthChecker(config, routingTable);
  const proxyEngine = new ProxyEngine(config, {
    routingTable,
    rateLimiter,
    tlsFingerprint,
    anomalyDetector,
    metricsStore,
  });
  const dashboardApi = new DashboardApi(config, {
    routingTable,
    rateLimiter,
    tlsFingerprint,
    anomalyDetector,
    postureManager,
    metricsStore,
  });

  healthChecker.start();
  postureManager.start();
  proxyEngine.start();
  dashboardApi.start();

  // per-second anomaly tick + fingerprint reputation decay
  setInterval(() => {
    anomalyDetector.tick();
    tlsFingerprint.decayTick();
  }, config.anomaly.tickIntervalMs);

  // periodic cleanup of idle rate-limiter state
  setInterval(() => rateLimiter.sweep(), 60_000);

  log.info('gateway fully initialized', {
    upstreams: config.upstreams.map((u) => u.id),
    dashboardPort: config.dashboard.port,
  });

  process.on('SIGINT', () => {
    log.info('shutting down');
    healthChecker.stop();
    postureManager.stop();
    process.exit(0);
  });
}

main();
