'use strict';

const { makeLogger } = require('../utils/logger');
const log = makeLogger('RoutingTable');

/**
 * Tracks live health + latency for each upstream and picks the best one for
 * each incoming request. This is the "dynamically rewrites routing tables
 * based on upstream latency" requirement.
 *
 * Selection strategy: among healthy upstreams, pick the one with the lowest
 * EWMA latency, weighted by a small random jitter so we don't pin 100% of
 * traffic to a single upstream the instant it looks fastest (classic
 * "thundering herd onto the fastest node" failure mode).
 */
class RoutingTable {
  constructor(config) {
    this.config = config;
    this.upstreams = new Map();
    for (const u of config.upstreams) {
      this.upstreams.set(u.id, {
        ...u,
        latencyEwmaMs: 50, // optimistic prior so a cold-started upstream isn't shunned forever
        healthy: true,
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        activeConnections: 0,
        totalRequests: 0,
        totalErrors: 0,
        // "capacity factor" lets PostureManager throttle an upstream's share
        // of traffic (e.g. quarantine one that looks compromised) without
        // removing it outright.
        capacityFactor: 1.0,
      });
    }
  }

  recordLatency(upstreamId, ms) {
    const u = this.upstreams.get(upstreamId);
    if (!u) return;
    const alpha = this.config.routing.latencyEwmaAlpha;
    u.latencyEwmaMs = alpha * ms + (1 - alpha) * u.latencyEwmaMs;
  }

  recordRequestResult(upstreamId, isError) {
    const u = this.upstreams.get(upstreamId);
    if (!u) return;
    u.totalRequests += 1;
    if (isError) u.totalErrors += 1;
  }

  markProbeResult(upstreamId, success, latencyMs) {
    const u = this.upstreams.get(upstreamId);
    if (!u) return;
    if (success) {
      u.consecutiveSuccesses += 1;
      u.consecutiveFailures = 0;
      this.recordLatency(upstreamId, latencyMs);
      if (!u.healthy && u.consecutiveSuccesses >= this.config.routing.healthyAfterSuccesses) {
        u.healthy = true;
        log.info(`upstream ${upstreamId} marked HEALTHY again`);
      }
    } else {
      u.consecutiveFailures += 1;
      u.consecutiveSuccesses = 0;
      if (u.healthy && u.consecutiveFailures >= this.config.routing.unhealthyAfterFailures) {
        u.healthy = false;
        log.warn(`upstream ${upstreamId} marked UNHEALTHY`);
      }
    }
  }

  setCapacityFactor(upstreamId, factor) {
    const u = this.upstreams.get(upstreamId);
    if (u) u.capacityFactor = factor;
  }

  /** @returns the chosen upstream config, or null if none are healthy */
  selectUpstream() {
    const candidates = [...this.upstreams.values()].filter((u) => u.healthy && u.capacityFactor > 0);
    if (candidates.length === 0) return null;

    // score = latency / (weight * capacityFactor), lower is better.
    // Add up to 15% random jitter to avoid pinning all traffic to one node.
    let best = null;
    let bestScore = Infinity;
    for (const u of candidates) {
      const effectiveWeight = Math.max(0.01, u.weight * u.capacityFactor);
      const jitter = 1 + (Math.random() * 0.15);
      const score = (u.latencyEwmaMs * jitter) / effectiveWeight;
      if (score < bestScore) {
        bestScore = score;
        best = u;
      }
    }
    return best;
  }

  snapshot() {
    return [...this.upstreams.values()].map((u) => ({
      id: u.id,
      host: u.host,
      port: u.port,
      healthy: u.healthy,
      latencyEwmaMs: Math.round(u.latencyEwmaMs * 10) / 10,
      capacityFactor: u.capacityFactor,
      totalRequests: u.totalRequests,
      totalErrors: u.totalErrors,
    }));
  }
}

module.exports = { RoutingTable };
