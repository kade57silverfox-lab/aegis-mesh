'use strict';

module.exports = {
  proxy: {
    httpsPort: 8443,
    httpFallbackPort: 8080,
    certPath: __dirname + '/certs/server.cert',
    keyPath: __dirname + '/certs/server.key',
    upstreamTimeoutMs: 4000,
  },

  dashboard: {
    port: 8090,
  },

  upstreams: [
    { id: 'upstream-1', host: '127.0.0.1', port: 9001, weight: 1 },
    { id: 'upstream-2', host: '127.0.0.1', port: 9002, weight: 1 },
    { id: 'upstream-3', host: '127.0.0.1', port: 9003, weight: 1 },
  ],

  routing: {
    // Smoothing factor for the EWMA latency estimate. Higher = reacts faster
    // to recent samples, lower = smoother/more stable.
    latencyEwmaAlpha: 0.3,
    healthCheckIntervalMs: 2000,
    healthCheckTimeoutMs: 1500,
    // consecutive failed probes before an upstream is marked unhealthy
    unhealthyAfterFailures: 2,
    // consecutive successful probes before an unhealthy upstream is restored
    healthyAfterSuccesses: 2,
  },

  rateLimiter: {
    // token bucket
    bucketCapacity: 40,          // max burst per client
    refillRatePerSec: 10,        // tokens/sec under NORMAL posture
    // sliding window (secondary guard against distributed low-and-slow bursts)
    windowSizeMs: 10_000,
    windowMaxRequests: 150,
    // multipliers applied by PostureManager to shrink capacity under attack
    postureMultipliers: {
      NORMAL: 1.0,
      ELEVATED: 0.5,
      LOCKDOWN: 0.15,
    },
  },

  anomaly: {
    // how often (ms) we recompute rolling stats and roll the per-second counters
    tickIntervalMs: 1000,
    rateZScoreThreshold: 3.0,
    entropyLowThreshold: 1.5,   // suspiciously repetitive payloads (e.g. flood of identical junk)
    entropyHighThreshold: 7.8,  // suspiciously high-entropy payloads (near-random / possibly obfuscated)
    minSamplesBeforeScoring: 5,
    // EWMA smoothing for the request-rate baseline. Kept separate from the
    // outlier-path alpha so a genuine attack can't quickly drag the baseline
    // up to meet it (see AnomalyDetector.tick() for the outlier-guard logic).
    baselineAlpha: 0.1,
    baselineOutlierAlpha: 0.01,
  },

  posture: {
    evaluateIntervalMs: 2000,
    escalateThreshold: 0.4,
    lockdownThreshold: 0.7,
    deescalateThreshold: 0.2,
    consecutiveTicksToEscalate: 3,
    consecutiveTicksToDeescalate: 5,
    scoreWeights: {
      rateAnomaly: 0.35,
      entropyAnomaly: 0.20,
      fingerprintReputation: 0.30,
      rejectionRatio: 0.15,
    },
  },

  fingerprint: {
    // reputation decays toward 0 (neutral) over time if a fingerprint behaves
    reputationDecayPerTick: 0.02,
    reputationPenaltyPerViolation: 0.18,
    blockReputationThreshold: 0.9,
    weakTlsVersions: ['TLSv1', 'TLSv1.1'],
  },

  metrics: {
    // ring buffer length per series (1 sample/sec => 1 hour of history)
    seriesLength: 3600,
  },
};
