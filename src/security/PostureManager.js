'use strict';

const { makeLogger } = require('../utils/logger');
const log = makeLogger('PostureManager');

const LEVELS = ['NORMAL', 'ELEVATED', 'LOCKDOWN'];

/**
 * The "self-optimizing" / "mutates its own security posture" core.
 *
 * Every `evaluateIntervalMs`, it:
 *   1. Computes a weighted attack score from the AnomalyDetector + TlsFingerprint
 *      reputation + the rate limiter's own rejection ratio.
 *   2. Uses hysteresis (N consecutive ticks above/below threshold) to decide
 *      whether to escalate, hold, or de-escalate the posture level.
 *   3. On any transition, pushes new parameters into RateLimiter (capacity
 *      multiplier) and records the event for the dashboard/audit log.
 *
 * De-escalation always steps down one level at a time (never LOCKDOWN -> NORMAL
 * in one jump) so a temporarily-quiet attacker can't "reset" defenses instantly.
 */
class PostureManager {
  constructor(config, { anomalyDetector, tlsFingerprint, rateLimiter, routingTable, metricsStore }) {
    this.config = config;
    this.anomalyDetector = anomalyDetector;
    this.tlsFingerprint = tlsFingerprint;
    this.rateLimiter = rateLimiter;
    this.routingTable = routingTable;
    this.metricsStore = metricsStore;

    this.level = 'NORMAL';
    this.consecutiveAbove = 0;
    this.consecutiveBelow = 0;
    this.lastScore = 0;
    this.history = [];
    this.timer = null;

    this._applyLevel(this.level); // set initial multipliers
  }

  start() {
    const interval = this.config.posture.evaluateIntervalMs;
    this.timer = setInterval(() => this._evaluate(), interval);
    log.info(`posture manager started, interval=${interval}ms, level=${this.level}`);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  computeAttackScore() {
    const w = this.config.posture.scoreWeights;
    const rateAnomaly = this.anomalyDetector.normalizedRateAnomaly();
    const entropyAnomaly = this.anomalyDetector.normalizedEntropyAnomaly();
    const fingerprintPenalty = this.tlsFingerprint.aggregateReputationPenalty();
    const rejectionRatio = this.rateLimiter.rejectionRatio();

    const score =
      w.rateAnomaly * rateAnomaly +
      w.entropyAnomaly * entropyAnomaly +
      w.fingerprintReputation * fingerprintPenalty +
      w.rejectionRatio * rejectionRatio;

    return {
      score: Math.min(1, score),
      components: { rateAnomaly, entropyAnomaly, fingerprintPenalty, rejectionRatio },
    };
  }

  _evaluate() {
    const { score, components } = this.computeAttackScore();
    this.lastScore = score;
    const { escalateThreshold, lockdownThreshold, deescalateThreshold,
      consecutiveTicksToEscalate, consecutiveTicksToDeescalate } = this.config.posture;

    const currentIdx = LEVELS.indexOf(this.level);
    const wantsEscalate = this.level === 'NORMAL' ? score >= escalateThreshold : score >= lockdownThreshold;
    const wantsDeescalate = score < deescalateThreshold;

    if (wantsEscalate) {
      this.consecutiveAbove += 1;
      this.consecutiveBelow = 0;
    } else if (wantsDeescalate) {
      this.consecutiveBelow += 1;
      this.consecutiveAbove = 0;
    } else {
      this.consecutiveAbove = 0;
      this.consecutiveBelow = 0;
    }

    if (this.consecutiveAbove >= consecutiveTicksToEscalate && currentIdx < LEVELS.length - 1) {
      this._transitionTo(LEVELS[currentIdx + 1], score, components);
      this.consecutiveAbove = 0;
    } else if (this.consecutiveBelow >= consecutiveTicksToDeescalate && currentIdx > 0) {
      this._transitionTo(LEVELS[currentIdx - 1], score, components);
      this.consecutiveBelow = 0;
    }

    this.metricsStore?.record('attackScore', score);
    this.history.push({ ts: Date.now(), score, level: this.level, components });
    if (this.history.length > 500) this.history.shift();
  }

  _transitionTo(newLevel, score, components) {
    const oldLevel = this.level;
    this.level = newLevel;
    this._applyLevel(newLevel);
    log.warn(`posture transition ${oldLevel} -> ${newLevel}`, { score: Math.round(score * 1000) / 1000, components });
  }

  _applyLevel(level) {
    const multiplier = this.config.rateLimiter.postureMultipliers[level];
    this.rateLimiter.setPostureMultiplier(multiplier);

    // Under LOCKDOWN, also proactively shave capacity from any upstream that's
    // currently the slowest, treating it as a possible target/compromised node
    // being amplified against — a conservative, reversible move (it's restored
    // automatically once posture de-escalates).
    if (level === 'LOCKDOWN') {
      const snap = this.routingTable.snapshot().filter((u) => u.healthy);
      if (snap.length > 1) {
        const slowest = snap.reduce((a, b) => (a.latencyEwmaMs > b.latencyEwmaMs ? a : b));
        this.routingTable.setCapacityFactor(slowest.id, 0.4);
      }
    } else {
      for (const u of this.config.upstreams) this.routingTable.setCapacityFactor(u.id, 1.0);
    }
  }

  snapshot() {
    return {
      level: this.level,
      lastScore: Math.round(this.lastScore * 1000) / 1000,
      consecutiveAbove: this.consecutiveAbove,
      consecutiveBelow: this.consecutiveBelow,
      recentHistory: this.history.slice(-60),
    };
  }
}

module.exports = { PostureManager, LEVELS };
