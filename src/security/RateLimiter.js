'use strict';

/**
 * Hybrid rate limiter:
 *  - Token bucket per client key (ip+fingerprint) handles burst shaping.
 *  - Sliding window count catches "low and slow" distributed abuse that
 *    a token bucket alone can tolerate (many clients each staying just
 *    under their own bucket limit).
 *
 * Capacity is scaled by a "posture multiplier" that PostureManager updates
 * live — this is the mechanism through which the gateway "mutates its own
 * security posture" at the rate-limiting layer.
 */
class RateLimiter {
  constructor(config) {
    this.config = config;
    this.buckets = new Map(); // key -> { tokens, lastRefillMs }
    this.windows = new Map(); // key -> number[] (timestamps ms)
    this.postureMultiplier = 1.0;
    this.stats = { allowed: 0, rejected: 0 };
  }

  setPostureMultiplier(multiplier) {
    this.postureMultiplier = multiplier;
  }

  _effectiveCapacity() {
    return Math.max(1, Math.floor(this.config.rateLimiter.bucketCapacity * this.postureMultiplier));
  }

  _effectiveRefillRate() {
    return Math.max(0.5, this.config.rateLimiter.refillRatePerSec * this.postureMultiplier);
  }

  _effectiveWindowMax() {
    return Math.max(1, Math.floor(this.config.rateLimiter.windowMaxRequests * this.postureMultiplier));
  }

  /** @returns {boolean} whether the request is allowed */
  allow(key) {
    const now = Date.now();
    const tokenOk = this._checkTokenBucket(key, now);
    const windowOk = this._checkSlidingWindow(key, now);
    const ok = tokenOk && windowOk;
    if (ok) this.stats.allowed += 1;
    else this.stats.rejected += 1;
    return ok;
  }

  _checkTokenBucket(key, now) {
    const capacity = this._effectiveCapacity();
    const refillRate = this._effectiveRefillRate();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: capacity, lastRefillMs: now };
      this.buckets.set(key, bucket);
    }
    const elapsedSec = (now - bucket.lastRefillMs) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * refillRate);
    bucket.lastRefillMs = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }
    return false;
  }

  _checkSlidingWindow(key, now) {
    const windowSize = this.config.rateLimiter.windowSizeMs;
    const maxRequests = this._effectiveWindowMax();
    let timestamps = this.windows.get(key);
    if (!timestamps) {
      timestamps = [];
      this.windows.set(key, timestamps);
    }
    // drop anything outside the window
    const cutoff = now - windowSize;
    while (timestamps.length && timestamps[0] < cutoff) timestamps.shift();

    if (timestamps.length >= maxRequests) return false;
    timestamps.push(now);
    return true;
  }

  rejectionRatio() {
    const total = this.stats.allowed + this.stats.rejected;
    return total === 0 ? 0 : this.stats.rejected / total;
  }

  /** periodic cleanup so long-idle clients don't leak memory forever */
  sweep() {
    const now = Date.now();
    const idleCutoffMs = 10 * 60 * 1000;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.lastRefillMs > idleCutoffMs) this.buckets.delete(key);
    }
    for (const [key, timestamps] of this.windows) {
      if (timestamps.length === 0 || now - timestamps[timestamps.length - 1] > idleCutoffMs) {
        this.windows.delete(key);
      }
    }
  }

  snapshot() {
    return {
      postureMultiplier: this.postureMultiplier,
      effectiveCapacity: this._effectiveCapacity(),
      effectiveRefillRate: Math.round(this._effectiveRefillRate() * 10) / 10,
      trackedClients: this.buckets.size,
      allowed: this.stats.allowed,
      rejected: this.stats.rejected,
      rejectionRatio: Math.round(this.rejectionRatio() * 1000) / 1000,
    };
  }
}

module.exports = { RateLimiter };
