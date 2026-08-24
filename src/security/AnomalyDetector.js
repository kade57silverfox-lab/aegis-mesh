'use strict';

const { RingBuffer } = require('../utils/ringbuffer');

/**
 * Deep statistical pattern analysis of incoming traffic, entirely explainable
 * (no ML black box):
 *
 *  1. Request-rate anomaly: per-second request counts are tracked with
 *     Welford's online algorithm (running mean + variance in O(1) memory,
 *     numerically stable — no need to store every sample). Each new second's
 *     count is scored against the running distribution as a z-score.
 *
 *  2. Payload entropy anomaly: Shannon entropy of request bodies is computed
 *     per-request. Extremely LOW entropy across many requests suggests a
 *     flood of identical/templated attack payloads; extremely HIGH entropy
 *     suggests obfuscated/encrypted/random-junk payloads used to defeat
 *     signature matching. Both directions are tracked.
 */
class AnomalyDetector {
  constructor(config) {
    this.config = config;

    // EWMA baseline for the per-second request-rate distribution (NOT a
    // simple all-time average — see note below on why that matters).
    this.rateBaselineMean = 0;
    this.rateBaselineVariance = 1; // start with a small nonzero variance to avoid a divide-by-zero z-score
    this.rateSamplesSeen = 0;
    this.currentSecondCount = 0;
    this.rateHistory = new RingBuffer(config.metrics.seriesLength);
    this.lastRateZScore = 0;

    // Entropy tracking
    this.entropyHistory = new RingBuffer(config.metrics.seriesLength);
    this.lastEntropyAnomalyScore = 0;

    this.totalRequests = 0;
  }

  /**
   * Call the instant a request arrives — BEFORE any rate-limit/accept-reject
   * decision. Attack volume has to register here regardless of whether the
   * request ultimately gets rejected, or the detector would be blind to the
   * very thing (request-rate spikes) it exists to catch: a flood that's
   * being successfully rate-limited would otherwise look statistically calm.
   */
  observeArrival() {
    this.currentSecondCount += 1;
    this.totalRequests += 1;
  }

  /** Call once a request body is available (or drained), for any request regardless of outcome. */
  observeBody(bodySample) {
    if (bodySample && bodySample.length > 0) {
      const entropy = shannonEntropy(bodySample);
      this.entropyHistory.push(entropy);
      const { entropyLowThreshold, entropyHighThreshold } = this.config.anomaly;
      if (entropy < entropyLowThreshold || entropy > entropyHighThreshold) {
        this.lastEntropyAnomalyScore = Math.min(1, this.lastEntropyAnomalyScore + 0.15);
      }
    }
  }

  /** Call once per second (driven by PostureManager's tick or its own timer). */
  tick() {
    const count = this.currentSecondCount;
    this.currentSecondCount = 0;
    this.rateHistory.push(count);
    this.rateSamplesSeen += 1;

    // Score against the baseline BEFORE updating it, so a sample that's
    // already anomalous doesn't get to help set its own bar.
    const stddev = Math.sqrt(Math.max(this.rateBaselineVariance, 1e-6));
    if (this.rateSamplesSeen > this.config.anomaly.minSamplesBeforeScoring) {
      this.lastRateZScore = (count - this.rateBaselineMean) / stddev;
    } else {
      this.lastRateZScore = 0;
    }

    // Outlier-guarded EWMA update: a sustained flood must NOT get absorbed
    // into "normal," or the detector's own baseline drifts up to match the
    // attack and z-scores quietly decay back toward zero the longer the
    // attack continues — the opposite of what a DDoS detector should do.
    // Samples that look like a clear outlier only update the baseline with
    // a much smaller effective weight (they still nudge it a little, so a
    // genuine, permanent step-change in legitimate traffic is eventually
    // absorbed — just slowly, not instantly).
    const outlierGuardZ = this.config.anomaly.rateZScoreThreshold * 1.5;
    const isOutlier = this.rateSamplesSeen > this.config.anomaly.minSamplesBeforeScoring &&
      Math.abs(this.lastRateZScore) > outlierGuardZ;
    const alpha = isOutlier ? this.config.anomaly.baselineOutlierAlpha : this.config.anomaly.baselineAlpha;

    const delta = count - this.rateBaselineMean;
    this.rateBaselineMean += alpha * delta;
    // EWMA of squared deviation approximates a moving variance
    this.rateBaselineVariance = (1 - alpha) * this.rateBaselineVariance + alpha * delta * delta;

    // decay the entropy anomaly score so it reflects recent behavior, not all-time
    this.lastEntropyAnomalyScore = Math.max(0, this.lastEntropyAnomalyScore - 0.05);

    return {
      requestsThisSecond: count,
      rateZScore: this.lastRateZScore,
      entropyAnomalyScore: this.lastEntropyAnomalyScore,
    };
  }

  /** Normalized (0..1) rate anomaly signal for PostureManager's weighted score. */
  normalizedRateAnomaly() {
    const threshold = this.config.anomaly.rateZScoreThreshold;
    // Only escalating (positive) z-scores count as an attack signal — a sudden
    // *drop* in traffic isn't a DDoS concern.
    const z = Math.max(0, this.lastRateZScore);
    return Math.min(1, z / (threshold * 2));
  }

  normalizedEntropyAnomaly() {
    return this.lastEntropyAnomalyScore;
  }

  snapshot() {
    return {
      totalRequests: this.totalRequests,
      requestsThisSecond: this.currentSecondCount,
      rateBaselineMean: Math.round(this.rateBaselineMean * 100) / 100,
      rateZScore: Math.round(this.lastRateZScore * 100) / 100,
      entropyAnomalyScore: Math.round(this.lastEntropyAnomalyScore * 100) / 100,
      rateHistory: this.rateHistory.last(120),
      entropyHistory: this.entropyHistory.last(120).map((v) => Math.round(v * 100) / 100),
    };
  }
}

/** Shannon entropy in bits/byte over a buffer (0 = all identical bytes, 8 = perfectly uniform random). */
function shannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) freq[buffer[i]] += 1;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

module.exports = { AnomalyDetector, shannonEntropy };
