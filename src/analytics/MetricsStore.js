'use strict';

const { RingBuffer } = require('../utils/ringbuffer');

/**
 * Generic named time-series store. Every metric gets its own ring buffer of
 * {ts, value} samples. This is the "data analyst" layer of the project: raw
 * events get turned into percentiles / moving averages / trend series that
 * the dashboard (or any future BI tool) can consume.
 */
class MetricsStore {
  constructor(config) {
    this.config = config;
    this.series = new Map(); // name -> RingBuffer
    this.latencySamples = new RingBuffer(config.metrics.seriesLength);
  }

  record(name, value) {
    if (!this.series.has(name)) {
      this.series.set(name, new RingBuffer(this.config.metrics.seriesLength));
    }
    this.series.get(name).push({ ts: Date.now(), value });
  }

  recordLatency(ms) {
    this.latencySamples.push(ms);
    this.record('latencyMs', ms);
  }

  percentile(name, p) {
    const buf = this.series.get(name);
    if (!buf) return null;
    const values = buf.toArray().map((s) => s.value).sort((a, b) => a - b);
    if (values.length === 0) return null;
    const idx = Math.min(values.length - 1, Math.floor((p / 100) * values.length));
    return values[idx];
  }

  movingAverage(name, windowCount = 30) {
    const buf = this.series.get(name);
    if (!buf) return null;
    const values = buf.last(windowCount).map((s) => s.value);
    if (values.length === 0) return null;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  latencyStats() {
    return {
      p50: this.percentile('latencyMs', 50),
      p95: this.percentile('latencyMs', 95),
      p99: this.percentile('latencyMs', 99),
      avg: this.movingAverage('latencyMs', 60),
    };
  }

  series_(name, count = 120) {
    const buf = this.series.get(name);
    if (!buf) return [];
    return buf.last(count);
  }
}

module.exports = { MetricsStore };
