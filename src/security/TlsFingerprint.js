'use strict';

const crypto = require('crypto');

/**
 * Derives a JA3/JA4-style fingerprint for each connection and tracks a
 * reputation score for it over time.
 *
 * NOTE on fidelity: true JA3 hashes the raw TLS ClientHello (protocol
 * version, cipher list, extensions, elliptic curves — all BEFORE the
 * handshake completes), which requires intercepting the raw TCP stream in
 * front of Node's TLS layer. Node's public `tls` API only exposes the
 * NEGOTIATED result (post-handshake), not the client's full offer list.
 *
 * This module builds a close, documented approximation from what IS
 * available post-handshake (negotiated protocol + cipher + ALPN) combined
 * with HTTP header ordering/casing, which is itself a well-known and
 * effective fingerprinting signal (it's most of what "JA4H" / HTTP
 * fingerprinting tools use). The README's "suggested upgrades" section
 * calls out swapping this for a raw-ClientHello parser as the natural
 * next step.
 */
class TlsFingerprint {
  constructor(config) {
    this.config = config;
    this.reputations = new Map(); // fingerprint -> { score, lastSeen, violations, requests }
  }

  /**
   * @param {import('tls').TLSSocket|import('net').Socket} socket
   * @param {import('http').IncomingMessage} req
   */
  derive(socket, req) {
    const isTls = typeof socket.getProtocol === 'function';
    const protocol = isTls ? socket.getProtocol() || 'none' : 'none';
    const cipher = isTls && socket.getCipher ? (socket.getCipher()?.name || 'none') : 'none';
    const alpn = isTls && socket.alpnProtocol ? socket.alpnProtocol : 'none';

    // Header order + casing is stable per HTTP client implementation
    // (curl, a browser, a custom script all order/case headers differently).
    const headerSignature = Object.keys(req.headers).join(',');

    const raw = `${protocol}|${cipher}|${alpn}|${headerSignature}|${req.headers['user-agent'] || ''}`;
    const fingerprint = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32);

    return { fingerprint, protocol, cipher, alpn };
  }

  /** Call once per request to register activity and check the negotiated TLS strength. */
  observe(fingerprint, protocol) {
    let rep = this.reputations.get(fingerprint);
    if (!rep) {
      rep = { score: 0, lastSeen: Date.now(), violations: 0, requests: 0 };
      this.reputations.set(fingerprint, rep);
    }
    rep.requests += 1;
    rep.lastSeen = Date.now();

    if (this.config.fingerprint.weakTlsVersions.includes(protocol)) {
      this.penalize(fingerprint, 'weak-tls-version');
    }
    return rep;
  }

  penalize(fingerprint, reason) {
    let rep = this.reputations.get(fingerprint);
    if (!rep) {
      rep = { score: 0, lastSeen: Date.now(), violations: 0, requests: 0 };
      this.reputations.set(fingerprint, rep);
    }
    rep.violations += 1;
    const raw = rep.score + this.config.fingerprint.reputationPenaltyPerViolation;
    rep.score = Math.min(1, Math.round(raw * 1000) / 1000);
    rep.lastReason = reason;
  }

  isBlocked(fingerprint) {
    const rep = this.reputations.get(fingerprint);
    return !!rep && rep.score >= this.config.fingerprint.blockReputationThreshold;
  }

  /** Aggregate penalty signal (0..1) fed into PostureManager's attack score. */
  aggregateReputationPenalty() {
    const reps = [...this.reputations.values()];
    if (reps.length === 0) return 0;
    const active = reps.filter((r) => Date.now() - r.lastSeen < 30_000);
    if (active.length === 0) return 0;
    const avg = active.reduce((sum, r) => sum + r.score, 0) / active.length;
    return avg;
  }

  /** Decay all reputations slightly toward 0 each tick so past bad behavior isn't permanent. */
  decayTick() {
    const decay = this.config.fingerprint.reputationDecayPerTick;
    for (const rep of this.reputations.values()) {
      rep.score = Math.max(0, rep.score - decay);
    }
  }

  snapshot(limit = 20) {
    return [...this.reputations.entries()]
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, limit)
      .map(([fp, rep]) => ({
        fingerprint: fp,
        score: Math.round(rep.score * 1000) / 1000,
        violations: rep.violations,
        requests: rep.requests,
        blocked: rep.score >= this.config.fingerprint.blockReputationThreshold,
      }));
  }
}

module.exports = { TlsFingerprint };
