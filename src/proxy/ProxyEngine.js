'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const { makeLogger } = require('../utils/logger');
const log = makeLogger('ProxyEngine');

const MAX_SNIFF_BYTES = 8192; // only sniff the first few KB of body for entropy scoring

/**
 * The actual reverse proxy. Streams request/response bodies (does not buffer
 * whole payloads in memory), and wires every request through:
 *   fingerprint -> anomaly observation -> rate limit -> route selection -> proxy -> record metrics
 */
class ProxyEngine {
  constructor(config, deps) {
    this.config = config;
    this.deps = deps; // { routingTable, rateLimiter, tlsFingerprint, anomalyDetector, metricsStore }
  }

  start() {
    const { certPath, keyPath, httpsPort, httpFallbackPort } = this.config.proxy;
    const handler = (req, res) => this._handleRequest(req, res);

    let server;
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      const options = { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
      server = https.createServer(options, handler);
      server.listen(httpsPort, () => log.info(`HTTPS reverse proxy listening on :${httpsPort}`));
    } else {
      log.warn(`no TLS certs found at ${certPath} — falling back to plain HTTP on :${httpFallbackPort}`);
      server = http.createServer(handler);
      server.listen(httpFallbackPort, () => log.info(`HTTP reverse proxy listening on :${httpFallbackPort}`));
    }
    return server;
  }

  _handleRequest(clientReq, clientRes) {
    const { routingTable, rateLimiter, tlsFingerprint, anomalyDetector, metricsStore } = this.deps;
    const socket = clientReq.socket;
    const clientIp = socket.remoteAddress || 'unknown';

    // Register arrival BEFORE any accept/reject decision — attack volume must
    // register in the rate-anomaly stats even for requests we go on to reject,
    // otherwise a flood that's being successfully rate-limited looks calm.
    anomalyDetector.observeArrival();

    // Sniff up to MAX_SNIFF_BYTES of the body for entropy analysis, and always
    // drain the body (even on a request we're about to reject) so the socket
    // doesn't hang and the entropy signal isn't blind to rejected traffic.
    const sniffChunks = [];
    let sniffedBytes = 0;
    clientReq.on('data', (chunk) => {
      if (sniffedBytes < MAX_SNIFF_BYTES) {
        const take = chunk.slice(0, MAX_SNIFF_BYTES - sniffedBytes);
        sniffChunks.push(take);
        sniffedBytes += take.length;
      }
    });
    clientReq.on('end', () => {
      anomalyDetector.observeBody(Buffer.concat(sniffChunks));
    });

    const { fingerprint, protocol } = tlsFingerprint.derive(socket, clientReq);
    tlsFingerprint.observe(fingerprint, protocol);

    if (tlsFingerprint.isBlocked(fingerprint)) {
      clientReq.resume(); // ensure body drains even though we won't proxy it
      return this._reject(clientRes, 403, 'blocked: fingerprint reputation too low');
    }

    const limiterKey = `${clientIp}:${fingerprint}`;
    if (!rateLimiter.allow(limiterKey)) {
      clientReq.resume();
      return this._reject(clientRes, 429, 'rate limit exceeded');
    }

    const upstream = routingTable.selectUpstream();
    if (!upstream) {
      clientReq.resume();
      return this._reject(clientRes, 503, 'no healthy upstreams available');
    }

    const start = process.hrtime.bigint();
    const upstreamReq = http.request(
      {
        host: upstream.host,
        port: upstream.port,
        path: clientReq.url,
        method: clientReq.method,
        headers: { ...clientReq.headers, 'x-forwarded-for': clientIp, 'x-gateway-fingerprint': fingerprint },
        timeout: this.config.proxy.upstreamTimeoutMs,
      },
      (upstreamRes) => {
        const latencyMs = Number(process.hrtime.bigint() - start) / 1e6;
        routingTable.recordLatency(upstream.id, latencyMs);
        routingTable.recordRequestResult(upstream.id, upstreamRes.statusCode >= 500);
        metricsStore.recordLatency(latencyMs);

        clientRes.writeHead(upstreamRes.statusCode, upstreamRes.headers);
        upstreamRes.pipe(clientRes);
      }
    );

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy(new Error('upstream timeout'));
    });

    upstreamReq.on('error', (err) => {
      log.error(`upstream error from ${upstream.id}: ${err.message}`);
      routingTable.recordRequestResult(upstream.id, true);
      routingTable.markProbeResult(upstream.id, false, this.config.proxy.upstreamTimeoutMs);
      if (!clientRes.headersSent) {
        this._reject(clientRes, 502, `upstream ${upstream.id} unavailable`);
      } else {
        clientRes.end();
      }
    });

    clientReq.pipe(upstreamReq);
  }

  _reject(res, status, reason) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: reason, status }));
  }
}

module.exports = { ProxyEngine };
