# Autonomous Self-Optimizing API Gateway

A dependency-free (Node core modules only) reverse proxy that:

- **Routes dynamically** — picks upstreams by live EWMA latency + health, not static config.
- **Rate-limits adaptively** — hybrid token-bucket + sliding-window limiter whose capacity shrinks automatically under attack.
- **Fingerprints connections** — derives a JA3/JA4-style TLS+header fingerprint per client and tracks its reputation over time.
- **Detects anomalies statistically** — Welford's algorithm + EWMA + z-scores + Shannon entropy on payloads, no ML black box, fully explainable.
- **Mutates its own security posture** — a hysteresis-based state machine (`NORMAL → ELEVATED → LOCKDOWN`) that tightens rate limits, blocks bad fingerprints, and sheds load automatically, then relaxes once the attack score drops.
- **Exposes itself** — a JSON metrics API + a live single-page dashboard (charts, posture badge, routing table, fingerprint reputation).

No external npm packages are required to run the gateway itself — everything (HTTP parsing, TLS introspection, statistics, proxying) is hand-built on `http`/`https`/`net`/`tls`/`crypto`. This is intentional: it's the part of the project meant to demonstrate systems-level understanding rather than library plumbing.

## Folder layout

```
autonomous-api-gateway/
├── README.md                  ← you are here
├── ARCHITECTURE.md            ← diagrams + data flow + role mapping detail
├── package.json
├── config.js                  ← all tunables in one place
├── src/
│   ├── index.js                    ← composition root / bootstrap
│   ├── proxy/
│   │   ├── ProxyEngine.js          ← the actual reverse proxy (request pipeline)
│   │   ├── RoutingTable.js         ← EWMA latency tracking + upstream selection
│   │   └── HealthChecker.js        ← active health probes
│   ├── security/
│   │   ├── RateLimiter.js          ← token bucket + sliding window, posture-aware
│   │   ├── TlsFingerprint.js       ← fingerprint derivation + reputation store
│   │   ├── AnomalyDetector.js      ← statistical payload/traffic analysis
│   │   └── PostureManager.js       ← the "self-optimizing" state machine
│   ├── analytics/
│   │   ├── MetricsStore.js         ← in-memory time-series ring buffers
│   │   └── DashboardApi.js         ← JSON API consumed by the dashboard
│   └── utils/
│       ├── logger.js
│       └── ringbuffer.js
├── dashboard/
│   └── index.html              ← live single-page dashboard (Chart.js via CDN)
├── upstreams/
│   └── mock-upstream.js        ← spins up N fake backends with jittery latency
├── scripts/
│   └── generate-tls-certs.sh   ← local self-signed certs for HTTPS testing
└── test/
    └── load-test.js            ← simulates normal traffic, then a burst, to
                                    watch the posture manager escalate/de-escalate
```

## Running it

```bash
npm install               # installs zero runtime deps; only used if you add your own
bash scripts/generate-tls-certs.sh     # creates certs/ (self-signed, local only)

node upstreams/mock-upstream.js        # terminal 1: 3 fake backends on 9001-9003
node src/index.js                      # terminal 2: gateway on :8443 (TLS) + :8090 (dashboard API/UI)
node test/load-test.js                 # terminal 3: generate traffic, then a burst

# open http://localhost:8090 in a browser for the live dashboard
```

If `certs/` doesn't exist, the gateway automatically falls back to plain HTTP on `:8080` so you can test the logic without dealing with TLS first.

## How this single project covers all 7 roles

| Role | Where it shows up in this repo |
|---|---|
| **Software Engineer** | `RoutingTable.js` and `PostureManager.js` — designing the EWMA latency model and the hysteresis state machine is an algorithms/systems-design problem, not CRUD. Trade-offs (false-positive vs. false-negative escalation) are documented inline. |
| **Software Developer** | `ProxyEngine.js` — the actual request/response pipeline: streaming request bodies without buffering the whole payload in memory, error handling, graceful upstream failover, clean module boundaries. |
| **Cybersecurity** | `TlsFingerprint.js` + `AnomalyDetector.js` + `PostureManager.js` — fingerprint reputation, entropy-based payload inspection, adaptive rate-limiting, automatic lockdown. This is the DDoS/anomaly-mitigation core. |
| **IT Support** | `HealthChecker.js` + structured `logger.js` + `/api/state` diagnostics endpoint — the kind of active monitoring, alerting thresholds, and human-readable status output an on-call engineer needs at 3am. |
| **Data Analyst** | `MetricsStore.js` — rolling percentiles (p50/p95/p99), moving averages, z-score computation. The dashboard's charts are literally a data-analysis deliverable sitting on top of raw traffic telemetry. |
| **Full-Stack Engineer** | The whole vertical slice: TCP/TLS layer → proxy logic → JSON API → browser dashboard consuming it live. Nothing is mocked at the UI layer; it's real state from a real running system. |
| **UI/UX Design Researcher** | `dashboard/index.html` — deliberately designed around *operator cognitive load during an incident*: the posture badge is the single largest visual element because that's the one fact an on-call person needs in under a second; everything else is progressive disclosure below it. See `ARCHITECTURE.md` for the design rationale. |

## What's already better than a typical portfolio version of this idea

1. **Explainable anomaly detection instead of a black-box ML claim.** Every escalation decision can be traced to specific numbers (z-score, entropy delta, fingerprint reputation) — this matters a lot in an interview, because you can defend *why* it fired.
2. **Hysteresis on the state machine.** A naive version flips NORMAL↔LOCKDOWN on every noisy sample. This one requires N consecutive intervals above/below threshold before transitioning, which is the actual technique used in real autoscalers/circuit breakers (and is a good thing to be able to talk about).
3. **Fingerprint reputation persists across requests**, so a client that behaves badly once doesn't get a clean slate on its next connection — the posture and the limiter both consult it.
4. **Zero-copy-ish streaming proxy** — request/response bodies are piped, not buffered, so the gateway doesn't fall over on large payloads.

## Suggested upgrades (good "future work" section for your writeup / demo)

- **True JA3/JA4 fingerprinting**: parse the raw TLS ClientHello before the handshake completes (needs a raw TCP listener in front of the TLS layer, or a native module) instead of the post-handshake approximation used here.
- **Distributed rate limiting**: swap the in-memory token buckets for Redis-backed counters so the gateway can run as a horizontally-scaled fleet with a shared view of abusive clients.
- **L4/eBPF mitigation**: for true volumetric DDoS, this app-layer gateway should hand off to an XDP/eBPF drop rule or a cloud scrubbing service — mention this limitation explicitly, it shows maturity.
- **ML-assisted anomaly scoring**: once you have enough labeled traffic, an isolation forest or a small autoencoder can complement (not replace) the statistical detector for multivariate anomalies.
- **mTLS control plane**: separate the dashboard/API from the public data plane with mutual TLS so metrics can't be scraped or posture manipulated by an attacker.
- **OpenTelemetry tracing** across gateway → upstream for real distributed tracing instead of just latency numbers.
- **Kubernetes operator** that reads the routing table and actually scales upstream replicas based on the same latency signal already being computed.
