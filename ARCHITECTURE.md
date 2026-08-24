# Architecture

## Request lifecycle

```
Client
  │  TLS handshake (or plain HTTP fallback)
  ▼
┌───────────────────────────────────────────────────────────┐
│                      ProxyEngine                           │
│  1. Extract client IP + derive TLS/header fingerprint       │
│  2. AnomalyDetector.observe(req)  → rate/entropy z-scores   │
│  3. TlsFingerprint reputation lookup                        │
│  4. RateLimiter.allow(ip, fingerprint)  → 429 if rejected    │
│  5. RoutingTable.selectUpstream()  → least-latency healthy   │
│  6. Stream request → upstream, stream response → client     │
│  7. Record latency + status back into RoutingTable/Metrics   │
└───────────────────────────────────────────────────────────┘
        │                          │                    │
        ▼                          ▼                    ▼
  HealthChecker            PostureManager          MetricsStore
  (active probes,          (reads aggregate        (time series,
   updates routing         attack score every       feeds Dashboard
   table health)           2s, transitions           API)
                           NORMAL/ELEVATED/
                           LOCKDOWN, mutates
                           RateLimiter +
                           TlsFingerprint block-
                           list + RoutingTable
                           capacity)
```

## The posture state machine

```
        score < deescalate_threshold for N ticks
   ┌────────────────────────────────────────────┐
   │                                              │
   ▼                                              │
┌────────┐   score > escalate_threshold   ┌───────────┐   score > lockdown_threshold   ┌──────────┐
│ NORMAL │ ───────────────────────────────▶ ELEVATED  │ ───────────────────────────────▶ LOCKDOWN │
└────────┘   for N consecutive ticks       └───────────┘   for N consecutive ticks       └──────────┘
   ▲                                              │                                            │
   └──────────────────────────────────────────────┴────────────────────────────────────────────┘
                        de-escalates one level at a time, never skips levels
```

Why hysteresis matters: without requiring N consecutive ticks above/below threshold,
a single noisy spike (e.g. one client uploading a large file) would trip the gateway
into LOCKDOWN and back every few seconds, which is worse than doing nothing — it adds
latency and rejected requests for legitimate traffic. Real autoscalers and circuit
breakers (Kubernetes HPA, AWS ALB target tracking, Netflix Hystrix) use the same
consecutive-breach pattern for exactly this reason.

## Attack score composition

```
attackScore = w1 * normalizedRateZScore
            + w2 * normalizedEntropyAnomaly
            + w3 * fingerprintReputationPenalty
            + w4 * rejectedRequestRatio
```

Weights and thresholds live in `config.js` so they can be tuned without touching logic.

## UI/UX design rationale for the dashboard

The dashboard is designed around one question an on-call engineer asks first during
an incident: **"how bad is it, right now, at a glance?"**

- The posture badge (`NORMAL` / `ELEVATED` / `LOCKDOWN`) is the single largest element
  on the page and uses a traffic-light color scheme — this is the only thing that
  needs to register in under one second of looking at the screen.
- Everything else is progressive disclosure: latency chart and routing table are
  "what's happening to good traffic," fingerprint reputation and rejection rate are
  "what's happening to bad traffic" — deliberately split into two visual zones so an
  engineer isn't forced to mentally merge the two questions.
- Numbers update by polling every 2s rather than a jittery real-time stream — during
  an actual incident, a dashboard that visibly jumps around every 100ms adds anxiety
  without adding decision-quality information.
- No red is used anywhere except the LOCKDOWN badge and blocked-fingerprint rows —
  color is reserved as a scarce signal, not decoration.
