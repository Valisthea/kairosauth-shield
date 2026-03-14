# @kairosauth/shield

**Enterprise-grade API protection powered by Kairos Lab cryptographic infrastructure.**

Shield wraps your API calls in 4 intelligent protection layers — rate limiting, circuit breaking, anomaly detection, and immutable on-chain audit trails. Built by the team behind [Kairos Lab](https://kairosauth.io), the passwordless identity protocol with on-chain proof anchoring.

---

## Why Shield?

Most APIs ship with basic rate limiting and call it security. That's not enough.

Your API key is a **single point of failure**. If it leaks, gets scraped, or is brute-forced, basic rate limiting won't stop a sophisticated attacker from draining your account, executing unauthorized trades, or accessing sensitive data.

**Shield adds defense-in-depth to any API** — the same multi-layer philosophy we use to protect identity at Kairos Lab, now available for your API integrations.

| Layer | What it does | Why it matters |
|-------|-------------|----------------|
| **Rate Shield** | Intelligent rate limiting with per-endpoint granularity | Prevents abuse before you hit the API's own limits (and get banned) |
| **Circuit Breaker** | Automatic failure detection with OPEN/HALF_OPEN/CLOSED states | Stops cascading failures — your app fails fast instead of hanging |
| **Anomaly Detector** | Pattern analysis: payload spikes, endpoint scanning, burst detection | Catches reconnaissance and credential stuffing in real-time |
| **On-Chain Audit** | Merkle-tree anchored audit trail via Kairos Lab infrastructure | Immutable proof of every security event — tamper-proof compliance |

---

## Quick Start

```bash
npm install @kairosauth/shield
```

```ts
import { Shield } from "@kairosauth/shield";

const shield = new Shield({
  rateShield: {
    maxRequests: 200,
    windowMs: 60_000,
  },
  circuitBreaker: {
    failureThreshold: 5,
    resetTimeoutMs: 30_000,
  },
  anomalyDetector: {
    maxPayloadSize: 1_048_576,
    action: "block",
  },
});

// Before each API call
const result = await shield.evaluate({
  clientId: apiKey,
  endpoint: "/api/v3/futures/order",
  method: "POST",
  payloadSize: body.length,
});

if (!result.allowed) {
  console.error(`Blocked by ${result.blockedBy}: ${result.reason}`);
  return;
}

// Make your API call...
const response = await fetch(url, options);

// Report outcome to circuit breaker
shield.reportOutcome("/api/v3/futures/order", response.ok, response.status);
```

---

## AsterDex V3 Adapter

Shield ships with a **pre-configured adapter for AsterDex V3** — tuned for the specific rate limits, endpoint patterns, and failure modes of the AsterDex trading API.

```ts
import { AsterDexShield } from "@kairosauth/shield/adapters/asterdex";

const shield = AsterDexShield.create({
  verbose: true,
  // Optional: enable on-chain audit trail
  onChainAudit: {
    apiEndpoint: "https://api.kairosauth.io",
    apiKey: "your-kairosauth-key",
  },
});

// Protect an order request
const result = await shield.protect({
  apiKey: process.env.ASTER_API_KEY!,
  endpoint: "/api/v3/futures/order",
  method: "POST",
  bodySize: 256,
});

if (!result.allowed) {
  throw new Error(`Shield blocked: ${result.reason}`);
}

// ... execute order ...

// Report response
shield.reportResponse("/api/v3/futures/order", 200);
```

### Pre-configured limits for AsterDex V3

| Endpoint | Max/min | Rationale |
|----------|---------|-----------|
| `/api/v3/futures/order` | 60 | Order spam protection |
| `/api/v3/futures/batch-order` | 20 | Batch order throttle |
| `/api/v3/futures/ticker*` | 600 | Market data (permissive) |
| `/api/v3/create-apikey` | 5/5min | Key creation hardened |
| General | 300 | Default safety net |

All limits are overridable — Shield never locks you in.

---

## Layers in Depth

### Rate Shield

Sliding window algorithm by default — no burst-at-boundary problem.

```ts
const shield = new Shield({
  rateShield: {
    maxRequests: 100,
    windowMs: 60_000,
    strategy: "sliding-window", // or "fixed-window"
    warningThreshold: 0.8, // Warn at 80% usage

    // Per-endpoint overrides
    endpointLimits: {
      "/api/orders": { maxRequests: 30, windowMs: 60_000 },
      "/api/market/*": { maxRequests: 500, windowMs: 60_000 },
    },
  },
});
```

The `warningThreshold` adds metadata to passing requests when usage is high — perfect for proactive alerting before you hit limits.

### Circuit Breaker

Three-state protection against cascading failures:

```
CLOSED → (failures exceed threshold) → OPEN → (timeout) → HALF_OPEN → (success) → CLOSED
                                                              ↓ (failure)
                                                             OPEN
```

```ts
const shield = new Shield({
  circuitBreaker: {
    failureThreshold: 5,       // Open after 5 consecutive failures
    resetTimeoutMs: 30_000,    // Try again after 30s
    halfOpenSuccesses: 2,      // Need 2 successes to fully close
    failureStatusCodes: [500, 502, 503, 504, 429],
  },
});
```

### Anomaly Detector

Pattern-based detection catches threats that rate limiting alone misses:

```ts
const shield = new Shield({
  anomalyDetector: {
    maxPayloadSize: 512_000,        // Flag oversized payloads
    endpointSpreadThreshold: 40,    // Flag endpoint scanning
    burstFactor: 5,                 // Flag sudden traffic spikes
    action: "block",                // "block" or "flag" (allow but mark)

    // Custom rules
    customRules: [
      (ctx) => {
        if (ctx.endpoint.includes("admin") && ctx.method === "DELETE") {
          return "Destructive admin operation blocked";
        }
        return null;
      },
    ],
  },
});
```

### On-Chain Audit

Every security event gets anchored to the blockchain via Kairos Lab's Merkle infrastructure:

```ts
const shield = new Shield({
  onChainAudit: {
    apiEndpoint: "https://api.kairosauth.io",
    apiKey: "your-key",
    batchSize: 100,              // Anchor every 100 events
    flushIntervalMs: 300_000,    // Or every 5 minutes
    auditScope: "blocks-only",   // "all", "blocks-only", "anomalies-only"
  },
});
```

This creates an **immutable, tamper-proof audit trail** — no one can retroactively delete evidence of a security incident.

---

## Monitoring

```ts
// Real-time status
const status = shield.getStatus();
console.log(status.layers.circuitBreaker);
// { active: true, circuits: { "/api/order": { state: "CLOSED", failureCount: 0 } } }

// Metrics snapshot
const metrics = shield.getMetrics();
console.log(metrics.last60s);
// { total: 142, blocked: 3, allowed: 139, avgEvaluationMs: 0.12 }

// Callbacks for external monitoring
const shield = new Shield({
  onBlock: (result) => {
    alerting.send(`API request blocked: ${result.reason}`);
  },
  onMetric: (metric) => {
    datadog.increment("shield.requests", { blocked: !metric.allowed });
  },
});
```

---

## Express Middleware

```ts
import { Shield } from "@kairosauth/shield";
import express from "express";

const shield = new Shield({ /* config */ });

function shieldMiddleware(req, res, next) {
  shield.evaluate({
    clientId: req.ip,
    endpoint: req.path,
    method: req.method,
    payloadSize: parseInt(req.headers["content-length"] || "0"),
  }).then((result) => {
    if (!result.allowed) {
      res.status(429).json({
        error: result.reason,
        retryAfter: result.layers["rate-shield"]?.metadata?.retryAfterSeconds,
        requestId: result.requestId,
      });
    } else {
      res.setHeader("X-Shield-Request-Id", result.requestId);
      next();
    }
  });
}

app.use("/api", shieldMiddleware);
```

---

## Performance

Shield is designed to add **< 0.1ms** of latency per request. All layers operate in-memory with zero external dependencies (except On-Chain Audit, which is async and non-blocking).

| Operation | Time |
|-----------|------|
| Full evaluation (3 layers) | ~0.05ms |
| With On-Chain Audit flush | async, non-blocking |
| Memory per 1,000 tracked clients | ~2MB |

---

## Graceful Shutdown

```ts
process.on("SIGTERM", async () => {
  await shield.shutdown(); // Flushes pending audit batches
  process.exit(0);
});
```

---

## Architecture

Shield follows **Kairos Lab's zero-trust philosophy**: every layer is independent and fail-safe. If a layer throws an error, it defaults to **allow** — Shield never blocks legitimate traffic due to internal failures.

```
Request → Rate Shield → Circuit Breaker → Anomaly Detector → ✅ ALLOWED
              ↓                ↓                 ↓
          ❌ BLOCKED       ❌ BLOCKED        ❌ BLOCKED
              ↓                ↓                 ↓
         On-Chain Audit   On-Chain Audit    On-Chain Audit
```

Evaluation stops at the first blocking layer (fail-fast) to minimize overhead.

---

## Links

- **Kairos Lab** — [kairosauth.io](https://kairosauth.io)
- **Documentation** — [kairosauth.io/docs](https://kairosauth.io/docs)
- **Shield Protocol Status** — [kairosauth.io/proof](https://kairosauth.io/proof)
- **GitHub** — [github.com/Valisthea/kairosauth-shield](https://github.com/Valisthea/kairosauth-shield)

---

## License

MIT — [Kairos Lab](https://kairosauth.io)
