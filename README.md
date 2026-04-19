# @kairosauth/api-guard

[![npm version](https://img.shields.io/npm/v/@kairosauth/api-guard)](https://www.npmjs.com/package/@kairosauth/api-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Multi-layer API protection for mission-critical applications.**

Shield wraps your API calls in 4 intelligent protection layers — rate limiting, circuit breaking, anomaly detection, and immutable on-chain audit trails. Stop abuse before it starts, fail fast when things break, and prove everything with tamper-proof evidence.

---

## Why Shield?

Most APIs ship with basic rate limiting and call it security. That is not enough.

Your API key is a **single point of failure**. If it leaks, gets scraped, or is brute-forced, basic rate limiting will not stop a sophisticated attacker from draining your account, executing unauthorized trades, or exfiltrating sensitive data.

**Shield adds defense-in-depth to any API** — the same multi-layer philosophy used to protect identity infrastructure at Kairos Lab, now available for your integrations.

| Layer | What it does | Why it matters |
|-------|-------------|----------------|
| **Rate Shield** | Sliding window rate limiting with per-endpoint granularity | Prevents abuse before you hit the API's own limits (and get banned) |
| **Circuit Breaker** | Automatic failure detection with OPEN / HALF_OPEN / CLOSED states | Stops cascading failures — your app fails fast instead of hanging |
| **Anomaly Detector** | Scoring-based pattern analysis: payload spikes, endpoint scanning, burst detection, bot detection | Catches reconnaissance and credential stuffing in real-time |
| **Audit Trail** | Merkle-tree anchored audit trail via Kairos Lab on-chain infrastructure | Immutable proof of every security event — tamper-proof compliance |

---

## Quick Start

### 1. Install

```bash
npm install @kairosauth/api-guard
```

### 2. Configure

```js
import { Shield } from '@kairosauth/api-guard';

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
    action: 'block',
  },
});
```

### 3. Protect

```js
const result = await shield.protect({
  clientId: apiKey,
  endpoint: '/api/v3/order',
  method: 'POST',
  payloadSize: body.length,
});

if (!result.allowed) {
  console.error(`Blocked by ${result.blockedBy}: ${result.reason}`);
  return;
}

// Make your API call
const response = await fetch(url, options);

// Report outcome to circuit breaker
shield.reportOutcome('/api/v3/order', response.ok, response.status);
```

That is it. Three steps to production-grade API protection.

---

## Architecture

```
                         +------------------+
                         |    Your App      |
                         +--------+---------+
                                  |
                          shield.protect(req)
                                  |
                    +-------------v--------------+
                    |        Rate Shield          |
                    |  Sliding window algorithm   |
                    |  Per-endpoint granularity    |
                    |  Predictive throttling       |
                    +-------------+--------------+
                                  |
                         allowed? |
                           +------+------+
                           |             |
                          YES         BLOCKED ---> onBlock()
                           |                       Audit Trail
                    +------v--------------+
                    |    Circuit Breaker   |
                    |  CLOSED > OPEN >     |
                    |  HALF_OPEN > CLOSED  |
                    +------+--------------+
                           |
                    +------v--------------+
                    |   Anomaly Detector   |
                    |  Scoring system       |
                    |  Pattern analysis     |
                    |  Custom rules         |
                    +------+--------------+
                           |
                          YES
                           |
                    +------v--------------+
                    |     Audit Trail      |
                    |  Hash > Merkle Tree  |
                    |  Anchor on-chain     |
                    +---------------------+
                           |
                    +------v--------------+
                    |     API Request      |
                    +---------------------+
```

Evaluation stops at the first blocking layer (fail-fast) to minimize overhead.

---

## AsterDex V3 Integration

Shield ships with a **pre-configured adapter for AsterDex V3** — tuned for the specific rate limits, endpoint patterns, and failure modes of the AsterDex trading API.

```js
import { createAsterDexV3Shield } from '@kairosauth/api-guard/adapters/asterdex-v3';

const shield = createAsterDexV3Shield({ verbose: true });

// Protect an order request
const result = await shield.protect({
  apiKey: process.env.ASTER_API_KEY,
  endpoint: '/api/v3/order',
  method: 'POST',
  bodySize: 256,
});

if (!result.allowed) {
  throw new Error(`Shield blocked: ${result.reason}`);
}

// ... execute order ...

// Report response
shield.reportResponse('/api/v3/order', 200);
```

### Pre-configured AsterDex V3 Limits

| Endpoint | Limit | Rationale |
|----------|-------|-----------|
| `/api/v3/order` | 10 req/s | Order spam protection |
| `/api/v3/cancel` | 10 req/s | Cancel spam protection |
| `/api/v3/position` | 50 req/s | Position queries |
| `/api/v3/account` | 50 req/s | Account queries |
| `/api/v3/ticker*` | 100 req/s | Market data (permissive) |
| General | 50 req/s | Default safety net |

All limits are overridable. Shield never locks you in.

### Wrapped Fetch

Automatically protect every request with zero boilerplate:

```js
const safeFetch = shield.wrapFetch(fetch, process.env.ASTER_API_KEY);

// This automatically runs Shield.protect() before fetch
// and reports the response status to the circuit breaker
const response = await safeFetch('https://api.asterdex.io/api/v3/account');
```

### EIP-712 Signing

Built-in helper for AsterDex V3 authentication:

```js
import { signAsterDexRequest } from '@kairosauth/api-guard/adapters/asterdex-v3';

const { signature, signedParams } = await signAsterDexRequest({
  params: { symbol: 'ETH-USDT', side: 'BUY', quantity: '1.5', price: '3200' },
  user: wallet.address,
  signer: wallet.address,
  nonce: Date.now(),
  wallet,
});
```

---

## Layers in Depth

### Rate Shield

Sliding window algorithm by default — no burst-at-boundary problem.

```js
const shield = new Shield({
  rateShield: {
    maxRequests: 100,
    windowMs: 60_000,
    strategy: 'sliding-window',   // or 'fixed-window'
    warningThreshold: 0.8,        // Warn at 80% usage

    // Per-endpoint overrides (supports * wildcards)
    endpointLimits: {
      '/api/orders': { maxRequests: 30, windowMs: 60_000 },
      '/api/market/*': { maxRequests: 500, windowMs: 60_000 },
    },
  },
});
```

The `warningThreshold` adds predictive throttling metadata to passing requests when usage is high. When usage exceeds 90%, Shield calculates a recommended delay to avoid hitting the hard limit.

### Circuit Breaker

Three-state protection against cascading failures:

```
CLOSED --> (failures >= threshold) --> OPEN --> (timeout) --> HALF_OPEN
                                                                 |
                                                         success | failure
                                                                 |
                                                          CLOSED   OPEN
```

```js
const shield = new Shield({
  circuitBreaker: {
    failureThreshold: 5,         // Open after 5 consecutive failures
    resetTimeoutMs: 30_000,      // Try again after 30s
    halfOpenSuccesses: 2,        // Need 2 successes to fully close
    failureStatusCodes: [500, 502, 503, 504, 429],
  },
});
```

### Anomaly Detector

Scoring-based detection catches threats that rate limiting alone misses:

```js
const shield = new Shield({
  anomalyDetector: {
    maxPayloadSize: 512_000,          // Oversized payload: +5 points
    endpointSpreadThreshold: 40,      // Endpoint scanning: +8 points
    burstFactor: 5,                   // Traffic spike: +6 points
    scoreThreshold: 10,               // Block when score >= 10
    action: 'block',                  // 'block' or 'flag' (allow but mark)

    // Custom rules return { score, reason } or null
    customRules: [
      (ctx) => {
        if (ctx.endpoint.includes('admin') && ctx.method === 'DELETE') {
          return { score: 10, reason: 'Destructive admin operation' };
        }
        return null;
      },
    ],
  },
});
```

Built-in detection rules and their scores:

| Rule | Score | Detects |
|------|-------|---------|
| Oversized Payload | 5 | Buffer overflow / data exfiltration |
| Endpoint Spread | 8 | API reconnaissance / scanning |
| Burst Detection | 6 | Credential stuffing / DDoS |
| Timing Regularity | 4 | Bot behavior (too-regular intervals) |
| Custom Rules | varies | Your own detection logic |

### Audit Trail

Every security event gets hashed and anchored on-chain via Kairos Lab infrastructure:

```js
const shield = new Shield({
  auditTrail: {
    apiEndpoint: 'https://api.kairosauth.io',
    apiKey: 'your-kairos-key',
    batchSize: 100,               // Anchor every 100 events
    flushIntervalMs: 300_000,     // Or every 5 minutes
    auditScope: 'blocks-only',   // 'all', 'blocks-only', 'anomalies-only'
  },
});
```

The audit trail creates an immutable, tamper-proof record. No one can retroactively delete evidence of a security incident.

---

## Event System

Shield emits events for real-time monitoring:

```js
const shield = new Shield({ /* config */ });

shield.on('block', (result) => {
  alerting.send(`Request blocked: ${result.reason}`);
});

shield.on('allow', (result) => {
  metrics.increment('api.requests.allowed');
});

shield.on('anomaly', ({ request, result, requestId }) => {
  logger.warn(`Anomaly detected: score ${result.metadata.score}`, {
    anomalies: result.metadata.anomalies,
  });
});
```

---

## Monitoring

```js
// Real-time status
const status = shield.getStatus();
console.log(status.layers.circuitBreaker);
// { active: true, circuits: { '/api/order': { state: 'CLOSED', failureCount: 0 } } }

// Metrics snapshot
const metrics = shield.getMetrics();
console.log(metrics.last60s);
// { total: 142, blocked: 3, allowed: 139, avgEvaluationMs: 0.12 }
```

---

## Configuration Reference

### Shield

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rateShield` | Object | - | Rate limiting config. Omit to disable. |
| `circuitBreaker` | Object | - | Circuit breaker config. Omit to disable. |
| `anomalyDetector` | Object | - | Anomaly detection config. Omit to disable. |
| `auditTrail` | Object | - | On-chain audit config. Omit to disable. |
| `onBlock` | Function | - | Called when a request is blocked. |
| `onAllow` | Function | - | Called when a request is allowed. |
| `onAnomaly` | Function | - | Called when an anomaly is detected. |
| `verbose` | boolean | `false` | Enable console logging. |

### RateShield

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxRequests` | number | `100` | Max requests per window. |
| `windowMs` | number | `60000` | Window duration in ms. |
| `strategy` | string | `'sliding-window'` | `'sliding-window'` or `'fixed-window'`. |
| `warningThreshold` | number | `0.8` | Usage ratio for early warning (0-1). |
| `endpointLimits` | Object | `{}` | Per-endpoint overrides (supports `*`). |

### CircuitBreaker

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `failureThreshold` | number | `5` | Failures before opening circuit. |
| `resetTimeoutMs` | number | `30000` | Wait before testing recovery. |
| `halfOpenSuccesses` | number | `2` | Successes needed to close circuit. |
| `failureStatusCodes` | number[] | `[500,502,503,504]` | Status codes treated as failures. |

### AnomalyDetector

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxPayloadSize` | number | `1048576` | Max payload size in bytes. |
| `endpointSpreadThreshold` | number | `50` | Max unique endpoints per window. |
| `spreadWindowMs` | number | `60000` | Window for spread detection. |
| `burstFactor` | number | `5` | Traffic spike sensitivity. |
| `scoreThreshold` | number | `10` | Score that triggers a block. |
| `customRules` | Function[] | `[]` | Custom detection rules. |
| `action` | string | `'block'` | `'block'` or `'flag'`. |

### AuditTrail

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiEndpoint` | string | **required** | Kairos Lab API endpoint. |
| `apiKey` | string | **required** | Kairos Lab API key. |
| `batchSize` | number | `100` | Events per Merkle batch. |
| `flushIntervalMs` | number | `300000` | Max time between flushes. |
| `auditScope` | string | `'blocks-only'` | `'all'`, `'blocks-only'`, `'anomalies-only'`. |

---

## Performance

Shield is designed to add **< 0.1ms** of latency per request. All layers operate in-memory with zero external dependencies (except Audit Trail, which is async and non-blocking).

| Operation | Time |
|-----------|------|
| Full evaluation (3 layers) | ~0.05ms |
| With Audit Trail flush | async, non-blocking |
| Memory per 1,000 tracked clients | ~2MB |

---

## Graceful Shutdown

```js
process.on('SIGTERM', async () => {
  await shield.shutdown(); // Flushes pending audit batches
  process.exit(0);
});
```

---

## Examples

See the [`examples/`](./examples) directory:

- **[asterdex-v3-basic.js](./examples/asterdex-v3-basic.js)** — Simple setup, order protection, circuit breaker handling
- **[asterdex-v3-advanced.js](./examples/asterdex-v3-advanced.js)** — Custom anomaly rules, audit trail, WebSocket protection, EIP-712 signing

---

## Links

- [Kairos Lab](https://kairosauth.io)
- [Documentation](https://kairosauth.io/docs/shield)
- [GitHub](https://github.com/kairoslab/kairosauth-shield)

---

**Powered by [Kairos Lab](https://kairosauth.io)**

MIT License
