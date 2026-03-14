# Examples

## AsterDex V3 Integration

### [`asterdex-v3-trading.ts`](./asterdex-v3-trading.ts)

Complete trading bot integration — EIP-712 signing, order placement, position management, all wrapped with Shield protection. Copy-paste ready.

```bash
# Required env vars
export ASTER_WALLET="0x..."        # Main wallet address
export ASTER_SIGNER="0x..."        # API wallet address
export ASTER_PRIVATE_KEY="0x..."   # API wallet private key
export KAIROS_API_KEY="..."        # Optional: for on-chain audit trail

npx tsx examples/asterdex-v3-trading.ts
```

### [`asterdex-v3-websocket.ts`](./asterdex-v3-websocket.ts)

WebSocket market data + Shield-protected REST execution. Shows the standard pattern for trading bots: stream data in real-time, execute with protection.

---

## General

### [`express-middleware.ts`](./express-middleware.ts)

Protect your own Express API with Shield middleware. Adds rate limit headers, request IDs, and a metrics endpoint.

---

## What Shield Does in These Examples

| Without Shield | With Shield |
|---|---|
| Hit AsterDex rate limit → 429 → possible IP ban (418) | Shield stops you before the 429 |
| AsterDex goes down → your bot hangs on timeouts | Circuit breaker fails fast, retries later |
| API key leaked → attacker drains account | Anomaly detector blocks unusual patterns |
| No proof of what happened | On-chain Merkle audit trail of every event |
