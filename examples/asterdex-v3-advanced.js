/**
 * AsterDex V3 — Advanced Shield Usage
 * Powered by Kairos Lab
 *
 * This example demonstrates:
 *   1. Custom anomaly rules (wash trading detection)
 *   2. Audit trail with on-chain anchoring
 *   3. WebSocket protection
 *   4. Multi-endpoint configuration with wrapped fetch
 *   5. EIP-712 signing for authenticated requests
 */

import { createAsterDexV3Shield, signAsterDexRequest } from '../src/adapters/asterdex-v3.js';
import { Shield } from '../src/shield.js';

// ── Configuration ───────────────────────────────────────────────

const API_KEY = process.env.ASTER_API_KEY ?? 'demo-api-key';
const KAIROS_API_KEY = process.env.KAIROS_API_KEY ?? 'demo-kairos-key';
const BASE_URL = 'https://api.asterdex.io';
const WS_URL = 'wss://ws.asterdex.io';

// ── Step 1: Custom anomaly rules ────────────────────────────────

/**
 * Detect wash trading patterns:
 * Rapid buy/sell cycles on the same symbol within a short window.
 */
const recentOrders = new Map(); // symbol -> { buys: number, sells: number, windowStart: number }

function washTradingDetector(ctx) {
  if (ctx.endpoint !== '/api/v3/order' || ctx.method !== 'POST') return null;

  const symbol = ctx.metadata?.symbol;
  const side = ctx.metadata?.side;
  if (!symbol || !side) return null;

  const now = Date.now();
  let tracker = recentOrders.get(symbol);

  if (!tracker || now - tracker.windowStart > 30_000) {
    tracker = { buys: 0, sells: 0, windowStart: now };
    recentOrders.set(symbol, tracker);
  }

  if (side === 'BUY') tracker.buys++;
  if (side === 'SELL') tracker.sells++;

  // Flag if both buy and sell counts exceed threshold in the window
  if (tracker.buys >= 5 && tracker.sells >= 5) {
    return {
      score: 8,
      reason: `Wash trading pattern: ${tracker.buys} buys + ${tracker.sells} sells on ${symbol} in ${((now - tracker.windowStart) / 1000).toFixed(0)}s`,
    };
  }

  return null;
}

/**
 * Block oversized batch orders.
 */
function batchOrderSizeRule(ctx) {
  if (ctx.endpoint === '/api/v3/order' && ctx.payloadSize > 10_000) {
    return {
      score: 4,
      reason: `Unusually large order payload: ${(ctx.payloadSize / 1024).toFixed(1)}KB`,
    };
  }
  return null;
}

// ── Step 2: Create Shield with full configuration ───────────────

const shield = createAsterDexV3Shield({
  verbose: true,

  // Merge custom anomaly rules
  anomalyDetector: {
    customRules: [washTradingDetector, batchOrderSizeRule],
    scoreThreshold: 8,
  },

  // Enable on-chain audit trail
  auditTrail: {
    apiEndpoint: 'https://api.kairosauth.io',
    apiKey: KAIROS_API_KEY,
    batchSize: 50,
    flushIntervalMs: 60_000,
    auditScope: 'all', // Anchor everything, not just blocks
  },

  // Event handlers for monitoring dashboard
  onBlock: (result) => {
    console.error(`[ALERT] Request ${result.requestId} blocked by ${result.blockedBy}`);
    // In production: send to alerting system (PagerDuty, Slack, etc.)
  },

  onAnomaly: ({ request, result, requestId }) => {
    console.warn(`[ANOMALY] ${requestId}: score ${result.metadata.score}`);
    for (const a of result.metadata.anomalies) {
      console.warn(`  - [${a.rule}] ${a.detail} (score: ${a.score})`);
    }
  },

  onMetric: (metric) => {
    // In production: send to your metrics pipeline (DataDog, Prometheus, etc.)
    // datadog.increment('asterdex.shield.request', { blocked: !metric.allowed });
  },
});

// ── Step 3: Wrapped fetch for automatic protection ──────────────

const safeFetch = shield.wrapFetch(globalThis.fetch, API_KEY);

async function getAccountInfo() {
  // safeFetch automatically evaluates Shield before calling fetch
  // and reports the response status to the circuit breaker
  try {
    const response = await safeFetch(`${BASE_URL}/api/v3/account`, {
      method: 'GET',
      headers: { 'X-API-Key': API_KEY },
    });
    return await response.json();
  } catch (err) {
    if (err.code === 'SHIELD_BLOCKED') {
      console.error(`Account request blocked: ${err.shieldResult.reason}`);
      return null;
    }
    throw err;
  }
}

async function getPositions() {
  try {
    const response = await safeFetch(`${BASE_URL}/api/v3/position`, {
      method: 'GET',
      headers: { 'X-API-Key': API_KEY },
    });
    return await response.json();
  } catch (err) {
    if (err.code === 'SHIELD_BLOCKED') {
      console.error(`Position request blocked: ${err.shieldResult.reason}`);
      return null;
    }
    throw err;
  }
}

// ── Step 4: WebSocket protection ────────────────────────────────

/**
 * Shield for WebSocket messages — create a separate Shield instance
 * with configuration tuned for WebSocket traffic patterns.
 */
const wsShield = new Shield({
  rateShield: {
    maxRequests: 100,
    windowMs: 1_000, // Per-second rate limit for WS messages
    strategy: 'sliding-window',
    endpointLimits: {
      'subscribe': { maxRequests: 10, windowMs: 1_000 },
      'unsubscribe': { maxRequests: 10, windowMs: 1_000 },
      'ping': { maxRequests: 5, windowMs: 1_000 },
    },
  },
  anomalyDetector: {
    maxPayloadSize: 4096, // WS messages should be small
    burstFactor: 10,
    scoreThreshold: 8,
    action: 'block',
  },
  verbose: false,
});

class ProtectedWebSocket {
  constructor(url, apiKey) {
    this.url = url;
    this.apiKey = apiKey;
    this.ws = null;
    this.messageHandlers = new Map();
  }

  async connect() {
    console.log(`Connecting to ${this.url}...`);
    // In a real app: this.ws = new WebSocket(this.url);
    // For demo purposes, we simulate the connection
    console.log('WebSocket connected (simulated)');
  }

  /**
   * Send a message through the WebSocket with Shield protection.
   */
  async send(channel, data) {
    const payload = JSON.stringify(data);

    const result = await wsShield.protect({
      clientId: this.apiKey,
      endpoint: channel,
      method: 'WS',
      payloadSize: payload.length,
    });

    if (!result.allowed) {
      console.warn(`[WS Shield] Message to '${channel}' blocked: ${result.reason}`);
      return false;
    }

    // In a real app: this.ws.send(payload);
    console.log(`[WS] Sent to '${channel}': ${payload.substring(0, 80)}...`);
    return true;
  }

  async subscribe(channel) {
    return this.send('subscribe', { op: 'subscribe', channel });
  }

  async unsubscribe(channel) {
    return this.send('unsubscribe', { op: 'unsubscribe', channel });
  }

  close() {
    // In a real app: this.ws.close();
    wsShield.shutdown();
    console.log('WebSocket closed');
  }
}

// ── Step 5: EIP-712 signed request example ──────────────────────

async function placeSignedOrder(wallet, orderParams) {
  // First, check Shield
  const shieldResult = await shield.protect({
    apiKey: API_KEY,
    endpoint: '/api/v3/order',
    method: 'POST',
    bodySize: JSON.stringify(orderParams).length,
    metadata: {
      symbol: orderParams.symbol,
      side: orderParams.side,
    },
  });

  if (!shieldResult.allowed) {
    console.error(`Signed order blocked: ${shieldResult.reason}`);
    return null;
  }

  // Sign the request with EIP-712
  try {
    const { signedParams } = await signAsterDexRequest({
      params: orderParams,
      user: wallet.address,
      signer: wallet.address,
      nonce: Date.now(),
      wallet,
    });

    console.log('Order signed and ready to submit:', signedParams);
    // In production: submit signedParams to AsterDex API
    return signedParams;
  } catch (err) {
    console.error(`Signing failed: ${err.message}`);
    return null;
  }
}

// ── Main ────────────────────────────────────────────────────────

async function main() {
  console.log('=== AsterDex V3 Shield — Advanced Example ===\n');

  // 1. REST API with wrapped fetch
  console.log('--- REST API Protection ---');
  await getAccountInfo();
  await getPositions();

  // 2. Direct protect calls with metadata
  console.log('\n--- Order Protection with Anomaly Detection ---');
  for (let i = 0; i < 3; i++) {
    await shield.protect({
      apiKey: API_KEY,
      endpoint: '/api/v3/order',
      method: 'POST',
      bodySize: 200,
      metadata: { symbol: 'ETH-USDT', side: 'BUY' },
    });
  }

  // 3. WebSocket protection
  console.log('\n--- WebSocket Protection ---');
  const ws = new ProtectedWebSocket(WS_URL, API_KEY);
  await ws.connect();
  await ws.subscribe('orderbook:ETH-USDT');
  await ws.subscribe('trades:BTC-USDT');
  await ws.send('ping', { op: 'ping', ts: Date.now() });
  ws.close();

  // 4. Status and metrics
  console.log('\n--- Shield Status ---');
  const status = shield.getStatus();
  console.log(JSON.stringify(status, null, 2));

  // 5. EIP-712 signing (requires ethers.js)
  console.log('\n--- EIP-712 Signing (requires ethers.js) ---');
  console.log('Skipped: install ethers and provide a wallet to test signing');

  // Graceful shutdown
  await shield.shutdown();
  console.log('\nShutdown complete.');
}

main().catch(console.error);
