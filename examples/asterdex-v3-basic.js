/**
 * AsterDex V3 — Basic Shield Usage
 * Powered by Kairos Lab
 *
 * This example demonstrates:
 *   1. Setting up Shield with the AsterDex V3 adapter
 *   2. Protecting an order request
 *   3. Handling circuit breaker events
 */

import { createAsterDexV3Shield } from '../src/adapters/asterdex-v3.js';

// ── Step 1: Create a Shield instance ────────────────────────────

const shield = createAsterDexV3Shield({
  verbose: true,

  // Listen for blocked requests
  onBlock: (result) => {
    console.error(`[BLOCKED] ${result.blockedBy}: ${result.reason}`);
  },
});

// Register event listeners for monitoring
shield.on('block', (result) => {
  console.warn(`Request ${result.requestId} was blocked by ${result.blockedBy}`);
});

shield.on('allow', (result) => {
  console.log(`Request ${result.requestId} allowed (${result.evaluationTimeMs.toFixed(2)}ms)`);
});

// ── Step 2: Protect API calls ───────────────────────────────────

const API_KEY = process.env.ASTER_API_KEY ?? 'demo-api-key';
const BASE_URL = 'https://api.asterdex.io';

async function placeOrder(symbol, side, quantity, price) {
  // Check Shield before making the API call
  const result = await shield.protect({
    apiKey: API_KEY,
    endpoint: '/api/v3/order',
    method: 'POST',
    bodySize: 256,
    metadata: { symbol, side },
  });

  if (!result.allowed) {
    console.error(`Order blocked: ${result.reason}`);

    // Check if it was the circuit breaker
    if (result.blockedBy === 'circuit-breaker') {
      const retryAfter = result.layers['circuit-breaker']?.metadata?.retryAfterSeconds;
      console.log(`Exchange may be down. Retry in ${retryAfter}s`);
    }

    return null;
  }

  // Shield approved — place the order
  console.log(`Placing ${side} order: ${quantity} ${symbol} @ ${price}`);

  try {
    const response = await fetch(`${BASE_URL}/api/v3/order`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify({
        symbol,
        side,
        type: 'LIMIT',
        quantity: String(quantity),
        price: String(price),
      }),
    });

    // Report outcome to Shield's circuit breaker
    shield.reportResponse('/api/v3/order', response.status);

    if (!response.ok) {
      const error = await response.text();
      console.error(`Order failed (${response.status}): ${error}`);
      return null;
    }

    const data = await response.json();
    console.log(`Order placed: ${data.orderId}`);
    return data;
  } catch (err) {
    // Network error — report failure
    shield.reportResponse('/api/v3/order', 0);
    console.error(`Network error: ${err.message}`);
    return null;
  }
}

// ── Step 3: Run the example ─────────────────────────────────────

async function main() {
  console.log('=== AsterDex V3 Shield — Basic Example ===\n');

  // Place a few orders
  await placeOrder('ETH-USDT', 'BUY', 1.5, 3200);
  await placeOrder('BTC-USDT', 'SELL', 0.1, 68000);
  await placeOrder('SOL-USDT', 'BUY', 50, 145);

  // Check Shield status
  const status = shield.getStatus();
  console.log('\n=== Shield Status ===');
  console.log(`Rate Shield: ${status.layers.rateShield.active ? 'Active' : 'Inactive'}`);
  console.log(`Circuit Breaker: ${status.layers.circuitBreaker.active ? 'Active' : 'Inactive'}`);
  console.log(`Anomaly Detector: ${status.layers.anomalyDetector.active ? 'Active' : 'Inactive'}`);

  // Check metrics
  const metrics = shield.getMetrics();
  console.log(`\nRequests (last 60s): ${metrics.last60s.total}`);
  console.log(`Blocked: ${metrics.last60s.blocked}`);
  console.log(`Avg evaluation: ${metrics.last60s.avgEvaluationMs.toFixed(3)}ms`);

  // Graceful shutdown
  await shield.shutdown();
  console.log('\nDone.');
}

main().catch(console.error);
