/**
 * AsterDex V3 + Kairos Lab Shield — Complete Trading Integration
 *
 * This example shows how to protect your AsterDex V3 trading bot
 * with @kairosauth/shield. Copy, configure, trade safely.
 *
 * Install:
 *   npm install @kairosauth/shield ethers
 */

import { AsterDexShield } from "@kairosauth/shield/adapters/asterdex";
import { ethers } from "ethers";

// ─── Configuration ─────────────────────────────────────────────

const CONFIG = {
  // AsterDex
  baseUrl: "https://fapi.asterdex.com",
  user: process.env.ASTER_WALLET!, // Main wallet address
  signer: process.env.ASTER_SIGNER!, // API wallet address
  privateKey: process.env.ASTER_PRIVATE_KEY!, // API wallet private key
  recvWindow: 50000,

  // Kairos Lab Shield (optional on-chain audit)
  kairosApiEndpoint: "https://api.kairosauth.io",
  kairosApiKey: process.env.KAIROS_API_KEY,
};

// ─── Initialize Shield ─────────────────────────────────────────

const shield = AsterDexShield.create({
  verbose: true,

  // Enable on-chain audit trail (optional — remove if not needed)
  ...(CONFIG.kairosApiKey && {
    onChainAudit: {
      apiEndpoint: CONFIG.kairosApiEndpoint,
      apiKey: CONFIG.kairosApiKey,
    },
  }),

  // Get notified when Shield blocks a request
  onBlock: (result) => {
    console.warn(
      `[Shield] Blocked: ${result.reason} (${result.blockedBy})`
    );
  },
});

// ─── EIP-712 Signing (AsterDex V3 auth) ────────────────────────

function generateNonce(): string {
  return (Math.trunc(Date.now() * 1000)).toString();
}

function serializeParams(params: Record<string, unknown>): string {
  // Sorted keys, no spaces — deterministic serialization
  const sorted = Object.keys(params)
    .filter((k) => params[k] !== null && params[k] !== undefined)
    .sort()
    .reduce((acc, k) => {
      acc[k] = params[k];
      return acc;
    }, {} as Record<string, unknown>);
  return JSON.stringify(sorted);
}

async function signRequest(
  params: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const wallet = new ethers.Wallet(CONFIG.privateKey);
  const nonce = generateNonce();
  const timestamp = Date.now();

  // Add required fields
  const fullParams = {
    ...params,
    recvWindow: CONFIG.recvWindow,
    timestamp,
  };

  // Serialize → ABI encode → Keccak256 → Sign
  const json = serializeParams(fullParams);
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const encoded = abiCoder.encode(
    ["string", "address", "address", "uint256"],
    [json, CONFIG.user, CONFIG.signer, BigInt(nonce)]
  );
  const hash = ethers.keccak256(encoded);
  const signature = await wallet.signMessage(ethers.getBytes(hash));

  return {
    ...fullParams,
    nonce,
    user: CONFIG.user,
    signer: CONFIG.signer,
    signature,
  };
}

// ─── Protected API Call ─────────────────────────────────────────

async function protectedRequest(
  method: "GET" | "POST" | "PUT" | "DELETE",
  endpoint: string,
  params: Record<string, unknown> = {},
  signed = true
): Promise<unknown> {
  // Step 1: Ask Shield if this request should proceed
  const check = await shield.protect({
    apiKey: CONFIG.signer,
    endpoint,
    method,
    bodySize: JSON.stringify(params).length,
  });

  if (!check.allowed) {
    throw new ShieldBlockedError(
      check.reason ?? "Request blocked by Shield",
      check.blockedBy ?? "unknown",
      check.layers["rate-shield"]?.metadata?.retryAfterSeconds as number
    );
  }

  // Step 2: Sign the request (if authenticated endpoint)
  const signedParams = signed ? await signRequest(params) : params;

  // Step 3: Execute
  let url = `${CONFIG.baseUrl}${endpoint}`;
  const options: RequestInit = {
    method,
    headers: {} as Record<string, string>,
  };

  if (method === "GET") {
    const qs = new URLSearchParams(
      signedParams as Record<string, string>
    ).toString();
    url += `?${qs}`;
  } else {
    (options.headers as Record<string, string>)["Content-Type"] =
      "application/x-www-form-urlencoded";
    options.body = new URLSearchParams(
      signedParams as Record<string, string>
    ).toString();
  }

  const response = await fetch(url, options);

  // Step 4: Report outcome to circuit breaker
  shield.reportResponse(endpoint, response.status);

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new AsterDexError(
      response.status,
      (error as { code?: number }).code ?? -1,
      (error as { msg?: string }).msg ?? "Unknown error"
    );
  }

  return response.json();
}

// ─── Error Classes ──────────────────────────────────────────────

class ShieldBlockedError extends Error {
  constructor(
    message: string,
    public readonly layer: string,
    public readonly retryAfterSeconds?: number
  ) {
    super(message);
    this.name = "ShieldBlockedError";
  }
}

class AsterDexError extends Error {
  constructor(
    public readonly httpStatus: number,
    public readonly code: number,
    message: string
  ) {
    super(`AsterDex ${code}: ${message}`);
    this.name = "AsterDexError";
  }
}

// ─── Trading Functions ──────────────────────────────────────────

/** Place a limit order */
async function placeLimitOrder(
  symbol: string,
  side: "BUY" | "SELL",
  quantity: string,
  price: string
) {
  return protectedRequest("POST", "/fapi/v3/order", {
    symbol,
    side,
    type: "LIMIT",
    quantity,
    price,
    timeInForce: "GTC",
  });
}

/** Place a market order */
async function placeMarketOrder(
  symbol: string,
  side: "BUY" | "SELL",
  quantity: string
) {
  return protectedRequest("POST", "/fapi/v3/order", {
    symbol,
    side,
    type: "MARKET",
    quantity,
  });
}

/** Cancel an order */
async function cancelOrder(symbol: string, orderId: number) {
  return protectedRequest("DELETE", "/fapi/v3/order", {
    symbol,
    orderId: orderId.toString(),
  });
}

/** Get account balance */
async function getBalance() {
  return protectedRequest("GET", "/fapi/v3/balance");
}

/** Get open positions */
async function getPositions() {
  return protectedRequest("GET", "/fapi/v3/position");
}

/** Get open orders */
async function getOpenOrders(symbol?: string) {
  return protectedRequest("GET", "/fapi/v3/openOrders", {
    ...(symbol && { symbol }),
  });
}

/** Set leverage */
async function setLeverage(symbol: string, leverage: number) {
  return protectedRequest("POST", "/fapi/v3/leverage", {
    symbol,
    leverage: leverage.toString(),
  });
}

/** Check server time (public, no auth) */
async function getServerTime() {
  return protectedRequest("GET", "/fapi/v3/time", {}, false);
}

// ─── Example Usage ──────────────────────────────────────────────

async function main() {
  try {
    // Check Shield status
    console.log("Shield status:", JSON.stringify(shield.getStatus(), null, 2));

    // Public endpoint (no auth needed)
    const time = await getServerTime();
    console.log("Server time:", time);

    // Get balance
    const balance = await getBalance();
    console.log("Balance:", balance);

    // Place a limit order
    const order = await placeLimitOrder("BTCUSDT", "BUY", "0.001", "50000");
    console.log("Order placed:", order);

    // Check metrics after some operations
    const metrics = shield.getMetrics();
    console.log("Shield metrics:", {
      totalRequests: metrics.lifetime.totalRequests,
      blocked: metrics.lifetime.totalBlocked,
      avgLatency: `${metrics.last60s.avgEvaluationMs.toFixed(2)}ms`,
    });
  } catch (err) {
    if (err instanceof ShieldBlockedError) {
      console.error(`Shield blocked request (${err.layer}): ${err.message}`);
      if (err.retryAfterSeconds) {
        console.error(`Retry after ${err.retryAfterSeconds}s`);
      }
    } else if (err instanceof AsterDexError) {
      console.error(`AsterDex error ${err.code}: ${err.message}`);
      if (err.httpStatus === 418) {
        console.error("IP banned — Shield circuit breaker will handle this");
      }
    } else {
      console.error("Unexpected error:", err);
    }
  }
}

// Graceful shutdown
process.on("SIGTERM", async () => {
  await shield.shutdown();
  process.exit(0);
});

main();
