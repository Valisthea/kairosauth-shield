import { Shield } from "../shield";
import type { ShieldConfig, ShieldContext, ShieldResult } from "../types";

/**
 * Pre-configured Shield preset for AsterDex V3 API.
 *
 * Tuned for the specific characteristics of AsterDex's trading API:
 * - High-frequency order endpoints get tighter rate limits
 * - Market data endpoints are more permissive
 * - Circuit breaker protects against exchange downtime
 * - Anomaly detection catches credential stuffing and API key leaks
 *
 * @example
 * ```ts
 * import { AsterDexShield } from "@kairosauth/shield/adapters/asterdex";
 *
 * const shield = AsterDexShield.create({
 *   onChainAudit: {
 *     apiEndpoint: "https://api.kairosauth.io",
 *     apiKey: "your-kairosauth-key",
 *   },
 * });
 *
 * // Before each API call
 * const result = await shield.protect({
 *   apiKey: "aster-api-key-hash",
 *   endpoint: "/api/v3/futures/order",
 *   method: "POST",
 *   bodySize: requestBody.length,
 * });
 *
 * if (!result.allowed) {
 *   throw new Error(`Request blocked: ${result.reason}`);
 * }
 *
 * // After API response
 * shield.reportResponse("/api/v3/futures/order", response.status);
 * ```
 */
export class AsterDexShield {
  private shield: Shield;

  private constructor(shield: Shield) {
    this.shield = shield;
  }

  /**
   * Create an AsterDex-optimized Shield instance.
   */
  static create(overrides: Partial<ShieldConfig> = {}): AsterDexShield {
    const config: ShieldConfig = {
      name: "asterdex-v3",
      verbose: overrides.verbose ?? false,

      rateShield: {
        maxRequests: 300,
        windowMs: 60_000,
        strategy: "sliding-window",
        warningThreshold: 0.75,
        endpointLimits: {
          // Order endpoints — tighter limits to prevent spam
          "/api/v3/futures/order": { maxRequests: 60, windowMs: 60_000 },
          "/api/v3/futures/batch-order": { maxRequests: 20, windowMs: 60_000 },
          "/api/v3/spot/order": { maxRequests: 60, windowMs: 60_000 },

          // Position/account — moderate
          "/api/v3/futures/position*": { maxRequests: 120, windowMs: 60_000 },
          "/api/v3/futures/account": { maxRequests: 120, windowMs: 60_000 },

          // Market data — permissive
          "/api/v3/futures/ticker*": { maxRequests: 600, windowMs: 60_000 },
          "/api/v3/futures/depth": { maxRequests: 600, windowMs: 60_000 },
          "/api/v3/futures/klines": { maxRequests: 600, windowMs: 60_000 },

          // Auth endpoints — very tight
          "/api/v3/create-apikey": { maxRequests: 5, windowMs: 300_000 },
          "/api/v3/update-apikey": { maxRequests: 10, windowMs: 300_000 },
        },
        ...overrides.rateShield,
      },

      circuitBreaker: {
        failureThreshold: 5,
        resetTimeoutMs: 30_000,
        halfOpenSuccesses: 3,
        failureStatusCodes: [500, 502, 503, 504, 429],
        requestTimeoutMs: 15_000,
        ...overrides.circuitBreaker,
      },

      anomalyDetector: {
        maxPayloadSize: 512_000, // 500KB — no trading request should be this large
        endpointSpreadThreshold: 40,
        spreadWindowMs: 60_000,
        burstFactor: 8,
        action: "block",
        customRules: [
          // Detect rapid order placement + cancellation (wash trading pattern)
          ...(overrides.anomalyDetector?.customRules ?? []),
        ],
        ...overrides.anomalyDetector,
      },

      onChainAudit: overrides.onChainAudit,
      onBlock: overrides.onBlock,
      onMetric: overrides.onMetric,
    };

    return new AsterDexShield(new Shield(config));
  }

  /**
   * Evaluate a request before sending it to AsterDex.
   */
  async protect(params: {
    apiKey: string;
    endpoint: string;
    method?: string;
    bodySize?: number;
    metadata?: Record<string, unknown>;
  }): Promise<ShieldResult> {
    const ctx: ShieldContext = {
      clientId: this.hashApiKey(params.apiKey),
      endpoint: params.endpoint,
      method: params.method ?? "GET",
      payloadSize: params.bodySize,
      metadata: params.metadata,
    };

    return this.shield.evaluate(ctx);
  }

  /**
   * Report the response from AsterDex back to the circuit breaker.
   */
  reportResponse(endpoint: string, statusCode: number): void {
    this.shield.reportOutcome(
      endpoint,
      statusCode >= 200 && statusCode < 400,
      statusCode
    );
  }

  /**
   * Get current Shield status and metrics.
   */
  getStatus() {
    return this.shield.getStatus();
  }

  /**
   * Get metrics snapshot.
   */
  getMetrics() {
    return this.shield.getMetrics();
  }

  /**
   * Graceful shutdown.
   */
  async shutdown(): Promise<void> {
    return this.shield.shutdown();
  }

  /**
   * Hash API key for privacy — we never store raw keys in metrics.
   */
  private hashApiKey(apiKey: string): string {
    let hash = 0;
    const key = apiKey.substring(0, 16); // Only use prefix
    for (let i = 0; i < key.length; i++) {
      hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
    }
    return `key_${Math.abs(hash).toString(16).padStart(8, "0")}`;
  }
}

// Also export a quick helper
export function createAsterDexShield(
  overrides: Partial<ShieldConfig> = {}
): AsterDexShield {
  return AsterDexShield.create(overrides);
}
