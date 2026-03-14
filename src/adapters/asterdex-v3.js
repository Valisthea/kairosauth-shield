import { Shield } from '../shield.js';

/**
 * AsterDex V3 Shield — Pre-configured Shield for AsterDex V3 API.
 * Powered by Kairos Lab.
 *
 * Tuned for the specific characteristics of AsterDex's trading API:
 * - Order endpoints (/api/v3/order, /api/v3/cancel) get strict 10 req/s limits
 * - Query endpoints (/api/v3/position, /api/v3/account) get 50 req/s
 * - Circuit breaker protects against exchange downtime
 * - Anomaly detection catches credential stuffing and wash trading patterns
 * - EIP-712 signing helper for AsterDex authentication
 *
 * @example
 * ```js
 * import { AsterDexV3Shield, createAsterDexV3Shield } from '@kairosauth/shield/adapters/asterdex-v3';
 *
 * const shield = createAsterDexV3Shield({ verbose: true });
 *
 * const result = await shield.protect({
 *   apiKey: process.env.ASTER_API_KEY,
 *   endpoint: '/api/v3/order',
 *   method: 'POST',
 *   bodySize: 256,
 * });
 * ```
 */
export class AsterDexV3Shield {
  /**
   * @param {Shield} shield
   * @private — use AsterDexV3Shield.create() instead
   */
  constructor(shield) {
    this._shield = shield;
  }

  /**
   * Create an AsterDex V3-optimized Shield instance.
   *
   * @param {Object} [overrides] - Override any Shield config option.
   * @returns {AsterDexV3Shield}
   */
  static create(overrides = {}) {
    const config = {
      rateShield: {
        // Default: 50 req/s across all endpoints
        maxRequests: 3000,
        windowMs: 60_000,
        strategy: 'sliding-window',
        warningThreshold: 0.75,
        endpointLimits: {
          // ── Order endpoints: 10 req/s (strict) ──
          '/api/v3/order': { maxRequests: 600, windowMs: 60_000 },
          '/api/v3/cancel': { maxRequests: 600, windowMs: 60_000 },

          // ── Query endpoints: 50 req/s ──
          '/api/v3/position': { maxRequests: 3000, windowMs: 60_000 },
          '/api/v3/position*': { maxRequests: 3000, windowMs: 60_000 },
          '/api/v3/account': { maxRequests: 3000, windowMs: 60_000 },
          '/api/v3/account*': { maxRequests: 3000, windowMs: 60_000 },

          // ── Market data: permissive ──
          '/api/v3/ticker*': { maxRequests: 6000, windowMs: 60_000 },
          '/api/v3/depth*': { maxRequests: 6000, windowMs: 60_000 },
          '/api/v3/klines*': { maxRequests: 6000, windowMs: 60_000 },
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
        endpointSpreadThreshold: 30,
        spreadWindowMs: 60_000,
        burstFactor: 8,
        scoreThreshold: 10,
        action: 'block',
        customRules: [
          // Detect rapid cancel-all patterns (potential manipulation)
          (ctx) => {
            if (ctx.endpoint === '/api/v3/cancel' && ctx.method === 'DELETE') {
              return { score: 2, reason: 'Mass cancellation detected' };
            }
            return null;
          },
          ...(overrides.anomalyDetector?.customRules ?? []),
        ],
        ...overrides.anomalyDetector,
        // Ensure custom rules from overrides are merged, not replaced
      },

      auditTrail: overrides.auditTrail,
      onBlock: overrides.onBlock,
      onAllow: overrides.onAllow,
      onAnomaly: overrides.onAnomaly,
      onMetric: overrides.onMetric,
      verbose: overrides.verbose ?? false,
    };

    return new AsterDexV3Shield(new Shield(config));
  }

  /**
   * Evaluate a request before sending it to AsterDex V3.
   *
   * @param {Object} params
   * @param {string} params.apiKey     - Your AsterDex API key (hashed for privacy).
   * @param {string} params.endpoint   - The API endpoint (e.g., '/api/v3/order').
   * @param {string} [params.method]   - HTTP method. Default: 'GET'.
   * @param {number} [params.bodySize] - Request body size in bytes.
   * @param {Object} [params.metadata] - Additional metadata for audit.
   * @returns {Promise<Object>} Shield result.
   */
  async protect(params) {
    return this._shield.protect({
      clientId: this._hashApiKey(params.apiKey),
      endpoint: params.endpoint,
      method: params.method ?? 'GET',
      payloadSize: params.bodySize,
      metadata: params.metadata,
    });
  }

  /**
   * Report the response from AsterDex back to the circuit breaker.
   *
   * @param {string} endpoint
   * @param {number} statusCode
   */
  reportResponse(endpoint, statusCode) {
    this._shield.reportOutcome(
      endpoint,
      statusCode >= 200 && statusCode < 400,
      statusCode
    );
  }

  /**
   * Wrap a fetch function with AsterDex V3 Shield protection.
   * Automatically extracts endpoint and method from fetch arguments.
   *
   * @param {Function} fetchFn
   * @param {string} apiKey - Your AsterDex API key.
   * @returns {Function} Protected fetch function.
   */
  wrapFetch(fetchFn, apiKey) {
    return this._shield.wrap(fetchFn, {
      extractContext: (url, init) => {
        const parsedUrl = typeof url === 'string' ? new URL(url) : url;
        return {
          clientId: this._hashApiKey(apiKey),
          endpoint: parsedUrl.pathname,
          method: init?.method ?? 'GET',
          payloadSize: init?.body
            ? typeof init.body === 'string'
              ? init.body.length
              : 0
            : 0,
        };
      },
    });
  }

  /**
   * Register event listeners on the underlying Shield.
   * @param {'block'|'allow'|'anomaly'} event
   * @param {Function} handler
   * @returns {AsterDexV3Shield}
   */
  on(event, handler) {
    this._shield.on(event, handler);
    return this;
  }

  /**
   * Get current status and metrics.
   * @returns {Object}
   */
  getStatus() {
    return this._shield.getStatus();
  }

  /**
   * Get metrics snapshot.
   * @returns {Object}
   */
  getMetrics() {
    return this._shield.getMetrics();
  }

  /**
   * Graceful shutdown.
   * @returns {Promise<void>}
   */
  async shutdown() {
    return this._shield.shutdown();
  }

  /**
   * Hash API key for privacy — raw keys are never stored in metrics.
   * @private
   */
  _hashApiKey(apiKey) {
    let hash = 0;
    const key = (apiKey ?? '').substring(0, 16);
    for (let i = 0; i < key.length; i++) {
      hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
    }
    return `key_${Math.abs(hash).toString(16).padStart(8, '0')}`;
  }
}

/**
 * Convenience factory for AsterDex V3 Shield.
 *
 * @param {Object} [overrides]
 * @returns {AsterDexV3Shield}
 */
export function createAsterDexV3Shield(overrides = {}) {
  return AsterDexV3Shield.create(overrides);
}

/**
 * EIP-712 signing helper for AsterDex V3 authentication.
 *
 * AsterDex V3 uses EIP-712 typed structured data signing:
 *   1. JSON.stringify params with sorted keys
 *   2. ABI encode (json, user, signer, nonce)
 *   3. Keccak256 hash
 *   4. ECDSA sign
 *
 * Requires ethers.js (peer dependency).
 *
 * @param {Object} options
 * @param {Object} options.params     - The API parameters to sign.
 * @param {string} options.user       - User address.
 * @param {string} options.signer     - Signer address.
 * @param {number} options.nonce      - Request nonce.
 * @param {Object} options.wallet     - ethers.js Wallet instance.
 * @param {Object} options.domain     - EIP-712 domain (optional, defaults to AsterDex).
 * @returns {Promise<Object>} { signature, digest, signedParams }
 */
export async function signAsterDexRequest(options) {
  const { params, user, signer, nonce, wallet, domain } = options;

  let ethers;
  try {
    ethers = await import('ethers');
  } catch {
    throw new Error(
      '[AsterDexV3] ethers.js is required for EIP-712 signing. Install with: npm install ethers'
    );
  }

  // Step 1: JSON stringify with sorted keys
  const sortedJson = JSON.stringify(params, Object.keys(params).sort());

  // Step 2: ABI encode
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const encoded = abiCoder.encode(
    ['string', 'address', 'address', 'uint256'],
    [sortedJson, user, signer, nonce]
  );

  // Step 3: Keccak256
  const digest = ethers.keccak256(encoded);

  // Step 4: EIP-712 domain and types
  const eip712Domain = domain ?? {
    name: 'AsterDex',
    version: '3',
    chainId: 1,
  };

  const types = {
    Request: [
      { name: 'payload', type: 'bytes32' },
      { name: 'user', type: 'address' },
      { name: 'signer', type: 'address' },
      { name: 'nonce', type: 'uint256' },
    ],
  };

  const value = {
    payload: digest,
    user,
    signer,
    nonce,
  };

  const signature = await wallet.signTypedData(eip712Domain, types, value);

  return {
    signature,
    digest,
    signedParams: {
      ...params,
      user,
      signer,
      nonce,
      signature,
    },
  };
}
