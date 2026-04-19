import { RateShield } from './layers/rate-shield.js';
import { CircuitBreaker } from './layers/circuit-breaker.js';
import { AnomalyDetector } from './layers/anomaly-detector.js';
import { AuditTrail } from './layers/audit-trail.js';
import { ShieldMetrics } from './metrics.js';

let idCounter = 0;

/**
 * Generate a unique request ID for tracing.
 * @returns {string}
 */
function generateRequestId() {
  const ts = Date.now().toString(36);
  const rnd = Math.random().toString(36).substring(2, 8);
  return `ksh_${ts}_${rnd}_${(idCounter++).toString(36)}`;
}

/**
 * Shield — Multi-layer API protection.
 * Powered by Kairos Lab.
 *
 * Runs requests through configurable protection layers:
 * Rate Shield -> Circuit Breaker -> Anomaly Detector
 * with optional on-chain audit trail anchoring.
 *
 * @example
 * ```js
 * import { Shield } from '@kairosauth/api-guard';
 *
 * const shield = new Shield({
 *   rateShield: { maxRequests: 200, windowMs: 60_000 },
 *   circuitBreaker: { failureThreshold: 5 },
 *   anomalyDetector: { maxPayloadSize: 1_048_576 },
 * });
 *
 * const result = await shield.protect({ clientId: ip, endpoint: '/api/order', method: 'POST' });
 * if (!result.allowed) throw new Error(result.reason);
 * ```
 */
export class Shield {
  /**
   * @param {Object} config
   * @param {Object} [config.rateShield]           - Rate limiting configuration. Omit to disable.
   * @param {Object} [config.circuitBreaker]       - Circuit breaker configuration. Omit to disable.
   * @param {Object} [config.anomalyDetector]      - Anomaly detection configuration. Omit to disable.
   * @param {Object} [config.auditTrail]           - On-chain audit trail configuration. Omit to disable.
   * @param {Function} [config.onBlock]            - Called when a request is blocked.
   * @param {Function} [config.onAllow]            - Called when a request is allowed.
   * @param {Function} [config.onAnomaly]          - Called when an anomaly is detected (even if allowed).
   * @param {Function} [config.onMetric]           - Called on every request for telemetry.
   * @param {boolean}  [config.verbose=false]      - Enable verbose logging to console.
   */
  constructor(config = {}) {
    this.config = config;
    this.metrics = new ShieldMetrics();

    // Initialize enabled layers
    this.rateShield = config.rateShield ? new RateShield(config.rateShield) : null;
    this.circuitBreaker = config.circuitBreaker ? new CircuitBreaker(config.circuitBreaker) : null;
    this.anomalyDetector = config.anomalyDetector ? new AnomalyDetector(config.anomalyDetector) : null;
    this.auditTrail = config.auditTrail ? new AuditTrail(config.auditTrail) : null;

    // Event listeners
    this._listeners = {
      block: [],
      allow: [],
      anomaly: [],
    };

    // Register config callbacks as listeners
    if (config.onBlock) this._listeners.block.push(config.onBlock);
    if (config.onAllow) this._listeners.allow.push(config.onAllow);
    if (config.onAnomaly) this._listeners.anomaly.push(config.onAnomaly);

    if (config.verbose) {
      const layers = this._getActiveLayerNames();
      console.log(`[Shield] Initialized with layers: ${layers.join(', ') || 'none'}`);
    }
  }

  /**
   * Register an event listener.
   * @param {'block'|'allow'|'anomaly'} event
   * @param {Function} handler
   * @returns {Shield} this (for chaining)
   */
  on(event, handler) {
    if (this._listeners[event]) {
      this._listeners[event].push(handler);
    }
    return this;
  }

  /**
   * Remove an event listener.
   * @param {'block'|'allow'|'anomaly'} event
   * @param {Function} handler
   * @returns {Shield} this
   */
  off(event, handler) {
    if (this._listeners[event]) {
      this._listeners[event] = this._listeners[event].filter((h) => h !== handler);
    }
    return this;
  }

  /**
   * Evaluate a request through all active protection layers.
   * Layers run in order: Rate Shield -> Circuit Breaker -> Anomaly Detector.
   * Evaluation stops at the first blocking layer (fail-fast).
   *
   * @param {Object} request
   * @param {string} request.clientId   - Client identifier (IP, API key, wallet address).
   * @param {string} request.endpoint   - The API endpoint being accessed.
   * @param {string} [request.method]   - HTTP method.
   * @param {number} [request.payloadSize] - Request body size in bytes.
   * @param {Object} [request.metadata] - Additional metadata for audit trail.
   * @returns {Promise<Object>} Shield result with allowed, blockedBy, reason, layers, etc.
   */
  async protect(request) {
    const start = performance.now();
    const requestId = generateRequestId();
    const layers = {};
    let blocked = false;
    let blockedBy = undefined;
    let reason = undefined;

    // Layer 1: Rate Shield
    if (this.rateShield && !blocked) {
      const result = this.rateShield.check(request);
      layers['rate-shield'] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = 'rate-shield';
        reason = result.reason;
      }
    }

    // Layer 2: Circuit Breaker
    if (this.circuitBreaker && !blocked) {
      const result = this.circuitBreaker.check(request);
      layers['circuit-breaker'] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = 'circuit-breaker';
        reason = result.reason;
      }
    }

    // Layer 3: Anomaly Detector
    if (this.anomalyDetector && !blocked) {
      const result = this.anomalyDetector.check(request);
      layers['anomaly-detector'] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = 'anomaly-detector';
        reason = result.reason;
      }
      // Emit anomaly event even if allowed (flag mode)
      if (result.metadata?.flagged) {
        this._emit('anomaly', { request, result, requestId });
      }
    }

    const evaluationTimeMs = performance.now() - start;

    const shieldResult = {
      allowed: !blocked,
      blockedBy,
      reason,
      layers,
      evaluationTimeMs,
      requestId,
    };

    // Build metric entry
    const metric = {
      timestamp: Date.now(),
      requestId,
      clientId: request.clientId,
      endpoint: request.endpoint,
      allowed: !blocked,
      blockedBy,
      evaluationTimeMs,
      layers,
    };

    this.metrics.record(metric);

    // On-chain audit (async, non-blocking)
    if (this.auditTrail) {
      this.auditTrail.record(metric).catch(() => {});
    }

    // Emit events
    if (blocked) {
      this._emit('block', shieldResult);
    } else {
      this._emit('allow', shieldResult);
    }

    // Metric callback
    if (this.config.onMetric) {
      try {
        await this.config.onMetric(metric);
      } catch {
        // Never let callbacks break the flow
      }
    }

    if (this.config.verbose) {
      const status = blocked ? `BLOCKED by ${blockedBy}` : 'ALLOWED';
      console.log(
        `[Shield] ${request.clientId} -> ${request.endpoint} | ${status} | ${evaluationTimeMs.toFixed(1)}ms`
      );
    }

    return shieldResult;
  }

  /**
   * Wrap a fetch function with Shield protection.
   * Returns a new function that evaluates the request through Shield
   * before calling the underlying fetch.
   *
   * @param {Function} fetchFn - The fetch function to wrap (e.g., globalThis.fetch).
   * @param {Object} options
   * @param {Function} options.extractContext - Extract Shield context from fetch arguments.
   *   Receives (url, init) and must return { clientId, endpoint, method, payloadSize }.
   * @returns {Function} Wrapped fetch function.
   *
   * @example
   * ```js
   * const safeFetch = shield.wrap(fetch, {
   *   extractContext: (url, init) => ({
   *     clientId: 'my-api-key',
   *     endpoint: new URL(url).pathname,
   *     method: init?.method ?? 'GET',
   *     payloadSize: init?.body?.length ?? 0,
   *   }),
   * });
   *
   * const response = await safeFetch('https://api.asterdex.io/api/v3/order', { method: 'POST', body });
   * ```
   */
  wrap(fetchFn, options = {}) {
    const shield = this;
    const extractContext = options.extractContext ?? ((url, init) => ({
      clientId: 'default',
      endpoint: typeof url === 'string' ? new URL(url).pathname : url.pathname ?? '/unknown',
      method: init?.method ?? 'GET',
      payloadSize: init?.body ? (typeof init.body === 'string' ? init.body.length : 0) : 0,
    }));

    return async function shieldedFetch(url, init) {
      const ctx = extractContext(url, init);
      const result = await shield.protect(ctx);

      if (!result.allowed) {
        const error = new Error(`[Shield] Request blocked by ${result.blockedBy}: ${result.reason}`);
        error.shieldResult = result;
        error.code = 'SHIELD_BLOCKED';
        throw error;
      }

      try {
        const response = await fetchFn(url, init);

        // Report outcome to circuit breaker
        shield.reportOutcome(ctx.endpoint, response.ok, response.status);

        return response;
      } catch (err) {
        // Network error — report failure to circuit breaker
        shield.reportOutcome(ctx.endpoint, false);
        throw err;
      }
    };
  }

  /**
   * Report the outcome of a request to the circuit breaker.
   * Call after your API request completes.
   *
   * @param {string} endpoint
   * @param {boolean} success
   * @param {number} [statusCode]
   */
  reportOutcome(endpoint, success, statusCode) {
    if (this.circuitBreaker) {
      this.circuitBreaker.reportOutcome(endpoint, success, statusCode);
    }
  }

  /**
   * Get current metrics snapshot.
   * @returns {Object}
   */
  getMetrics() {
    return this.metrics.getSnapshot();
  }

  /**
   * Get current state of all layers.
   * @returns {Object}
   */
  getStatus() {
    return {
      layers: {
        rateShield: this.rateShield
          ? { active: true, ...this.rateShield.getStatus() }
          : { active: false },
        circuitBreaker: this.circuitBreaker
          ? { active: true, ...this.circuitBreaker.getStatus() }
          : { active: false },
        anomalyDetector: this.anomalyDetector
          ? { active: true, ...this.anomalyDetector.getStatus() }
          : { active: false },
        auditTrail: this.auditTrail
          ? { active: true, ...this.auditTrail.getStatus() }
          : { active: false },
      },
      metrics: this.metrics.getSnapshot(),
    };
  }

  /**
   * Gracefully shut down — flush pending audit batches, clear intervals.
   */
  async shutdown() {
    if (this.auditTrail) {
      await this.auditTrail.flush();
    }
    if (this.rateShield) this.rateShield.destroy();
    if (this.anomalyDetector) this.anomalyDetector.destroy();
    this.metrics.clear();
    if (this.config.verbose) {
      console.log('[Shield] Shut down gracefully.');
    }
  }

  /** @private */
  _emit(event, data) {
    if (!this._listeners[event]) return;
    for (const handler of this._listeners[event]) {
      try {
        handler(data);
      } catch {
        // Never let event handlers break the flow
      }
    }
  }

  /** @private */
  _getActiveLayerNames() {
    const names = [];
    if (this.rateShield) names.push('Rate Shield');
    if (this.circuitBreaker) names.push('Circuit Breaker');
    if (this.anomalyDetector) names.push('Anomaly Detector');
    if (this.auditTrail) names.push('Audit Trail');
    return names;
  }
}
