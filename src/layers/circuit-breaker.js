/**
 * Circuit Breaker — Prevents cascading failures by stopping requests
 * to endpoints that are consistently failing.
 * Powered by Kairos Lab.
 *
 * States:
 *   CLOSED    — Normal operation, requests pass through.
 *   OPEN      — Endpoint is failing, all requests are rejected instantly.
 *   HALF_OPEN — Testing if endpoint has recovered, limited requests allowed.
 *
 * Protects both the client (fast failure instead of timeouts)
 * and the server (prevents overload during recovery).
 */
export class CircuitBreaker {
  /** @type {'CLOSED'|'OPEN'|'HALF_OPEN'} */
  static CLOSED = 'CLOSED';
  static OPEN = 'OPEN';
  static HALF_OPEN = 'HALF_OPEN';

  /**
   * @param {Object} config
   * @param {number}   [config.failureThreshold=5]          - Failures before opening the circuit.
   * @param {number}   [config.resetTimeoutMs=30000]        - Time before attempting HALF_OPEN.
   * @param {number}   [config.halfOpenSuccesses=2]         - Successes in HALF_OPEN before fully closing.
   * @param {number[]} [config.failureStatusCodes]          - HTTP status codes treated as failures.
   * @param {number}   [config.requestTimeoutMs=10000]      - Timeout for individual requests.
   */
  constructor(config = {}) {
    this.failureThreshold = config.failureThreshold ?? 5;
    this.resetTimeoutMs = config.resetTimeoutMs ?? 30_000;
    this.halfOpenSuccesses = config.halfOpenSuccesses ?? 2;
    this.failureStatusCodes = config.failureStatusCodes ?? [500, 502, 503, 504];
    this.requestTimeoutMs = config.requestTimeoutMs ?? 10_000;

    /** @type {Map<string, Object>} */
    this._circuits = new Map();
  }

  /**
   * Check whether a request to the given endpoint is allowed.
   *
   * @param {Object} ctx
   * @param {string} ctx.endpoint
   * @returns {Object} { allowed, reason?, metadata }
   */
  check(ctx) {
    const circuit = this._getCircuit(ctx.endpoint);

    switch (circuit.state) {
      case 'CLOSED':
        return {
          allowed: true,
          metadata: {
            state: 'CLOSED',
            failureCount: circuit.failureCount,
            threshold: this.failureThreshold,
          },
        };

      case 'OPEN': {
        const elapsed = Date.now() - circuit.lastFailureTime;
        if (elapsed >= this.resetTimeoutMs) {
          // Transition to HALF_OPEN — allow a test request
          circuit.state = 'HALF_OPEN';
          circuit.successCount = 0;
          circuit.lastStateChange = Date.now();
          return {
            allowed: true,
            metadata: {
              state: 'HALF_OPEN',
              message: 'Circuit testing recovery -- limited requests allowed',
            },
          };
        }

        const retryAfterMs = this.resetTimeoutMs - elapsed;
        return {
          allowed: false,
          reason: `Circuit OPEN for ${ctx.endpoint} -- endpoint is experiencing failures. Retry in ${Math.ceil(retryAfterMs / 1000)}s`,
          metadata: {
            state: 'OPEN',
            retryAfterMs,
            retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
            failureCount: circuit.failureCount,
            openedAt: circuit.lastStateChange,
          },
        };
      }

      case 'HALF_OPEN':
        return {
          allowed: true,
          metadata: {
            state: 'HALF_OPEN',
            successCount: circuit.successCount,
            requiredSuccesses: this.halfOpenSuccesses,
          },
        };

      default:
        return { allowed: true, metadata: { state: 'UNKNOWN' } };
    }
  }

  /**
   * Report the outcome of a request. Call after each API response.
   *
   * @param {string}  endpoint
   * @param {boolean} success
   * @param {number}  [statusCode]
   */
  reportOutcome(endpoint, success, statusCode) {
    const circuit = this._getCircuit(endpoint);
    const isFailure =
      !success ||
      (statusCode !== undefined && this.failureStatusCodes.includes(statusCode));

    if (isFailure) {
      circuit.failureCount++;
      circuit.lastFailureTime = Date.now();

      if (circuit.state === 'HALF_OPEN') {
        // Failed during recovery — reopen
        circuit.state = 'OPEN';
        circuit.lastStateChange = Date.now();
      } else if (
        circuit.state === 'CLOSED' &&
        circuit.failureCount >= this.failureThreshold
      ) {
        // Threshold exceeded — open circuit
        circuit.state = 'OPEN';
        circuit.lastStateChange = Date.now();
      }
    } else {
      if (circuit.state === 'HALF_OPEN') {
        circuit.successCount++;
        if (circuit.successCount >= this.halfOpenSuccesses) {
          // Recovery confirmed — close circuit
          circuit.state = 'CLOSED';
          circuit.failureCount = 0;
          circuit.successCount = 0;
          circuit.lastStateChange = Date.now();
        }
      } else if (circuit.state === 'CLOSED') {
        // Reset failure count on success
        circuit.failureCount = 0;
      }
    }
  }

  /**
   * Get current status of all circuits.
   * @returns {Object}
   */
  getStatus() {
    const circuits = {};
    for (const [endpoint, circuit] of this._circuits) {
      circuits[endpoint] = {
        state: circuit.state,
        failureCount: circuit.failureCount,
      };
    }
    return {
      circuits,
      config: {
        failureThreshold: this.failureThreshold,
        resetTimeoutMs: this.resetTimeoutMs,
      },
    };
  }

  /**
   * Manually reset a circuit to CLOSED state.
   * @param {string} endpoint
   */
  reset(endpoint) {
    const circuit = this._circuits.get(endpoint);
    if (circuit) {
      circuit.state = 'CLOSED';
      circuit.failureCount = 0;
      circuit.successCount = 0;
      circuit.lastStateChange = Date.now();
    }
  }

  /**
   * Reset all circuits.
   */
  resetAll() {
    this._circuits.clear();
  }

  /** @private */
  _getCircuit(endpoint) {
    let circuit = this._circuits.get(endpoint);
    if (!circuit) {
      circuit = {
        state: 'CLOSED',
        failureCount: 0,
        successCount: 0,
        lastFailureTime: 0,
        lastStateChange: Date.now(),
      };
      this._circuits.set(endpoint, circuit);
    }
    return circuit;
  }
}
