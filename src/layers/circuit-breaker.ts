import type {
  CircuitBreakerConfig,
  CircuitState,
  ShieldContext,
  LayerResult,
} from "../types";

interface CircuitEntry {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailureTime: number;
  lastStateChange: number;
}

/**
 * Circuit Breaker — Prevents cascading failures by stopping requests
 * to endpoints that are consistently failing.
 *
 * States:
 * - CLOSED: Normal operation, requests pass through.
 * - OPEN: Endpoint is failing, all requests are rejected instantly.
 * - HALF_OPEN: Testing if endpoint has recovered, limited requests allowed.
 *
 * This protects both the client (fast failure instead of timeouts)
 * and the server (prevents overload during recovery).
 */
export class CircuitBreaker {
  private config: Required<
    Pick<
      CircuitBreakerConfig,
      | "failureThreshold"
      | "resetTimeoutMs"
      | "halfOpenSuccesses"
      | "failureStatusCodes"
      | "requestTimeoutMs"
    >
  >;
  private circuits = new Map<string, CircuitEntry>();

  constructor(config: CircuitBreakerConfig = {}) {
    this.config = {
      failureThreshold: config.failureThreshold ?? 5,
      resetTimeoutMs: config.resetTimeoutMs ?? 30_000,
      halfOpenSuccesses: config.halfOpenSuccesses ?? 2,
      failureStatusCodes: config.failureStatusCodes ?? [500, 502, 503, 504],
      requestTimeoutMs: config.requestTimeoutMs ?? 10_000,
    };
  }

  check(ctx: ShieldContext): LayerResult {
    const circuit = this.getCircuit(ctx.endpoint);

    switch (circuit.state) {
      case "CLOSED":
        return {
          allowed: true,
          metadata: {
            state: "CLOSED",
            failureCount: circuit.failureCount,
            threshold: this.config.failureThreshold,
          },
        };

      case "OPEN": {
        const elapsed = Date.now() - circuit.lastFailureTime;
        if (elapsed >= this.config.resetTimeoutMs) {
          // Transition to half-open
          circuit.state = "HALF_OPEN";
          circuit.successCount = 0;
          circuit.lastStateChange = Date.now();
          return {
            allowed: true,
            metadata: {
              state: "HALF_OPEN",
              message: "Circuit testing recovery — limited requests allowed",
            },
          };
        }

        const retryAfterMs = this.config.resetTimeoutMs - elapsed;
        return {
          allowed: false,
          reason: `Circuit OPEN for ${ctx.endpoint} — endpoint is experiencing failures. Retry in ${Math.ceil(retryAfterMs / 1000)}s`,
          metadata: {
            state: "OPEN",
            retryAfterMs,
            retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
            failureCount: circuit.failureCount,
            openedAt: circuit.lastStateChange,
          },
        };
      }

      case "HALF_OPEN":
        return {
          allowed: true,
          metadata: {
            state: "HALF_OPEN",
            successCount: circuit.successCount,
            requiredSuccesses: this.config.halfOpenSuccesses,
          },
        };
    }
  }

  /**
   * Report the outcome of a request. Call after each API response.
   */
  reportOutcome(
    endpoint: string,
    success: boolean,
    statusCode?: number
  ): void {
    const circuit = this.getCircuit(endpoint);
    const isFailure =
      !success ||
      (statusCode !== undefined &&
        this.config.failureStatusCodes.includes(statusCode));

    if (isFailure) {
      circuit.failureCount++;
      circuit.lastFailureTime = Date.now();

      if (circuit.state === "HALF_OPEN") {
        // Failed during recovery test — reopen
        circuit.state = "OPEN";
        circuit.lastStateChange = Date.now();
      } else if (
        circuit.state === "CLOSED" &&
        circuit.failureCount >= this.config.failureThreshold
      ) {
        // Threshold exceeded — open circuit
        circuit.state = "OPEN";
        circuit.lastStateChange = Date.now();
      }
    } else {
      if (circuit.state === "HALF_OPEN") {
        circuit.successCount++;
        if (circuit.successCount >= this.config.halfOpenSuccesses) {
          // Recovery confirmed — close circuit
          circuit.state = "CLOSED";
          circuit.failureCount = 0;
          circuit.successCount = 0;
          circuit.lastStateChange = Date.now();
        }
      } else if (circuit.state === "CLOSED") {
        // Reset failure count on success (consecutive failure counting)
        circuit.failureCount = 0;
      }
    }
  }

  getStatus() {
    const circuits: Record<string, { state: CircuitState; failureCount: number }> = {};
    for (const [endpoint, circuit] of this.circuits) {
      circuits[endpoint] = {
        state: circuit.state,
        failureCount: circuit.failureCount,
      };
    }
    return {
      circuits,
      config: {
        failureThreshold: this.config.failureThreshold,
        resetTimeoutMs: this.config.resetTimeoutMs,
      },
    };
  }

  /**
   * Manually reset a circuit to CLOSED state.
   */
  reset(endpoint: string): void {
    const circuit = this.circuits.get(endpoint);
    if (circuit) {
      circuit.state = "CLOSED";
      circuit.failureCount = 0;
      circuit.successCount = 0;
      circuit.lastStateChange = Date.now();
    }
  }

  /**
   * Reset all circuits.
   */
  resetAll(): void {
    this.circuits.clear();
  }

  private getCircuit(endpoint: string): CircuitEntry {
    let circuit = this.circuits.get(endpoint);
    if (!circuit) {
      circuit = {
        state: "CLOSED",
        failureCount: 0,
        successCount: 0,
        lastFailureTime: 0,
        lastStateChange: Date.now(),
      };
      this.circuits.set(endpoint, circuit);
    }
    return circuit;
  }
}
