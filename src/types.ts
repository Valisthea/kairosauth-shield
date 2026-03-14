/**
 * Core Shield configuration.
 */
export interface ShieldConfig {
  /** Unique name for this Shield instance (used in metrics & logs). */
  name?: string;

  /** Rate limiting configuration. Omit to disable. */
  rateShield?: RateShieldConfig;

  /** Circuit breaker configuration. Omit to disable. */
  circuitBreaker?: CircuitBreakerConfig;

  /** Anomaly detection configuration. Omit to disable. */
  anomalyDetector?: AnomalyDetectorConfig;

  /** On-chain audit trail configuration. Omit to disable. */
  onChainAudit?: OnChainAuditConfig;

  /** Called when a request is blocked by any layer. */
  onBlock?: (result: ShieldResult) => void | Promise<void>;

  /** Called on every request for telemetry. */
  onMetric?: (metric: MetricEntry) => void | Promise<void>;

  /** Enable verbose logging to console. Default: false. */
  verbose?: boolean;
}

/**
 * Context passed to Shield.evaluate() for each incoming request.
 */
export interface ShieldContext {
  /** Client identifier — IP address, API key, wallet address, etc. */
  clientId: string;

  /** The API endpoint or route being accessed. */
  endpoint: string;

  /** HTTP method. */
  method?: string;

  /** Request payload size in bytes (optional, used for anomaly detection). */
  payloadSize?: number;

  /** Additional metadata to include in audit trails. */
  metadata?: Record<string, unknown>;
}

/**
 * Result of evaluating a request through Shield layers.
 */
export interface ShieldResult {
  /** Whether the request is allowed to proceed. */
  allowed: boolean;

  /** Which layer blocked the request, if any. */
  blockedBy?: string;

  /** Human-readable reason for blocking. */
  reason?: string;

  /** Per-layer results for inspection. */
  layers: Record<string, LayerResult>;

  /** Time taken to evaluate all layers (ms). */
  evaluationTimeMs: number;

  /** Unique request ID for tracing. */
  requestId: string;
}

/**
 * Result from a single protection layer.
 */
export interface LayerResult {
  allowed: boolean;
  reason?: string;
  metadata?: Record<string, unknown>;
}

// ─── Rate Shield ───────────────────────────────────────────────

export interface RateShieldConfig {
  /** Max requests per window. Default: 100. */
  maxRequests?: number;

  /** Time window in milliseconds. Default: 60000 (1 minute). */
  windowMs?: number;

  /** Per-endpoint overrides. Key = endpoint pattern (supports * wildcard). */
  endpointLimits?: Record<string, { maxRequests: number; windowMs?: number }>;

  /**
   * Strategy for rate limiting.
   * - "sliding-window": More accurate, slightly more memory (default).
   * - "fixed-window": Simpler, less memory.
   */
  strategy?: "sliding-window" | "fixed-window";

  /** When usage exceeds this ratio (0-1), attach warning headers. Default: 0.8. */
  warningThreshold?: number;
}

// ─── Circuit Breaker ───────────────────────────────────────────

export interface CircuitBreakerConfig {
  /** Number of failures before opening the circuit. Default: 5. */
  failureThreshold?: number;

  /** Time in ms to wait before attempting half-open. Default: 30000. */
  resetTimeoutMs?: number;

  /** Number of successes in half-open before fully closing. Default: 2. */
  halfOpenSuccesses?: number;

  /** Which HTTP status codes count as failures. Default: [500, 502, 503, 504]. */
  failureStatusCodes?: number[];

  /** Timeout for individual requests in ms. Default: 10000. */
  requestTimeoutMs?: number;
}

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

// ─── Anomaly Detector ──────────────────────────────────────────

export interface AnomalyDetectorConfig {
  /** Flag requests larger than this (bytes). Default: 1MB. */
  maxPayloadSize?: number;

  /** Flag if a client sends more than N unique endpoints in windowMs. Default: 50. */
  endpointSpreadThreshold?: number;

  /** Window for spread detection in ms. Default: 60000. */
  spreadWindowMs?: number;

  /** Flag if request rate changes by this factor vs baseline. Default: 5. */
  burstFactor?: number;

  /** Custom rules evaluated in order. Return null to pass, string reason to block. */
  customRules?: Array<(ctx: ShieldContext) => string | null>;

  /** Action when anomaly detected: "block" or "flag" (allow but mark). Default: "block". */
  action?: "block" | "flag";
}

// ─── On-Chain Audit ────────────────────────────────────────────

export interface OnChainAuditConfig {
  /** KairosAuth API endpoint for anchoring proofs. */
  apiEndpoint: string;

  /** KairosAuth API key. */
  apiKey: string;

  /** Batch size — anchor after N events. Default: 100. */
  batchSize?: number;

  /** Max time before flushing batch (ms). Default: 300000 (5 min). */
  flushIntervalMs?: number;

  /** Which events to anchor: "all", "blocks-only", "anomalies-only". Default: "blocks-only". */
  auditScope?: "all" | "blocks-only" | "anomalies-only";
}

// ─── Metrics ───────────────────────────────────────────────────

export interface MetricEntry {
  timestamp: number;
  requestId: string;
  clientId: string;
  endpoint: string;
  allowed: boolean;
  blockedBy?: string;
  evaluationTimeMs: number;
  layers: Record<string, LayerResult>;
}
