import { RateShield } from "./layers/rate-shield";
import { CircuitBreaker } from "./layers/circuit-breaker";
import { AnomalyDetector } from "./layers/anomaly-detector";
import { OnChainAudit } from "./layers/on-chain-audit";
import { ShieldMetrics } from "./metrics";
import type {
  ShieldConfig,
  ShieldContext,
  ShieldResult,
  LayerResult,
} from "./types";

let idCounter = 0;
function generateRequestId(): string {
  const ts = Date.now().toString(36);
  const rnd = Math.random().toString(36).substring(2, 8);
  return `ksh_${ts}_${rnd}_${(idCounter++).toString(36)}`;
}

/**
 * KairosAuth Shield — Multi-layer API protection.
 *
 * @example
 * ```ts
 * import { Shield } from "@kairosauth/shield";
 *
 * const shield = new Shield({
 *   rateShield: { maxRequests: 200, windowMs: 60_000 },
 *   circuitBreaker: { failureThreshold: 5 },
 *   anomalyDetector: { maxPayloadSize: 1_048_576 },
 * });
 *
 * const result = await shield.evaluate({
 *   clientId: req.ip,
 *   endpoint: req.path,
 *   method: req.method,
 * });
 *
 * if (!result.allowed) {
 *   return res.status(429).json({ error: result.reason });
 * }
 * ```
 */
export class Shield {
  private rateShield?: RateShield;
  private circuitBreaker?: CircuitBreaker;
  private anomalyDetector?: AnomalyDetector;
  private onChainAudit?: OnChainAudit;
  private metrics: ShieldMetrics;
  private config: ShieldConfig;

  constructor(config: ShieldConfig = {}) {
    this.config = config;
    this.metrics = new ShieldMetrics();

    if (config.rateShield) {
      this.rateShield = new RateShield(config.rateShield);
    }
    if (config.circuitBreaker) {
      this.circuitBreaker = new CircuitBreaker(config.circuitBreaker);
    }
    if (config.anomalyDetector) {
      this.anomalyDetector = new AnomalyDetector(config.anomalyDetector);
    }
    if (config.onChainAudit) {
      this.onChainAudit = new OnChainAudit(config.onChainAudit);
    }

    if (config.verbose) {
      console.log(
        `[KairosAuth Shield] Initialized with layers: ${this.getActiveLayerNames().join(", ") || "none"}`
      );
    }
  }

  /**
   * Evaluate a request through all active protection layers.
   * Layers are evaluated in order: Rate Shield → Circuit Breaker → Anomaly Detector.
   * Evaluation stops at the first blocking layer (fail-fast).
   */
  async evaluate(ctx: ShieldContext): Promise<ShieldResult> {
    const start = performance.now();
    const requestId = generateRequestId();
    const layers: Record<string, LayerResult> = {};
    let blocked = false;
    let blockedBy: string | undefined;
    let reason: string | undefined;

    // Layer 1: Rate Shield
    if (this.rateShield && !blocked) {
      const result = this.rateShield.check(ctx);
      layers["rate-shield"] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = "rate-shield";
        reason = result.reason;
      }
    }

    // Layer 2: Circuit Breaker
    if (this.circuitBreaker && !blocked) {
      const result = this.circuitBreaker.check(ctx);
      layers["circuit-breaker"] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = "circuit-breaker";
        reason = result.reason;
      }
    }

    // Layer 3: Anomaly Detector
    if (this.anomalyDetector && !blocked) {
      const result = this.anomalyDetector.check(ctx);
      layers["anomaly-detector"] = result;
      if (!result.allowed) {
        blocked = true;
        blockedBy = "anomaly-detector";
        reason = result.reason;
      }
    }

    const evaluationTimeMs = performance.now() - start;

    const shieldResult: ShieldResult = {
      allowed: !blocked,
      blockedBy,
      reason,
      layers,
      evaluationTimeMs,
      requestId,
    };

    // Metrics collection
    const metric = {
      timestamp: Date.now(),
      requestId,
      clientId: ctx.clientId,
      endpoint: ctx.endpoint,
      allowed: !blocked,
      blockedBy,
      evaluationTimeMs,
      layers,
    };

    this.metrics.record(metric);

    // On-chain audit (async, non-blocking)
    if (this.onChainAudit) {
      this.onChainAudit.record(metric).catch(() => {});
    }

    // Callbacks
    if (blocked && this.config.onBlock) {
      try {
        await this.config.onBlock(shieldResult);
      } catch {
        // Never let callbacks break the flow
      }
    }

    if (this.config.onMetric) {
      try {
        await this.config.onMetric(metric);
      } catch {
        // Silent
      }
    }

    if (this.config.verbose) {
      const status = blocked ? `BLOCKED by ${blockedBy}` : "ALLOWED";
      console.log(
        `[Shield] ${ctx.clientId} → ${ctx.endpoint} | ${status} | ${evaluationTimeMs.toFixed(1)}ms`
      );
    }

    return shieldResult;
  }

  /**
   * Report the outcome of a request (success/failure) to the circuit breaker.
   * Call this after your API request completes.
   */
  reportOutcome(endpoint: string, success: boolean, statusCode?: number): void {
    if (this.circuitBreaker) {
      this.circuitBreaker.reportOutcome(endpoint, success, statusCode);
    }
  }

  /**
   * Get current metrics snapshot.
   */
  getMetrics() {
    return this.metrics.getSnapshot();
  }

  /**
   * Get the current state of all layers.
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
        onChainAudit: this.onChainAudit
          ? { active: true, ...this.onChainAudit.getStatus() }
          : { active: false },
      },
      metrics: this.metrics.getSnapshot(),
    };
  }

  /**
   * Gracefully shut down — flush pending audit batches, clear intervals.
   */
  async shutdown(): Promise<void> {
    if (this.onChainAudit) {
      await this.onChainAudit.flush();
    }
    this.metrics.clear();
    if (this.config.verbose) {
      console.log("[Shield] Shut down gracefully.");
    }
  }

  private getActiveLayerNames(): string[] {
    const names: string[] = [];
    if (this.rateShield) names.push("Rate Shield");
    if (this.circuitBreaker) names.push("Circuit Breaker");
    if (this.anomalyDetector) names.push("Anomaly Detector");
    if (this.onChainAudit) names.push("On-Chain Audit");
    return names;
  }
}
