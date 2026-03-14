export { Shield } from "./shield";
export { RateShield } from "./layers/rate-shield";
export { CircuitBreaker } from "./layers/circuit-breaker";
export { AnomalyDetector } from "./layers/anomaly-detector";
export { OnChainAudit } from "./layers/on-chain-audit";
export { ShieldMetrics } from "./metrics";

export type {
  ShieldConfig,
  ShieldResult,
  ShieldContext,
  LayerResult,
  RateShieldConfig,
  CircuitBreakerConfig,
  AnomalyDetectorConfig,
  OnChainAuditConfig,
  MetricEntry,
} from "./types";
