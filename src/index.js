/**
 * @kairosauth/shield — API Protection SDK
 * Powered by Kairos Lab
 *
 * Multi-layer API protection: rate limiting, circuit breaking,
 * anomaly detection, and on-chain audit trails.
 */

export { Shield } from './shield.js';
export { RateShield } from './layers/rate-shield.js';
export { CircuitBreaker } from './layers/circuit-breaker.js';
export { AnomalyDetector } from './layers/anomaly-detector.js';
export { AuditTrail } from './layers/audit-trail.js';
export { ShieldMetrics } from './metrics.js';
