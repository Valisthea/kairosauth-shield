import type {
  AnomalyDetectorConfig,
  ShieldContext,
  LayerResult,
} from "../types";

interface ClientProfile {
  endpoints: Map<string, number>; // endpoint → count in current window
  windowStart: number;
  requestTimestamps: number[];
  totalRequests: number;
}

/**
 * Anomaly Detector — Identifies suspicious request patterns
 * that indicate reconnaissance, abuse, or compromised credentials.
 *
 * Detection rules:
 * 1. Oversized payloads (potential buffer overflow / data exfiltration)
 * 2. Endpoint spread (scanning many different endpoints = reconnaissance)
 * 3. Burst detection (sudden spike vs baseline = credential stuffing)
 * 4. Custom rules (user-defined detection logic)
 */
export class AnomalyDetector {
  private config: Required<
    Pick<
      AnomalyDetectorConfig,
      | "maxPayloadSize"
      | "endpointSpreadThreshold"
      | "spreadWindowMs"
      | "burstFactor"
      | "action"
    >
  > &
    AnomalyDetectorConfig;
  private profiles = new Map<string, ClientProfile>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(config: AnomalyDetectorConfig = {}) {
    this.config = {
      maxPayloadSize: config.maxPayloadSize ?? 1_048_576, // 1MB
      endpointSpreadThreshold: config.endpointSpreadThreshold ?? 50,
      spreadWindowMs: config.spreadWindowMs ?? 60_000,
      burstFactor: config.burstFactor ?? 5,
      action: config.action ?? "block",
      ...config,
    };

    this.cleanupInterval = setInterval(() => this.cleanup(), 300_000);
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();
  }

  check(ctx: ShieldContext): LayerResult {
    const anomalies: string[] = [];

    // Rule 1: Payload size
    if (
      ctx.payloadSize !== undefined &&
      ctx.payloadSize > this.config.maxPayloadSize
    ) {
      anomalies.push(
        `Payload size ${(ctx.payloadSize / 1024).toFixed(0)}KB exceeds limit ${(this.config.maxPayloadSize / 1024).toFixed(0)}KB`
      );
    }

    // Rule 2: Endpoint spread (reconnaissance detection)
    const profile = this.getProfile(ctx.clientId);
    const now = Date.now();

    // Reset window if expired
    if (now - profile.windowStart >= this.config.spreadWindowMs) {
      profile.endpoints.clear();
      profile.windowStart = now;
      profile.requestTimestamps = [];
    }

    profile.endpoints.set(
      ctx.endpoint,
      (profile.endpoints.get(ctx.endpoint) ?? 0) + 1
    );
    profile.requestTimestamps.push(now);
    profile.totalRequests++;

    if (profile.endpoints.size > this.config.endpointSpreadThreshold) {
      anomalies.push(
        `Endpoint spread: ${profile.endpoints.size} unique endpoints in ${this.config.spreadWindowMs / 1000}s (threshold: ${this.config.endpointSpreadThreshold})`
      );
    }

    // Rule 3: Burst detection
    if (profile.totalRequests > 20) {
      // Need baseline
      const recentWindow = this.config.spreadWindowMs / 10; // Last 1/10th of window
      const recentCount = profile.requestTimestamps.filter(
        (t) => t > now - recentWindow
      ).length;
      const expectedRate =
        profile.requestTimestamps.length /
        (this.config.spreadWindowMs / recentWindow);

      if (
        recentCount > expectedRate * this.config.burstFactor &&
        recentCount > 5
      ) {
        anomalies.push(
          `Burst detected: ${recentCount} requests in last ${recentWindow / 1000}s (expected ~${expectedRate.toFixed(1)})`
        );
      }
    }

    // Rule 4: Custom rules
    if (this.config.customRules) {
      for (const rule of this.config.customRules) {
        try {
          const result = rule(ctx);
          if (result) anomalies.push(result);
        } catch {
          // Custom rules must never crash the detector
        }
      }
    }

    if (anomalies.length === 0) {
      return {
        allowed: true,
        metadata: {
          endpointSpread: profile.endpoints.size,
          requestsInWindow: profile.requestTimestamps.length,
        },
      };
    }

    const shouldBlock = this.config.action === "block";

    return {
      allowed: !shouldBlock,
      reason: shouldBlock
        ? `Anomaly detected: ${anomalies[0]}`
        : undefined,
      metadata: {
        anomalies,
        action: this.config.action,
        flagged: true,
      },
    };
  }

  getStatus() {
    return {
      trackedClients: this.profiles.size,
      config: {
        maxPayloadSize: this.config.maxPayloadSize,
        endpointSpreadThreshold: this.config.endpointSpreadThreshold,
        burstFactor: this.config.burstFactor,
        action: this.config.action,
      },
    };
  }

  private getProfile(clientId: string): ClientProfile {
    let profile = this.profiles.get(clientId);
    if (!profile) {
      profile = {
        endpoints: new Map(),
        windowStart: Date.now(),
        requestTimestamps: [],
        totalRequests: 0,
      };
      this.profiles.set(clientId, profile);
    }
    return profile;
  }

  private cleanup() {
    const now = Date.now();
    const maxAge = this.config.spreadWindowMs * 3;
    for (const [clientId, profile] of this.profiles) {
      if (now - profile.windowStart > maxAge) {
        this.profiles.delete(clientId);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.profiles.clear();
  }
}
