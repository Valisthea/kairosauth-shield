import type { RateShieldConfig, ShieldContext, LayerResult } from "../types";

interface WindowEntry {
  timestamps: number[];
  windowStart: number;
}

/**
 * Rate Shield — Intelligent rate limiting with per-endpoint granularity.
 *
 * Uses sliding window algorithm by default for accurate rate limiting
 * without the burst-at-boundary problem of fixed windows.
 *
 * Features:
 * - Per-client + per-endpoint tracking
 * - Configurable warning threshold (sends early warning before hard limit)
 * - Wildcard endpoint pattern matching
 * - Automatic memory cleanup of expired windows
 */
export class RateShield {
  private config: Required<
    Pick<RateShieldConfig, "maxRequests" | "windowMs" | "strategy" | "warningThreshold">
  > &
    RateShieldConfig;
  private windows = new Map<string, WindowEntry>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(config: RateShieldConfig = {}) {
    this.config = {
      maxRequests: config.maxRequests ?? 100,
      windowMs: config.windowMs ?? 60_000,
      strategy: config.strategy ?? "sliding-window",
      warningThreshold: config.warningThreshold ?? 0.8,
      ...config,
    };

    // Periodic cleanup of stale entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 300_000);
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();
  }

  check(ctx: ShieldContext): LayerResult {
    const key = `${ctx.clientId}::${ctx.endpoint}`;
    const now = Date.now();
    const { maxRequests, windowMs } = this.getLimitsForEndpoint(ctx.endpoint);

    let entry = this.windows.get(key);
    if (!entry) {
      entry = { timestamps: [], windowStart: now };
      this.windows.set(key, entry);
    }

    if (this.config.strategy === "sliding-window") {
      // Remove timestamps outside the window
      const cutoff = now - windowMs;
      entry.timestamps = entry.timestamps.filter((t) => t > cutoff);
    } else {
      // Fixed window: reset if window expired
      if (now - entry.windowStart >= windowMs) {
        entry.timestamps = [];
        entry.windowStart = now;
      }
    }

    const currentCount = entry.timestamps.length;

    if (currentCount >= maxRequests) {
      const retryAfterMs = this.config.strategy === "sliding-window"
        ? (entry.timestamps[0]! + windowMs) - now
        : (entry.windowStart + windowMs) - now;

      return {
        allowed: false,
        reason: `Rate limit exceeded: ${maxRequests} requests per ${windowMs / 1000}s`,
        metadata: {
          limit: maxRequests,
          remaining: 0,
          resetMs: Math.max(0, retryAfterMs),
          retryAfterSeconds: Math.ceil(Math.max(0, retryAfterMs) / 1000),
        },
      };
    }

    // Record this request
    entry.timestamps.push(now);

    const remaining = maxRequests - currentCount - 1;
    const usage = (currentCount + 1) / maxRequests;
    const warning = usage >= this.config.warningThreshold;

    return {
      allowed: true,
      metadata: {
        limit: maxRequests,
        remaining,
        usage: Math.round(usage * 100),
        warning,
        ...(warning && {
          warningMessage: `${Math.round(usage * 100)}% of rate limit used (${remaining} remaining)`,
        }),
      },
    };
  }

  getStatus() {
    return {
      trackedClients: this.windows.size,
      config: {
        maxRequests: this.config.maxRequests,
        windowMs: this.config.windowMs,
        strategy: this.config.strategy,
      },
    };
  }

  private getLimitsForEndpoint(endpoint: string): {
    maxRequests: number;
    windowMs: number;
  } {
    if (this.config.endpointLimits) {
      for (const [pattern, limits] of Object.entries(
        this.config.endpointLimits
      )) {
        if (this.matchPattern(pattern, endpoint)) {
          return {
            maxRequests: limits.maxRequests,
            windowMs: limits.windowMs ?? this.config.windowMs,
          };
        }
      }
    }
    return {
      maxRequests: this.config.maxRequests,
      windowMs: this.config.windowMs,
    };
  }

  private matchPattern(pattern: string, endpoint: string): boolean {
    if (pattern === endpoint) return true;
    if (pattern.includes("*")) {
      const regex = new RegExp(
        "^" + pattern.replace(/\*/g, ".*") + "$"
      );
      return regex.test(endpoint);
    }
    return false;
  }

  private cleanup() {
    const now = Date.now();
    const maxAge = this.config.windowMs * 2;
    for (const [key, entry] of this.windows) {
      const latest = entry.timestamps[entry.timestamps.length - 1] ?? entry.windowStart;
      if (now - latest > maxAge) {
        this.windows.delete(key);
      }
    }
  }

  destroy() {
    clearInterval(this.cleanupInterval);
    this.windows.clear();
  }
}
