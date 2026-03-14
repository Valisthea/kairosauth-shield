/**
 * Rate Shield — Intelligent rate limiting with sliding window algorithm.
 * Powered by Kairos Lab.
 *
 * Features:
 * - Sliding window algorithm (no burst-at-boundary problem)
 * - Per-endpoint and per-IP limits
 * - Predictive throttling (warning before hard limit)
 * - Wildcard endpoint pattern matching
 * - Automatic memory cleanup of expired windows
 */
export class RateShield {
  /**
   * @param {Object} config
   * @param {number}  [config.maxRequests=100]      - Max requests per window.
   * @param {number}  [config.windowMs=60000]       - Window duration in ms.
   * @param {Object}  [config.endpointLimits]       - Per-endpoint overrides. Key = endpoint pattern (supports * wildcard).
   * @param {'sliding-window'|'fixed-window'} [config.strategy='sliding-window'] - Rate limiting strategy.
   * @param {number}  [config.warningThreshold=0.8] - Usage ratio (0-1) at which to attach warning metadata.
   */
  constructor(config = {}) {
    this.maxRequests = config.maxRequests ?? 100;
    this.windowMs = config.windowMs ?? 60_000;
    this.endpointLimits = config.endpointLimits ?? {};
    this.strategy = config.strategy ?? 'sliding-window';
    this.warningThreshold = config.warningThreshold ?? 0.8;

    /** @type {Map<string, {timestamps: number[], windowStart: number}>} */
    this._windows = new Map();

    // Periodic cleanup every 5 minutes
    this._cleanupInterval = setInterval(() => this._cleanup(), 300_000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  /**
   * Check whether a request is allowed under the current rate limits.
   *
   * @param {Object} ctx
   * @param {string} ctx.clientId
   * @param {string} ctx.endpoint
   * @returns {Object} { allowed, reason?, metadata }
   */
  check(ctx) {
    const key = `${ctx.clientId}::${ctx.endpoint}`;
    const now = Date.now();
    const { maxRequests, windowMs } = this._getLimits(ctx.endpoint);

    let entry = this._windows.get(key);
    if (!entry) {
      entry = { timestamps: [], windowStart: now };
      this._windows.set(key, entry);
    }

    if (this.strategy === 'sliding-window') {
      // Remove timestamps outside the sliding window
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

    // Hard limit reached
    if (currentCount >= maxRequests) {
      const retryAfterMs =
        this.strategy === 'sliding-window'
          ? entry.timestamps[0] + windowMs - now
          : entry.windowStart + windowMs - now;

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
    const warning = usage >= this.warningThreshold;

    // Predictive throttling: calculate recommended delay if approaching limit
    const predictiveDelay = usage > 0.9
      ? Math.round((windowMs / maxRequests) * (usage / (1 - usage)))
      : 0;

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
        ...(predictiveDelay > 0 && {
          recommendedDelayMs: predictiveDelay,
          throttleAdvice: `Consider slowing down — recommend ${predictiveDelay}ms delay between requests`,
        }),
      },
    };
  }

  /**
   * Get current status.
   * @returns {Object}
   */
  getStatus() {
    return {
      trackedClients: this._windows.size,
      config: {
        maxRequests: this.maxRequests,
        windowMs: this.windowMs,
        strategy: this.strategy,
      },
    };
  }

  /**
   * Destroy this layer, clearing intervals and data.
   */
  destroy() {
    clearInterval(this._cleanupInterval);
    this._windows.clear();
  }

  /** @private */
  _getLimits(endpoint) {
    for (const [pattern, limits] of Object.entries(this.endpointLimits)) {
      if (this._matchPattern(pattern, endpoint)) {
        return {
          maxRequests: limits.maxRequests,
          windowMs: limits.windowMs ?? this.windowMs,
        };
      }
    }
    return { maxRequests: this.maxRequests, windowMs: this.windowMs };
  }

  /** @private */
  _matchPattern(pattern, endpoint) {
    if (pattern === endpoint) return true;
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(endpoint);
    }
    return false;
  }

  /** @private */
  _cleanup() {
    const now = Date.now();
    const maxAge = this.windowMs * 2;
    for (const [key, entry] of this._windows) {
      const latest = entry.timestamps[entry.timestamps.length - 1] ?? entry.windowStart;
      if (now - latest > maxAge) {
        this._windows.delete(key);
      }
    }
  }
}
