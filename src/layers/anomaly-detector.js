/**
 * Anomaly Detector — Identifies suspicious request patterns
 * that indicate reconnaissance, abuse, or compromised credentials.
 * Powered by Kairos Lab.
 *
 * Detection rules:
 *   1. Oversized payloads (potential buffer overflow / data exfiltration)
 *   2. Endpoint spread (scanning many different endpoints = reconnaissance)
 *   3. Burst detection (sudden spike vs baseline = credential stuffing)
 *   4. Timing anomalies (too-regular request intervals = bot behavior)
 *   5. Custom rules (user-defined detection logic)
 *
 * Scoring system: each anomaly adds points; threshold triggers block.
 */
export class AnomalyDetector {
  /**
   * @param {Object} config
   * @param {number}   [config.maxPayloadSize=1048576]       - Flag requests larger than this (bytes). Default 1MB.
   * @param {number}   [config.endpointSpreadThreshold=50]   - Flag if client hits N+ unique endpoints in window.
   * @param {number}   [config.spreadWindowMs=60000]         - Window for spread detection.
   * @param {number}   [config.burstFactor=5]                - Flag if rate changes by this factor vs baseline.
   * @param {number}   [config.scoreThreshold=10]            - Total anomaly score that triggers a block.
   * @param {Array<Function>} [config.customRules]           - Custom rules: (ctx) => { score, reason } | null.
   * @param {'block'|'flag'} [config.action='block']         - Action when anomaly detected.
   */
  constructor(config = {}) {
    this.maxPayloadSize = config.maxPayloadSize ?? 1_048_576;
    this.endpointSpreadThreshold = config.endpointSpreadThreshold ?? 50;
    this.spreadWindowMs = config.spreadWindowMs ?? 60_000;
    this.burstFactor = config.burstFactor ?? 5;
    this.scoreThreshold = config.scoreThreshold ?? 10;
    this.customRules = config.customRules ?? [];
    this.action = config.action ?? 'block';

    /** @type {Map<string, Object>} */
    this._profiles = new Map();

    // Periodic cleanup every 5 minutes
    this._cleanupInterval = setInterval(() => this._cleanup(), 300_000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  /**
   * Check a request for anomalies.
   *
   * @param {Object} ctx
   * @param {string} ctx.clientId
   * @param {string} ctx.endpoint
   * @param {number} [ctx.payloadSize]
   * @returns {Object} { allowed, reason?, metadata }
   */
  check(ctx) {
    const anomalies = [];
    let totalScore = 0;

    // Rule 1: Payload size (score: 5)
    if (ctx.payloadSize !== undefined && ctx.payloadSize > this.maxPayloadSize) {
      const score = 5;
      totalScore += score;
      anomalies.push({
        rule: 'oversized-payload',
        score,
        detail: `Payload ${(ctx.payloadSize / 1024).toFixed(0)}KB exceeds limit ${(this.maxPayloadSize / 1024).toFixed(0)}KB`,
      });
    }

    // Get or create client profile
    const profile = this._getProfile(ctx.clientId);
    const now = Date.now();

    // Reset window if expired
    if (now - profile.windowStart >= this.spreadWindowMs) {
      profile.endpoints.clear();
      profile.windowStart = now;
      profile.requestTimestamps = [];
    }

    // Track endpoint access
    profile.endpoints.set(ctx.endpoint, (profile.endpoints.get(ctx.endpoint) ?? 0) + 1);
    profile.requestTimestamps.push(now);
    profile.totalRequests++;

    // Rule 2: Endpoint spread / reconnaissance (score: 8)
    if (profile.endpoints.size > this.endpointSpreadThreshold) {
      const score = 8;
      totalScore += score;
      anomalies.push({
        rule: 'endpoint-spread',
        score,
        detail: `${profile.endpoints.size} unique endpoints in ${this.spreadWindowMs / 1000}s (threshold: ${this.endpointSpreadThreshold})`,
      });
    }

    // Rule 3: Burst detection (score: 6)
    if (profile.totalRequests > 20) {
      const recentWindow = this.spreadWindowMs / 10;
      const recentCount = profile.requestTimestamps.filter((t) => t > now - recentWindow).length;
      const expectedRate =
        profile.requestTimestamps.length / (this.spreadWindowMs / recentWindow);

      if (recentCount > expectedRate * this.burstFactor && recentCount > 5) {
        const score = 6;
        totalScore += score;
        anomalies.push({
          rule: 'burst-detected',
          score,
          detail: `${recentCount} requests in last ${recentWindow / 1000}s (expected ~${expectedRate.toFixed(1)})`,
        });
      }
    }

    // Rule 4: Timing regularity / bot detection (score: 4)
    if (profile.requestTimestamps.length >= 10) {
      const intervals = [];
      for (let i = 1; i < profile.requestTimestamps.length; i++) {
        intervals.push(profile.requestTimestamps[i] - profile.requestTimestamps[i - 1]);
      }
      const recentIntervals = intervals.slice(-10);
      const avgInterval = recentIntervals.reduce((a, b) => a + b, 0) / recentIntervals.length;
      const variance =
        recentIntervals.reduce((sum, iv) => sum + Math.pow(iv - avgInterval, 2), 0) /
        recentIntervals.length;
      const stdDev = Math.sqrt(variance);

      // Very low variance = bot-like regularity
      if (avgInterval > 0 && stdDev / avgInterval < 0.05) {
        const score = 4;
        totalScore += score;
        anomalies.push({
          rule: 'timing-regularity',
          score,
          detail: `Request intervals too regular (stddev/mean = ${(stdDev / avgInterval).toFixed(3)}) -- possible bot`,
        });
      }
    }

    // Rule 5: Custom rules
    for (const rule of this.customRules) {
      try {
        const result = rule(ctx);
        if (result) {
          const score = result.score ?? 5;
          totalScore += score;
          anomalies.push({
            rule: 'custom',
            score,
            detail: typeof result === 'string' ? result : result.reason ?? 'Custom rule triggered',
          });
        }
      } catch {
        // Custom rules must never crash the detector
      }
    }

    // No anomalies detected
    if (anomalies.length === 0) {
      return {
        allowed: true,
        metadata: {
          score: 0,
          endpointSpread: profile.endpoints.size,
          requestsInWindow: profile.requestTimestamps.length,
        },
      };
    }

    const shouldBlock = this.action === 'block' && totalScore >= this.scoreThreshold;

    return {
      allowed: !shouldBlock,
      reason: shouldBlock
        ? `Anomaly detected (score ${totalScore}/${this.scoreThreshold}): ${anomalies[0].detail}`
        : undefined,
      metadata: {
        score: totalScore,
        threshold: this.scoreThreshold,
        anomalies,
        action: shouldBlock ? 'blocked' : 'flagged',
        flagged: true,
      },
    };
  }

  /**
   * Get current status.
   * @returns {Object}
   */
  getStatus() {
    return {
      trackedClients: this._profiles.size,
      config: {
        maxPayloadSize: this.maxPayloadSize,
        endpointSpreadThreshold: this.endpointSpreadThreshold,
        burstFactor: this.burstFactor,
        scoreThreshold: this.scoreThreshold,
        action: this.action,
      },
    };
  }

  /**
   * Destroy this layer.
   */
  destroy() {
    clearInterval(this._cleanupInterval);
    this._profiles.clear();
  }

  /** @private */
  _getProfile(clientId) {
    let profile = this._profiles.get(clientId);
    if (!profile) {
      profile = {
        endpoints: new Map(),
        windowStart: Date.now(),
        requestTimestamps: [],
        totalRequests: 0,
      };
      this._profiles.set(clientId, profile);
    }
    return profile;
  }

  /** @private */
  _cleanup() {
    const now = Date.now();
    const maxAge = this.spreadWindowMs * 3;
    for (const [clientId, profile] of this._profiles) {
      if (now - profile.windowStart > maxAge) {
        this._profiles.delete(clientId);
      }
    }
  }
}
