/**
 * ShieldMetrics — In-memory metrics collector with rolling window.
 * Keeps the last 10,000 entries for real-time dashboard and status queries.
 *
 * Powered by Kairos Lab
 */
export class ShieldMetrics {
  constructor() {
    /** @type {Array<Object>} */
    this.entries = [];
    this.maxEntries = 10_000;
    this.counters = {
      totalRequests: 0,
      totalBlocked: 0,
      totalAllowed: 0,
      blockedByLayer: {},
    };
  }

  /**
   * Record a metric entry.
   * @param {Object} entry
   */
  record(entry) {
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }

    this.counters.totalRequests++;
    if (entry.allowed) {
      this.counters.totalAllowed++;
    } else {
      this.counters.totalBlocked++;
      if (entry.blockedBy) {
        this.counters.blockedByLayer[entry.blockedBy] =
          (this.counters.blockedByLayer[entry.blockedBy] ?? 0) + 1;
      }
    }
  }

  /**
   * Get a snapshot of current metrics across multiple time windows.
   * @returns {Object}
   */
  getSnapshot() {
    const now = Date.now();
    const last60s = this.entries.filter((e) => e.timestamp > now - 60_000);
    const last5m = this.entries.filter((e) => e.timestamp > now - 300_000);

    return {
      lifetime: { ...this.counters },
      last60s: {
        total: last60s.length,
        blocked: last60s.filter((e) => !e.allowed).length,
        allowed: last60s.filter((e) => e.allowed).length,
        avgEvaluationMs:
          last60s.length > 0
            ? last60s.reduce((sum, e) => sum + e.evaluationTimeMs, 0) /
              last60s.length
            : 0,
      },
      last5m: {
        total: last5m.length,
        blocked: last5m.filter((e) => !e.allowed).length,
        allowed: last5m.filter((e) => e.allowed).length,
        topBlockedEndpoints: this._getTopBlocked(last5m, 5),
        topClients: this._getTopClients(last5m, 5),
      },
    };
  }

  /**
   * Clear all metrics.
   */
  clear() {
    this.entries = [];
    this.counters = {
      totalRequests: 0,
      totalBlocked: 0,
      totalAllowed: 0,
      blockedByLayer: {},
    };
  }

  /** @private */
  _getTopBlocked(entries, limit) {
    const blocked = entries.filter((e) => !e.allowed);
    const counts = new Map();
    for (const e of blocked) {
      counts.set(e.endpoint, (counts.get(e.endpoint) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([endpoint, count]) => ({ endpoint, count }));
  }

  /** @private */
  _getTopClients(entries, limit) {
    const clients = new Map();
    for (const e of entries) {
      const c = clients.get(e.clientId) ?? { total: 0, blocked: 0 };
      c.total++;
      if (!e.allowed) c.blocked++;
      clients.set(e.clientId, c);
    }
    return [...clients.entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .slice(0, limit)
      .map(([clientId, stats]) => ({ clientId, ...stats }));
  }
}
