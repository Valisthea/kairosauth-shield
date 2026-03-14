import type { MetricEntry } from "./types";

/**
 * In-memory metrics collector with rolling window.
 * Keeps the last 10,000 entries for real-time dashboard and status queries.
 */
export class ShieldMetrics {
  private entries: MetricEntry[] = [];
  private maxEntries = 10_000;
  private counters = {
    totalRequests: 0,
    totalBlocked: 0,
    totalAllowed: 0,
    blockedByLayer: {} as Record<string, number>,
  };

  record(entry: MetricEntry): void {
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
        topBlockedEndpoints: this.getTopBlocked(last5m, 5),
        topClients: this.getTopClients(last5m, 5),
      },
    };
  }

  clear(): void {
    this.entries = [];
    this.counters = {
      totalRequests: 0,
      totalBlocked: 0,
      totalAllowed: 0,
      blockedByLayer: {},
    };
  }

  private getTopBlocked(
    entries: MetricEntry[],
    limit: number
  ): Array<{ endpoint: string; count: number }> {
    const blocked = entries.filter((e) => !e.allowed);
    const counts = new Map<string, number>();
    for (const e of blocked) {
      counts.set(e.endpoint, (counts.get(e.endpoint) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([endpoint, count]) => ({ endpoint, count }));
  }

  private getTopClients(
    entries: MetricEntry[],
    limit: number
  ): Array<{ clientId: string; total: number; blocked: number }> {
    const clients = new Map<
      string,
      { total: number; blocked: number }
    >();
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
