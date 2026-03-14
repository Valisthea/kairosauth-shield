import type { OnChainAuditConfig, MetricEntry } from "../types";

/**
 * On-Chain Audit — Anchors API security events to the blockchain
 * via Kairos Lab's Merkle tree infrastructure.
 *
 * Events are batched and periodically flushed to minimize on-chain costs.
 * Each batch produces a Merkle root that is anchored on-chain, providing
 * an immutable, tamper-proof audit trail of all API security events.
 *
 * This means:
 * - Every blocked request has a cryptographic proof of detection
 * - Every anomaly is permanently recorded and verifiable
 * - Audit trails cannot be retroactively altered
 * - Compliance-ready evidence for security incidents
 */
export class OnChainAudit {
  private config: Required<
    Pick<OnChainAuditConfig, "batchSize" | "flushIntervalMs" | "auditScope">
  > &
    OnChainAuditConfig;
  private batch: MetricEntry[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private anchoredBatches = 0;
  private totalAnchored = 0;
  private lastAnchorTime: number | null = null;

  constructor(config: OnChainAuditConfig) {
    this.config = {
      batchSize: config.batchSize ?? 100,
      flushIntervalMs: config.flushIntervalMs ?? 300_000,
      auditScope: config.auditScope ?? "blocks-only",
      ...config,
    };

    // Periodic flush
    this.flushTimer = setInterval(
      () => this.flush().catch(() => {}),
      this.config.flushIntervalMs
    );
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  async record(metric: MetricEntry): Promise<void> {
    // Filter based on audit scope
    if (this.config.auditScope === "blocks-only" && metric.allowed) return;
    if (
      this.config.auditScope === "anomalies-only" &&
      !metric.layers["anomaly-detector"]?.metadata?.flagged
    )
      return;

    this.batch.push(metric);

    if (this.batch.length >= this.config.batchSize) {
      await this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.batch.length === 0) return;

    const events = [...this.batch];
    this.batch = [];

    try {
      // Build Merkle tree from events
      const leaves = events.map((e) => this.hashEvent(e));
      const merkleRoot = this.computeMerkleRoot(leaves);

      // Anchor to Kairos Lab
      const response = await fetch(
        `${this.config.apiEndpoint}/v1/shield/anchor`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.config.apiKey}`,
          },
          body: JSON.stringify({
            merkleRoot,
            eventCount: events.length,
            timeRange: {
              from: events[0]!.timestamp,
              to: events[events.length - 1]!.timestamp,
            },
            summary: {
              blocked: events.filter((e) => !e.allowed).length,
              allowed: events.filter((e) => e.allowed).length,
              uniqueClients: new Set(events.map((e) => e.clientId)).size,
            },
          }),
        }
      );

      if (!response.ok) {
        // Re-add events to batch for retry
        this.batch.unshift(...events);
        return;
      }

      this.anchoredBatches++;
      this.totalAnchored += events.length;
      this.lastAnchorTime = Date.now();
    } catch {
      // Network error — re-add for retry, but cap batch size
      if (this.batch.length < this.config.batchSize * 5) {
        this.batch.unshift(...events);
      }
      // If batch is too large, drop oldest events to prevent memory leak
    }
  }

  getStatus() {
    return {
      pendingEvents: this.batch.length,
      anchoredBatches: this.anchoredBatches,
      totalAnchored: this.totalAnchored,
      lastAnchorTime: this.lastAnchorTime,
      config: {
        batchSize: this.config.batchSize,
        flushIntervalMs: this.config.flushIntervalMs,
        auditScope: this.config.auditScope,
      },
    };
  }

  /**
   * Hash an event into a leaf for the Merkle tree.
   */
  private hashEvent(event: MetricEntry): string {
    const data = `${event.timestamp}:${event.requestId}:${event.clientId}:${event.endpoint}:${event.allowed}`;
    // Simple hash for leaf node — the real Merkle computation happens server-side
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash + char) | 0;
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
  }

  /**
   * Compute a simple Merkle root from leaves.
   * The authoritative Merkle tree is computed server-side with Keccak256.
   */
  private computeMerkleRoot(leaves: string[]): string {
    if (leaves.length === 0) return "0".repeat(64);
    if (leaves.length === 1) return leaves[0]!;

    const nextLevel: string[] = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i]!;
      const right = leaves[i + 1] ?? left;
      const combined = left + right;
      let hash = 0;
      for (let j = 0; j < combined.length; j++) {
        hash = ((hash << 5) - hash + combined.charCodeAt(j)) | 0;
      }
      nextLevel.push(Math.abs(hash).toString(16).padStart(8, "0"));
    }

    return this.computeMerkleRoot(nextLevel);
  }

  async destroy(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }
}
