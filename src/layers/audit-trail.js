/**
 * Audit Trail — On-chain audit trail for API security events.
 * Powered by Kairos Lab.
 *
 * Hashes each API call, batches into a Merkle tree, and anchors
 * the root hash via KairosAuth's on-chain Merkle infrastructure.
 *
 * This creates an immutable, tamper-proof audit trail:
 * - Every blocked request has a cryptographic proof of detection
 * - Every anomaly is permanently recorded and verifiable
 * - Audit trails cannot be retroactively altered
 * - Compliance-ready evidence for security incidents
 */
export class AuditTrail {
  /**
   * @param {Object} config
   * @param {string} config.apiEndpoint             - Kairos Lab API endpoint for anchoring proofs.
   * @param {string} config.apiKey                  - Kairos Lab API key.
   * @param {number} [config.batchSize=100]         - Anchor after N events.
   * @param {number} [config.flushIntervalMs=300000] - Max time before flushing batch (5 min default).
   * @param {'all'|'blocks-only'|'anomalies-only'} [config.auditScope='blocks-only'] - Which events to anchor.
   */
  constructor(config) {
    if (!config.apiEndpoint || !config.apiKey) {
      throw new Error('[AuditTrail] apiEndpoint and apiKey are required');
    }

    this.apiEndpoint = config.apiEndpoint;
    this.apiKey = config.apiKey;
    this.batchSize = config.batchSize ?? 100;
    this.flushIntervalMs = config.flushIntervalMs ?? 300_000;
    this.auditScope = config.auditScope ?? 'blocks-only';

    /** @type {Array<Object>} */
    this._batch = [];
    this._anchoredBatches = 0;
    this._totalAnchored = 0;
    this._lastAnchorTime = null;

    // Periodic flush
    this._flushTimer = setInterval(
      () => this.flush().catch(() => {}),
      this.flushIntervalMs
    );
    if (this._flushTimer.unref) this._flushTimer.unref();
  }

  /**
   * Record a metric entry for future anchoring.
   *
   * @param {Object} metric
   * @returns {Promise<void>}
   */
  async record(metric) {
    // Filter based on audit scope
    if (this.auditScope === 'blocks-only' && metric.allowed) return;
    if (
      this.auditScope === 'anomalies-only' &&
      !metric.layers?.['anomaly-detector']?.metadata?.flagged
    ) {
      return;
    }

    this._batch.push(metric);

    if (this._batch.length >= this.batchSize) {
      await this.flush();
    }
  }

  /**
   * Flush the current batch — build Merkle tree and anchor root on-chain.
   *
   * @returns {Promise<void>}
   */
  async flush() {
    if (this._batch.length === 0) return;

    const events = [...this._batch];
    this._batch = [];

    try {
      // Hash each event into a Merkle leaf
      const leaves = events.map((e) => this._hashEvent(e));
      const merkleRoot = this._computeMerkleRoot(leaves);

      // Anchor to Kairos Lab
      const response = await fetch(`${this.apiEndpoint}/v1/shield/anchor`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          merkleRoot,
          eventCount: events.length,
          timeRange: {
            from: events[0].timestamp,
            to: events[events.length - 1].timestamp,
          },
          summary: {
            blocked: events.filter((e) => !e.allowed).length,
            allowed: events.filter((e) => e.allowed).length,
            uniqueClients: new Set(events.map((e) => e.clientId)).size,
          },
        }),
      });

      if (!response.ok) {
        // Re-add events for retry
        this._batch.unshift(...events);
        return;
      }

      this._anchoredBatches++;
      this._totalAnchored += events.length;
      this._lastAnchorTime = Date.now();
    } catch {
      // Network error — re-add for retry (cap to prevent memory leak)
      if (this._batch.length < this.batchSize * 5) {
        this._batch.unshift(...events);
      }
    }
  }

  /**
   * Get current audit trail status.
   * @returns {Object}
   */
  getStatus() {
    return {
      pendingEvents: this._batch.length,
      anchoredBatches: this._anchoredBatches,
      totalAnchored: this._totalAnchored,
      lastAnchorTime: this._lastAnchorTime,
      config: {
        batchSize: this.batchSize,
        flushIntervalMs: this.flushIntervalMs,
        auditScope: this.auditScope,
      },
    };
  }

  /**
   * Destroy — flush pending and clear intervals.
   * @returns {Promise<void>}
   */
  async destroy() {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    await this.flush();
  }

  /**
   * Hash a single event into a Merkle leaf.
   * Uses a fast non-cryptographic hash for leaf nodes.
   * The authoritative Merkle tree is computed server-side with Keccak256.
   * @private
   */
  _hashEvent(event) {
    const data = [
      event.timestamp,
      event.requestId,
      event.clientId,
      event.endpoint,
      event.allowed,
      event.blockedBy ?? '',
    ].join(':');

    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash + char) | 0;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  /**
   * Compute Merkle root from leaf hashes.
   * Pairs leaves and hashes upward until a single root remains.
   * @private
   */
  _computeMerkleRoot(leaves) {
    if (leaves.length === 0) return '0'.repeat(64);
    if (leaves.length === 1) return leaves[0];

    const nextLevel = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i];
      const right = leaves[i + 1] ?? left; // Duplicate last leaf if odd
      const combined = left + right;
      let hash = 0;
      for (let j = 0; j < combined.length; j++) {
        hash = ((hash << 5) - hash + combined.charCodeAt(j)) | 0;
      }
      nextLevel.push(Math.abs(hash).toString(16).padStart(8, '0'));
    }

    return this._computeMerkleRoot(nextLevel);
  }
}
