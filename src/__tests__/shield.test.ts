import { describe, it, expect, vi } from "vitest";
import { Shield } from "../shield";

describe("Shield", () => {
  it("allows requests with no layers configured", async () => {
    const shield = new Shield();
    const result = await shield.evaluate({
      clientId: "test",
      endpoint: "/api/test",
    });
    expect(result.allowed).toBe(true);
    expect(result.requestId).toMatch(/^ksh_/);
    expect(result.evaluationTimeMs).toBeLessThan(10);
  });

  it("blocks when rate limit exceeded", async () => {
    const shield = new Shield({
      rateShield: { maxRequests: 3, windowMs: 60_000 },
    });

    for (let i = 0; i < 3; i++) {
      const r = await shield.evaluate({ clientId: "user1", endpoint: "/api" });
      expect(r.allowed).toBe(true);
    }

    const blocked = await shield.evaluate({
      clientId: "user1",
      endpoint: "/api",
    });
    expect(blocked.allowed).toBe(false);
    expect(blocked.blockedBy).toBe("rate-shield");
  });

  it("rate limits per client independently", async () => {
    const shield = new Shield({
      rateShield: { maxRequests: 2, windowMs: 60_000 },
    });

    await shield.evaluate({ clientId: "a", endpoint: "/api" });
    await shield.evaluate({ clientId: "a", endpoint: "/api" });
    const blockedA = await shield.evaluate({
      clientId: "a",
      endpoint: "/api",
    });
    expect(blockedA.allowed).toBe(false);

    const allowedB = await shield.evaluate({
      clientId: "b",
      endpoint: "/api",
    });
    expect(allowedB.allowed).toBe(true);
  });

  it("circuit breaker opens after failures", async () => {
    const shield = new Shield({
      circuitBreaker: {
        failureThreshold: 3,
        resetTimeoutMs: 1000,
      },
    });

    // All pass initially
    const r1 = await shield.evaluate({
      clientId: "user",
      endpoint: "/failing",
    });
    expect(r1.allowed).toBe(true);

    // Report 3 failures
    shield.reportOutcome("/failing", false, 500);
    shield.reportOutcome("/failing", false, 500);
    shield.reportOutcome("/failing", false, 500);

    // Circuit should be open
    const r2 = await shield.evaluate({
      clientId: "user",
      endpoint: "/failing",
    });
    expect(r2.allowed).toBe(false);
    expect(r2.blockedBy).toBe("circuit-breaker");
  });

  it("anomaly detector blocks oversized payloads", async () => {
    const shield = new Shield({
      anomalyDetector: { maxPayloadSize: 1000, action: "block" },
    });

    const r = await shield.evaluate({
      clientId: "user",
      endpoint: "/api",
      payloadSize: 5000,
    });
    expect(r.allowed).toBe(false);
    expect(r.blockedBy).toBe("anomaly-detector");
  });

  it("anomaly detector flags without blocking in flag mode", async () => {
    const shield = new Shield({
      anomalyDetector: { maxPayloadSize: 1000, action: "flag" },
    });

    const r = await shield.evaluate({
      clientId: "user",
      endpoint: "/api",
      payloadSize: 5000,
    });
    expect(r.allowed).toBe(true);
    expect(r.layers["anomaly-detector"]?.metadata?.flagged).toBe(true);
  });

  it("calls onBlock callback when blocked", async () => {
    const onBlock = vi.fn();
    const shield = new Shield({
      rateShield: { maxRequests: 1, windowMs: 60_000 },
      onBlock,
    });

    await shield.evaluate({ clientId: "u", endpoint: "/a" });
    await shield.evaluate({ clientId: "u", endpoint: "/a" });

    expect(onBlock).toHaveBeenCalledOnce();
    expect(onBlock.mock.calls[0]![0]!.allowed).toBe(false);
  });

  it("collects metrics", async () => {
    const shield = new Shield({
      rateShield: { maxRequests: 100, windowMs: 60_000 },
    });

    for (let i = 0; i < 5; i++) {
      await shield.evaluate({
        clientId: "user",
        endpoint: "/api",
      });
    }

    const metrics = shield.getMetrics();
    expect(metrics.lifetime.totalRequests).toBe(5);
    expect(metrics.lifetime.totalAllowed).toBe(5);
    expect(metrics.last60s.total).toBe(5);
  });

  it("fail-fast: stops at first blocking layer", async () => {
    const shield = new Shield({
      rateShield: { maxRequests: 1, windowMs: 60_000 },
      anomalyDetector: { maxPayloadSize: 100, action: "block" },
    });

    await shield.evaluate({ clientId: "u", endpoint: "/a" });

    // Second request: rate limit blocks first, anomaly detector never runs
    const r = await shield.evaluate({
      clientId: "u",
      endpoint: "/a",
      payloadSize: 500,
    });

    expect(r.allowed).toBe(false);
    expect(r.blockedBy).toBe("rate-shield");
    expect(r.layers["anomaly-detector"]).toBeUndefined();
  });

  it("getStatus returns layer info", () => {
    const shield = new Shield({
      rateShield: { maxRequests: 100 },
      circuitBreaker: { failureThreshold: 5 },
    });

    const status = shield.getStatus();
    expect(status.layers.rateShield.active).toBe(true);
    expect(status.layers.circuitBreaker.active).toBe(true);
    expect(status.layers.anomalyDetector.active).toBe(false);
    expect(status.layers.onChainAudit.active).toBe(false);
  });
});
