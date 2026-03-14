import { describe, it, expect } from "vitest";
import { AsterDexShield, createAsterDexShield } from "../adapters/asterdex";

describe("AsterDexShield", () => {
  it("creates with default config", () => {
    const shield = AsterDexShield.create();
    const status = shield.getStatus();
    expect(status.layers.rateShield.active).toBe(true);
    expect(status.layers.circuitBreaker.active).toBe(true);
    expect(status.layers.anomalyDetector.active).toBe(true);
  });

  it("allows normal requests", async () => {
    const shield = AsterDexShield.create();
    const result = await shield.protect({
      apiKey: "test-api-key-12345",
      endpoint: "/api/v3/futures/ticker",
      method: "GET",
    });
    expect(result.allowed).toBe(true);
  });

  it("enforces order endpoint limits", async () => {
    const shield = AsterDexShield.create();

    // Exhaust order limit (60 per minute)
    for (let i = 0; i < 60; i++) {
      await shield.protect({
        apiKey: "trader-key",
        endpoint: "/api/v3/futures/order",
        method: "POST",
        bodySize: 100,
      });
    }

    const blocked = await shield.protect({
      apiKey: "trader-key",
      endpoint: "/api/v3/futures/order",
      method: "POST",
      bodySize: 100,
    });

    expect(blocked.allowed).toBe(false);
    expect(blocked.blockedBy).toBe("rate-shield");
  });

  it("createAsterDexShield helper works", () => {
    const shield = createAsterDexShield({ verbose: false });
    expect(shield.getStatus().layers.rateShield.active).toBe(true);
  });

  it("reports responses to circuit breaker", async () => {
    const shield = AsterDexShield.create();

    // Report failures
    for (let i = 0; i < 5; i++) {
      shield.reportResponse("/api/v3/futures/order", 500);
    }

    // Circuit should be open
    const result = await shield.protect({
      apiKey: "test-key",
      endpoint: "/api/v3/futures/order",
      method: "POST",
    });

    expect(result.allowed).toBe(false);
    expect(result.blockedBy).toBe("circuit-breaker");
  });

  it("hashes API keys in metrics (never stores raw)", async () => {
    const shield = AsterDexShield.create();
    await shield.protect({
      apiKey: "my-secret-api-key-1234567890",
      endpoint: "/api/v3/futures/account",
    });

    const metrics = shield.getMetrics();
    const clients = metrics.last5m.topClients;
    if (clients.length > 0) {
      expect(clients[0]!.clientId).toMatch(/^key_/);
      expect(clients[0]!.clientId).not.toContain("my-secret");
    }
  });
});
