/**
 * AsterDex V3 WebSocket + Kairos Lab Shield — Real-time Market Data
 *
 * This example shows how to combine Shield protection on REST calls
 * with real-time WebSocket market data from AsterDex V3.
 *
 * Pattern: WebSocket for data, Shield-protected REST for execution.
 *
 * Install:
 *   npm install @kairosauth/shield ethers ws
 */

import { AsterDexShield } from "@kairosauth/shield/adapters/asterdex";
import WebSocket from "ws";

// ─── Shield Setup ──────────────────────────────────────────────

const shield = AsterDexShield.create({
  verbose: true,
  onBlock: (result) => {
    console.warn(`[Shield] ${result.blockedBy}: ${result.reason}`);
  },
});

// ─── WebSocket Manager ─────────────────────────────────────────

class AsterDexStream {
  private ws: WebSocket | null = null;
  private pingInterval: ReturnType<typeof setInterval> | null = null;
  private subscriptionId = 1;

  constructor(private baseUrl = "wss://fstream.asterdex.com") {}

  connect(streams: string[]): void {
    const url = `${this.baseUrl}/stream?streams=${streams.join("/")}`;
    this.ws = new WebSocket(url);

    this.ws.on("open", () => {
      console.log("[WS] Connected to AsterDex");
      // AsterDex requires ping every 5 min, pong within 15 min
      this.pingInterval = setInterval(() => {
        this.ws?.ping();
      }, 4 * 60 * 1000); // Ping every 4 min (safe margin)
    });

    this.ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());
        this.handleMessage(msg);
      } catch {
        // Ignore malformed messages
      }
    });

    this.ws.on("close", () => {
      console.log("[WS] Disconnected — reconnecting in 5s");
      this.cleanup();
      setTimeout(() => this.connect(streams), 5000);
    });

    this.ws.on("error", (err) => {
      console.error("[WS] Error:", err.message);
    });
  }

  subscribe(streams: string[]): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({
          method: "SUBSCRIBE",
          params: streams,
          id: this.subscriptionId++,
        })
      );
    }
  }

  unsubscribe(streams: string[]): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({
          method: "UNSUBSCRIBE",
          params: streams,
          id: this.subscriptionId++,
        })
      );
    }
  }

  private handleMessage(msg: Record<string, unknown>): void {
    const stream = msg.stream as string;
    const data = msg.data as Record<string, unknown>;

    if (!stream || !data) return;

    if (stream.includes("@aggTrade")) {
      this.onTrade(data);
    } else if (stream.includes("@bookTicker")) {
      this.onBookTicker(data);
    } else if (stream.includes("@kline")) {
      this.onKline(data);
    }
  }

  private onTrade(data: Record<string, unknown>): void {
    console.log(
      `[Trade] ${data.s} ${data.m ? "SELL" : "BUY"} ${data.q} @ ${data.p}`
    );
  }

  private onBookTicker(data: Record<string, unknown>): void {
    console.log(
      `[Book] ${data.s} bid=${data.b} ask=${data.a}`
    );
  }

  private onKline(data: Record<string, unknown>): void {
    const k = data.k as Record<string, unknown>;
    if (k) {
      console.log(
        `[Kline] ${k.s} ${k.i} O=${k.o} H=${k.h} L=${k.l} C=${k.c} V=${k.v}`
      );
    }
  }

  private cleanup(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  close(): void {
    this.cleanup();
    this.ws?.close();
  }
}

// ─── Strategy Example: Simple Momentum ──────────────────────────

/**
 * Example strategy that listens to trades via WebSocket
 * and executes Shield-protected orders when conditions are met.
 */
async function momentumStrategy() {
  const stream = new AsterDexStream();

  // Connect to real-time data
  stream.connect([
    "btcusdt@aggTrade",
    "btcusdt@bookTicker",
    "btcusdt@kline_1m",
  ]);

  // Simulated trading loop — in production, this reacts to WS events
  const interval = setInterval(async () => {
    // All REST calls go through Shield automatically
    const check = await shield.protect({
      apiKey: "your-api-key",
      endpoint: "/fapi/v3/position",
      method: "GET",
    });

    if (check.allowed) {
      console.log("[Strategy] Position check allowed");
      // ... fetch positions, evaluate strategy, place orders ...
    } else {
      console.log(
        `[Strategy] Paused — Shield: ${check.reason}`
      );
    }

    // Monitor Shield health
    const metrics = shield.getMetrics();
    if (metrics.last60s.blocked > 5) {
      console.warn(
        `[Strategy] High block rate: ${metrics.last60s.blocked}/${metrics.last60s.total} in last 60s`
      );
    }
  }, 10_000);

  // Graceful shutdown
  process.on("SIGTERM", async () => {
    clearInterval(interval);
    stream.close();
    await shield.shutdown();
    console.log("[Strategy] Shut down gracefully");
    process.exit(0);
  });
}

momentumStrategy();
