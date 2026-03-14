/**
 * Express Middleware Example — Protect your own API with Shield
 *
 * If you're building an API that proxies or wraps AsterDex (or any API),
 * Shield can protect your endpoints as Express middleware.
 *
 * Install:
 *   npm install @kairosauth/shield express
 */

import { Shield } from "@kairosauth/shield";
import express from "express";

const app = express();
app.use(express.json());

// ─── Shield Configuration ──────────────────────────────────────

const shield = new Shield({
  name: "my-api",

  rateShield: {
    maxRequests: 100,
    windowMs: 60_000,
    warningThreshold: 0.8,
    endpointLimits: {
      "/api/trade/*": { maxRequests: 30, windowMs: 60_000 },
      "/api/auth/*": { maxRequests: 10, windowMs: 300_000 },
    },
  },

  circuitBreaker: {
    failureThreshold: 5,
    resetTimeoutMs: 30_000,
  },

  anomalyDetector: {
    maxPayloadSize: 512_000,
    endpointSpreadThreshold: 30,
    burstFactor: 5,
    action: "block",
  },

  onBlock: (result) => {
    console.warn(
      `[Shield] Blocked ${result.requestId}: ${result.reason}`
    );
  },
});

// ─── Middleware ─────────────────────────────────────────────────

function shieldMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const clientId =
    (req.headers["x-api-key"] as string) ||
    req.ip ||
    "unknown";

  shield
    .evaluate({
      clientId,
      endpoint: req.path,
      method: req.method,
      payloadSize: parseInt(req.headers["content-length"] || "0"),
    })
    .then((result) => {
      // Always attach request ID for tracing
      res.setHeader("X-Shield-Request-Id", result.requestId);

      if (!result.allowed) {
        const rateShield = result.layers["rate-shield"]?.metadata;

        res.status(429).json({
          error: "Too many requests",
          message: result.reason,
          requestId: result.requestId,
          retryAfter: rateShield?.retryAfterSeconds ?? 60,
        });

        return;
      }

      // Attach rate limit headers (like GitHub API does)
      const meta = result.layers["rate-shield"]?.metadata;
      if (meta) {
        res.setHeader("X-RateLimit-Limit", String(meta.limit ?? ""));
        res.setHeader("X-RateLimit-Remaining", String(meta.remaining ?? ""));
        if (meta.warning) {
          res.setHeader("X-RateLimit-Warning", String(meta.warningMessage ?? ""));
        }
      }

      next();
    })
    .catch(() => {
      // Shield errors should never block requests
      next();
    });
}

// ─── Routes ────────────────────────────────────────────────────

// Apply Shield to all /api routes
app.use("/api", shieldMiddleware);

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", shield: shield.getStatus() });
});

app.post("/api/trade/order", (req, res) => {
  // Your trading logic here...
  res.json({ success: true, order: req.body });
});

app.get("/api/trade/positions", (_req, res) => {
  res.json({ positions: [] });
});

// Shield metrics endpoint (useful for monitoring dashboards)
app.get("/api/shield/metrics", (_req, res) => {
  res.json(shield.getMetrics());
});

// ─── Server ────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on :${PORT} with Kairos Lab Shield active`);
});

process.on("SIGTERM", async () => {
  await shield.shutdown();
  process.exit(0);
});
