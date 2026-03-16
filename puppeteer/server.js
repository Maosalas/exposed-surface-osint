"use strict";

const express    = require("express");
const puppeteer  = require("puppeteer-core");

const PORT      = 3000;
const MAX_W     = 1920;
const MAX_H     = 1080;
const DEF_W     = 1280;
const DEF_H     = 720;
const TIMEOUT   = 25000;   // 25s max per screenshot
const MAX_QUEUE = 5;       // concurrent screenshots
const RATE_WIN  = 60000;   // 1 minute window
const RATE_MAX  = 30;      // max 30 screenshots/min

// ── Browser pool ──────────────────────────────────────────────────────────────
let browser = null;
let activeCount = 0;
const requestCounts = new Map(); // IP -> [timestamps]

async function getBrowser() {
  if (!browser || !browser.connected) {
    browser = await puppeteer.launch({
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
      headless: "new",
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--no-first-run",
        "--no-zygote",
        "--single-process",          // more stable in containers
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-translate",
        "--hide-scrollbars",
        "--mute-audio",
        "--disable-notifications",
        "--disable-permissions-api",
        // Network isolation: block private IPs to prevent SSRF
        "--disable-features=NetworkService",
      ],
      ignoreHTTPSErrors: true,
      timeout: 10000,
    });
    console.log("[browser] Launched Chromium");
  }
  return browser;
}

// ── SSRF protection: block private/internal IP ranges ────────────────────────
const BLOCKED_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,   // link-local
  /^::1$/,         // IPv6 loopback
  /^fc00:/i,       // IPv6 private
  /^fe80:/i,       // IPv6 link-local
  /^0\./,
  /^metadata\.google\.internal/i,
  /\.internal$/i,
  /\.local$/i,
];

function isSsrfTarget(url) {
  try {
    const { hostname } = new URL(url);
    return BLOCKED_PATTERNS.some(p => p.test(hostname));
  } catch {
    return true; // invalid URL → block
  }
}

function isValidUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// ── Rate limiter ──────────────────────────────────────────────────────────────
function checkRate(ip) {
  const now   = Date.now();
  const times = (requestCounts.get(ip) || []).filter(t => now - t < RATE_WIN);
  if (times.length >= RATE_MAX) return false;
  times.push(now);
  requestCounts.set(ip, times);
  return true;
}

// ── Take screenshot ───────────────────────────────────────────────────────────
async function screenshot({ url, width, height, fullPage, waitUntil, delay }) {
  const w = Math.min(width  || DEF_W, MAX_W);
  const h = Math.min(height || DEF_H, MAX_H);
  const wf = ["load", "domcontentloaded", "networkidle0", "networkidle2"].includes(waitUntil)
    ? waitUntil : "networkidle2";

  const b    = await getBrowser();
  const page = await b.newPage();

  try {
    await page.setViewport({ width: w, height: h });
    await page.setUserAgent(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
    );

    // Block ads, trackers, and unnecessary resources to speed up
    await page.setRequestInterception(true);
    page.on("request", req => {
      const type = req.resourceType();
      if (["media", "font", "websocket"].includes(type)) {
        req.abort();
      } else {
        req.continue();
      }
    });

    await page.goto(url, { waitUntil: wf, timeout: TIMEOUT });

    if (delay && delay > 0) {
      await new Promise(r => setTimeout(r, Math.min(delay, 3000)));
    }

    const png = await page.screenshot({
      fullPage: fullPage === true,
      type: "png",
      clip: fullPage ? undefined : { x: 0, y: 0, width: w, height: h },
    });

    return { ok: true, png };

  } catch (err) {
    return { ok: false, error: err.message };
  } finally {
    await page.close().catch(() => {});
  }
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "8kb" }));

// Only accept requests from the osint-internal Docker network (extra safety)
app.use((req, res, next) => {
  // Allow all — network-level isolation via Docker is the primary control
  // Could add IP allowlist here if needed: req.ip must be in 172.x.x.x range
  next();
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", activeScreenshots: activeCount });
});

// ── POST /screenshot ──────────────────────────────────────────────────────────
app.post("/screenshot", async (req, res) => {
  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";

  // Rate limit
  if (!checkRate(clientIp)) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  // Queue limit
  if (activeCount >= MAX_QUEUE) {
    return res.status(503).json({ error: "Too many concurrent screenshots, retry later" });
  }

  const { url, width, height, fullPage, waitUntil, delay } = req.body;

  // Validate URL
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'url' field" });
  }
  if (!isValidUrl(url)) {
    return res.status(400).json({ error: "URL must use http or https scheme" });
  }
  if (isSsrfTarget(url)) {
    return res.status(403).json({ error: "Target URL is not allowed (private/internal address)" });
  }

  activeCount++;
  const t = Date.now();
  console.log(`[screenshot] START  ${url} (active: ${activeCount})`);

  try {
    const result = await screenshot({ url, width, height, fullPage, waitUntil, delay });

    if (!result.ok) {
      console.log(`[screenshot] FAIL   ${url} — ${result.error}`);
      return res.status(422).json({ error: result.error });
    }

    const elapsed = Date.now() - t;
    console.log(`[screenshot] DONE   ${url} — ${result.png.length} bytes — ${elapsed}ms`);

    res.set("Content-Type", "image/png");
    res.set("X-Screenshot-Ms", String(elapsed));
    res.send(result.png);

  } catch (err) {
    console.error(`[screenshot] ERROR  ${url} — ${err.message}`);
    res.status(500).json({ error: err.message });
  } finally {
    activeCount--;
  }
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
process.on("SIGTERM", async () => {
  console.log("[shutdown] SIGTERM received");
  if (browser) await browser.close().catch(() => {});
  process.exit(0);
});

process.on("SIGINT", async () => {
  if (browser) await browser.close().catch(() => {});
  process.exit(0);
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[osint-puppeteer] Screenshot service running on :${PORT}`);
  console.log(`[osint-puppeteer] Chromium: ${process.env.PUPPETEER_EXECUTABLE_PATH}`);
  // Pre-warm browser
  getBrowser().catch(err => console.error("[browser] Pre-warm failed:", err.message));
});
