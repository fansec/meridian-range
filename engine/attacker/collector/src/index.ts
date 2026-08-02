/**
 * attacker-collector - the exfil sink (Meridian Range).
 *
 *  Stands in for attacker-controlled infrastructure. Lives INSIDE labnet (internal: true), so nothing
 *  it "collects" ever leaves the lab. It only ever receives BENIGN canary data the scenarios produce,
 *  never real secrets/PII (SCOPE #2/#4/#5). Universal sink (app.all): logs every request as one JSON line.
 *
 *  Endpoint used by the shipped scenarios: POST /pwned (01 / 02 canary exfil). The sink accepts
 *  any method + path, so later modules (e.g. an auth-track OAuth callback) can reuse it without changes.
 *  Models the attacker origin https://attacker.lab.consulereit.nl, a lab-LAN-only name.
 */
import express from "express";
import { appendFileSync } from "node:fs";

const PORT = Number(process.env.PORT ?? 9000);
const LAB_LOG_FILE = process.env.LAB_LOG_FILE; // optional: mirror hits to a file for the live terminal pane
const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(express.text({ type: "*/*", limit: "64kb" }));

// Permissive CORS: the attacker controls this box, so it happily accepts a cross-origin beacon from
// their drive-by page (attacker.lab.consulereit.nl). Without it a real browser blocks the exfil preflight - the
// Node harness never sees this because it does not enforce CORS. Labnet-internal; benign data only.
app.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");
  next();
});
app.options("*", (_req, res) => res.sendStatus(204));

app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Universal sink - one JSON line per hit. This is what the redacted evidence quotes.
app.all("*", (req, res) => {
  const body =
    typeof req.body === "object" && req.body && Object.keys(req.body).length
      ? req.body
      : typeof req.body === "string" && req.body
        ? req.body
        : undefined;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    method: req.method,
    path: req.path,
    query: Object.keys(req.query).length ? req.query : undefined,
    from: req.ip,
    ua: req.headers["user-agent"] ?? null,
    body,
  });
  console.log(`[collector] EXFIL ${line}`);
  if (LAB_LOG_FILE) {
    try {
      appendFileSync(LAB_LOG_FILE, `EXFIL ${line}\n`);
    } catch {
      /* best-effort */
    }
  }
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`[collector] exfil sink on :${PORT} (labnet-internal; benign canary only)`));
