'use strict';
/**
 * Threat Index — zero-dependency Node.js server.
 *
 * Endpoints:
 *   GET  /                     -> the dashboard (public/index.html)
 *   GET  /api/vulnerabilities  -> the dataset, parsed out of index.html (single source of truth)
 *   POST /api/scan  {url}      -> passive security posture scan + graded report (see scanner.js)
 *   GET  /api/config           -> echoes config injected via ConfigMap/Secret (env vars)
 *   GET  /api/burn?ms=2000     -> burns CPU for the given ms — use it to trigger the HPA
 *   GET  /healthz | /readyz    -> probes
 *
 * Built-ins only (no npm packages) -> minimal supply-chain surface (A03:2025).
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const scanner = require('./scanner');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');

function loadDataset() {
  try {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
    const m = html.match(/<script id="vuln-data" type="application\/json">([\s\S]*?)<\/script>/);
    return m ? JSON.parse(m[1]) : [];
  } catch (e) { console.error('Failed to load dataset:', e.message); return []; }
}
const DATASET = loadDataset();
console.log(`Loaded ${DATASET.length} threat entries`);

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function sendJSON(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function serveStatic(req, res, urlPath) {
  const safe = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safe === '/' ? 'index.html' : safe);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

// --- tiny in-memory rate limit for /api/scan (per process): 20 / 60s ---
let scanTimes = [];
function scanAllowed() {
  const now = Date.now();
  scanTimes = scanTimes.filter((t) => now - t < 60000);
  if (scanTimes.length >= 20) return false;
  scanTimes.push(now);
  return true;
}

function readBody(req, limit, cb) {
  let body = ''; let over = false;
  req.on('data', (c) => { body += c; if (body.length > limit) { over = true; req.destroy(); } });
  req.on('end', () => cb(over ? null : body));
  req.on('error', () => cb(null));
}

async function handleScan(req, res) {
  if (!scanAllowed()) return sendJSON(res, 429, { error: 'rate_limited', message: 'Too many scans — wait a minute and retry.' });
  readBody(req, 4096, async (body) => {
    let url;
    try { url = JSON.parse(body || '{}').url; } catch { /* ignore */ }
    if (!url || typeof url !== 'string') return sendJSON(res, 400, { error: 'bad_request', message: 'Provide a URL to scan.' });
    try {
      const report = await scanner.scan(url.trim());
      sendJSON(res, 200, report);
    } catch (e) {
      if (e.code === 'BLOCKED') return sendJSON(res, 400, { error: 'blocked', message: e.message });
      if (e.code === 'BAD_URL') return sendJSON(res, 400, { error: 'bad_url', message: e.message });
      sendJSON(res, 502, { error: 'scan_failed', message: 'Could not reach or scan that target (' + e.message + ').' });
    }
  });
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;

  if (p === '/healthz') return sendJSON(res, 200, { status: 'ok' });
  if (p === '/readyz') return sendJSON(res, 200, { status: 'ready', entries: DATASET.length });

  if (p === '/api/vulnerabilities') { res.setHeader('Cache-Control', 'no-store'); return sendJSON(res, 200, DATASET); }

  if (p === '/api/scan') {
    if (req.method !== 'POST') return sendJSON(res, 405, { error: 'method_not_allowed' });
    return handleScan(req, res);
  }

  if (p === '/api/config') {
    return sendJSON(res, 200, {
      appEnvironment: process.env.APP_ENVIRONMENT || 'unset',
      featureBanner: process.env.FEATURE_BANNER || 'unset',
      apiKeyConfigured: Boolean(process.env.API_KEY),
      pod: process.env.HOSTNAME || 'unknown'
    });
  }

  if (p === '/api/burn') {
    const ms = Math.min(parseInt(u.searchParams.get('ms') || '2000', 10) || 2000, 15000);
    const end = Date.now() + ms; let n = 0;
    while (Date.now() < end) { n += Math.sqrt(n + 1) * Math.random(); }
    return sendJSON(res, 200, { burnedMs: ms, pod: process.env.HOSTNAME || 'unknown' });
  }

  return serveStatic(req, res, p);
});

server.listen(PORT, () => console.log(`Threat Index listening on :${PORT}`));
['SIGTERM', 'SIGINT'].forEach((sig) =>
  process.on(sig, () => server.close(() => { console.log(`${sig} received, shutting down`); process.exit(0); })));
