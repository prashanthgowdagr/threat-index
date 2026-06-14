'use strict';
/**
 * Threat Index — zero-dependency Node.js server.
 *
 * Deliberately uses only Node built-ins (no npm packages) so the container has
 * essentially no third-party supply-chain surface — a practical nod to
 * A03:2025 Software Supply Chain Failures.
 *
 * Endpoints:
 *   GET /                     -> the dashboard (public/index.html)
 *   GET /api/vulnerabilities  -> the dataset, parsed out of index.html (single source of truth)
 *   GET /api/config           -> echoes config injected via ConfigMap/Secret (env vars)
 *   GET /api/burn?ms=2000     -> burns CPU for the given ms — use it to trigger the HPA
 *   GET /healthz              -> liveness probe
 *   GET /readyz               -> readiness probe
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---- Single source of truth: extract the dataset embedded in index.html ----
function loadDataset() {
  try {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
    const m = html.match(/<script id="vuln-data" type="application\/json">([\s\S]*?)<\/script>/);
    return m ? JSON.parse(m[1]) : [];
  } catch (e) {
    console.error('Failed to load dataset:', e.message);
    return [];
  }
}
const DATASET = loadDataset();
console.log(`Loaded ${DATASET.length} threat entries`);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

// Serve only files that resolve inside PUBLIC_DIR (defends against path traversal).
function serveStatic(req, res, urlPath) {
  const safe = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, '');
  let filePath = path.join(PUBLIC_DIR, safe === '/' ? 'index.html' : safe);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const p = u.pathname;

  if (p === '/healthz') return sendJSON(res, 200, { status: 'ok' });
  if (p === '/readyz')  return sendJSON(res, 200, { status: 'ready', entries: DATASET.length });

  if (p === '/api/vulnerabilities') {
    res.setHeader('Cache-Control', 'no-store');
    return sendJSON(res, 200, DATASET);
  }

  // Demonstrates ConfigMap (non-secret) + Secret (secret) injection via env vars.
  // The secret value is intentionally NOT returned — only whether it was wired in.
  if (p === '/api/config') {
    return sendJSON(res, 200, {
      appEnvironment: process.env.APP_ENVIRONMENT || 'unset',
      featureBanner: process.env.FEATURE_BANNER || 'unset',
      apiKeyConfigured: Boolean(process.env.API_KEY),   // true if the Secret is mounted, value hidden
      pod: process.env.HOSTNAME || 'unknown'
    });
  }

  // CPU burn — drives utilization up so you can watch the HorizontalPodAutoscaler react.
  if (p === '/api/burn') {
    const ms = Math.min(parseInt(u.searchParams.get('ms') || '2000', 10) || 2000, 15000);
    const end = Date.now() + ms;
    let n = 0;
    while (Date.now() < end) { n += Math.sqrt(n + 1) * Math.random(); }
    return sendJSON(res, 200, { burnedMs: ms, pod: process.env.HOSTNAME || 'unknown' });
  }

  return serveStatic(req, res, p);
});

server.listen(PORT, () => console.log(`Threat Index listening on :${PORT}`));

// Graceful shutdown so Kubernetes rolling updates / scale-downs are clean.
['SIGTERM', 'SIGINT'].forEach(sig =>
  process.on(sig, () => server.close(() => { console.log(`${sig} received, shutting down`); process.exit(0); }))
);
