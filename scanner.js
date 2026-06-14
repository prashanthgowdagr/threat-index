'use strict';
/**
 * scanner.js — passive, non-intrusive web security posture checks.
 *
 * It only READS what a target already returns (headers, TLS handshake, cookies,
 * CORS, redirect behaviour). It sends NO attack payloads and attempts NO
 * exploitation. Categories that can't be observed passively (injection, access
 * control, auth logic, supply chain, infra) are reported as "manual" so nothing
 * is silently dropped.
 *
 * SSRF guard: the target hostname is resolved and every resulting IP is checked
 * against private / loopback / link-local / cloud-metadata ranges before any
 * connection is made, and again on every redirect hop. (Known limitation:
 * DNS rebinding between resolve and connect — acceptable for an authorized-use
 * study tool; production would pin the validated IP for the socket.)
 *
 * Zero npm dependencies — built-ins only.
 */
const https = require('https');
const http = require('http');
const tls = require('tls');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 4;
const MAX_BODY = 300 * 1024;
const UA = 'ThreatIndexScanner/1.0 (passive posture check)';

const SEV_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

// ---------------------------------------------------------------- SSRF guard
function ipToLong(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + (parseInt(o, 10) & 255), 0) >>> 0;
}
function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;             // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;   // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true;                            // multicast / reserved
  return false;
}
function isPrivateIPv6(ip) {
  const s = ip.toLowerCase();
  if (s === '::1' || s === '::') return true;
  if (s.startsWith('fe80') || s.startsWith('fec0')) return true; // link-local / site-local
  if (s.startsWith('fc') || s.startsWith('fd')) return true;     // unique-local fc00::/7
  const m = s.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);             // IPv4-mapped
  if (m) return isPrivateIPv4(m[1]);
  return false;
}
function isPrivateIP(ip) {
  return net.isIPv4(ip) ? isPrivateIPv4(ip) : isPrivateIPv6(ip);
}

async function assertSafeHost(hostname) {
  if (!hostname || hostname.toLowerCase() === 'localhost') {
    const e = new Error('Target host is localhost and was not scanned.'); e.code = 'BLOCKED'; throw e;
  }
  let addrs;
  if (net.isIP(hostname)) {
    addrs = [{ address: hostname }];
  } else {
    try { addrs = await dns.lookup(hostname, { all: true }); }
    catch { const e = new Error('Could not resolve the target hostname.'); e.code = 'BLOCKED'; throw e; }
  }
  for (const a of addrs) {
    if (isPrivateIP(a.address)) {
      const e = new Error('Target resolves to a private / internal / metadata address and was not scanned.');
      e.code = 'BLOCKED'; throw e;
    }
  }
}

// ---------------------------------------------------------------- HTTP fetch
function requestOnce(urlObj, method) {
  return new Promise((resolve, reject) => {
    const lib = urlObj.protocol === 'https:' ? https : http;
    const req = lib.request(urlObj, {
      method: method || 'GET',
      headers: { 'User-Agent': UA, 'Accept': '*/*' },
      rejectUnauthorized: false,          // inspect even a bad cert, then report it
      timeout: TIMEOUT_MS
    }, (res) => {
      let body = ''; let bytes = 0;
      res.on('data', (c) => {
        bytes += c.length;
        if (bytes <= MAX_BODY) body += c.toString('utf8');
        if (bytes > MAX_BODY) res.destroy();
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      res.on('close', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(new Error('Request timed out.')); });
    req.on('error', reject);
    req.end();
  });
}

async function fetchFollow(startUrl) {
  let current = new URL(startUrl);
  let redirects = 0;
  for (;;) {
    await assertSafeHost(current.hostname);
    const res = await requestOnce(current, 'GET');
    if (res.status >= 300 && res.status < 400 && res.headers.location && redirects < MAX_REDIRECTS) {
      redirects++;
      current = new URL(res.headers.location, current);
      continue;
    }
    return { ...res, finalUrl: current.toString(), finalHost: current.hostname, redirects };
  }
}

// ---------------------------------------------------------------- TLS check
function tlsInfo(host, port) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: port || 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError ? String(socket.authorizationError) : null;
      let daysLeft = null;
      if (cert && cert.valid_to) daysLeft = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
      socket.end();
      resolve({ protocol, authorized, authError, daysLeft, issuer: cert && cert.issuer && cert.issuer.O });
    });
    socket.on('error', (e) => resolve({ error: e.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'TLS handshake timed out.' }); });
  });
}

// ---------------------------------------------------------------- enforcement
async function httpsEnforced(host) {
  try {
    const res = await requestOnce(new URL(`http://${host}/`), 'HEAD');
    if (res.status >= 300 && res.status < 400 && /^https:/i.test(res.headers.location || '')) return { enforced: true };
    if (res.status >= 300 && res.status < 400) return { enforced: false, reason: 'redirects, but not to HTTPS' };
    return { enforced: false, reason: 'serves content over plain HTTP' };
  } catch {
    return { enforced: true, reason: 'HTTP not reachable (HTTPS-only)' }; // good: no plaintext listener
  }
}

// ---------------------------------------------------------------- analysis
function analyze(target) {
  const findings = [];
  const push = (f) => findings.push(f);

  const h = target.headers || {};
  const isHttps = target.finalUrl.startsWith('https:');

  // --- A04 Cryptographic Failures / transport ---
  if (!isHttps) {
    push({ category: 'A04', categoryId: 'A04', title: 'Site served over HTTP', severity: 'high', status: 'fail',
      detail: 'The page was reachable over plain HTTP; traffic can be read or modified in transit.',
      recommendation: 'Serve everything over HTTPS and redirect HTTP to HTTPS.' });
  }
  if (target.enforce && !target.enforce.enforced) {
    push({ category: 'A04', categoryId: 'A04', title: 'HTTP not redirected to HTTPS', severity: 'high', status: 'fail',
      detail: 'Plain HTTP ' + (target.enforce.reason || '') + '.',
      recommendation: 'Add a 301 redirect from HTTP to HTTPS at the edge / ingress.' });
  } else if (target.enforce) {
    push({ category: 'A04', categoryId: 'A04', title: 'HTTPS enforced', severity: 'info', status: 'pass',
      detail: target.enforce.reason || 'HTTP redirects to HTTPS.', recommendation: '' });
  }

  if (isHttps && target.tls) {
    const t = target.tls;
    if (t.error) {
      push({ category: 'A04', categoryId: 'A04', title: 'TLS handshake issue', severity: 'high', status: 'fail',
        detail: t.error, recommendation: 'Investigate the TLS configuration / certificate chain.' });
    } else {
      const proto = t.protocol || 'unknown';
      if (/TLSv1(\.0)?$|TLSv1\.1/.test(proto)) {
        push({ category: 'A04', categoryId: 'A04', title: 'Obsolete TLS version (' + proto + ')', severity: 'high', status: 'fail',
          detail: 'Deprecated TLS versions are vulnerable to known attacks.', recommendation: 'Require TLS 1.2 minimum; prefer TLS 1.3.' });
      } else {
        push({ category: 'A04', categoryId: 'A04', title: 'Modern TLS (' + proto + ')', severity: 'info', status: 'pass', detail: '', recommendation: '' });
      }
      if (!t.authorized) {
        push({ category: 'A04', categoryId: 'A04', title: 'Certificate not trusted', severity: 'high', status: 'fail',
          detail: t.authError || 'The certificate did not validate.', recommendation: 'Use a certificate from a trusted CA matching the hostname.' });
      } else if (t.daysLeft != null && t.daysLeft < 0) {
        push({ category: 'A04', categoryId: 'A04', title: 'Certificate expired', severity: 'high', status: 'fail',
          detail: 'Expired ' + Math.abs(t.daysLeft) + ' day(s) ago.', recommendation: 'Renew and automate certificate rotation.' });
      } else if (t.daysLeft != null && t.daysLeft < 14) {
        push({ category: 'A04', categoryId: 'A04', title: 'Certificate expiring soon', severity: 'medium', status: 'warn',
          detail: 'Expires in ' + t.daysLeft + ' day(s).', recommendation: 'Renew now; automate renewal.' });
      }
    }

    const hsts = h['strict-transport-security'];
    if (!hsts) {
      push({ category: 'A04', categoryId: 'A04', title: 'Missing HSTS header', severity: 'medium', status: 'fail',
        detail: 'Without Strict-Transport-Security, browsers may downgrade to HTTP.',
        recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains' });
    } else {
      const m = /max-age=(\d+)/.exec(hsts);
      if (m && Number(m[1]) < 15768000) {
        push({ category: 'A04', categoryId: 'A04', title: 'HSTS max-age is short', severity: 'low', status: 'warn',
          detail: 'max-age=' + m[1] + ' (< 6 months).', recommendation: 'Use max-age of at least 31536000 (1 year).' });
      } else {
        push({ category: 'A04', categoryId: 'A04', title: 'HSTS enabled', severity: 'info', status: 'pass', detail: '', recommendation: '' });
      }
    }
  }

  // --- A02 Security Misconfiguration / headers ---
  const csp = h['content-security-policy'];
  if (!csp) {
    push({ category: 'A05', categoryId: 'A05', title: 'Missing Content-Security-Policy', severity: 'medium', status: 'fail',
      detail: 'A CSP is the main browser defence that limits the impact of XSS.',
      recommendation: "Add a Content-Security-Policy starting from default-src 'self' and tighten." });
  } else if (/unsafe-inline|unsafe-eval/.test(csp)) {
    push({ category: 'A05', categoryId: 'A05', title: "CSP allows 'unsafe-inline' / 'unsafe-eval'", severity: 'low', status: 'warn',
      detail: 'These directives weaken the XSS protection a CSP provides.',
      recommendation: 'Remove unsafe-* and use nonces or hashes for inline scripts.' });
  } else {
    push({ category: 'A05', categoryId: 'A05', title: 'Content-Security-Policy present', severity: 'info', status: 'pass', detail: '', recommendation: '' });
  }

  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    push({ category: 'A02', categoryId: 'A02', title: 'Missing X-Content-Type-Options: nosniff', severity: 'low', status: 'fail',
      detail: 'Browsers may MIME-sniff responses, enabling some attacks.', recommendation: 'Add: X-Content-Type-Options: nosniff' });
  }

  const hasFrameProtection = h['x-frame-options'] || /frame-ancestors/i.test(csp || '');
  if (!hasFrameProtection) {
    push({ category: 'A02', categoryId: 'A02', title: 'No clickjacking protection', severity: 'medium', status: 'fail',
      detail: 'Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed.',
      recommendation: "Add CSP frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY." });
  }

  if (!h['referrer-policy']) {
    push({ category: 'A02', categoryId: 'A02', title: 'Missing Referrer-Policy', severity: 'low', status: 'fail',
      detail: 'URLs (which may contain sensitive data) can leak to other sites via the Referer header.',
      recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin' });
  }

  if (!h['permissions-policy']) {
    push({ category: 'A02', categoryId: 'A02', title: 'Missing Permissions-Policy', severity: 'low', status: 'warn',
      detail: 'Powerful browser features (camera, geolocation, etc.) are not explicitly restricted.',
      recommendation: 'Add a Permissions-Policy disabling features the site does not use.' });
  }

  // info disclosure
  const discl = [];
  if (h['server']) discl.push('Server: ' + h['server']);
  if (h['x-powered-by']) discl.push('X-Powered-By: ' + h['x-powered-by']);
  if (h['x-aspnet-version']) discl.push('X-AspNet-Version: ' + h['x-aspnet-version']);
  if (discl.length) {
    push({ category: 'A02', categoryId: 'A02', title: 'Server/technology disclosed in headers', severity: 'low', status: 'fail',
      detail: discl.join('; '), recommendation: 'Remove or genericise version-revealing response headers.' });
  }

  // --- CORS (A01 / A02) ---
  const acao = h['access-control-allow-origin'];
  if (acao === '*') {
    const creds = (h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    push({ category: 'A01', categoryId: 'A01', title: 'Permissive CORS (Access-Control-Allow-Origin: *)', severity: creds ? 'high' : 'medium', status: 'fail',
      detail: creds ? 'Wildcard origin combined with credentials is especially dangerous.' : 'Any origin can read responses from this endpoint.',
      recommendation: 'Allow-list specific trusted origins instead of *.' });
  }

  // --- Cookies (A04 / A07) ---
  let sc = h['set-cookie'];
  if (sc) {
    if (!Array.isArray(sc)) sc = [sc];
    let noSecure = 0, noHttpOnly = 0, noSameSite = 0;
    sc.forEach((c) => {
      const l = c.toLowerCase();
      if (isHttps && !/;\s*secure/.test(l)) noSecure++;
      if (!/;\s*httponly/.test(l)) noHttpOnly++;
      if (!/;\s*samesite/.test(l)) noSameSite++;
    });
    if (noSecure) push({ category: 'A04', categoryId: 'A04', title: noSecure + ' cookie(s) missing Secure', severity: 'medium', status: 'fail',
      detail: 'Cookies without Secure can be sent over plaintext HTTP.', recommendation: 'Set the Secure attribute on all cookies.' });
    if (noHttpOnly) push({ category: 'A07', categoryId: 'A07', title: noHttpOnly + ' cookie(s) missing HttpOnly', severity: 'medium', status: 'fail',
      detail: 'Cookies readable by JavaScript can be stolen via XSS.', recommendation: 'Set HttpOnly on session/auth cookies.' });
    if (noSameSite) push({ category: 'A01', categoryId: 'A01', title: noSameSite + ' cookie(s) missing SameSite', severity: 'low', status: 'warn',
      detail: 'Missing SameSite weakens CSRF protection.', recommendation: 'Set SameSite=Lax (or Strict) on cookies.' });
  }

  // --- A09-ish best practice ---
  if (target.securityTxt === true) {
    push({ category: 'A09', categoryId: 'A09', title: 'security.txt published', severity: 'info', status: 'pass', detail: '', recommendation: '' });
  } else if (target.securityTxt === false) {
    push({ category: 'A09', categoryId: 'A09', title: 'No security.txt', severity: 'info', status: 'info',
      detail: 'No /.well-known/security.txt to guide vulnerability reporting.', recommendation: 'Publish a security.txt with a contact for reports.' });
  }

  return findings;
}

// ---------------------------------------------------------------- scoring
function scoreFindings(findings) {
  let score = 100;
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
  findings.forEach((f) => {
    if (f.status === 'pass') { summary.pass++; return; }
    if (f.status === 'fail') { score -= SEV_WEIGHT[f.severity] || 0; summary[f.severity]++; }
    else if (f.status === 'warn') { score -= Math.round((SEV_WEIGHT[f.severity] || 0) / 2); summary[f.severity]++; }
    else { summary[f.severity] = (summary[f.severity] || 0) + 1; } // info
  });
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F';
  return { score, grade, summary };
}

// register items NOT observable by passive scanning, with the honest reason why
const MANUAL = [
  ['A01', 'Broken Access Control', 'Authorization flaws need authenticated, authorized active testing.'],
  ['A03', 'Software Supply Chain Failures', 'Lives in your build pipeline and dependencies, not in HTTP responses.'],
  ['A05', 'Injection', 'Detecting injection requires sending test payloads (active testing).'],
  ['A06', 'Insecure Design', 'Requires architecture and threat-model review, not a scan.'],
  ['A07', 'Authentication Failures', 'MFA, lockout and session logic need authenticated testing.'],
  ['A08', 'Software or Data Integrity Failures', 'Verified inside your CI/CD and signing pipeline.'],
  ['A10', 'Mishandling of Exceptional Conditions', 'Needs active fault-injection testing.'],
  ['K8s', 'Exposed Kubernetes API / kubelet', 'Checked in your AWS/EKS control-plane configuration.'],
  ['IAM', 'Over-permissive IAM / IRSA', 'IAM policies live in your AWS account.'],
  ['OBJ', 'Publicly Exposed Storage', 'Audited via your cloud account, not the web app.'],
  ['NET', 'Missing Network Policies', 'Internal to the cluster network.'],
  ['ROOT', 'Containers Running as Root', 'Inspected in your Kubernetes manifests.'],
  ['SG', 'Unrestricted Security Groups', 'Reviewed in your VPC configuration.'],
  ['SEC', 'Unencrypted / Hardcoded Secrets', 'Checked inside the cluster / cloud.']
];

// ---------------------------------------------------------------- main
async function scan(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); }
  catch { const e = new Error('That is not a valid URL. Include http:// or https://'); e.code = 'BAD_URL'; throw e; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const e = new Error('Only http:// and https:// targets are supported.'); e.code = 'BAD_URL'; throw e;
  }

  await assertSafeHost(parsed.hostname);                 // first gate (throws BLOCKED)

  const main = await fetchFollow(parsed.toString());     // re-guards each redirect hop
  const host = main.finalHost;
  const isHttps = main.finalUrl.startsWith('https:');
  const port = new URL(main.finalUrl).port || (isHttps ? 443 : 80);

  const [tlsResult, enforce, securityTxt] = await Promise.all([
    isHttps ? tlsInfo(host, Number(port)) : Promise.resolve(null),
    httpsEnforced(host).catch(() => null),
    requestOnce(new URL((isHttps ? 'https' : 'http') + '://' + host + '/.well-known/security.txt'), 'HEAD')
      .then((r) => r.status === 200).catch(() => false)
  ]);

  const target = { headers: main.headers, finalUrl: main.finalUrl, tls: tlsResult, enforce, securityTxt };
  const findings = analyze(target);
  const { score, grade, summary } = scoreFindings(findings);
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => {
    const sa = a.status === 'pass' ? 1 : 0, sb = b.status === 'pass' ? 1 : 0;
    if (sa !== sb) return sa - sb;
    return sevRank[a.severity] - sevRank[b.severity];
  });

  const observed = [...new Set(findings.filter((f) => f.status !== 'pass' || true).map((f) => f.categoryId))];
  const notObserved = MANUAL
    .filter((m) => !(m[0] === 'A05' && findings.some((f) => f.categoryId === 'A05')))
    .map((m) => ({ id: m[0], title: m[1], reason: m[2] }));

  return {
    target: rawUrl,
    finalUrl: main.finalUrl,
    scannedAt: new Date().toISOString(),
    grade, score, summary,
    findings,
    notObserved,
    meta: {
      status: main.status,
      redirects: main.redirects,
      tlsProtocol: tlsResult && tlsResult.protocol,
      certDaysLeft: tlsResult && tlsResult.daysLeft,
      httpsEnforced: enforce && enforce.enforced,
      server: main.headers && main.headers['server']
    }
  };
}

module.exports = { scan };
