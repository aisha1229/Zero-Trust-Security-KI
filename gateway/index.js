// =====================================================================
// API GATEWAY = Policy Enforcement Point (PEP), port 3000.
// Satu-satunya pintu masuk. Alur setiap request ke /nilai, /kelas, /transkrip:
//   1. authenticate : verifikasi JWT (tanda tangan, masa berlaku, issuer)
//   2. authorize    : tanya Policy Engine (policy.js) -> allow/deny + alasan
//   3. audit        : catat keputusan ke audit log
//   4. proxy        : jika allow, teruskan ke service + header X-Gateway-Secret
// =====================================================================
const express = require('express');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('../shared/config');
const auth = require('./auth');
const { decide } = require('./policy');
const { audit, labelOf } = require('./audit');

const app = express();
app.disable('x-powered-by');

// ---------- Endpoint /auth/* (ditangani gateway sendiri) ----------
const jsonOnly = express.json({ limit: '10kb' });
app.post('/auth/login', jsonOnly, auth.login);
app.post('/auth/refresh', jsonOnly, auth.refresh);
app.post('/auth/logout', jsonOnly, auth.logout);
app.post('/auth/service', jsonOnly, auth.serviceToken);

// ---------- Proxy ke service ----------
function makeProxy(target) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    on: {
      proxyReq(proxyReq) {
        // Gateway menempelkan secret (menimpa header palsu dari client, jika ada).
        proxyReq.setHeader('X-Gateway-Secret', config.gatewaySecret);
      },
      error(err, req, res) {
        console.error('[proxy] error:', err.message);
        if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Gateway', reason: 'service tidak dapat dihubungi' }));
      },
    },
  });
}
const nilaiProxy = makeProxy(config.nilaiUrl);
const transkripProxy = makeProxy(config.transkripUrl);

// ---------- Langkah 1: autentikasi token ----------
function authenticate(req, res, next) {
  const device = req.get('X-Device-ID');
  const refuse = (reason) => {
    audit({ subject: 'anonim', method: req.method, endpoint: req.originalUrl, device, allow: false, reason });
    return res.status(401).json({ error: 'Unauthorized', reason });
  };

  const header = req.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) return refuse('access token tidak ada');

  let payload;
  try {
    payload = jwt.verify(header.slice(7), config.jwtSecret, {
      algorithms: ['HS256'], issuer: config.jwtIssuer,
    });
  } catch (err) {
    return refuse(err.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid');
  }

  // Token service wajib bertipe 'service' DAN role 'service' (dan sebaliknya).
  const isService = payload.typ === 'service' && payload.role === 'service';
  const isUser = payload.typ === 'access' && payload.role !== 'service';
  if (!isService && !isUser) return refuse('jenis token tidak valid');

  req.subject = { type: isService ? 'service' : 'user', id: String(payload.sub), role: payload.role };
  next();
}

// ---------- Langkah 2 & 3: keputusan kebijakan + audit ----------
function authorize(req, res, next) {
  const decision = decide({
    subject: req.subject,
    method: req.method,
    path: req.path,           // path mentah (tanpa query) -> sama dengan yang diteruskan
    query: req.query,
    deviceId: req.get('X-Device-ID'),
    now: new Date(),
  });

  audit({
    subject: labelOf(req.subject), role: req.subject.role, method: req.method,
    endpoint: req.originalUrl, device: req.get('X-Device-ID'),
    allow: decision.allow, reason: decision.reason,
  });

  if (!decision.allow)
    return res.status(decision.status).json({ error: 'Forbidden', reason: decision.reason });
  next();
}

// ---------- Langkah 4: teruskan ke service ----------
function forward(req, res, next) {
  const first = req.path.split('/')[1];
  if (first === 'transkrip') return transkripProxy(req, res, next);
  return nilaiProxy(req, res, next);   // /nilai dan /kelas ditangani Service Nilai
}

app.all(/^\/(nilai|kelas|transkrip)(\/|$)/, authenticate, authorize, forward);

// ---------- Selain itu: tolak (default deny) ----------
app.use((req, res) => {
  audit({
    subject: 'anonim', method: req.method, endpoint: req.originalUrl,
    device: req.get('X-Device-ID'), allow: false, reason: 'endpoint tidak dikenal (default deny)',
  });
  res.status(404).json({ error: 'Not Found', reason: 'endpoint tidak dikenal' });
});

// Error handler (mis. JSON rusak) -> balasan JSON, tanpa membocorkan stack trace.
app.use((err, req, res, next) => {
  audit({
    subject: 'anonim', method: req.method, endpoint: req.originalUrl,
    device: req.get('X-Device-ID'), allow: false, reason: 'request tidak valid (body/JSON rusak)',
  });
  res.status(400).json({ error: 'Bad Request', reason: 'request tidak valid' });
});

app.listen(config.ports.gateway, config.host, () =>
  console.log(`[gateway] PEP berjalan di http://${config.host}:${config.ports.gateway}`)
);
