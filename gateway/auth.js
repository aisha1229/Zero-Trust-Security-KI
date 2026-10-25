// =====================================================================
// Endpoint /auth/* - ditangani langsung oleh gateway (PE/PA):
//   POST /auth/login    : kredensial valid + device terdaftar
//   POST /auth/refresh  : refresh token valid & belum dicabut
//   POST /auth/logout   : mencabut refresh token
//   POST /auth/service  : client ID + secret valid -> token service 5 menit
// =====================================================================
const jwt = require('jsonwebtoken');
const config = require('../shared/config');
const db = require('../shared/db').open();
const { verifySecret, DUMMY_HASH, sha256, randomToken } = require('../shared/crypto');
const { isDeviceRegistered } = require('./policy');
const { audit } = require('./audit');

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertRefresh: db.prepare(
    'INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at, revoked, created_at) VALUES (?,?,?,?,0,?)'
  ),
  findRefresh: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
  revokeRefresh: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?'),
  client: db.prepare('SELECT * FROM service_clients WHERE client_id = ?'),
};

// Access token user: JWT 10 menit, minimal berisi sub dan role.
function signAccessToken(user) {
  return jwt.sign({ sub: String(user.id), role: user.role, typ: 'access' }, config.jwtSecret, {
    algorithm: 'HS256', expiresIn: config.accessTokenTtl, issuer: config.jwtIssuer,
  });
}

// Token service: JWT 5 menit, role: service.
function signServiceToken(clientId) {
  return jwt.sign({ sub: clientId, role: 'service', typ: 'service' }, config.jwtSecret, {
    algorithm: 'HS256', expiresIn: config.serviceTokenTtl, issuer: config.jwtIssuer,
  });
}

function reply(res, req, { allow, status, reason, subject, role, body }) {
  audit({
    subject, role, method: req.method, endpoint: req.originalUrl,
    device: req.get('X-Device-ID'), allow, reason,
  });
  if (allow) return res.status(status).json(body);
  return res.status(status).json({ error: status === 401 ? 'Unauthorized' : status === 400 ? 'Bad Request' : 'Forbidden', reason });
}

const isStr = (v) => typeof v === 'string' && v.length > 0;

// ---------------- POST /auth/login ----------------
function login(req, res) {
  const { username, password } = req.body || {};
  if (!isStr(username) || !isStr(password))
    return reply(res, req, { allow: false, status: 400, reason: 'username dan password wajib diisi', subject: 'anonim' });

  const user = q.userByName.get(username);
  // Verifikasi tetap dijalankan walau user tidak ada (timing seragam).
  const passOk = verifySecret(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !passOk)
    return reply(res, req, { allow: false, status: 401, reason: 'kredensial tidak valid', subject: `anonim:${username.slice(0, 40)}` });

  const subject = `user:${user.id}`;
  const deviceId = req.get('X-Device-ID');
  if (!isDeviceRegistered(user.id, deviceId))
    return reply(res, req, { allow: false, status: 403, reason: 'device tidak terdaftar untuk user ini (X-Device-ID)', subject, role: user.role });

  const refreshToken = randomToken();
  const now = Date.now();
  q.insertRefresh.run(user.id, sha256(refreshToken), deviceId, now + config.refreshTokenTtlMs, now);

  return reply(res, req, {
    allow: true, status: 200, reason: 'login berhasil', subject, role: user.role,
    body: {
      access_token: signAccessToken(user),
      token_type: 'Bearer',
      expires_in: 600,
      refresh_token: refreshToken,
      role: user.role,
    },
  });
}

// Cari refresh token yang valid (ada, belum dicabut, belum kedaluwarsa).
function findValidRefresh(token) {
  if (!isStr(token)) return { error: 'refresh_token wajib diisi' };
  const row = q.findRefresh.get(sha256(token));
  if (!row) return { error: 'refresh token tidak valid' };
  if (row.revoked) return { error: 'refresh token sudah dicabut', row };
  if (row.expires_at < Date.now()) return { error: 'refresh token kedaluwarsa', row };
  return { row };
}

// ---------------- POST /auth/refresh ----------------
function refresh(req, res) {
  const { error, row } = findValidRefresh((req.body || {}).refresh_token);
  if (error)
    return reply(res, req, { allow: false, status: 401, reason: error, subject: row ? `user:${row.user_id}` : 'anonim' });
  const user = q.userById.get(row.user_id);
  if (!user)
    return reply(res, req, { allow: false, status: 401, reason: 'akun tidak ditemukan', subject: `user:${row.user_id}` });
  return reply(res, req, {
    allow: true, status: 200, reason: 'access token diperbarui', subject: `user:${user.id}`, role: user.role,
    body: { access_token: signAccessToken(user), token_type: 'Bearer', expires_in: 600 },
  });
}

// ---------------- POST /auth/logout ----------------
function logout(req, res) {
  const { error, row } = findValidRefresh((req.body || {}).refresh_token);
  if (error)
    return reply(res, req, { allow: false, status: 401, reason: error, subject: row ? `user:${row.user_id}` : 'anonim' });
  q.revokeRefresh.run(row.id);   // refresh token dicabut -> tidak bisa dipakai lagi
  const user = q.userById.get(row.user_id);
  return reply(res, req, {
    allow: true, status: 200, reason: 'logout berhasil, refresh token dicabut',
    subject: `user:${row.user_id}`, role: user && user.role,
    body: { message: 'logout berhasil, refresh token dicabut' },
  });
}

// ---------------- POST /auth/service ----------------
function serviceToken(req, res) {
  const { client_id, client_secret } = req.body || {};
  if (!isStr(client_id) || !isStr(client_secret))
    return reply(res, req, { allow: false, status: 400, reason: 'client_id dan client_secret wajib diisi', subject: 'anonim' });
  const client = q.client.get(client_id);
  const ok = verifySecret(client_secret, client ? client.secret_hash : DUMMY_HASH);
  if (!client || !ok)
    return reply(res, req, { allow: false, status: 401, reason: 'client ID/secret tidak valid', subject: `anonim:${client_id.slice(0, 40)}` });
  return reply(res, req, {
    allow: true, status: 200, reason: 'token service diterbitkan', subject: `service:${client.client_id}`, role: 'service',
    body: { access_token: signServiceToken(client.client_id), token_type: 'Bearer', expires_in: 300, role: 'service' },
  });
}

module.exports = { login, refresh, logout, serviceToken };
