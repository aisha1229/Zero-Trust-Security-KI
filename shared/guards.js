// =====================================================================
// Middleware keamanan yang dipasang di KEDUA service (Nilai & Transkrip).
// Prinsip "assume breach": service tidak percaya begitu saja pada gateway.
//   1) gatewayGuard : request harus membawa X-Gateway-Secret yang benar
//                     -> service tidak bisa diakses langsung (4.1)
//   2) tokenGuard   : token tetap diverifikasi ulang (tanda tangan + masa
//                     berlaku) walau request membawa gateway secret (4.1)
// =====================================================================
const jwt = require('jsonwebtoken');
const config = require('./config');
const { safeEqual } = require('./crypto');

function deny(res, status, reason) {
  return res.status(status).json({ error: status === 401 ? 'Unauthorized' : 'Forbidden', reason });
}

function gatewayGuard(req, res, next) {
  const given = req.get('X-Gateway-Secret');
  if (!given || !safeEqual(given, config.gatewaySecret)) {
    console.log(`[guard] TOLAK ${req.method} ${req.originalUrl} -> X-Gateway-Secret tidak ada/salah`);
    return deny(res, 403, 'akses langsung ke service ditolak (X-Gateway-Secret tidak ada/salah)');
  }
  next();
}

function tokenGuard(req, res, next) {
  const header = req.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) {
    return deny(res, 401, 'token tidak ada');
  }
  try {
    const payload = jwt.verify(header.slice(7), config.jwtSecret, {
      algorithms: ['HS256'],           // kunci algoritma -> tolak alg:none / downgrade
      issuer: config.jwtIssuer,
    });
    req.auth = { sub: String(payload.sub), role: payload.role, typ: payload.typ };
    next();
  } catch (err) {
    const reason = err.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid';
    console.log(`[guard] TOLAK ${req.method} ${req.originalUrl} -> ${reason}`);
    return deny(res, 401, reason);
  }
}

// Konversi nilai angka -> huruf & bobot (dipakai Service Nilai dan Transkrip).
function hurufDariAngka(n) {
  if (n >= 85) return 'A';
  if (n >= 80) return 'A-';
  if (n >= 75) return 'B+';
  if (n >= 70) return 'B';
  if (n >= 65) return 'B-';
  if (n >= 60) return 'C+';
  if (n >= 55) return 'C';
  if (n >= 40) return 'D';
  return 'E';
}
const BOBOT = { A: 4, 'A-': 3.7, 'B+': 3.3, B: 3, 'B-': 2.7, 'C+': 2.3, C: 2, D: 1, E: 0 };

module.exports = { gatewayGuard, tokenGuard, hurufDariAngka, BOBOT };
