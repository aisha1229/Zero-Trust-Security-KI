// Utilitas kripto tanpa dependensi tambahan (modul bawaan Node.js).
const crypto = require('crypto');

// Hash password/secret dengan scrypt + salt acak. Format: scrypt$<salt>$<hash>
function hashSecret(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifySecret(plain, stored) {
  try {
    const [scheme, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const test = crypto.scryptSync(String(plain), salt, 64);
    return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
  } catch {
    return false;
  }
}

// Hash dummy supaya waktu respons login tidak membocorkan "username tidak ada".
const DUMMY_HASH = hashSecret('dummy-password-untuk-timing');

// Perbandingan string dalam waktu konstan (mencegah timing attack).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Refresh token disimpan sebagai hash SHA-256 (DB bocor != token bocor).
function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(48).toString('hex');
}

module.exports = { hashSecret, verifySecret, DUMMY_HASH, safeEqual, sha256, randomToken };
