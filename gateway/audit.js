// =====================================================================
// AUDIT LOG (4.4) - gateway mencatat SETIAP keputusan akses:
// waktu, subjek (user/service), endpoint, device, hasil (allow/deny), alasan.
// Disimpan di tabel audit_log (SQLite) dan dicetak ke console.
// =====================================================================
const db = require('../shared/db').open();

const insert = db.prepare(
  `INSERT INTO audit_log (waktu, subjek, role, metode, endpoint, device, hasil, alasan)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
);

function audit({ subject, role = null, method, endpoint, device = null, allow, reason }) {
  const waktu = new Date().toISOString();
  const hasil = allow ? 'allow' : 'deny';
  try {
    insert.run(waktu, subject, role, method, endpoint, device, hasil, reason);
  } catch (e) {
    console.error('[audit] gagal menulis log:', e.message);
  }
  console.log(
    `[audit] ${waktu} | ${hasil.toUpperCase().padEnd(5)} | ${subject} (${role || '-'}) | ` +
    `${method} ${endpoint} | device=${device || '-'} | ${reason}`
  );
}

// Label subjek untuk log: "user:3" atau "service:nilai-service"
const labelOf = (s) => `${s.type}:${s.id}`;

module.exports = { audit, labelOf };
