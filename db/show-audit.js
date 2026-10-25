// Menampilkan audit log terakhir. Pemakaian: npm run audit [jumlah]
const db = require('../shared/db').open();
const n = Number(process.argv[2]) || 30;
const rows = db.prepare('SELECT waktu, subjek, role, metode, endpoint, device, hasil, alasan FROM audit_log ORDER BY id DESC LIMIT ?').all(n).reverse();
console.table(rows);
