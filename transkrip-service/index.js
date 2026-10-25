// =====================================================================
// SERVICE TRANSKRIP (Resource), port 3002.
// Data transkrip mahasiswa. Hanya bisa dicapai lewat gateway.
//   - GET  /transkrip/:nim     : mahasiswa (NIM sendiri) / admin (semua)
//   - POST /transkrip/sinkron  : HANYA token service
// =====================================================================
const express = require('express');
const config = require('../shared/config');
const db = require('../shared/db').open();
const { gatewayGuard, tokenGuard, hurufDariAngka, BOBOT } = require('../shared/guards');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '200kb' }));
app.use(gatewayGuard, tokenGuard);   // secret gateway + verifikasi ulang token

const q = {
  user: db.prepare('SELECT id, role, nim FROM users WHERE id = ?'),
  mhsByNim: db.prepare("SELECT nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'"),
  transkrip: db.prepare(
    `SELECT kelas_id, kode_mk, nama_mk, sks, nilai_angka, nilai_huruf FROM transkrip WHERE nim = ? ORDER BY kode_mk`
  ),
  upsert: db.prepare(
    `INSERT INTO transkrip (nim, kelas_id, kode_mk, nama_mk, sks, nilai_angka, nilai_huruf, synced_at)
     VALUES (@nim, @kelas_id, @kode_mk, @nama_mk, @sks, @nilai_angka, @nilai_huruf, @synced_at)
     ON CONFLICT (nim, kelas_id) DO UPDATE SET
       nilai_angka = excluded.nilai_angka, nilai_huruf = excluded.nilai_huruf, synced_at = excluded.synced_at`
  ),
};

const forbid = (res, reason) => res.status(403).json({ error: 'Forbidden', reason });

// ---------- GET /transkrip/:nim ----------
app.get('/transkrip/:nim', (req, res) => {
  if (req.auth.typ !== 'access') return forbid(res, 'token service tidak boleh membaca transkrip');
  const user = q.user.get(Number(req.auth.sub));
  if (!user || user.role !== req.auth.role) return forbid(res, 'akun tidak valid');

  const nim = req.params.nim;
  if (user.role === 'mahasiswa') {
    if (user.nim !== nim) return forbid(res, 'mahasiswa hanya boleh melihat transkrip NIM sendiri');
  } else if (user.role !== 'admin') {
    return forbid(res, 'role tidak diizinkan melihat transkrip');
  }

  const mhs = q.mhsByNim.get(nim);
  if (!mhs) return res.status(404).json({ error: 'Not Found', reason: 'mahasiswa tidak ditemukan' });

  const matkul = q.transkrip.all(nim);
  const totalSks = matkul.reduce((s, m) => s + m.sks, 0);
  const totalMutu = matkul.reduce((s, m) => s + m.sks * (BOBOT[m.nilai_huruf] ?? 0), 0);
  res.json({
    nim, nama: mhs.nama, total_sks: totalSks,
    ipk: totalSks ? Number((totalMutu / totalSks).toFixed(2)) : null,
    mata_kuliah: matkul,
  });
});

// ---------- POST /transkrip/sinkron ----------
app.post('/transkrip/sinkron', (req, res) => {
  // Hanya token service. Token user mana pun ditolak (walau gateway sudah memeriksa).
  if (req.auth.typ !== 'service' || req.auth.role !== 'service')
    return forbid(res, 'hanya token service yang boleh menyinkronkan transkrip');

  const b = req.body || {};
  const valid =
    Number.isInteger(b.kelas_id) && typeof b.kode_mk === 'string' && typeof b.nama_mk === 'string' &&
    Number.isInteger(b.sks) && Array.isArray(b.nilai) && b.nilai.length > 0 &&
    b.nilai.every((n) => typeof n.nim === 'string' && typeof n.nilai_angka === 'number' &&
      n.nilai_angka >= 0 && n.nilai_angka <= 100);
  if (!valid) return res.status(400).json({ error: 'Bad Request', reason: 'payload sinkron tidak valid' });
  if (b.nilai.some((n) => !q.mhsByNim.get(n.nim)))
    return res.status(422).json({ error: 'Unprocessable', reason: 'ada NIM yang bukan mahasiswa terdaftar' });

  const now = new Date().toISOString();
  db.transaction(() => {
    for (const n of b.nilai) {
      q.upsert.run({
        nim: n.nim, kelas_id: b.kelas_id, kode_mk: b.kode_mk, nama_mk: b.nama_mk, sks: b.sks,
        nilai_angka: n.nilai_angka, nilai_huruf: hurufDariAngka(n.nilai_angka), synced_at: now,
      });
    }
  })();
  res.json({ message: 'transkrip tersinkron', kelas_id: b.kelas_id, jumlah_mahasiswa: b.nilai.length });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));
app.use((err, req, res, next) => res.status(400).json({ error: 'Bad Request', reason: 'request tidak valid' }));

app.listen(config.ports.transkrip, config.host, () =>
  console.log(`[transkrip] Service Transkrip berjalan di http://${config.host}:${config.ports.transkrip}`)
);
