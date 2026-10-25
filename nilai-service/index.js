// =====================================================================
// SERVICE NILAI (Resource), port 3001.
// Data nilai & kelas. Hanya bisa dicapai lewat gateway.
//   - gatewayGuard : X-Gateway-Secret wajib benar
//   - tokenGuard   : verifikasi ulang tanda tangan & masa berlaku token
//   - Pembatasan data (defense in depth): walau gateway sudah memutuskan,
//     service tetap membatasi hasil berdasarkan identitas di token.
//   - Finalisasi: setelah nilai difinalisasi, service memanggil Service
//     Transkrip MELALUI gateway memakai token service.
// =====================================================================
const express = require('express');
const config = require('../shared/config');
const db = require('../shared/db').open();
const { gatewayGuard, tokenGuard, hurufDariAngka } = require('../shared/guards');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(gatewayGuard, tokenGuard);   // urutan: secret dulu, lalu token

const q = {
  user: db.prepare('SELECT id, role, nim FROM users WHERE id = ?'),
  nilaiMhs: db.prepare(
    `SELECT n.id, n.kelas_id, k.kode_mk, k.nama_mk, n.nim, n.nilai_angka, n.nilai_huruf, n.final
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.nim = ? ORDER BY n.id`
  ),
  nilaiDosen: db.prepare(
    `SELECT n.id, n.kelas_id, k.kode_mk, k.nama_mk, n.nim, n.nilai_angka, n.nilai_huruf, n.final
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE k.dosen_id = ? ORDER BY n.id`
  ),
  nilaiDosenKelas: db.prepare(
    `SELECT n.id, n.kelas_id, k.kode_mk, k.nama_mk, n.nim, n.nilai_angka, n.nilai_huruf, n.final
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE k.dosen_id = ? AND k.id = ? ORDER BY n.id`
  ),
  nilaiById: db.prepare(
    `SELECT n.*, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`
  ),
  updateNilai: db.prepare('UPDATE nilai SET nilai_angka = ?, nilai_huruf = ? WHERE id = ? AND final = 0'),
  kelas: db.prepare('SELECT * FROM kelas WHERE id = ?'),
  nilaiKelas: db.prepare('SELECT nim, nilai_angka, nilai_huruf FROM nilai WHERE kelas_id = ?'),
  finalNilai: db.prepare('UPDATE nilai SET final = 1 WHERE kelas_id = ?'),
  finalKelas: db.prepare('UPDATE kelas SET finalized = 1 WHERE id = ?'),
};

const forbid = (res, reason) => res.status(403).json({ error: 'Forbidden', reason });

// Ambil data user dari DB berdasarkan sub token (bukan percaya isi token begitu saja).
function currentUser(req) {
  if (req.auth.typ !== 'access') return null;
  const u = q.user.get(Number(req.auth.sub));
  return u && u.role === req.auth.role ? u : null;
}

// ---------- GET /nilai ----------
app.get('/nilai', (req, res) => {
  const user = currentUser(req);
  if (!user || !['mahasiswa', 'dosen'].includes(user.role))
    return forbid(res, 'role tidak diizinkan melihat nilai');

  if (user.role === 'mahasiswa') {
    // Mahasiswa: hanya nilai miliknya (berdasarkan NIM di DB).
    return res.json({ data: q.nilaiMhs.all(user.nim) });
  }
  // Dosen: hanya kelas yang diampu (opsional ?kelas_id=).
  const kelasId = req.query.kelas_id;
  const rows = typeof kelasId === 'string'
    ? q.nilaiDosenKelas.all(user.id, Number(kelasId))
    : q.nilaiDosen.all(user.id);
  res.json({ data: rows });
});

// ---------- PUT /nilai/:id ----------
app.put('/nilai/:id', (req, res) => {
  const user = currentUser(req);
  if (!user || user.role !== 'dosen') return forbid(res, 'hanya dosen yang boleh mengubah nilai');

  const row = q.nilaiById.get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Not Found', reason: 'data nilai tidak ditemukan' });
  if (row.dosen_id !== user.id) return forbid(res, 'kelas tidak diampu oleh dosen ini');
  if (row.final) return forbid(res, 'nilai sudah final');

  const angka = (req.body || {}).nilai_angka;
  if (typeof angka !== 'number' || !Number.isFinite(angka) || angka < 0 || angka > 100)
    return res.status(400).json({ error: 'Bad Request', reason: 'nilai_angka harus angka 0-100' });

  const huruf = hurufDariAngka(angka);
  q.updateNilai.run(angka, huruf, row.id);
  res.json({ message: 'nilai diperbarui', id: row.id, nilai_angka: angka, nilai_huruf: huruf });
});

// ---------- Token service (didapat dari gateway, di-cache) ----------
let cachedToken = null; // { token, exp }
async function getServiceToken(forceNew = false) {
  if (!forceNew && cachedToken && cachedToken.exp - Date.now() > 30_000) return cachedToken.token;
  const r = await fetch(`${config.gatewayUrl}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: config.serviceClient.id, client_secret: config.serviceClient.secret }),
  });
  if (!r.ok) throw new Error(`gagal mendapat token service (HTTP ${r.status})`);
  const data = await r.json();
  cachedToken = { token: data.access_token, exp: Date.now() + data.expires_in * 1000 };
  return cachedToken.token;
}

// Panggil Service Transkrip MELALUI gateway (bukan langsung) dengan token service.
async function sinkronTranskrip(payload) {
  const call = (token) => fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  let r = await call(await getServiceToken());
  if (r.status === 401) r = await call(await getServiceToken(true)); // token kedaluwarsa -> ulang sekali
  if (!r.ok) {
    const detail = await r.text();
    throw new Error(`sinkron transkrip ditolak (HTTP ${r.status}): ${detail}`);
  }
  return r.json();
}

// ---------- POST /kelas/:id/finalisasi ----------
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const user = currentUser(req);
  if (!user || user.role !== 'dosen') return forbid(res, 'hanya dosen yang boleh memfinalisasi nilai');

  const kelas = q.kelas.get(Number(req.params.id));
  if (!kelas) return res.status(404).json({ error: 'Not Found', reason: 'kelas tidak ditemukan' });
  if (kelas.dosen_id !== user.id) return forbid(res, 'kelas tidak diampu oleh dosen ini');
  if (kelas.finalized) return res.status(409).json({ error: 'Conflict', reason: 'kelas sudah difinalisasi' });

  const nilai = q.nilaiKelas.all(kelas.id);
  if (nilai.length === 0 || nilai.some((n) => n.nilai_angka === null))
    return res.status(422).json({ error: 'Unprocessable', reason: 'ada nilai yang belum diisi' });

  try {
    // Sinkron dulu; jika gagal, finalisasi dibatalkan (nilai tetap bisa diubah).
    const hasil = await sinkronTranskrip({
      kelas_id: kelas.id, kode_mk: kelas.kode_mk, nama_mk: kelas.nama_mk, sks: kelas.sks, nilai,
    });
    db.transaction(() => {
      q.finalNilai.run(kelas.id);
      q.finalKelas.run(kelas.id);
    })();
    res.json({ message: 'kelas difinalisasi dan transkrip tersinkron', kelas_id: kelas.id, sinkron: hasil });
  } catch (err) {
    console.error('[nilai] finalisasi gagal:', err.message);
    res.status(502).json({ error: 'Bad Gateway', reason: 'sinkron transkrip gagal, finalisasi dibatalkan' });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));
app.use((err, req, res, next) => res.status(400).json({ error: 'Bad Request', reason: 'request tidak valid' }));

app.listen(config.ports.nilai, config.host, () =>
  console.log(`[nilai] Service Nilai berjalan di http://${config.host}:${config.ports.nilai}`)
);
