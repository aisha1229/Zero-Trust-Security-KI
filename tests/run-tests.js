// =====================================================================
// Tes otomatis semua kebutuhan bagian 4. Jalankan SETELAH `npm start`:
//     npm test
// Catatan: tes ini mereset data (seed) dan sementara mengubah
// config/policy.json (dikembalikan di akhir).
// =====================================================================
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const jwt = require('jsonwebtoken');
const config = require('../shared/config');

const GW = config.gatewayUrl;
const NILAI = config.nilaiUrl;
const TRANSKRIP = config.transkripUrl;
const PASSWORD = 'Passw0rd!';
const DEVICE = {
  admin: 'DEV-ADMIN-01', dosen1: 'DEV-DOSEN1-01', dosen2: 'DEV-DOSEN2-01',
  mhs1: 'DEV-MHS1-01', mhs2: 'DEV-MHS2-01', mhs3: 'DEV-MHS3-01',
};
const NIM = { mhs1: '247006111001', mhs2: '247006111002', mhs3: '247006111003' };

let pass = 0, fail = 0;
function check(nama, kondisi, info = '') {
  if (kondisi) { pass++; console.log(`  \x1b[32mPASS\x1b[0m ${nama}`); }
  else { fail++; console.log(`  \x1b[31mFAIL\x1b[0m ${nama} ${info}`); }
}
const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);

async function req(base, method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const r = await fetch(base + url, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await r.json(); } catch { /* bukan JSON */ }
  return { status: r.status, data };
}
const gw = (m, u, o) => req(GW, m, u, o);

async function login(user, device = DEVICE[user], password = PASSWORD) {
  return gw('POST', '/auth/login', { body: { username: user, password }, device });
}

// ----- util jam akses (mengubah config/policy.json sementara) -----
const policyFile = config.policyConfigPath;
const policyAsli = fs.readFileSync(policyFile, 'utf8');
const pad = (n) => String(n).padStart(2, '0');
function setJam(start, end) {
  fs.writeFileSync(policyFile, JSON.stringify({ accessHours: { start, end } }));
}
const jamBuka = () => setJam('00:00', '24:00');
function jamTutup() {   // jendela 30 menit yang berjarak 12 jam dari sekarang
  const h = (new Date().getHours() + 12) % 24;
  setJam(`${pad(h)}:00`, `${pad(h)}:30`);
}

async function main() {
  try { await fetch(GW + '/'); } catch {
    console.error('Gateway belum berjalan. Jalankan `npm start` di terminal lain terlebih dahulu.');
    process.exit(2);
  }
  execFileSync(process.execPath, [path.join(__dirname, '..', 'db', 'seed.js')], { stdio: 'ignore' });
  jamBuka();

  // ---------------------------------------------------------------
  section('4.1 Autentikasi & token');
  let r = await login('mhs1');
  check('login mahasiswa berhasil (kredensial + device valid)', r.status === 200 && r.data.access_token && r.data.refresh_token);
  const tok = {};
  const refresh = {};
  for (const u of Object.keys(DEVICE)) {
    const x = await login(u);
    tok[u] = x.data.access_token; refresh[u] = x.data.refresh_token;
  }
  const dec = jwt.decode(tok.mhs1);
  check('access token berisi sub dan role', dec.sub && dec.role === 'mahasiswa');
  check('access token berlaku 10 menit', dec.exp - dec.iat === 600, `(${dec.exp - dec.iat}s)`);
  r = await login('mhs1', DEVICE.mhs1, 'salah');
  check('login password salah ditolak (401)', r.status === 401);
  r = await login('mhs1', 'DEV-TIDAK-TERDAFTAR');
  check('login dari device tidak terdaftar ditolak (403)', r.status === 403);
  r = await login('mhs1', DEVICE.dosen1);
  check('login memakai device milik user lain ditolak (403)', r.status === 403);
  r = await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PASSWORD } });
  check('login tanpa X-Device-ID ditolak (403)', r.status === 403);

  r = await gw('POST', '/auth/refresh', { body: { refresh_token: refresh.mhs1 } });
  check('refresh token menghasilkan access token baru', r.status === 200 && r.data.access_token);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: 'ngawur' } });
  check('refresh token palsu ditolak (401)', r.status === 401);

  const lg = await login('mhs3');
  r = await gw('POST', '/auth/logout', { body: { refresh_token: lg.data.refresh_token } });
  check('logout berhasil', r.status === 200);
  r = await gw('POST', '/auth/refresh', { body: { refresh_token: lg.data.refresh_token } });
  check('refresh token setelah logout ditolak (dicabut)', r.status === 401 && /dicabut/.test(r.data.reason));

  r = await gw('POST', '/auth/service', { body: { client_id: 'nilai-service', client_secret: 'salah' } });
  check('token service dengan secret salah ditolak (401)', r.status === 401);
  r = await gw('POST', '/auth/service', { body: { client_id: config.serviceClient.id, client_secret: config.serviceClient.secret } });
  const svcTok = r.data && r.data.access_token;
  const sd = svcTok && jwt.decode(svcTok);
  check('token service diterbitkan, role=service', r.status === 200 && sd.role === 'service');
  check('token service berlaku 5 menit', sd && sd.exp - sd.iat === 300);

  // ---------------------------------------------------------------
  section('4.1 Gateway secret & verifikasi ulang di service');
  r = await req(NILAI, 'GET', '/nilai');
  check('akses langsung Service Nilai tanpa secret ditolak (403)', r.status === 403);
  r = await req(TRANSKRIP, 'GET', `/transkrip/${NIM.mhs1}`, { token: tok.mhs1 });
  check('akses langsung Service Transkrip (token valid, tanpa secret) ditolak (403)', r.status === 403);
  r = await req(NILAI, 'GET', '/nilai', { headers: { 'X-Gateway-Secret': config.gatewaySecret } });
  check('secret benar tapi tanpa token tetap ditolak (401)', r.status === 401);
  r = await req(NILAI, 'GET', '/nilai', { token: 'token.palsu.sekali', headers: { 'X-Gateway-Secret': config.gatewaySecret } });
  check('secret benar + token palsu ditolak (401)', r.status === 401);
  const kedaluwarsa = jwt.sign({ sub: '4', role: 'mahasiswa', typ: 'access' }, config.jwtSecret, { expiresIn: -10, issuer: config.jwtIssuer });
  r = await req(NILAI, 'GET', '/nilai', { token: kedaluwarsa, headers: { 'X-Gateway-Secret': config.gatewaySecret } });
  check('secret benar + token kedaluwarsa ditolak (401)', r.status === 401);
  const salahKunci = jwt.sign({ sub: '4', role: 'mahasiswa', typ: 'access' }, 'kunci-lain', { expiresIn: '10m', issuer: config.jwtIssuer });
  r = await req(NILAI, 'GET', '/nilai', { token: salahKunci, headers: { 'X-Gateway-Secret': config.gatewaySecret } });
  check('secret benar + tanda tangan salah ditolak (401)', r.status === 401);
  r = await gw('GET', '/nilai', { token: kedaluwarsa, device: DEVICE.mhs1 });
  check('gateway menolak token kedaluwarsa (401)', r.status === 401);
  r = await gw('GET', '/nilai', { token: salahKunci, device: DEVICE.mhs1 });
  check('gateway menolak token bertanda tangan salah (401)', r.status === 401);
  r = await gw('GET', '/nilai', { device: DEVICE.mhs1 });
  check('gateway menolak request tanpa token (401)', r.status === 401);
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEVICE.mhs1, headers: { 'X-Gateway-Secret': 'palsu' } });
  check('X-Gateway-Secret palsu dari client tidak berpengaruh (tetap lewat gateway)', r.status === 200);

  // ---------------------------------------------------------------
  section('4.2 Kebijakan akses - GET /nilai');
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEVICE.mhs1 });
  check('mahasiswa hanya melihat nilai miliknya', r.status === 200 && r.data.data.length === 2 && r.data.data.every((n) => n.nim === NIM.mhs1));
  r = await gw('GET', `/nilai?nim=${NIM.mhs2}`, { token: tok.mhs1, device: DEVICE.mhs1 });
  check('mahasiswa meminta nilai NIM lain ditolak (403)', r.status === 403);
  r = await gw('GET', '/nilai?nim=a&nim=b', { token: tok.mhs1, device: DEVICE.mhs1 });
  check('parameter ganda (nim=a&nim=b) ditolak (400)', r.status === 400);
  r = await gw('GET', '/nilai', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('dosen hanya melihat kelas yang diampu', r.status === 200 && r.data.data.length === 3 && r.data.data.every((n) => n.kelas_id === 1));
  r = await gw('GET', '/nilai?kelas_id=2', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('dosen meminta kelas yang tidak diampu ditolak (403)', r.status === 403);
  r = await gw('GET', '/nilai', { token: tok.admin, device: DEVICE.admin });
  check('admin tidak boleh melihat nilai (403)', r.status === 403);
  r = await gw('GET', '/nilai', { token: svcTok });
  check('token service tidak boleh membaca nilai (403)', r.status === 403);

  // ---------------------------------------------------------------
  section('4.3 Verifikasi konteks - device terdaftar');
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: 'DEV-ATTACKER-99' });
  check('device tidak terdaftar ditolak (403)', r.status === 403 && /device/.test(r.data.reason));
  r = await gw('GET', '/nilai', { token: tok.mhs1 });
  check('tanpa X-Device-ID ditolak (403)', r.status === 403);
  r = await gw('GET', '/nilai', { token: tok.mhs1, device: DEVICE.dosen1 });
  check('device milik user lain ditolak (403)', r.status === 403);

  // ---------------------------------------------------------------
  section('4.2 + 4.3 PUT /nilai/:id (kepemilikan, final, jam akses)');
  r = await gw('PUT', '/nilai/1', { token: tok.mhs1, device: DEVICE.mhs1, body: { nilai_angka: 100 } });
  check('mahasiswa tidak boleh mengubah nilai (403)', r.status === 403);
  r = await gw('PUT', '/nilai/4', { token: tok.dosen1, device: DEVICE.dosen1, body: { nilai_angka: 100 } });
  check('dosen mengubah nilai kelas yang tidak diampu ditolak (403)', r.status === 403);
  jamTutup();
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEVICE.dosen1, body: { nilai_angka: 95 } });
  check('ubah nilai di luar jam akses ditolak (403)', r.status === 403 && /jam akses/.test(r.data.reason));
  jamBuka();
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEVICE.dosen1, body: { nilai_angka: 88 } });
  check('dosen mengubah nilai kelasnya dalam jam akses (200)', r.status === 200 && r.data.nilai_huruf === 'A');
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEVICE.dosen1, body: { nilai_angka: 500 } });
  check('nilai di luar 0-100 ditolak (400)', r.status === 400);

  // ---------------------------------------------------------------
  section('4.2 + 4.3 Finalisasi + sinkron transkrip antar-service');
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.mhs1, device: DEVICE.mhs1 });
  check('mahasiswa tidak boleh finalisasi (403)', r.status === 403);
  r = await gw('POST', '/kelas/2/finalisasi', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('dosen memfinalisasi kelas yang tidak diampu ditolak (403)', r.status === 403);
  jamTutup();
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('finalisasi di luar jam akses ditolak (403)', r.status === 403 && /jam akses/.test(r.data.reason));
  jamBuka();
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('dosen memfinalisasi kelasnya (200) + transkrip tersinkron', r.status === 200 && r.data.sinkron && r.data.sinkron.jumlah_mahasiswa === 3, JSON.stringify(r.data));
  r = await gw('PUT', '/nilai/1', { token: tok.dosen1, device: DEVICE.dosen1, body: { nilai_angka: 10 } });
  check('nilai yang sudah final tidak bisa diubah (403)', r.status === 403 && /final/.test(r.data.reason));
  r = await gw('POST', '/kelas/1/finalisasi', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('finalisasi ulang ditolak (409)', r.status === 409);

  // ---------------------------------------------------------------
  section('4.2 GET /transkrip/:nim');
  r = await gw('GET', `/transkrip/${NIM.mhs1}`, { token: tok.mhs1, device: DEVICE.mhs1 });
  check('mahasiswa melihat transkrip sendiri (hasil sinkron: 1 matkul, nilai 88)', r.status === 200 && r.data.mata_kuliah.length === 1 && r.data.mata_kuliah[0].nilai_angka === 88, JSON.stringify(r.data));
  r = await gw('GET', `/transkrip/${NIM.mhs2}`, { token: tok.mhs1, device: DEVICE.mhs1 });
  check('mahasiswa melihat transkrip NIM lain ditolak (403)', r.status === 403);
  r = await gw('GET', `/transkrip/${NIM.mhs2}`, { token: tok.admin, device: DEVICE.admin });
  check('admin melihat transkrip semua mahasiswa (200)', r.status === 200 && r.data.nim === NIM.mhs2);
  r = await gw('GET', `/transkrip/${NIM.mhs1}`, { token: tok.dosen1, device: DEVICE.dosen1 });
  check('dosen tidak boleh melihat transkrip (403)', r.status === 403);
  r = await gw('GET', `/transkrip/${NIM.mhs1}`, { token: svcTok });
  check('token service tidak boleh membaca transkrip (403)', r.status === 403);

  // ---------------------------------------------------------------
  section('4.2 POST /transkrip/sinkron (hanya token service)');
  const payload = { kelas_id: 2, kode_mk: 'IF102', nama_mk: 'Basis Data', sks: 3, nilai: [{ nim: NIM.mhs1, nilai_angka: 78 }] };
  for (const u of ['admin', 'dosen1', 'mhs1']) {
    r = await gw('POST', '/transkrip/sinkron', { token: tok[u], device: DEVICE[u], body: payload });
    check(`token user (${u}) ditolak di /transkrip/sinkron (403)`, r.status === 403);
  }
  r = await gw('POST', '/transkrip/sinkron', { body: payload });
  check('tanpa token ditolak (401)', r.status === 401);
  r = await gw('POST', '/transkrip/sinkron', { token: svcTok, body: payload });
  check('token service diterima (200)', r.status === 200);

  // ---------------------------------------------------------------
  section('Default deny');
  r = await gw('DELETE', '/nilai/1', { token: tok.dosen1, device: DEVICE.dosen1 });
  check('endpoint/metode tanpa kebijakan ditolak (DELETE /nilai/1)', r.status === 403 && /default deny/.test(r.data.reason));
  r = await gw('GET', '/rahasia');
  check('path tidak dikenal ditolak (404)', r.status === 404);

  // ---------------------------------------------------------------
  section('4.4 Audit log');
  const db = require('../shared/db').open();
  const total = db.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
  const allow = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='allow'").get().c;
  const deny = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='deny'").get().c;
  const lengkap = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE waktu IS NULL OR subjek IS NULL OR endpoint IS NULL OR hasil IS NULL OR alasan IS NULL OR alasan = ''").get().c;
  check(`audit log mencatat keputusan (total ${total}: ${allow} allow, ${deny} deny)`, total > 50 && allow > 0 && deny > 0);
  check('setiap baris punya waktu, subjek, endpoint, hasil, alasan', lengkap === 0);
  const svc = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE subjek LIKE 'service:%'").get().c;
  check('panggilan service tercatat dengan subjek service', svc > 0);
}

main()
  .catch((e) => { fail++; console.error('Tes berhenti karena error:', e); })
  .finally(() => {
    fs.writeFileSync(policyFile, policyAsli);   // kembalikan jam akses semula
    console.log(`\nHasil: ${pass} lolos, ${fail} gagal`);
    process.exit(fail ? 1 : 0);
  });
