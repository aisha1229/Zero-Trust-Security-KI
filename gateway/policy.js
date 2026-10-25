// =====================================================================
// POLICY ENGINE (PE) - modul keputusan allow/deny.
// Sesuai NIST SP 800-207: PEP (gateway) bertanya, PE memutuskan.
//
// Prinsip yang diterapkan:
//   - Default deny   : endpoint/metode yang tidak ada di tabel kebijakan ditolak.
//   - Least privilege: tiap endpoint hanya untuk role tertentu (Tabel 3).
//   - Verifikasi konteks: device terdaftar + jam akses (4.3).
//   - Atribut dari DB : kepemilikan data (kelas diampu, NIM) TIDAK diambil dari
//     isi token, tapi dibaca dari database (4.2).
//
// Fungsi utama: decide(ctx) -> { allow, status, reason }
// =====================================================================
const fs = require('fs');
const config = require('../shared/config');
const db = require('../shared/db').open();

// ---------- Query atribut dari database ----------
const q = {
  user: db.prepare('SELECT id, username, role, nim FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  kelas: db.prepare('SELECT id, dosen_id, finalized FROM kelas WHERE id = ?'),
  nilai: db.prepare(
    `SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?`
  ),
};

// ---------- Verifikasi konteks (4.3) ----------
function isDeviceRegistered(userId, deviceId) {
  if (!deviceId || typeof deviceId !== 'string') return false;
  return !!q.device.get(userId, deviceId);
}

function toMinutes(hhmm) {
  const [h, m] = String(hhmm).split(':').map(Number);
  return h * 60 + (m || 0);
}

// Jam akses dibaca dari config/policy.json SETIAP kali -> mudah didemokan.
function getAccessHours() {
  try {
    const cfg = JSON.parse(fs.readFileSync(config.policyConfigPath, 'utf8'));
    return cfg.accessHours;
  } catch {
    return { start: '07:00', end: '21:00' }; // fallback sesuai tugas
  }
}

function withinAccessHours(now = new Date()) {
  const { start, end } = getAccessHours();
  const menit = now.getHours() * 60 + now.getMinutes();
  return menit >= toMinutes(start) && menit < toMinutes(end);
}

// ---------- Helper hasil keputusan ----------
const allow = (reason) => ({ allow: true, status: 200, reason });
const deny = (reason, status = 403) => ({ allow: false, status, reason });

const isStr = (v) => typeof v === 'string' && v.length > 0;

// ---------- Tabel kebijakan (Tabel 3) ----------
// Setiap aturan: metode + pola path + role yang diizinkan + kondisi tambahan.
const RULES = [
  {
    // GET /nilai : mahasiswa (hanya miliknya), dosen (hanya kelas diampu)
    method: 'GET', pattern: /^\/nilai$/, roles: ['mahasiswa', 'dosen'],
    check(ctx, user) {
      const { nim, kelas_id } = ctx.query;
      if (nim !== undefined && !isStr(nim)) return deny('parameter nim tidak valid', 400);
      if (kelas_id !== undefined && !isStr(kelas_id)) return deny('parameter kelas_id tidak valid', 400);
      if (user.role === 'mahasiswa') {
        if (nim !== undefined && nim !== user.nim)
          return deny('mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('mahasiswa melihat nilai miliknya');
      }
      // dosen
      if (kelas_id !== undefined) {
        const kelas = q.kelas.get(Number(kelas_id));
        if (!kelas) return deny('kelas tidak ditemukan', 404);
        if (kelas.dosen_id !== user.id) return deny('kelas tidak diampu oleh dosen ini');
      }
      return allow('dosen melihat nilai kelas yang diampu');
    },
  },
  {
    // PUT /nilai/:id : dosen, kelas diampu, nilai belum final, dalam jam akses
    method: 'PUT', pattern: /^\/nilai\/(\d+)$/, roles: ['dosen'],
    check(ctx, user, m) {
      const nilai = q.nilai.get(Number(m[1]));
      if (!nilai) return deny('data nilai tidak ditemukan', 404);
      if (nilai.dosen_id !== user.id) return deny('kelas tidak diampu oleh dosen ini');
      if (nilai.final) return deny('nilai sudah final, tidak boleh diubah');
      if (!withinAccessHours(ctx.now))
        return deny(`di luar jam akses (${fmtHours()})`);
      return allow('dosen mengubah nilai kelas yang diampu');
    },
  },
  {
    // POST /kelas/:id/finalisasi : dosen, kelas diampu, dalam jam akses
    method: 'POST', pattern: /^\/kelas\/(\d+)\/finalisasi$/, roles: ['dosen'],
    check(ctx, user, m) {
      const kelas = q.kelas.get(Number(m[1]));
      if (!kelas) return deny('kelas tidak ditemukan', 404);
      if (kelas.dosen_id !== user.id) return deny('kelas tidak diampu oleh dosen ini');
      if (!withinAccessHours(ctx.now))
        return deny(`di luar jam akses (${fmtHours()})`);
      return allow('dosen memfinalisasi kelas yang diampu');
    },
  },
  {
    // GET /transkrip/:nim : mahasiswa (NIM sendiri), admin (semua NIM)
    method: 'GET', pattern: /^\/transkrip\/(\d+)$/, roles: ['mahasiswa', 'admin'],
    check(ctx, user, m) {
      if (user.role === 'admin') return allow('admin melihat transkrip semua mahasiswa');
      if (user.nim !== m[1]) return deny('mahasiswa hanya boleh melihat transkrip NIM sendiri');
      return allow('mahasiswa melihat transkrip sendiri');
    },
  },
  {
    // POST /transkrip/sinkron : HANYA token service (token user mana pun ditolak)
    method: 'POST', pattern: /^\/transkrip\/sinkron$/, roles: ['service'],
    check() {
      return allow('Service Nilai menyinkronkan transkrip');
    },
  },
];

function fmtHours() {
  const { start, end } = getAccessHours();
  return `${start}-${end}`;
}

// ---------- Keputusan utama ----------
// ctx = { subject:{type,id,role}, method, path, query, deviceId, now }
function decide(ctx) {
  // 1) Cari aturan. Tidak ada aturan -> DEFAULT DENY.
  let rule = null, match = null;
  for (const r of RULES) {
    if (r.method !== ctx.method) continue;
    const m = r.pattern.exec(ctx.path);
    if (m) { rule = r; match = m; break; }
  }
  if (!rule) return deny('tidak ada kebijakan untuk endpoint ini (default deny)');

  const { subject } = ctx;
  let user = null;

  // 2) Verifikasi konteks untuk USER: akun masih ada + device terdaftar.
  if (subject.type === 'user') {
    user = q.user.get(Number(subject.id));
    if (!user) return deny('akun tidak ditemukan', 401);
    if (!isDeviceRegistered(user.id, ctx.deviceId))
      return deny('device tidak terdaftar untuk user ini (X-Device-ID)');
  }

  // 3) Least privilege: role harus termasuk yang diizinkan.
  if (!rule.roles.includes(subject.role))
    return deny(`role '${subject.role}' tidak diizinkan untuk endpoint ini`);

  // 4) Kondisi tambahan (kepemilikan data dari DB, status final, jam akses).
  return rule.check(ctx, user, match);
}

module.exports = { decide, isDeviceRegistered, withinAccessHours, getAccessHours };
