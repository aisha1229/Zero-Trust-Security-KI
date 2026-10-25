// =====================================================================
// Seed data awal (aman dijalankan ulang -> mereset data ke kondisi awal).
//   1 admin, 2 dosen, 3 mahasiswa, 2 kelas (dosen berbeda),
//   tiap user punya 1 device terdaftar, + 1 client service.
// Jalankan: npm run seed
// =====================================================================
const config = require('../shared/config');
const { hashSecret } = require('../shared/crypto');
const db = require('../shared/db').open();

const PASSWORD = 'Passw0rd!';   // password semua akun demo

const users = [
  { id: 1, username: 'admin',  role: 'admin',     nim: null,           nama: 'Admin Prodi',      device: 'DEV-ADMIN-01' },
  { id: 2, username: 'dosen1', role: 'dosen',     nim: null,           nama: 'Dr. Budi Santoso', device: 'DEV-DOSEN1-01' },
  { id: 3, username: 'dosen2', role: 'dosen',     nim: null,           nama: 'Dr. Siti Rahma',   device: 'DEV-DOSEN2-01' },
  { id: 4, username: 'mhs1',   role: 'mahasiswa', nim: '247006111001', nama: 'Andi Pratama',     device: 'DEV-MHS1-01' },
  { id: 5, username: 'mhs2',   role: 'mahasiswa', nim: '247006111002', nama: 'Bunga Lestari',    device: 'DEV-MHS2-01' },
  { id: 6, username: 'mhs3',   role: 'mahasiswa', nim: '247006111003', nama: 'Citra Dewi',       device: 'DEV-MHS3-01' },
];

const kelas = [
  { id: 1, kode_mk: 'IF101', nama_mk: 'Pemrograman Web', sks: 3, dosen_id: 2 },
  { id: 2, kode_mk: 'IF102', nama_mk: 'Basis Data',      sks: 3, dosen_id: 3 },
];

// nilai[kelas_id] = skor tiap mahasiswa (urut mhs1, mhs2, mhs3)
const skor = { 1: [85, 72, 90], 2: [78, 66, 88] };

function huruf(n) {
  return n >= 85 ? 'A' : n >= 80 ? 'A-' : n >= 75 ? 'B+' : n >= 70 ? 'B' : n >= 65 ? 'B-' : n >= 60 ? 'C+' : n >= 55 ? 'C' : n >= 40 ? 'D' : 'E';
}

db.transaction(() => {
  // Kosongkan (urutan menghormati foreign key) dan reset auto-increment.
  for (const t of ['audit_log', 'transkrip', 'nilai', 'refresh_tokens', 'kelas', 'devices', 'service_clients', 'users'])
    db.exec(`DELETE FROM ${t}`);
  db.exec("DELETE FROM sqlite_sequence");

  const passHash = hashSecret(PASSWORD);
  const insU = db.prepare('INSERT INTO users (id, username, password_hash, role, nim, nama) VALUES (?,?,?,?,?,?)');
  const insD = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?,?)');
  for (const u of users) {
    insU.run(u.id, u.username, passHash, u.role, u.nim, u.nama);
    insD.run(u.id, u.device);
  }

  const insK = db.prepare('INSERT INTO kelas (id, kode_mk, nama_mk, sks, dosen_id) VALUES (?,?,?,?,?)');
  const insN = db.prepare('INSERT INTO nilai (kelas_id, nim, nilai_angka, nilai_huruf) VALUES (?,?,?,?)');
  const mhs = users.filter((u) => u.role === 'mahasiswa');
  for (const k of kelas) {
    insK.run(k.id, k.kode_mk, k.nama_mk, k.sks, k.dosen_id);
    mhs.forEach((m, i) => insN.run(k.id, m.nim, skor[k.id][i], huruf(skor[k.id][i])));
  }

  db.prepare('INSERT INTO service_clients (client_id, secret_hash, nama) VALUES (?,?,?)')
    .run(config.serviceClient.id, hashSecret(config.serviceClient.secret), 'Service Nilai');
})();

console.log('Seed selesai.');
console.log(`- Password semua akun: ${PASSWORD}`);
console.table(users.map((u) => ({ username: u.username, role: u.role, nim: u.nim, device_id: u.device })));
console.log(`- Service client: ${config.serviceClient.id} / ${config.serviceClient.secret}`);
