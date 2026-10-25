# Sistem Nilai - Zero Trust Security

Tugas Praktikum Individu **Zero Trust Security** - Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

Sistem Nilai dengan **API Gateway sebagai Policy Enforcement Point (PEP)** sesuai NIST SP 800-207.
Prinsip yang diterapkan: *never trust, always verify*; *least privilege*; *assume breach*.

## Arsitektur

```
                 access token + X-Device-ID
  Client  ───────────────────────────────►  API Gateway (PEP) :3000 ──► Audit Log (tabel audit_log)
 (Postman/curl)                              │  ▲
                                             │  │ allow / deny
                                             ▼  │
                                        Policy Engine / Admin (gateway/policy.js, gateway/auth.js)
                                             │ baca atribut
                       jika allow            ▼
                     + X-Gateway-Secret   Database (SQLite, satu DB bersama)
              ┌──────────────┴──────────────┐
              ▼                             ▼
     Service Nilai :3001   ── sinkron ──►  (lewat gateway, token service) ──► Service Transkrip :3002
```

| Komponen | Port | Peran NIST | File |
|---|---|---|---|
| API Gateway | 3000 | PEP | `gateway/index.js` |
| Policy Engine / Administrator | modul di gateway | PE / PA | `gateway/policy.js`, `gateway/auth.js` |
| Service Nilai | 3001 | Resource | `nilai-service/index.js` |
| Service Transkrip | 3002 | Resource | `transkrip-service/index.js` |
| Database | - | Resource | `shared/db.js` (SQLite, `data/nilai.db`) |
| Audit Log | - | Data source | `gateway/audit.js` (tabel `audit_log`) |

## Prasyarat
- Node.js **20 atau lebih baru** (diuji dengan Node 22; `better-sqlite3` dipatok 12.6.2 karena punya file siap-pakai untuk Node 20-25 di Windows)
- Postman atau curl untuk pengujian

## Cara menjalankan (lokal)

```bash
npm install          # pasang dependensi
npm run seed         # buat database + data awal (aman diulang, mereset data)
npm start            # jalankan gateway + 2 service sekaligus (Ctrl+C untuk berhenti)
```

Di terminal lain:

```bash
npm test             # tes otomatis semua kebutuhan bagian 4 (harus 60 lolos, 0 gagal)
npm run audit        # lihat 30 baris audit log terakhir (npm run audit 100 untuk lebih banyak)
```

> `npm test` me-reset data (seed) dan sementara mengubah `config/policy.json` (dikembalikan di akhir).

Jalankan tiap komponen terpisah (opsional, 3 terminal): `npm run nilai`, `npm run transkrip`, `npm run gateway`.

## Cara menjalankan (Docker Compose)

```bash
docker compose up --build
```

Database ada di named volume `nilai-data`. Untuk melihat audit log: `docker compose exec gateway node db/show-audit.js`.
Port 3001/3002 sengaja dibuka hanya ke `127.0.0.1` supaya demo "akses langsung ditolak" bisa dicoba.

> Catatan: konfigurasi Docker belum diuji di lingkungan pembuatan project ini. Jika ada error, jalankan secara lokal (npm).

## Akun & device ID data awal

Password semua akun: **`Passw0rd!`**

| Username | Role | NIM | Device ID terdaftar |
|---|---|---|---|
| `admin`  | admin     | -            | `DEV-ADMIN-01` |
| `dosen1` | dosen (mengampu kelas 1: IF101 Pemrograman Web) | - | `DEV-DOSEN1-01` |
| `dosen2` | dosen (mengampu kelas 2: IF102 Basis Data)      | - | `DEV-DOSEN2-01` |
| `mhs1`   | mahasiswa | 247006111001 | `DEV-MHS1-01` |
| `mhs2`   | mahasiswa | 247006111002 | `DEV-MHS2-01` |
| `mhs3`   | mahasiswa | 247006111003 | `DEV-MHS3-01` |

Service client (Service Nilai): `client_id = nilai-service`, `client_secret = nilai-service-secret-dev`.

Data nilai: 3 mahasiswa di kelas 1 dan kelas 2. ID nilai 1-3 = kelas 1, ID nilai 4-6 = kelas 2.

## Konfigurasi jam akses (4.3)

Edit `config/policy.json` - **dibaca ulang di setiap request, tidak perlu restart**:

```json
{ "accessHours": { "start": "07:00", "end": "21:00" } }
```

Jam memakai zona waktu komputer yang menjalankan gateway. Untuk demo "di luar jam akses", ubah ke rentang yang tidak mencakup waktu sekarang (misalnya `"01:00"` sampai `"02:00"`), lalu kembalikan.
Pengaturan lain lewat environment variable (lihat `shared/config.js`): `JWT_SECRET`, `GATEWAY_SECRET`, `SERVICE_CLIENT_SECRET`, `DB_PATH`, port, dsb.

## Mencoba dengan Postman

Impor `postman/Zero-Trust-Sistem-Nilai.postman_collection.json`, lalu jalankan folder berurutan lewat Collection Runner (mulai dari folder 1 karena token disimpan otomatis ke variabel). Setiap request punya asersi status HTTP yang diharapkan. Pastikan jam akses mencakup waktu sekarang, dan jalankan `npm run seed` sebelum mengulang.

## Mencoba dengan curl

Di Windows, kutip JSON di CMD/PowerShell merepotkan; pakai Postman atau simpan body ke file lalu `-d @file.json`.

```bash
# 1. Login (butuh X-Device-ID yang terdaftar)
curl -s -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" -H "X-Device-ID: DEV-MHS1-01" \
  -d '{"username":"mhs1","password":"Passw0rd!"}'

# 2. Pakai access token (ganti <TOKEN>)
curl -s http://127.0.0.1:3000/nilai -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEV-MHS1-01"

# 3. Mahasiswa meminta nilai orang lain -> 403
curl -s "http://127.0.0.1:3000/nilai?nim=247006111002" -H "Authorization: Bearer <TOKEN>" -H "X-Device-ID: DEV-MHS1-01"

# 4. Akses langsung ke service tanpa gateway secret -> 403
curl -s http://127.0.0.1:3001/nilai

# 5. Dosen: ubah nilai dan finalisasi (token dosen1, device DEV-DOSEN1-01)
curl -s -X PUT http://127.0.0.1:3000/nilai/1 -H "Authorization: Bearer <TOKEN_DOSEN>" \
  -H "X-Device-ID: DEV-DOSEN1-01" -H "Content-Type: application/json" -d '{"nilai_angka":88}'
curl -s -X POST http://127.0.0.1:3000/kelas/1/finalisasi -H "Authorization: Bearer <TOKEN_DOSEN>" -H "X-Device-ID: DEV-DOSEN1-01"
```

## Pemetaan kebutuhan (bagian 4) ke kode

| Kebutuhan | Diterapkan di |
|---|---|
| 4.1 Access token JWT 10 menit, berisi `sub` + `role`, via `Authorization: Bearer` | `gateway/auth.js` → `signAccessToken`; diverifikasi di `gateway/index.js` → `authenticate` |
| 4.1 Refresh token 1 hari di database, logout mencabut | `gateway/auth.js` → `login`, `refresh`, `logout`; tabel `refresh_tokens` (disimpan sebagai hash SHA-256) |
| 4.1 Token service (`POST /auth/service`, 5 menit, `role: service`) | `gateway/auth.js` → `serviceToken`, `signServiceToken`; dipakai Service Nilai di `nilai-service/index.js` → `getServiceToken` |
| 4.1 Gateway secret `X-Gateway-Secret` | Ditambahkan di `gateway/index.js` → `makeProxy` (`proxyReq`); diperiksa di `shared/guards.js` → `gatewayGuard` |
| 4.1 Verifikasi ulang token di service | `shared/guards.js` → `tokenGuard` (tanda tangan, masa berlaku, issuer, algoritma dikunci HS256) |
| 4.2 Kebijakan akses (Tabel 3) | `gateway/policy.js` → tabel `RULES` + `decide()`; atribut dibaca dari DB |
| 4.2 `POST /transkrip/sinkron` hanya token service | Rule di `policy.js` (`roles: ['service']`) + pemeriksaan ulang di `transkrip-service/index.js` |
| 4.2 Finalisasi memanggil sinkron transkrip lewat gateway | `nilai-service/index.js` → `sinkronTranskrip` (ke `GATEWAY_URL`, bukan langsung ke port 3002) |
| 4.3 Device terdaftar (`X-Device-ID`) | `gateway/policy.js` → `isDeviceRegistered` (dipakai di `decide()` dan login) |
| 4.3 Jam akses 07.00-21.00, dapat dikonfigurasi | `gateway/policy.js` → `withinAccessHours`, `getAccessHours`; file `config/policy.json` |
| 4.4 Audit log (waktu, subjek, endpoint, device, hasil, alasan) | `gateway/audit.js`; tabel `audit_log`; lihat dengan `npm run audit` |
| Default deny | `policy.js` (endpoint tanpa aturan ditolak) dan `gateway/index.js` (path tak dikenal ditolak) |

## Keputusan desain dan keterbatasan

- **JWT HS256** dengan satu secret bersama (sesuai rekomendasi tugas). Karena service memegang secret yang sama, service yang bocor secara teori bisa membuat token. Perbaikan lanjutan: RS256, di mana service hanya memegang public key.
- **Access token tidak dicabut saat logout** (hanya refresh token, sesuai tugas); ia kedaluwarsa sendiri dalam 10 menit. Refresh token juga belum dirotasi.
- **Service tetap membatasi data** berdasarkan identitas token walau gateway sudah memutuskan allow (*assume breach*); jam akses hanya diputuskan di gateway.
- Alasan penolakan dikirim ke client agar mudah didemokan; di produksi sebaiknya hanya dicatat di audit log.
- Tidak ada TLS (HTTP di localhost), rate limiting, atau pembatasan percobaan login. Nilai default secret hanya untuk praktikum; ganti lewat environment variable untuk pemakaian nyata.
- Seluruh pencocokan path bersifat ketat (huruf besar-kecil, garis miring akhir): yang tidak cocok dengan aturan ditolak (default deny).

## Struktur folder

```
gateway/            index.js (PEP), policy.js (PE), auth.js (PA), audit.js
nilai-service/      index.js
transkrip-service/  index.js
shared/             config.js, db.js, crypto.js, guards.js
db/                 seed.js, show-audit.js
config/             policy.json (jam akses)
tests/              run-tests.js (60 tes otomatis)
postman/            koleksi Postman
docs/               DEMO_SCRIPT.md (panduan video demo 6-9 menit)
start-all.js        menjalankan ketiga proses sekaligus
Dockerfile, docker-compose.yml
```
