// =====================================================================
// Konfigurasi bersama untuk gateway, Service Nilai, dan Service Transkrip.
// Semua nilai bisa di-override lewat environment variable (dipakai Docker).
// PENTING: nilai default di bawah HANYA untuk demo/praktikum.
// =====================================================================
const path = require('path');

module.exports = {
  // --- Alamat & port -------------------------------------------------
  ports: {
    gateway: Number(process.env.GATEWAY_PORT || 3000),
    nilai: Number(process.env.NILAI_PORT || 3001),
    transkrip: Number(process.env.TRANSKRIP_PORT || 3002),
  },
  // Service mendengarkan di 127.0.0.1 (hanya lokal). Di Docker diubah ke 0.0.0.0.
  host: process.env.HOST || '127.0.0.1',
  gatewayUrl: process.env.GATEWAY_URL || 'http://127.0.0.1:3000',
  nilaiUrl: process.env.NILAI_URL || 'http://127.0.0.1:3001',
  transkripUrl: process.env.TRANSKRIP_URL || 'http://127.0.0.1:3002',

  // --- Rahasia -------------------------------------------------------
  jwtSecret: process.env.JWT_SECRET || 'dev-jwt-secret-ganti-di-produksi',
  jwtIssuer: 'sistem-nilai-gateway',
  // Header X-Gateway-Secret: bukti bahwa request memang lewat gateway.
  gatewaySecret: process.env.GATEWAY_SECRET || 'dev-gateway-secret-ganti-di-produksi',
  // Kredensial Service Nilai untuk meminta token service (POST /auth/service).
  serviceClient: {
    id: process.env.SERVICE_CLIENT_ID || 'nilai-service',
    secret: process.env.SERVICE_CLIENT_SECRET || 'nilai-service-secret-dev',
  },

  // --- Masa berlaku token (sesuai tugas 4.1) ---------------------------
  accessTokenTtl: '10m',            // access token user: 10 menit
  serviceTokenTtl: '5m',            // token service: 5 menit
  refreshTokenTtlMs: 24 * 60 * 60 * 1000, // refresh token: 1 hari

  // --- Database & kebijakan --------------------------------------------
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'data', 'nilai.db'),
  // File jam akses dibaca ulang di SETIAP keputusan -> bisa diubah saat demo tanpa restart.
  policyConfigPath: process.env.POLICY_CONFIG || path.join(__dirname, '..', 'config', 'policy.json'),
};
