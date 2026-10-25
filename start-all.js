// Menjalankan gateway + 2 service sekaligus (untuk `npm start`).
// Ctrl+C menghentikan semuanya.
const { spawn } = require('child_process');
const path = require('path');

const apps = [
  ['nilai-service/index.js', 'nilai'],
  ['transkrip-service/index.js', 'transkrip'],
  ['gateway/index.js', 'gateway'],     // gateway terakhir: service sudah siap
];

const children = apps.map(([file]) =>
  spawn(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit' })
);

function stopAll() { children.forEach((c) => c.kill()); }
process.on('SIGINT', () => { stopAll(); process.exit(0); });
process.on('SIGTERM', () => { stopAll(); process.exit(0); });
children.forEach((c) => c.on('exit', (code) => {
  if (code) { console.error(`Sebuah proses berhenti (kode ${code}), menghentikan semuanya...`); stopAll(); process.exit(code); }
}));
