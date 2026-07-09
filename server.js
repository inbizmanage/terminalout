const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

// ─────────── Args ───────────
const args = {};
process.argv.slice(2).forEach(val => {
    const parts = val.split('=');
    args[parts[0]] = parts.length === 2 ? parts[1] : true;
});

const port     = parseInt(args['--port']      || 7681);
const ttydPort = parseInt(args['--ttyd-port'] || 7682);
const useSsl   = args['--ssl'] === 'true';
const certPath = args['--cert'];
const keyPath  = args['--key'];
const cfgPath  = args['--config'];

// ─────────── Config ───────────
let cfg = {};
if (cfgPath && fs.existsSync(cfgPath)) {
    cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
}
const TOTP_SECRET = cfg.totp_secret || 'JBSWY3DPEHPK3PXP';

// ─────────── Búsqueda de Capturas de Pantalla (Host) ───────────
const globDirs = [
    path.join(process.env.HOME || '/home/dxdx', 'Imágenes/Capturas de pantalla'),
    path.join(process.env.HOME || '/home/dxdx', 'Pictures/Screenshots'),
    path.join(process.env.HOME || '/home/dxdx', 'Pictures'),
    path.join(process.env.HOME || '/home/dxdx', 'Imágenes'),
    path.join(process.env.HOME || '/home/dxdx', 'Desktop'),
    path.join(process.env.HOME || '/home/dxdx', 'Escritorio'),
    '/tmp'
];

function getLatestScreenshot() {
    let latestFile = null;
    let latestMtime = 0;
    
    for (const dir of globDirs) {
        if (!fs.existsSync(dir)) continue;
        try {
            const files = fs.readdirSync(dir);
            for (const file of files) {
                const ext = path.extname(file).toLowerCase();
                if (ext === '.png' || ext === '.jpg' || ext === '.jpeg') {
                    const fullPath = path.join(dir, file);
                    const stat = fs.statSync(fullPath);
                    if (stat.isFile() && stat.mtimeMs > latestMtime) {
                        latestMtime = stat.mtimeMs;
                        latestFile = fullPath;
                    }
                }
            }
        } catch (e) {
            // Ignorar errores
        }
    }
    return latestFile;
}


// ─────────── Icons ───────────
const icon192Path = path.join(__dirname, 'icon-192.png');
const icon512Path = path.join(__dirname, 'icon-512.png');

// ─────────── Sessions ───────────
const sessions = new Map(); // token -> {expires}
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 horas

function createSession() {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { expires: Date.now() + SESSION_TTL });
    return token;
}

function isValidSession(token) {
    const s = sessions.get(token);
    if (!s) return false;
    if (Date.now() > s.expires) { sessions.delete(token); return false; }
    return true;
}

function getSessionToken(req) {
    const cookieHeader = req.headers['cookie'] || '';
    const match = cookieHeader.match(/(?:^|;\s*)tsession=([a-f0-9]+)/);
    return match ? match[1] : null;
}

// ─────────── TOTP ───────────
function base32Decode(s) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, val = 0;
    const out = [];
    for (const c of s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '')) {
        const idx = chars.indexOf(c);
        if (idx === -1) continue;
        val = (val << 5) | idx;
        bits += 5;
        if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); }
    }
    return Buffer.from(out);
}

function hotp(secret, counter) {
    const key = base32Decode(secret);
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', key).update(msg).digest();
    const offset = hmac[19] & 0xf;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    return code.toString().padStart(6, '0');
}

function verifyTotp(token) {
    const counter = Math.floor(Date.now() / 1000 / 30);
    // Aceptar ventana de ±1 para compensar desfase de reloj
    for (let i = -1; i <= 1; i++) {
        if (hotp(TOTP_SECRET, counter + i) === token.trim()) return true;
    }
    return false;
}

// ─────────── QR Code Generator (puro JS, sin librerías) ───────────
// Genera un QR en SVG usando qrcode-svg inline style
// Usamos un encoding base85 liviano para generar el QR
// Como no tenemos librerías, generamos el QR usando una URL de API pública
// que funciona offline via data-URI de Google Charts o similar.
// En cambio, hacemos un QR real con algoritmo Reed-Solomon simplificado.
// Para simplificidad, usamos la API de qr.io que se puede llamar una sola vez
// y cacheamos la imagen. O mejor: usamos Canvas en el browser.

// ─────────── PWA Manifest ───────────
const manifest = {
    "name": "terminalout",
    "short_name": "Terminal",
    "description": "Terminal Web Remota Segura",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0f172a",
    "theme_color": "#0ea5e9",
    "orientation": "any",
    "icons": [
        { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable" },
        { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" }
    ]
};

// ─────────── Service Worker ───────────
const serviceWorkerCode = `
const CACHE = 'terminalout-v2';
self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('fetch', e => e.respondWith(fetch(e.request).catch(() => caches.match(e.request))));
`;

// ─────────── Login Page HTML ───────────
function buildLoginPage(error, serverUrl, totpUri) {
    const encodedUri = encodeURIComponent(totpUri);
    return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#0ea5e9">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="manifest" href="/manifest.json">
<title>terminalout – Acceso</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #020617;
    --surface: rgba(15,23,42,0.9);
    --border: rgba(148,163,184,0.12);
    --accent: #0ea5e9;
    --accent2: #38bdf8;
    --text: #e2e8f0;
    --muted: #64748b;
    --error: #f43f5e;
    --success: #10b981;
  }

  html, body {
    height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, sans-serif;
    overflow-x: hidden;
  }

  /* Fondo animado */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background:
      radial-gradient(ellipse 80% 60% at 50% 0%, rgba(14,165,233,0.15) 0%, transparent 60%),
      radial-gradient(ellipse 60% 40% at 100% 100%, rgba(99,102,241,0.1) 0%, transparent 50%);
    pointer-events: none;
    z-index: 0;
  }

  .grid-bg {
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(148,163,184,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(148,163,184,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    min-height: 100dvh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    gap: 24px;
    flex-wrap: wrap;
  }

  /* Panel principal de login */
  .login-card {
    width: 100%;
    max-width: 380px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 32px 28px;
    backdrop-filter: blur(20px);
    box-shadow: 0 25px 50px rgba(0,0,0,0.6), 0 0 0 1px rgba(14,165,233,0.08) inset;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
  }

  .logo-icon {
    width: 42px;
    height: 42px;
    background: linear-gradient(135deg, #0ea5e9, #6366f1);
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    box-shadow: 0 8px 16px rgba(14,165,233,0.3);
  }

  .logo-text { 
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 18px;
    color: white;
    letter-spacing: -0.5px;
  }

  .logo-sub {
    font-size: 11px;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }

  h2 {
    font-size: 22px;
    font-weight: 700;
    color: white;
    margin-bottom: 6px;
  }

  .subtitle {
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 24px;
    line-height: 1.5;
  }

  .error-box {
    background: rgba(244,63,94,0.1);
    border: 1px solid rgba(244,63,94,0.3);
    border-radius: 10px;
    padding: 10px 14px;
    font-size: 13px;
    color: var(--error);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 8px;
  }

  input[type=text], input[type=password] {
    width: 100%;
    padding: 12px 16px;
    background: rgba(15,23,42,0.8);
    border: 1px solid var(--border);
    border-radius: 12px;
    color: var(--text);
    font-size: 16px;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.15em;
    transition: border-color 0.2s, box-shadow 0.2s;
    -webkit-appearance: none;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(14,165,233,0.15);
  }

  .field { margin-bottom: 16px; }

  .totp-hint {
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
  }

  button[type=submit] {
    width: 100%;
    padding: 14px;
    background: linear-gradient(135deg, #0ea5e9, #0284c7);
    border: none;
    border-radius: 12px;
    color: white;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    margin-top: 8px;
    transition: all 0.2s;
    box-shadow: 0 4px 14px rgba(14,165,233,0.4);
    letter-spacing: 0.02em;
    -webkit-appearance: none;
  }

  button[type=submit]:active {
    transform: scale(0.97);
    box-shadow: 0 2px 6px rgba(14,165,233,0.3);
  }

  .divider {
    height: 1px;
    background: var(--border);
    margin: 24px 0;
  }

  /* Panel lateral de QR */
  .qr-panel {
    width: 100%;
    max-width: 300px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .qr-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
    backdrop-filter: blur(20px);
    text-align: center;
  }

  .qr-card h3 {
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 12px;
  }

  .qr-wrap {
    background: white;
    border-radius: 12px;
    padding: 12px;
    display: inline-block;
    margin-bottom: 10px;
  }

  .qr-wrap canvas {
    display: block;
    max-width: 100%;
  }

  .qr-label {
    font-size: 11px;
    color: var(--muted);
    line-height: 1.5;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: rgba(14,165,233,0.1);
    border: 1px solid rgba(14,165,233,0.25);
    border-radius: 20px;
    padding: 4px 10px;
    font-size: 11px;
    color: var(--accent2);
    font-weight: 600;
  }

  .status-row {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-top: 8px;
  }

  .dot {
    width: 7px;
    height: 7px;
    background: var(--success);
    border-radius: 50%;
    box-shadow: 0 0 6px var(--success);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.6; transform: scale(1.3); }
  }

  @media (max-width: 600px) {
    .qr-panel { max-width: 380px; }
    .container { flex-direction: column; align-items: center; }
  }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="container">

  <!-- Login Card -->
  <div class="login-card">
    <div class="logo">
      <div class="logo-icon">⬡</div>
      <div>
        <div class="logo-text">terminalout</div>
        <div class="logo-sub">&gt;_ Acceso Seguro</div>
      </div>
    </div>

    <h2>Iniciar sesión</h2>
    <p class="subtitle">Ingresa el código de 6 dígitos de Google Authenticator para continuar.</p>

    ${error ? `<div class="error-box">⚠ ${error}</div>` : ''}

    <form method="POST" action="/auth/login" autocomplete="off">
      <div class="field">
        <label>Código de Autenticador</label>
        <input type="text" name="totp" id="totp-input"
          maxlength="6" inputmode="numeric" pattern="[0-9]*"
          placeholder="000000" autofocus autocomplete="one-time-code">
        <div class="totp-hint">📱 Abre Google Authenticator en tu teléfono</div>
      </div>
      <button type="submit">Acceder →</button>
    </form>

    <div class="divider"></div>

    <div class="status-row">
      <div class="dot"></div>
      <span style="font-size:12px;color:var(--muted)">Servidor activo · HTTPS</span>
      <span class="badge">🔒 2FA</span>
    </div>
  </div>

  <!-- QR Panel -->
  <div class="qr-panel">

    <!-- QR: URL para acceder desde el móvil -->
    <div class="qr-card">
      <h3>📱 Abrir en tu teléfono</h3>
      <div class="qr-wrap">
        <canvas id="url-qr" width="180" height="180"></canvas>
      </div>
      <div class="qr-label">Escanea para abrir la terminal en tu móvil</div>
      <div id="url-display" style="margin-top:8px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent2);word-break:break-all;"></div>
    </div>

    <!-- QR: Configurar Google Authenticator -->
    <div class="qr-card">
      <h3>🔑 Configurar Autenticador</h3>
      <div class="qr-wrap">
        <canvas id="totp-qr" width="180" height="180"></canvas>
      </div>
      <div class="qr-label">Escanea con <strong>Google Authenticator</strong> o <strong>Aegis</strong> para configurar el 2FA</div>
    </div>

  </div>
</div>

<!-- QR Code Library (inline - no external deps needed at runtime) -->
<script>
${getQrCodeJS(serverUrl, totpUri)}

// Mostrar la URL actual en la tarjeta
document.getElementById('url-display').textContent = window.location.href;

// Generar QR de URL del servidor
const urlQr = document.getElementById('url-qr');
const urlCtx = urlQr.getContext('2d');
try {
    drawQR(urlCtx, window.location.href, 180);
} catch(e) { console.error('QR URL error:', e); }

// Generar QR de TOTP
const totpQr = document.getElementById('totp-qr');
const totpCtx = totpQr.getContext('2d');
try {
    drawQR(totpCtx, ${JSON.stringify(totpUri)}, 180);
} catch(e) { console.error('QR TOTP error:', e); }

// Auto-submit cuando se ingresen 6 dígitos
const input = document.getElementById('totp-input');
if (input) {
    input.addEventListener('input', () => {
        if (/^[0-9]{6}$/.test(input.value)) {
            input.form.submit();
        }
    });
}
</script>
</body>
</html>`;
}

// ─────────── QR Code JS Inline ───────────
function getQrCodeJS(serverUrl, totpUri) {
    const escapedUrl  = JSON.stringify(serverUrl  || '');
    const escapedTotp = JSON.stringify(totpUri    || '');
    return `
function drawQR(ctx, text, size) {
    // Implementado via imagen del endpoint /qr
}

// Reemplazar canvas con imagen generada desde el servidor
(function() {
    function makeQRImg(canvasId, data) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const parent = canvas.parentElement;
        const img = document.createElement('img');
        img.width = 180;
        img.height = 180;
        img.style.display = 'block';
        img.style.borderRadius = '4px';
        img.style.imageRendering = 'pixelated';
        img.src = '/qr?data=' + encodeURIComponent(data) + '&size=180';
        img.alt = 'QR Code';
        parent.replaceChild(img, canvas);
    }

    makeQRImg('url-qr',  window.location.href);
    makeQRImg('totp-qr', ${escapedTotp});
})();
`;
}


// ─────────── QR Code SVG Generator ───────────
// Generador de QR Code en SVG puro usando el algoritmo estándar
// Basado en la implementación de QRCode.js
function generateQRSVG(text) {
    // Usar módulo de Node crypto para generar un QR simple
    // Implementamos la matriz QR versión 2-L como PNG via canvas-like approach
    // Vamos a generar un SVG de QR real usando el algoritmo Reed-Solomon
    
    // Como alternativa directa y funcional: generamos un PNG usando
    // la librería de dibujo simple sin dependencias externas
    return null; // Se maneja en el endpoint /qr
}

// ─────────── Render QR usando Python (backend) ───────────
const { execSync, exec } = require('child_process');

function generateQRPng(text, size, callback) {
    const tmpFile = `/tmp/qr_${Date.now()}_${Math.floor(Math.random()*1000)}.png`;
    const escapedText = text.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/`/g, '\\`');
    const pythonCode = `
import qrcode
qr = qrcode.QRCode(version=1, box_size=10, border=1)
qr.add_data("""${escapedText}""")
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("${tmpFile}")
`;
    exec(`python3 -c '${pythonCode.replace(/'/g, "'\\''")}'`, (err) => {
        if (err) {
            console.error("Error generating QR:", err);
            callback(null);
        } else {
            callback(tmpFile);
        }
    });
}

// ─────────── Inject HTML ───────────
function injectHTML(rawHtml) {
    const pwaMeta = `
    <link rel="manifest" href="/manifest.json">
    <meta name="theme-color" content="#0ea5e9">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <style>
      #mobile-keyboard-bar {
          display: none;
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          height: 50px;
          background: rgba(2, 6, 23, 0.96);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border-top: 1px solid rgba(14, 165, 233, 0.25);
          z-index: 999999;
          flex-direction: row;
          align-items: center;
          padding: 5px 6px;
          box-sizing: border-box;
          gap: 6px;
          overflow-x: auto;
          -webkit-overflow-scrolling: touch;
          white-space: nowrap;
      }
      /* Ocultar barra de scroll para limpieza */
      #mobile-keyboard-bar::-webkit-scrollbar {
          display: none;
      }
      #mobile-keyboard-bar {
          -ms-overflow-style: none;  /* IE and Edge */
          scrollbar-width: none;  /* Firefox */
      }
      #mobile-keyboard-bar.active { display: flex; }
      
      .terminal-key-btn {
          display: inline-flex;
          flex-shrink: 0;
          height: 38px;
          padding: 0 14px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 8px;
          color: #94a3b8;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 700;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          user-select: none;
          -webkit-user-select: none;
          touch-action: manipulation;
          transition: all 0.15s ease;
          letter-spacing: -0.01em;
      }
      .terminal-key-btn:active {
          background: rgba(14, 165, 233, 0.3);
          border-color: rgba(14, 165, 233, 0.6);
          color: #fff;
          transform: scale(0.95);
      }
      .terminal-key-btn.active {
          background: rgba(14, 165, 233, 0.25);
          border-color: #0ea5e9;
          color: #38bdf8;
          box-shadow: 0 0 12px rgba(14, 165, 233, 0.35);
      }
      
      /* Botones de acción especial destacables */
      .terminal-key-btn.special-btn {
          background: rgba(14, 165, 233, 0.15);
          border-color: rgba(14, 165, 233, 0.35);
          color: #38bdf8;
      }
      
      body.mobile-bar-active .xterm-viewport,
      body.mobile-bar-active .xterm-screen { margin-bottom: 50px !important; }
      body.mobile-bar-active { background-color: #020617 !important; }

      #pwa-install-btn {
          display: none;
          position: fixed;
          top: 14px;
          right: 14px;
          padding: 9px 16px;
          background: rgba(14, 165, 233, 0.15);
          border: 1px solid rgba(14, 165, 233, 0.4);
          border-radius: 22px;
          color: #38bdf8;
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          z-index: 100000;
          box-shadow: 0 4px 14px rgba(0,0,0,0.5), 0 0 12px rgba(14, 165, 233, 0.2);
          align-items: center;
          gap: 6px;
          transition: all 0.2s;
          user-select: none;
          -webkit-user-select: none;
      }
      #pwa-install-btn:active {
          background: rgba(14, 165, 233, 0.35);
          transform: scale(0.95);
      }
      
      /* Header styles */
      #app-header {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          height: 50px;
          background: rgba(15, 23, 42, 0.9);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border-bottom: 1px solid rgba(14, 165, 233, 0.2);
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0 16px;
          z-index: 100000;
          box-sizing: border-box;
      }
      .header-logo {
          display: flex;
          align-items: center;
          gap: 8px;
      }
      .logo-dot {
          width: 8px;
          height: 8px;
          background: #10b981;
          border-radius: 50%;
          box-shadow: 0 0 8px #10b981;
          animation: pulse 2s infinite;
      }
      .logo-title {
          font-family: 'JetBrains Mono', monospace;
          font-weight: 700;
          color: #fff;
          font-size: 16px;
      }
      .header-status {
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          font-weight: 600;
          color: #38bdf8;
      }
      
      /* Main App Layout */
      .app-screen {
          display: none;
          position: fixed;
          top: 50px;
          bottom: 55px;
          left: 0;
          right: 0;
          background: #020617;
          overflow-y: auto;
          padding: 20px 16px;
          box-sizing: border-box;
          z-index: 99999;
          color: #f8fafc;
          font-family: system-ui, -apple-system, sans-serif;
      }
      .app-screen.active {
          display: block;
      }
      
      /* Navigation Bar at Bottom */
      #app-nav-bar {
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          height: 55px;
          background: rgba(15, 23, 42, 0.95);
          backdrop-filter: blur(12px);
          border-top: 1px solid rgba(255, 255, 255, 0.08);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 100000;
          box-sizing: border-box;
      }
      .nav-home-btn {
          width: 50px;
          height: 8px;
          background: rgba(255, 255, 255, 0.3);
          border-radius: 4px;
          cursor: pointer;
          transition: background 0.2s, transform 0.2s;
      }
      .nav-home-btn:active {
          background: rgba(255, 255, 255, 0.6);
          transform: scale(0.95);
      }

      /* Home Screen Grid */
      .home-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          padding-top: 20px;
      }
      .app-icon-wrap {
          display: flex;
          flex-direction: column;
          align-items: center;
          cursor: pointer;
      }
      .app-icon {
          width: 60px;
          height: 60px;
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 28px;
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3);
          transition: transform 0.2s;
      }
      .app-icon-wrap:active .app-icon {
          transform: scale(0.9);
      }
      .terminal-icon { background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid rgba(255,255,255,0.1); }
      .files-icon { background: linear-gradient(135deg, #eab308, #ca8a04); }
      .monitor-icon { background: linear-gradient(135deg, #0ea5e9, #0284c7); }
      .gallery-icon { background: linear-gradient(135deg, #ec4899, #db2777); }
      
      .app-name {
          margin-top: 8px;
          font-size: 11px;
          font-weight: 500;
          color: #e2e8f0;
          text-align: center;
      }

      /* App Toolbars */
      .app-toolbar {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 16px;
          font-weight: 700;
          font-size: 15px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          padding-bottom: 10px;
      }
      .tool-btn {
          background: rgba(255, 255, 255, 0.08);
          border: 1px solid rgba(255, 255, 255, 0.12);
          color: #fff;
          padding: 6px 12px;
          border-radius: 8px;
          font-size: 12px;
          cursor: pointer;
      }
      .tool-btn:active {
          background: rgba(255, 255, 255, 0.18);
      }
      .current-path {
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: #94a3b8;
          word-break: break-all;
      }

      /* Files List */
      .files-list {
          display: flex;
          flex-direction: column;
          gap: 2px;
      }
      .file-item {
          display: flex;
          align-items: center;
          padding: 12px;
          background: rgba(255, 255, 255, 0.03);
          border-radius: 8px;
          cursor: pointer;
          transition: background 0.15s;
      }
      .file-item:active {
          background: rgba(255, 255, 255, 0.08);
      }
      .file-icon {
          font-size: 20px;
          margin-right: 12px;
      }
      .file-name {
          flex: 1;
          font-size: 14px;
          color: #e2e8f0;
          word-break: break-all;
      }
      .file-size {
          font-size: 11px;
          color: #64748b;
          font-family: 'JetBrains Mono', monospace;
      }

      /* Process Table */
      .process-table-container {
          overflow-x: auto;
          margin-top: 10px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: 10px;
      }
      .process-table {
          width: 100%;
          border-collapse: collapse;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          text-align: left;
      }
      .process-table th, .process-table td {
          padding: 10px 8px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      }
      .process-table th {
          background: rgba(255, 255, 255, 0.03);
          color: #94a3b8;
          font-weight: 700;
      }
      .process-table td {
          color: #e2e8f0;
      }
      .kill-btn {
          background: rgba(239, 68, 68, 0.15);
          border: 1px solid rgba(239, 68, 68, 0.35);
          color: #ef4444;
          padding: 3px 8px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: bold;
      }
      .kill-btn:active {
          background: rgba(239, 68, 68, 0.35);
      }

      /* Terminal View Specific CSS */
      body.show-terminal > div:not(#app-header):not(#app-nav-bar):not(#mobile-keyboard-bar):not(#pwa-install-btn):not(.app-screen):not(script) {
          margin-top: 50px !important;
          height: calc(100vh - 105px) !important;
          box-sizing: border-box;
      }
      body:not(.show-terminal) > div:not(#app-header):not(#app-nav-bar):not(#mobile-keyboard-bar):not(#pwa-install-btn):not(.app-screen):not(script) {
          display: none !important;
      }
      body.show-terminal #mobile-keyboard-bar {
          bottom: 55px !important;
      }
      body.show-terminal.mobile-bar-active > div:not(#app-header):not(#app-nav-bar):not(#mobile-keyboard-bar):not(#pwa-install-btn):not(.app-screen):not(script) {
          height: calc(100vh - 155px) !important;
      }

      /* Dashboard Cards & Layout */
      .dash-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
          margin-bottom: 12px;
      }
      .dash-card {
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 14px;
          padding: 14px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      }
      .single-card {
          margin-bottom: 20px;
          flex-direction: row;
          align-items: center;
          justify-content: space-between;
      }
      .card-title {
          font-size: 11px;
          font-weight: 700;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: 0.05em;
      }
      .card-value {
          font-size: 22px;
          font-weight: 700;
          color: #fff;
          margin: 6px 0 10px 0;
          font-family: 'JetBrains Mono', monospace;
      }
      .card-value-large {
          font-size: 18px;
          font-weight: 700;
          color: #38bdf8;
          font-family: 'JetBrains Mono', monospace;
      }
      .progress-track {
          background: rgba(255, 255, 255, 0.08);
          height: 6px;
          border-radius: 3px;
          overflow: hidden;
      }
      .progress-bar {
          background: linear-gradient(90deg, #0ea5e9, #38bdf8);
          height: 100%;
          width: 0%;
          transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .temp-icon {
          align-self: flex-end;
          font-size: 20px;
      }
    </style>`;

    const pwaBody = `
    <div id="app-header">
      <div class="header-logo">
        <span class="logo-dot"></span>
        <span class="logo-title" id="header-app-title">LinuxMobile</span>
      </div>
      <div class="header-status">
        <span id="header-time">00:00</span>
      </div>
    </div>
    
    <button id="pwa-install-btn">📥 Instalar App</button>

    <!-- Home Screen -->
    <div id="home-screen" class="app-screen active">
      <div class="home-grid">
        <div class="app-icon-wrap" id="app-terminal-btn">
          <div class="app-icon terminal-icon">📟</div>
          <div class="app-name">Terminal</div>
        </div>
        <div class="app-icon-wrap" id="app-files-btn">
          <div class="app-icon files-icon">📁</div>
          <div class="app-name">Archivos</div>
        </div>
        <div class="app-icon-wrap" id="app-monitor-btn">
          <div class="app-icon monitor-icon">📊</div>
          <div class="app-name">Monitor</div>
        </div>
        <div class="app-icon-wrap" id="app-gallery-btn">
          <div class="app-icon gallery-icon">🖼️</div>
          <div class="app-name">Capturas</div>
        </div>
      </div>
    </div>

    <!-- Files App -->
    <div id="files-app" class="app-screen">
      <div class="app-toolbar">
        <button class="tool-btn" id="files-back-btn">⬅️ Atrás</button>
        <span class="current-path" id="files-path">/home/dxdx</span>
      </div>
      <div class="files-list" id="files-list-container">
        <!-- cargado dinámicamente -->
      </div>
    </div>

    <!-- Monitor App -->
    <div id="monitor-app" class="app-screen">
      <div class="app-toolbar">
        <button class="tool-btn" id="monitor-back-btn">⬅️ Atrás</button>
        <span>Monitor de Sistema</span>
      </div>
      <div class="dash-grid">
        <div class="dash-card">
          <div class="card-title">CPU</div>
          <div class="card-value" id="stat-cpu">--%</div>
          <div class="progress-track"><div class="progress-bar" id="bar-cpu" style="width: 0%"></div></div>
        </div>
        <div class="dash-card">
          <div class="card-title">Memoria</div>
          <div class="card-value" id="stat-mem">-- MB</div>
          <div class="progress-track"><div class="progress-bar" id="bar-mem" style="width: 0%"></div></div>
        </div>
        <div class="dash-card">
          <div class="card-title">Disco (/)</div>
          <div class="card-value" id="stat-disk">-- GB</div>
          <div class="progress-track"><div class="progress-bar" id="bar-disk" style="width: 0%"></div></div>
        </div>
        <div class="dash-card">
          <div class="card-title">Temperatura</div>
          <div class="card-value" id="stat-temp">--°C</div>
          <div class="temp-icon">🔥</div>
        </div>
      </div>
      <div class="dash-card single-card">
        <div class="card-title">Uptime</div>
        <div class="card-value-large" id="stat-uptime">--:--:--</div>
      </div>
      <h3 class="section-title" style="font-size:13px;color:#94a3b8;margin:15px 0 8px 0;text-transform:uppercase;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:4px;">Procesos Activos</h3>
      <div class="process-table-container">
        <table class="process-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>CPU%</th>
              <th>MEM%</th>
              <th>Comando</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody id="process-list-body">
            <!-- cargado dinámicamente -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- Gallery App -->
    <div id="gallery-app" class="app-screen">
      <div class="app-toolbar">
        <button class="tool-btn" id="gallery-back-btn">⬅️ Atrás</button>
        <span>Capturas del Servidor</span>
      </div>
      <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);border-radius:12px;padding:16px;text-align:center;">
        <h4 style="margin:0 0 12px 0;font-size:14px;color:#94a3b8;">Última Captura Reciente:</h4>
        <div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:8px;min-height:150px;display:flex;align-items:center;justify-content:center;">
          <img id="gallery-img-preview" src="" alt="Vista previa" style="max-width:100%;max-height:350px;display:none;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.5);" />
          <div id="gallery-no-img" style="color:#64748b;font-size:12px;">Cargando captura...</div>
        </div>
        <button class="action-btn" id="btn-refresh-gallery" style="background:rgba(14,165,233,0.15);border:1px solid rgba(14,165,233,0.3);color:#38bdf8;padding:8px 16px;border-radius:8px;font-size:12px;margin-top:12px;cursor:pointer;">🔄 Actualizar</button>
      </div>
    </div>

    <!-- Bottom Navigation Bar (Home Button) -->
    <div id="app-nav-bar">
      <div class="nav-home-btn" id="nav-home-btn"></div>
    </div>

    <div id="mobile-keyboard-bar">
      <div class="terminal-key-btn special-btn" id="btn-ctrlc2">Ctrl+C x2</div>
      <div class="terminal-key-btn special-btn" id="btn-paste">📋 Pegar</div>
      <div class="terminal-key-btn special-btn" id="btn-last-img">📸 Captura</div>
      <div class="terminal-key-btn" id="btn-esc">ESC</div>
      <div class="terminal-key-btn" id="btn-tab">TAB</div>
      <div class="terminal-key-btn" id="btn-ctrl">CTRL</div>
      <div class="terminal-key-btn" id="btn-alt">ALT</div>
      <div class="terminal-key-btn" id="btn-up">↑</div>
      <div class="terminal-key-btn" id="btn-down">↓</div>
      <div class="terminal-key-btn" id="btn-left">←</div>
      <div class="terminal-key-btn" id="btn-right">→</div>
      <div class="terminal-key-btn" id="btn-pipe">|</div>
      <div class="terminal-key-btn" id="btn-slash">/</div>
      <div class="terminal-key-btn" id="btn-minus">-</div>
      <div class="terminal-key-btn" id="btn-tilde">~</div>
    </div>
    <script>
      (function() {
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        window.ctrlActive = false;
        window.altActive  = false;

        if (isMobile) {
            document.body.classList.add('mobile-bar-active');
            const bar = document.getElementById('mobile-keyboard-bar');
            if (bar) bar.classList.add('active');
        }

        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(()=>{});
        }

        // Posicionamiento dinámico con Visual Viewport (Evitar que el teclado oculte la barra)
        if (window.visualViewport) {
            const adjustBarPosition = () => {
                const bar = document.getElementById('mobile-keyboard-bar');
                if (!bar || !bar.classList.contains('active')) return;
                
                // Calcular diferencia entre la altura de ventana interna y el viewport visible
                const keyboardHeight = window.innerHeight - window.visualViewport.height;
                // Si el teclado está abierto, lo situamos arriba del teclado, de lo contrario bottom: 0
                bar.style.bottom = Math.max(0, keyboardHeight) + 'px';
                
                // Desplazar viewport para mantener la visibilidad si es necesario
                window.scrollTo(0, 0);
            };
            window.visualViewport.addEventListener('resize', adjustBarPosition);
            window.visualViewport.addEventListener('scroll', adjustBarPosition);
        }

        let deferredPrompt = null;
        const installBtn = document.getElementById('pwa-install-btn');
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            if (installBtn) installBtn.style.display = 'flex';
        });
        if (installBtn) {
            installBtn.addEventListener('click', async () => {
                if (!deferredPrompt) return;
                deferredPrompt.prompt();
                await deferredPrompt.userChoice;
                deferredPrompt = null;
                installBtn.style.display = 'none';
            });
        }
        window.addEventListener('appinstalled', () => {
            if (installBtn) installBtn.style.display = 'none';
        });

        // WebSocket proxy transparente
        let activeWs = null;
        const OrigWS = window.WebSocket;
        window.WebSocket = new Proxy(OrigWS, {
            construct(target, args) {
                const ws = Reflect.construct(target, args);
                activeWs = ws;
                const origSend = ws.send;
                ws.send = function(data) {
                    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
                        const bytes = new Uint8Array(data.buffer || data);
                        if (bytes[0] === 48 && bytes.length > 1) {
                            if (window.ctrlActive) {
                                window.ctrlActive = false;
                                document.getElementById('btn-ctrl').classList.remove('active');
                                const ch = new TextDecoder().decode(bytes.subarray(1));
                                let out = '';
                                for (let i = 0; i < ch.length; i++) {
                                    const c = ch.charCodeAt(i);
                                    if (c >= 97 && c <= 122) out += String.fromCharCode(c - 96);
                                    else if (c >= 65 && c <= 90) out += String.fromCharCode(c - 64);
                                    else out += ch[i];
                                }
                                const enc = new TextEncoder().encode(out);
                                const nb = new Uint8Array(1 + enc.length);
                                nb[0] = 48; nb.set(enc, 1);
                                origSend.call(this, nb.buffer);
                                return;
                            }
                            if (window.altActive) {
                                window.altActive = false;
                                document.getElementById('btn-alt').classList.remove('active');
                                const nb = new Uint8Array(1 + 1 + bytes.length - 1);
                                nb[0] = 48; nb[1] = 27; nb.set(bytes.subarray(1), 2);
                                origSend.call(this, nb.buffer);
                                return;
                            }
                        }
                    }
                    origSend.apply(this, arguments);
                };
                return ws;
            }
        });

        function send(s) {
            if (!activeWs || activeWs.readyState !== 1) return;
            const enc = new TextEncoder().encode(s);
            const b = new Uint8Array(1 + enc.length);
            b[0] = 48; b.set(enc, 1);
            activeWs.send(b.buffer);
        }

        const ESC = String.fromCharCode(27);
        const map = {
            'btn-esc': () => send(ESC),
            'btn-tab': () => send('\\t'),
            'btn-up':  () => send(ESC+'[A'),
            'btn-down':() => send(ESC+'[B'),
            'btn-left':() => send(ESC+'[D'),
            'btn-right':()=> send(ESC+'[C'),
            'btn-pipe':() => send('|'),
            'btn-slash':()=> send('/'),
            'btn-minus':()=> send('-'),
            'btn-tilde':()=> send('~'),
            // Enviar Ctrl+C dos veces
            'btn-ctrlc2': () => {
                send(String.fromCharCode(3));
                setTimeout(() => send(String.fromCharCode(3)), 50);
            }
        };
        Object.entries(map).forEach(([id, fn]) => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('click', fn);
        });

        // Botón Pegar Portapapeles
        const pasteBtn = document.getElementById('btn-paste');
        if (pasteBtn) {
            pasteBtn.addEventListener('click', async () => {
                try {
                    // La API de clipboard requiere HTTPS (proveído por Cloudflare)
                    if (navigator.clipboard && navigator.clipboard.readText) {
                        const text = await navigator.clipboard.readText();
                        if (text) {
                            send(text);
                            return;
                        }
                    }
                } catch (e) {
                    console.log('Clipboard API no disponible o bloqueada:', e);
                }
                
                // Fallback con Prompt clásico
                const val = prompt("Pega el texto aquí:");
                if (val) {
                    send(val);
                }
            });
        }

        // Botón Obtener Ruta de la Última Foto / Screenshot (Host)
        const lastImgBtn = document.getElementById('btn-last-img');
        if (lastImgBtn) {
            lastImgBtn.addEventListener('click', async () => {
                try {
                    const res = await fetch('/api/last-screenshot');
                    const data = await res.json();
                    if (data && data.path) {
                        // Enviar la ruta del archivo escribiéndola en la terminal
                        send(data.path);
                    } else {
                        alert("No se encontró ninguna captura reciente en el servidor.");
                    }
                } catch (e) {
                    alert("Error al conectar con la API de capturas.");
                }
            });
        }

        const ctrlBtn = document.getElementById('btn-ctrl');
        if (ctrlBtn) ctrlBtn.addEventListener('click', () => {
            window.ctrlActive = !window.ctrlActive;
            ctrlBtn.classList.toggle('active', window.ctrlActive);
            if (window.ctrlActive) {
                window.altActive = false;
                document.getElementById('btn-alt').classList.remove('active');
            }
        });

        const altBtn = document.getElementById('btn-alt');
        if (altBtn) altBtn.addEventListener('click', () => {
            window.altActive = !window.altActive;
            altBtn.classList.toggle('active', window.altActive);
            if (window.altActive) {
                window.ctrlActive = false;
                document.getElementById('btn-ctrl').classList.remove('active');
            }
        });

        // --- Lógica de LinuxMobile OS ---
        const screens = ['home-screen', 'files-app', 'monitor-app', 'gallery-app'];
        
        function openApp(appName) {
            // Desactivar todas las pantallas personalizadas
            screens.forEach(s => {
                document.getElementById(s).classList.remove('active');
            });
            
            if (appName === 'terminal') {
                document.body.classList.add('show-terminal');
                document.getElementById('header-app-title').textContent = 'Terminal';
                const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
                if (isMobile) {
                    document.getElementById('mobile-keyboard-bar').classList.add('active');
                }
                setTimeout(() => window.dispatchEvent(new Event('resize')), 100);
            } else {
                document.body.classList.remove('show-terminal');
                document.getElementById('mobile-keyboard-bar').classList.remove('active');
                
                if (appName === 'home') {
                    document.getElementById('home-screen').classList.add('active');
                    document.getElementById('header-app-title').textContent = 'LinuxMobile';
                } else if (appName === 'files') {
                    document.getElementById('files-app').classList.add('active');
                    document.getElementById('header-app-title').textContent = 'Explorador';
                    loadDirectory('/home/dxdx');
                } else if (appName === 'monitor') {
                    document.getElementById('monitor-app').classList.add('active');
                    document.getElementById('header-app-title').textContent = 'Monitor';
                    loadProcesses();
                } else if (appName === 'gallery') {
                    document.getElementById('gallery-app').classList.add('active');
                    document.getElementById('header-app-title').textContent = 'Capturas';
                    loadGallery();
                }
            }
        }
        
        document.getElementById('app-terminal-btn').addEventListener('click', () => openApp('terminal'));
        document.getElementById('app-files-btn').addEventListener('click', () => openApp('files'));
        document.getElementById('app-monitor-btn').addEventListener('click', () => openApp('monitor'));
        document.getElementById('app-gallery-btn').addEventListener('click', () => openApp('gallery'));
        document.getElementById('nav-home-btn').addEventListener('click', () => openApp('home'));
        document.getElementById('files-back-btn').addEventListener('click', () => openApp('home'));
        document.getElementById('monitor-back-btn').addEventListener('click', () => openApp('home'));
        document.getElementById('gallery-back-btn').addEventListener('click', () => openApp('home'));

        // --- Lógica del Explorador de Archivos ---
        let currentDirectory = '/home/dxdx';
        
        async function loadDirectory(path) {
            try {
                const res = await fetch('/api/files/list?path=' + encodeURIComponent(path));
                const data = await res.json();
                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }
                currentDirectory = data.currentPath;
                document.getElementById('files-path').textContent = currentDirectory;
                
                const container = document.getElementById('files-list-container');
                container.innerHTML = '';
                
                // Opción para subir de nivel
                if (currentDirectory !== '/' && currentDirectory !== '') {
                    const parentDir = currentDirectory.substring(0, currentDirectory.lastIndexOf('/')) || '/';
                    const upItem = document.createElement('div');
                    upItem.className = 'file-item';
                    upItem.innerHTML = '<span class="file-icon">📁</span><span class="file-name">.. (Subir nivel)</span>';
                    upItem.addEventListener('click', () => loadDirectory(parentDir));
                    container.appendChild(upItem);
                }
                
                data.files.forEach(file => {
                    const item = document.createElement('div');
                    item.className = 'file-item';
                    const icon = file.isDir ? '📁' : '📄';
                    const sizeStr = file.isDir ? '' : formatBytes(file.size);
                    item.innerHTML = '<span class="file-icon">' + icon + '</span><span class="file-name">' + file.name + '</span><span class="file-size">' + sizeStr + '</span>';
                    item.addEventListener('click', () => {
                        if (file.isDir) {
                            loadDirectory(currentDirectory + '/' + file.name);
                        } else {
                            window.open('/api/files/view?path=' + encodeURIComponent(currentDirectory + '/' + file.name));
                        }
                    });
                    container.appendChild(item);
                });
            } catch (e) {
                console.error(e);
            }
        }
        
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        // --- Lógica del Monitor del Sistema ---
        async function loadProcesses() {
            try {
                const res = await fetch('/api/system-processes');
                const list = await res.json();
                const tbody = document.getElementById('process-list-body');
                tbody.innerHTML = '';
                list.forEach(proc => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td>' + proc.pid + '</td><td style="color:#10b981">' + proc.cpu + '%</td><td style="color:#38bdf8">' + proc.mem + '%</td><td style="max-width:120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + proc.command + '</td><td><button class="kill-btn" data-pid="' + proc.pid + '">Kill</button></td>';
                    tbody.appendChild(tr);
                });
                
                // Listeners para botones de Kill
                tbody.querySelectorAll('.kill-btn').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const pid = e.target.getAttribute('data-pid');
                        if (confirm('¿Seguro que deseas matar el proceso ' + pid + '?')) {
                            const resKill = await fetch('/api/process/kill', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                body: 'pid=' + pid
                            });
                            const dataKill = await resKill.json();
                            if (dataKill.success) {
                                loadProcesses();
                            } else {
                                alert('No se pudo matar el proceso.');
                            }
                        }
                    });
                });
            } catch (e) {
                console.error(e);
            }
        }

        setInterval(() => {
            const monitorApp = document.getElementById('monitor-app');
            if (monitorApp && monitorApp.classList.contains('active')) {
                loadProcesses();
            }
        }, 3000);

        // --- Lógica de la Galería de Capturas ---
        async function loadGallery() {
            const img = document.getElementById('gallery-img-preview');
            const noImg = document.getElementById('gallery-no-img');
            img.style.display = 'none';
            noImg.style.display = 'block';
            noImg.textContent = 'Cargando captura...';
            try {
                const res = await fetch('/api/last-screenshot');
                const data = await res.json();
                if (data && data.path) {
                    img.src = '/api/files/view?path=' + encodeURIComponent(data.path);
                    img.onload = () => {
                        img.style.display = 'block';
                        noImg.style.display = 'none';
                    };
                } else {
                    noImg.textContent = 'No se encontró ninguna captura reciente.';
                }
            } catch (e) {
                noImg.textContent = 'Error al cargar la captura.';
            }
        }
        document.getElementById('btn-refresh-gallery').addEventListener('click', loadGallery);

        // --- Actualizar Reloj del Header ---
        function updateClock() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const clockEl = document.getElementById('header-time');
            if (clockEl) clockEl.textContent = timeStr;
        }
        setInterval(updateClock, 1000);
        updateClock();

        // --- Detener propagación de clics y toques para evitar problemas con ttyd/xterm ---
        const customElements = ['app-header', 'app-nav-bar', 'home-screen', 'files-app', 'monitor-app', 'gallery-app'];
        customElements.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                ['click', 'mousedown', 'mouseup', 'touchstart', 'touchend', 'pointerdown', 'pointerup'].forEach(evt => {
                    el.addEventListener(evt, (e) => {
                        e.stopPropagation();
                    });
                });
            }
        });

        // --- Actualizar Métricas en Segundo Plano ---
        async function updateStats() {
            try {
                const res = await fetch('/api/system-status');
                if (res.status === 401) return;
                const data = await res.json();
                
                document.getElementById('stat-cpu').textContent = data.cpu + '%';
                const barCpu = document.getElementById('bar-cpu');
                if (barCpu) barCpu.style.width = data.cpu + '%';
                
                document.getElementById('stat-mem').textContent = data.mem.used + ' / ' + data.mem.total + ' MB';
                const barMem = document.getElementById('bar-mem');
                if (barMem) barMem.style.width = data.mem.percent + '%';
                
                document.getElementById('stat-disk').textContent = data.disk.used + ' / ' + data.disk.total;
                const barDisk = document.getElementById('bar-disk');
                if (barDisk) barDisk.style.width = data.disk.percent + '%';
                
                document.getElementById('stat-temp').textContent = data.temp;
                document.getElementById('stat-uptime').textContent = data.uptime;
            } catch (e) {
                console.error(e);
            }
        }
        setInterval(updateStats, 2500);
        updateStats();
      })();
    </script>
    `;

    let html = rawHtml;
    html = html.replace('</head>', pwaMeta + '</head>');
    html = html.replace('</body>', pwaBody + '</body>');
    return html;
}

// ─────────── System Info Helpers ───────────
let lastCpuTime = { idle: 0, total: 0 };
function getCpuUsage(callback) {
    fs.readFile('/proc/stat', 'utf8', (err, data) => {
        if (err) return callback(0);
        const firstLine = data.split('\n')[0];
        const parts = firstLine.split(/\s+/).slice(1).map(Number);
        const idle = parts[3] + parts[4]; // idle + iowait
        const total = parts.reduce((a, b) => a + b, 0);
        
        const diffIdle = idle - lastCpuTime.idle;
        const diffTotal = total - lastCpuTime.total;
        lastCpuTime = { idle, total };
        
        if (diffTotal === 0) return callback(0);
        const usage = Math.round(100 * (1 - diffIdle / diffTotal));
        callback(usage);
    });
}

function getMemInfo(callback) {
    fs.readFile('/proc/meminfo', 'utf8', (err, data) => {
        if (err) return callback({ total: 0, used: 0, percent: 0 });
        const lines = data.split('\n');
        let total = 0, available = 0;
        for (const line of lines) {
            if (line.startsWith('MemTotal:')) {
                total = parseInt(line.match(/\d+/)[0], 10);
            } else if (line.startsWith('MemAvailable:')) {
                available = parseInt(line.match(/\d+/)[0], 10);
            }
        }
        const used = total - available;
        const percent = total > 0 ? Math.round((used / total) * 100) : 0;
        callback({
            total: Math.round(total / 1024),
            used: Math.round(used / 1024),
            percent
        });
    });
}

function getSystemStatus(callback) {
    getCpuUsage((cpu) => {
        getMemInfo((mem) => {
            exec("df -h / | tail -n 1", (err, stdout) => {
                let disk = { total: 'N/A', used: 'N/A', percent: 0 };
                if (!err && stdout) {
                    const parts = stdout.trim().split(/\s+/);
                    if (parts.length >= 5) {
                        disk = {
                            total: parts[1],
                            used: parts[2],
                            percent: parseInt(parts[4].replace('%', ''), 10)
                        };
                    }
                }
                exec("uptime -p", (errUptime, stdoutUptime) => {
                    const uptime = errUptime ? 'N/A' : stdoutUptime.trim().replace(/^up /, '');
                    let temp = 'N/A';
                    try {
                        if (fs.existsSync('/sys/class/thermal/thermal_zone0/temp')) {
                            const tempMillidegrees = parseInt(fs.readFileSync('/sys/class/thermal/thermal_zone0/temp', 'utf8').trim(), 10);
                            temp = Math.round(tempMillidegrees / 1000) + '°C';
                        }
                    } catch (e) {}
                    
                    callback({
                        cpu,
                        mem,
                        disk,
                        uptime,
                        temp
                    });
                });
            });
        });
    });
}

// ─────────── HTTP Request Handler ───────────
function getServerUrl(req) {
    const proto = req.headers['x-forwarded-proto'] || (useSsl ? 'https' : 'http');
    const host  = req.headers['x-forwarded-host'] || req.headers['host'] || `localhost:${port}`;
    if (host.includes('trycloudflare.com') || host.includes(':')) {
        return `${proto}://${host}`;
    }
    return `${proto}://${host}:${port}`;
}

function parseCookies(req) {
    const out = {};
    const h = req.headers['cookie'] || '';
    h.split(';').forEach(part => {
        const [k, ...v] = part.trim().split('=');
        if (k) out[k.trim()] = v.join('=').trim();
    });
    return out;
}

function parseBody(req, cb) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => cb(body));
}

function handleRequest(req, res) {
    const reqUrl = url.parse(req.url, true);
    const path_ = reqUrl.pathname;

    // ── Static assets de PWA ──────────────────────────────
    if (path_ === '/manifest.json') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
        res.end(JSON.stringify(manifest));
        return;
    }
    if (path_ === '/sw.js') {
        res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-cache' });
        res.end(serviceWorkerCode);
        return;
    }
    if (path_ === '/icon-192.png') {
        if (fs.existsSync(icon192Path)) {
            res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'max-age=86400' });
            fs.createReadStream(icon192Path).pipe(res);
        } else { res.writeHead(404); res.end(); }
        return;
    }
    if (path_ === '/icon-512.png') {
        if (fs.existsSync(icon512Path)) {
            res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'max-age=86400' });
            fs.createReadStream(icon512Path).pipe(res);
        } else { res.writeHead(404); res.end(); }
        return;
    }

    // ── Endpoint QR Code PNG (genera via Python) ──────────
    if (path_ === '/qr') {
        const data = reqUrl.query.data || '';
        const size = parseInt(reqUrl.query.size || '200');
        generateQRPng(data, size, (tmpFile) => {
            if (!tmpFile) {
                res.writeHead(500); res.end(); return;
            }
            res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'max-age=3600' });
            fs.createReadStream(tmpFile).on('end', () => {
                try { fs.unlinkSync(tmpFile); } catch(e) {}
            }).pipe(res);
        });
        return;
    }

    // ── Auth: login POST ──────────────────────────────────
    if (path_ === '/auth/login' && req.method === 'POST') {
        parseBody(req, (body) => {
            const params = new URLSearchParams(body);
            const totp = params.get('totp') || '';
            if (verifyTotp(totp)) {
                const token = createSession();
                res.writeHead(302, {
                    'Set-Cookie': `tsession=${token}; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL/1000}; Path=/`,
                    'Location': '/'
                });
                res.end();
            } else {
                const serverUrl = getServerUrl(req);
                const totpUri = `otpauth://totp/terminalout?secret=${TOTP_SECRET}&issuer=Local%20Terminal`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(buildLoginPage('Código incorrecto. Intenta de nuevo.', serverUrl, totpUri));
            }
        });
        return;
    }

    // ── Auth: logout ─────────────────────────────────────
    if (path_ === '/auth/logout') {
        const token = getSessionToken(req);
        if (token) sessions.delete(token);
        res.writeHead(302, {
            'Set-Cookie': 'tsession=; HttpOnly; Max-Age=0; Path=/',
            'Location': '/'
        });
        res.end();
        return;
    }

    // ── Verificar sesión ─────────────────────────────────
    const token = getSessionToken(req);
    if (!isValidSession(token)) {
        const serverUrl = getServerUrl(req);
        const totpUri = `otpauth://totp/terminalout?secret=${TOTP_SECRET}&issuer=Local%20Terminal`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildLoginPage(null, serverUrl, totpUri));
        return;
    }

    // ── Endpoint API: Obtener última captura (Host) ───────
    if (path_ === '/api/last-screenshot') {
        const last = getLatestScreenshot();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ path: last || '' }));
        return;
    }

    // ── Endpoint API: Obtener estado del sistema ──────────
    if (path_ === '/api/system-status') {
        getSystemStatus((status) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(status));
        });
        return;
    }

    // ── Endpoint API: Listar Archivos ─────────────────────
    if (path_ === '/api/files/list') {
        const targetDir = reqUrl.query.path || '/home/dxdx';
        fs.readdir(targetDir, { withFileTypes: true }, (err, files) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
                return;
            }
            const list = files.map(f => {
                let size = 0;
                try {
                    if (f.isFile()) {
                        size = fs.statSync(path.join(targetDir, f.name)).size;
                    }
                } catch(e) {}
                return {
                    name: f.name,
                    isDir: f.isDirectory(),
                    size: size
                };
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ currentPath: targetDir, files: list }));
        });
        return;
    }

    // ── Endpoint API: Descargar/Ver Archivo ────────────────
    if (path_ === '/api/files/view') {
        const filePath = reqUrl.query.path;
        if (!filePath || !fs.existsSync(filePath)) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end("File not found");
            return;
        }
        const stat = fs.statSync(filePath);
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': stat.size,
            'Content-Disposition': `attachment; filename="${encodeURIComponent(path.basename(filePath))}"`
        });
        fs.createReadStream(filePath).pipe(res);
        return;
    }

    // ── Endpoint API: Listar Procesos ─────────────────────
    if (path_ === '/api/system-processes') {
        exec("ps -aux --sort=-%cpu | head -n 25", (err, stdout) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
                return;
            }
            const lines = stdout.trim().split('\n');
            const list = lines.slice(1).map(line => {
                const parts = line.split(/\s+/);
                return {
                    user: parts[0],
                    pid: parts[1],
                    cpu: parts[2],
                    mem: parts[3],
                    command: parts.slice(10).join(' ')
                };
            }).filter(p => p.pid && p.command);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(list));
        });
        return;
    }

    // ── Endpoint API: Matar Proceso ───────────────────────
    if (path_ === '/api/process/kill' && req.method === 'POST') {
        parseBody(req, (body) => {
            const params = new URLSearchParams(body);
            const pid = parseInt(params.get('pid'), 10);
            if (pid) {
                exec(`kill -9 ${pid}`, (err) => {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: !err }));
                });
            } else {
                res.writeHead(400); res.end("Missing PID");
            }
        });
        return;
    }

    // ── Proxy a ttyd (usuario autenticado) ───────────────
    const proxyHeaders = { ...req.headers };
    delete proxyHeaders['accept-encoding'];
    delete proxyHeaders['cookie'];
    proxyHeaders['host'] = `127.0.0.1:${ttydPort}`;

    if (path_ === '/' || path_ === '/index.html' || reqUrl.pathname.startsWith('/?')) {
        const proxyReq = http.request({
            host: '127.0.0.1', port: ttydPort,
            path: req.url, method: req.method, headers: proxyHeaders
        }, (proxyRes) => {
            let data = '';
            proxyRes.on('data', chunk => data += chunk);
            proxyRes.on('end', () => {
                const ct = proxyRes.headers['content-type'] || '';
                if (ct.includes('text/html')) {
                    const modified = injectHTML(data);
                    const headers = { ...proxyRes.headers };
                    delete headers['content-length'];
                    res.writeHead(proxyRes.statusCode, headers);
                    res.end(modified);
                } else {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    res.end(data);
                }
            });
        });
        proxyReq.on('error', () => { res.writeHead(502); res.end(); });
        req.pipe(proxyReq);
        return;
    }

    // Proxy genérico
    const proxyReq = http.request({
        host: '127.0.0.1', port: ttydPort,
        path: req.url, method: req.method, headers: proxyHeaders
    }, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    proxyReq.on('error', () => { res.writeHead(502); res.end(); });
    req.pipe(proxyReq);
}

// ─────────── Servidor Principal ───────────
let server;
if (useSsl && certPath && keyPath) {
    server = https.createServer({
        cert: fs.readFileSync(certPath),
        key:  fs.readFileSync(keyPath)
    }, handleRequest);
} else {
    server = http.createServer(handleRequest);
}

// ─────────── WebSocket Proxy (solo si hay sesión) ───────────
server.on('upgrade', (req, socket, head) => {
    // Verificar sesión en la cookie del upgrade
    const cookies = parseCookies(req);
    const token = cookies['tsession'];
    if (!isValidSession(token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }

    const upHeaders = { ...req.headers };
    upHeaders['host']   = `127.0.0.1:${ttydPort}`;
    upHeaders['origin'] = `http://127.0.0.1:${ttydPort}`;

    const target = net.connect(ttydPort, '127.0.0.1', () => {
        let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
        for (const [k, v] of Object.entries(upHeaders)) {
            raw += `${k}: ${v}\r\n`;
        }
        raw += '\r\n';
        target.write(raw);
        target.write(head);
        socket.pipe(target);
        target.pipe(socket);
    });
    target.on('error', () => socket.end());
    socket.on('error', () => target.end());
});

server.listen(port, '0.0.0.0', () => {
    console.log(`Proxy server listening on port ${port}`);
});
