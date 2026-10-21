// ============================================================
// CyberScan AI — Frontend Logic (Backend-integrated)
// ============================================================
// Backend Python harus berjalan di http://127.0.0.1:5000
// Jalankan: python app.py
// ============================================================

const API_BASE = 'http://127.0.0.1:5000';

// ---------- DOM ----------
const chatArea    = document.getElementById('chatArea');
const messagesEl  = document.getElementById('messages');
const welcomeEl   = document.getElementById('welcome');
const userInput   = document.getElementById('userInput');
const sendBtn     = document.getElementById('sendBtn');
const newChatBtn  = document.getElementById('newChatBtn');
const sidebar     = document.getElementById('sidebar');
const toggleSidebar = document.getElementById('toggleSidebar');
const openSidebar   = document.getElementById('openSidebar');
const historyList   = document.getElementById('historyList');
const serverStatus  = document.getElementById('serverStatus');
const healthBtn     = document.getElementById('healthBtn');

let isProcessing = false;
let history = []; // [{id, title, target, scanType, ts}]

// ============================================================
// SIDEBAR TOGGLE
// ============================================================
toggleSidebar.addEventListener('click', () => {
  sidebar.classList.add('hidden');
  openSidebar.style.display = 'flex';
});

openSidebar.addEventListener('click', () => {
  sidebar.classList.remove('hidden');
  openSidebar.style.display = 'none';
});

// ============================================================
// AUTO-RESIZE TEXTAREA
// ============================================================
userInput.addEventListener('input', () => {
  userInput.style.height = 'auto';
  userInput.style.height = Math.min(userInput.scrollHeight, 200) + 'px';
});

// ============================================================
// ENTER UNTUK KIRIM
// ============================================================
userInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

sendBtn.addEventListener('click', sendMessage);

// ============================================================
// SUGGESTION CARDS
// ============================================================
document.querySelectorAll('.suggestion-card').forEach(card => {
  card.addEventListener('click', () => {
    userInput.value = card.dataset.prompt;
    userInput.style.height = 'auto';
    userInput.style.height = Math.min(userInput.scrollHeight, 200) + 'px';
    sendMessage();
  });
});

// ============================================================
// NEW CHAT
// ============================================================
newChatBtn.addEventListener('click', () => {
  messagesEl.innerHTML = '';
  welcomeEl.style.display = 'block';
  userInput.value = '';
  userInput.style.height = 'auto';
  userInput.focus();
});

// ============================================================
// HEALTH CHECK
// ============================================================
async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/health`, { method: 'GET' });
    if (res.ok) {
      serverStatus.textContent = '● Online';
      serverStatus.style.color = '#10b981';
      serverStatus.style.background = '#ecfdf5';
      return true;
    }
    throw new Error(`HTTP ${res.status}`);
  } catch {
    serverStatus.textContent = '● Offline';
    serverStatus.style.color = '#ef4444';
    serverStatus.style.background = '#fee2e2';
    return false;
  }
}

healthBtn.addEventListener('click', async () => {
  serverStatus.textContent = '● Mengecek...';
  const ok = await checkHealth();
  addMessage('bot', ok
    ? '✅ Backend terhubung di <code>' + API_BASE + '</code>.'
    : '❌ Backend tidak merespons. Jalankan <code>python app.py</code> di folder backend.',
    true);
});

// Panggil health check saat load + interval
checkHealth();
setInterval(checkHealth, 30000);

// ============================================================
// UTILITY
// ============================================================
function scrollToBottom() {
  chatArea.scrollTop = chatArea.scrollHeight;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatText(text) {
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>');
}

// ============================================================
// ADD MESSAGE
// ============================================================
function addMessage(role, content, isHTML = false) {
  welcomeEl.style.display = 'none';

  const msg = document.createElement('div');
  msg.className = `message ${role}`;

  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  avatar.textContent = role === 'user' ? '👤' : '🛡️';

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.innerHTML = isHTML ? content : formatText(content);

  msg.appendChild(avatar);
  msg.appendChild(bubble);
  messagesEl.appendChild(msg);
  scrollToBottom();
  return bubble;
}

// ============================================================
// TYPING INDICATOR
// ============================================================
function showTyping(label = 'Menganalisis...') {
  const msg = document.createElement('div');
  msg.className = 'message bot';
  msg.id = 'typing';
  msg.innerHTML = `
    <div class="avatar">🛡️</div>
    <div class="bubble">
      <div class="typing-indicator">
        <span></span><span></span><span></span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:6px;">${label}</div>
    </div>
  `;
  messagesEl.appendChild(msg);
  scrollToBottom();
  return msg;
}

function hideTyping() {
  const t = document.getElementById('typing');
  if (t) t.remove();
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ============================================================
// HISTORY (in-memory)
// ============================================================
function pushHistory(entry) {
  history.unshift(entry);
  renderHistory();
}

function renderHistory() {
  historyList.innerHTML = '';
  history.slice(0, 20).forEach(item => {
    const el = document.createElement('div');
    el.className = 'history-item';
    el.dataset.id = item.id;
    el.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 8v4l3 3M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <span title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</span>
    `;
    historyList.appendChild(el);
  });
}

// ============================================================
// MAIN: SEND MESSAGE
// ============================================================
async function sendMessage() {
  const text = userInput.value.trim();
  if (!text || isProcessing) return;

  isProcessing = true;
  sendBtn.disabled = true;

  addMessage('user', text);
  userInput.value = '';
  userInput.style.height = 'auto';

  const typing = showTyping('Memproses pemindaian...');

  // Simulasi delay minimal untuk UX
  await sleep(300);
  hideTyping();

  const responseHTML = await analyzeRequest(text);
  addMessage('bot', responseHTML, true);

  // Simpan ke history
  const targetMatch = text.match(/([a-z0-9-]+\.)+[a-z]{2,}|(\d{1,3}\.){3}\d{1,3}/i);
  if (targetMatch) {
    pushHistory({
      id: Date.now(),
      title: `${targetMatch[0]} — ${detectScanType(text)}`,
      ts: new Date().toISOString(),
    });
  }

  isProcessing = false;
  sendBtn.disabled = false;
  userInput.focus();
}

// ============================================================
// DETEKSI SCAN TYPE (untuk label history)
// ============================================================
function detectScanType(text) {
  const lower = text.toLowerCase();
  if (/ssl|tls|sertifikat|certificate/.test(lower)) return 'SSL';
  if (/port|nmap/.test(lower)) return 'Port';
  if (/header|csp|hsts/.test(lower)) return 'Header';
  if (/dns|spf|dkim|dmarc/.test(lower)) return 'DNS';
  if (/blacklist|malware|phishing|reputasi/.test(lower)) return 'Blacklist';
  if (/kerentanan|vulnerability|owasp|xss|sql/.test(lower)) return 'OWASP';
  return 'Umum';
}

// ============================================================
// ANALYZE REQUEST — Call Backend
// ============================================================
async function analyzeRequest(text) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 detik

    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      let errMsg = `HTTP ${res.status}`;
      try {
        const err = await res.json();
        errMsg = err.error || errMsg;
      } catch {}
      return renderError(errMsg);
    }

    const json = await res.json();
    return renderResult(json);

  } catch (e) {
    if (e.name === 'AbortError') {
      return renderError('⏱️ Permintaan timeout (>60 detik). Coba target lain atau ulangi.');
    }
    return renderError(
      `Tidak dapat menghubungi backend di <code>${API_BASE}</code>.<br><br>` +
      `Pastikan:<br>` +
      `1. Backend berjalan: <code>python app.py</code><br>` +
      `2. Alamat sesuai (<code>API_BASE</code> di script.js)<br>` +
      `3. CORS diizinkan (sudah di-enable di app.py)<br><br>` +
      `<em>Detail: ${e.message}</em>`
    );
  }
}

// ============================================================
// RENDER HELPERS
// ============================================================
function renderError(msg) {
  return `<h3>❌ Terjadi Kesalahan</h3><p>${msg}</p>`;
}

function badge(level) {
  const map = {
    ok:      'badge ok',
    info:    'badge info',
    warning: 'badge warn',
    warn:    'badge warn',
    danger:  'badge danger',
    clean:   'badge ok',
    unknown: 'badge info',
  };
  const label = {
    ok: 'OK', info: 'INFO', warning: 'WARN', warn: 'WARN',
    danger: 'RISK', clean: 'BERSIH', unknown: '?',
  }[level] || String(level).toUpperCase();
  return `<span class="${map[level] || 'badge info'}">${label}</span>`;
}

function renderFindings(findings = []) {
  if (!findings.length) return '';
  let html = '<h3>⚠️ Temuan</h3><ul>';
  for (const f of findings) {
    html += `<li>${badge(f.level)} ${escapeHtml(f.message)}</li>`;
  }
  html += '</ul>';
  return html;
}

function renderRecommendations(recs = []) {
  if (!recs.length) return '';
  let html = '<h3>💡 Rekomendasi</h3><ol>';
  for (const r of recs) html += `<li>${escapeHtml(r)}</li>`;
  html += '</ol>';
  return html;
}

function scanTable(rows) {
  let html = '';
  for (const [k, v] of rows) {
    html += `<div class="scan-row"><span class="label">${escapeHtml(String(k))}</span><span class="value">${v}</span></div>`;
  }
  return html;
}

// ============================================================
// RENDER RESULT ROUTER
// ============================================================
function renderResult({ type, data }) {
  if (type === 'help') {
    return `
      <h3>👋 Saya siap membantu pemindaian keamanan</h3>
      <p>Ketik target + jenis scan. Contoh:</p>
      <ul>
        <li><code>Pindai SSL example.com</code></li>
        <li><code>Scan port pada example.com</code></li>
        <li><code>Analisis header HTTP example.com</code></li>
        <li><code>Cek DNS example.com</code></li>
        <li><code>Periksa blacklist example.com</code></li>
        <li><code>Cek kerentanan OWASP example.com</code></li>
      </ul>
      <p style="font-size:13px;color:var(--text-secondary);margin-top:12px;">
        ⚠️ Hanya pindai aset yang Anda miliki atau memiliki izin eksplisit.
      </p>`;
  }

  if (type === 'ssl')       return renderSSL(data);
  if (type === 'port')      return renderPort(data);
  if (type === 'header')    return renderHeader(data);
  if (type === 'dns')       return renderDNS(data);
  if (type === 'blacklist') return renderBlacklist(data);
  if (type === 'vuln')      return renderVuln(data);
  return renderError('Tipe scan tidak dikenal.');
}

// ============================================================
// RENDER: SSL
// ============================================================
function renderSSL(d) {
  if (!d.reachable) {
    return `<h3>🔒 Pemindaian SSL/TLS</h3>
      <p><strong>Target:</strong> <code>${escapeHtml(d.target)}</code></p>
      ${renderFindings(d.findings)}`;
  }

  const c = d.certificate || {};
  return `
    <h3>🔒 Laporan Pemindaian SSL/TLS</h3>
    <p><strong>Target:</strong> <code>${escapeHtml(d.target)}:${d.port}</code></p>
    <div class="scan-result">
      <div class="scan-header">📊 Hasil</div>
      ${scanTable([
        ['Skor Keamanan', `${badge(d.score >= 80 ? 'ok' : d.score >= 50 ? 'warning' : 'danger')} ${d.score}/100`],
        ['Protokol',    escapeHtml((d.protocols || []).join(', ') || '-')],
        ['Cipher Suite', escapeHtml(d.cipher || '-')],
        ['Subject CN',  escapeHtml(c.subject_cn || '-')],
        ['Issuer',      escapeHtml(c.issuer_cn || '-')],
        ['Berlaku Hingga', escapeHtml(c.not_after || '-')],
        ['Sisa Hari',   c.days_left != null ? `${c.days_left} hari` : '-'],
        ['SHA-256',     `<code style="font-size:11px">${escapeHtml((c.fingerprint_sha256 || '').slice(0, 32))}…</code>`],
      ])}
    </div>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// RENDER: PORT
// ============================================================
function renderPort(d) {
  let portsHtml = '';
  if (d.open_ports && d.open_ports.length) {
    const riskyPorts = [3306, 6379, 27017, 9200, 1433, 3389, 23, 21, 445];
    for (const p of d.open_ports) {
      const risky = riskyPorts.includes(p.port);
      portsHtml += `<div class="scan-row"><span class="label">Port ${p.port} (${escapeHtml(p.service)})</span><span class="value">${badge(risky ? 'danger' : 'ok')} Terbuka</span></div>`;
    }
  } else {
    portsHtml = `<div class="scan-row"><span class="label">Tidak ada port umum terbuka</span><span class="value">${badge('ok')}</span></div>`;
  }

  return `
    <h3>🔍 Laporan Pemindaian Port</h3>
    <p><strong>Target:</strong> <code>${escapeHtml(d.target)}</code> · ${d.scanned} port dipindai</p>
    <div class="scan-result">
      <div class="scan-header">📡 Port Terbuka</div>
      ${portsHtml}
    </div>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// RENDER: HEADERS
// ============================================================
function renderHeader(d) {
  const h = d.headers || {};
  return `
    <h3>📋 Analisis Header Keamanan HTTP</h3>
    <p><strong>URL:</strong> <code>${escapeHtml(d.url || d.target)}</code> · Status <strong>${d.status_code ?? '-'}</strong></p>
    <div class="scan-result">
      <div class="scan-header">🛡️ Skor Header: ${badge(d.score >= 70 ? 'ok' : d.score >= 40 ? 'warning' : 'danger')} ${d.score}/100</div>
      ${scanTable([
        ['Strict-Transport-Security', h['Strict-Transport-Security'] ? badge('ok') : badge('danger')],
        ['Content-Security-Policy',   h['Content-Security-Policy']   ? badge('ok') : badge('danger')],
        ['X-Frame-Options',           h['X-Frame-Options']           ? badge('ok') : badge('warning')],
        ['X-Content-Type-Options',    h['X-Content-Type-Options']    ? badge('ok') : badge('warning')],
        ['Referrer-Policy',           h['Referrer-Policy']           ? badge('ok') : badge('warning')],
        ['Permissions-Policy',        h['Permissions-Policy']        ? badge('ok') : badge('warning')],
      ])}
    </div>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// RENDER: DNS
// ============================================================
function renderDNS(d) {
  const ea = d.email_auth || {};
  const recs = d.records || {};
  return `
    <h3>🌐 Audit Keamanan DNS</h3>
    <p><strong>Domain:</strong> <code>${escapeHtml(d.target)}</code></p>
    <div class="scan-result">
      <div class="scan-header">📧 Email Authentication</div>
      ${scanTable([
        ['SPF',   ea.SPF   ? badge('ok') + ' ' + escapeHtml(ea.SPF)   : badge('danger')],
        ['DMARC', ea.DMARC ? badge('ok') + ' ' + escapeHtml(ea.DMARC) : badge('danger')],
        ['DKIM',  ea.DKIM  ? badge('ok') + ' ' + escapeHtml(ea.DKIM)  : badge('warning')],
        ['DNSSEC', ea.DNSSEC ? badge('ok') : badge('warning')],
      ])}
    </div>
    <div class="scan-result">
      <div class="scan-header">📡 Record DNS</div>
      ${scanTable([
        ['A',    escapeHtml((recs.A || []).join(', ')    || '-')],
        ['AAAA', escapeHtml((recs.AAAA || []).join(', ') || '-')],
        ['MX',   escapeHtml((recs.MX || []).join(', ')   || '-')],
        ['NS',   escapeHtml((recs.NS || []).join(', ')   || '-')],
      ])}
    </div>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// RENDER: BLACKLIST
// ============================================================
function renderBlacklist(d) {
  let sources = '';
  for (const [k, v] of Object.entries(d.sources || {})) {
    sources += `<div class="scan-row"><span class="label">${escapeHtml(k)}</span><span class="value">${escapeHtml(String(v))}</span></div>`;
  }
  return `
    <h3>🦠 Pemeriksaan Reputasi & Blacklist</h3>
    <p><strong>Target:</strong> <code>${escapeHtml(d.target)}</code></p>
    <div class="scan-result">
      <div class="scan-header">🔍 Sumber Database</div>
      ${sources}
    </div>
    <p style="margin-top:10px;"><strong>Verdict:</strong> ${badge(d.verdict)}</p>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// RENDER: VULN (OWASP)
// ============================================================
function renderVuln(d) {
  let cats = '';
  for (const [k, v] of Object.entries(d.categories || {})) {
    cats += `<div class="scan-row"><span class="label">${escapeHtml(k)}</span><span class="value">${badge(v)}</span></div>`;
  }
  return `
    <h3>⚠️ Pemindaian Kerentanan (OWASP Top 10)</h3>
    <p><strong>Target:</strong> <code>${escapeHtml(d.target)}</code></p>
    <div class="scan-result">
      <div class="scan-header">Risk Score: ${badge(d.risk_score >= 30 ? 'danger' : d.risk_score >= 10 ? 'warning' : 'ok')} ${d.risk_score}/100</div>
      ${cats}
    </div>
    ${renderFindings(d.findings)}
    ${renderRecommendations(d.recommendations)}
  `;
}

// ============================================================
// INIT
// ============================================================
userInput.focus();