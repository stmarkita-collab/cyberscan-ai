// ============================================================
// CyberScan AI - Logika Aplikasi
// ============================================================

const chatArea = document.getElementById('chatArea');
const messagesEl = document.getElementById('messages');
const welcomeEl = document.getElementById('welcome');
const userInput = document.getElementById('userInput');
const sendBtn = document.getElementById('sendBtn');
const newChatBtn = document.getElementById('newChatBtn');
const sidebar = document.getElementById('sidebar');
const toggleSidebar = document.getElementById('toggleSidebar');
const openSidebar = document.getElementById('openSidebar');

let isProcessing = false;

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
// ENTER UNTUK KIRIM (Shift+Enter untuk baris baru)
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
// UTILITY: SCROLL KE BAWAH
// ============================================================
function scrollToBottom() {
  chatArea.scrollTop = chatArea.scrollHeight;
}

// ============================================================
// UTILITY: FORMAT MARKDOWN SEDERHANA
// ============================================================
function formatText(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
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

  if (isHTML) {
    bubble.innerHTML = content;
  } else {
    bubble.innerHTML = formatText(content);
  }

  msg.appendChild(avatar);
  msg.appendChild(bubble);
  messagesEl.appendChild(msg);
  scrollToBottom();
  return bubble;
}

// ============================================================
// TYPING INDICATOR
// ============================================================
function showTyping() {
  const msg = document.createElement('div');
  msg.className = 'message bot';
  msg.id = 'typing';
  msg.innerHTML = `
    <div class="avatar">🛡️</div>
    <div class="bubble">
      <div class="typing-indicator">
        <span></span><span></span><span></span>
      </div>
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

// ============================================================
// DELAY HELPER
// ============================================================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ============================================================
// MAIN: SEND MESSAGE
// ============================================================
async function sendMessage() {
  const text = userInput.value.trim();
  if (!text || isProcessing) return;

  isProcessing = true;
  sendBtn.disabled = true;

  // Tambahkan pesan user
  addMessage('user', text);
  userInput.value = '';
  userInput.style.height = 'auto';

  // Tampilkan typing
  const typing = showTyping();
  await sleep(800 + Math.random() * 600);
  hideTyping();

  // Proses & hasilkan respons
  const response = await analyzeRequest(text);
  addMessage('bot', response, true);

  isProcessing = false;
  sendBtn.disabled = false;
  userInput.focus();
}

// ============================================================
// ANALISIS REQUEST & GENERATE RESPONSE
// ============================================================
async function analyzeRequest(text) {
  const lower = text.toLowerCase();

  // Deteksi jenis pemindaian
  if (/ssl|tls|sertifikat|certificate/.test(lower)) {
    return generateSSLReport(extractDomain(text));
  }
  if (/port|port scan|nmap/.test(lower)) {
    return generatePortReport(extractIP(text));
  }
  if (/header|http header|csp|hsts/.test(lower)) {
    return generateHeaderReport(extractDomain(text));
  }
  if (/dns|spf|dkim|dmarc/.test(lower)) {
    return generateDNSReport(extractDomain(text));
  }
  if (/blacklist|malware|phishing|reputasi/.test(lower)) {
    return generateBlacklistReport(extractDomain(text));
  }
  if (/kerentanan|vulnerability|owasp|xss|sql/.test(lower)) {
    return generateVulnReport(extractDomain(text));
  }

  // Default: berikan panduan
  return generateHelpResponse();
}

// ============================================================
// EXTRACT TARGET
// ============================================================
function extractDomain(text) {
  const domainRegex = /([a-z0-9-]+\.)+[a-z]{2,}/i;
  const match = text.match(domainRegex);
  return match ? match[0] : 'example.com';
}

function extractIP(text) {
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const match = text.match(ipRegex);
  return match ? match[0] : '192.168.1.1';
}

// ============================================================
// REPORT GENERATORS (SIMULASI)
// ============================================================

function generateSSLReport(domain) {
  const score = 85 + Math.floor(Math.random() * 12);
  return `
<h3>🔒 Laporan Pemindaian SSL/TLS</h3>
<p><strong>Target:</strong> <code>${domain}</code></p>
<p><strong>Status Pemindaian:</strong> ✅ Selesai</p>

<div class="scan-result">
  <div class="scan-header">📊 Ringkasan Hasil</div>
  <div class="scan-row"><span class="label">Skor Keamanan</span><span class="value"><span class="badge ok">${score}/100</span></span></div>
  <div class="scan-row"><span class="label">Protokol</span><span class="value">TLS 1.3</span></div>
  <div class="scan-row"><span class="label">Sertifikat</span><span class="value"><span class="badge ok">Valid</span></span></div>
  <div class="scan-row"><span class="label">Penerbit</span><span class="value">Let's Encrypt</span></div>
  <div class="scan-row"><span class="label">Kedaluwarsa</span><span class="value">${getFutureDate(75)}</span></div>
  <div class="scan-row"><span class="label">Cipher Suite</span><span class="value">TLS_AES_256_GCM_SHA384</span></div>
  <div class="scan-row"><span class="label">Forward Secrecy</span><span class="value"><span class="badge ok">Aktif</span></span></div>
</div>

<h3>⚠️ Temuan</h3>
<ul>
  <li><span class="badge warn">MENENGAH</span> Protokol TLS 1.0 masih diaktifkan — sebaiknya dinonaktifkan.</li>
  <li><span class="badge info">INFO</span> Sertifikat akan kedaluwarsa dalam 75 hari. Jadwalkan pembaruan.</li>
</ul>

<h3>💡 Rekomendasi</h3>
<ol>
  <li>Nonaktifkan TLS 1.0 dan TLS 1.1.</li>
  <li>Aktifkan HSTS dengan <code>max-age=31536000</code>.</li>
  <li>Gunakan OCSP stapling untuk performa & keamanan lebih baik.</li>
</ol>
  `;
}

function generatePortReport(ip) {
  return `
<h3>🔍 Laporan Pemindaian Port</h3>
<p><strong>Target:</strong> <code>${ip}</code></p>
<p><strong>Metode:</strong> TCP SYN Scan (simulasi)</p>

<div class="scan-result">
  <div class="scan-header">📡 Port Terbuka Terdeteksi</div>
  <div class="scan-row"><span class="label">Port 22 (SSH)</span><span class="value"><span class="badge warn">Terbuka</span></span></div>
  <div class="scan-row"><span class="label">Port 80 (HTTP)</span><span class="value"><span class="badge warn">Terbuka</span></span></div>
  <div class="scan-row"><span class="label">Port 443 (HTTPS)</span><span class="value"><span class="badge ok">Terbuka & Aman</span></span></div>
  <div class="scan-row"><span class="label">Port 3306 (MySQL)</span><span class="value"><span class="badge danger">Terbuka!</span></span></div>
  <div class="scan-row"><span class="label">Port 8080 (HTTP-alt)</span><span class="value"><span class="badge warn">Terbuka</span></span></div>
</div>

<h3>🚨 Risiko Kritis</h3>
<ul>
  <li><strong>Port 3306 (MySQL)</strong> terbuka ke publik — database berpotensi diakses dari luar. <span class="badge danger">KRITIS</span></li>
  <li><strong>Port 22 (SSH)</strong> terekspos — rentan brute force. <span class="badge warn">TINGGI</span></li>
</ul>

<h3>💡 Rekomendasi</h3>
<ol>
  <li>Blokir port 3306 dari akses publik menggunakan firewall.</li>
  <li>Aktifkan autentikasi berbasis kunci SSH & fail2ban.</li>
  <li>Pertimbangkan penggunaan VPN untuk akses administratif.</li>
</ol>
  `;
}

function generateHeaderReport(domain) {
  return `
<h3>📋 Analisis Header Keamanan HTTP</h3>
<p><strong>Target:</strong> <code>${domain}</code></p>

<div class="scan-result">
  <div class="scan-header">🛡️ Header Keamanan</div>
  <div class="scan-row"><span class="label">Strict-Transport-Security</span><span class="value"><span class="badge ok">Ada</span></span></div>
  <div class="scan-row"><span class="label">Content-Security-Policy</span><span class="value"><span class="badge danger">Tidak Ada</span></span></div>
  <div class="scan-row"><span class="label">X-Frame-Options</span><span class="value"><span class="badge ok">DENY</span></span></div>
  <div class="scan-row"><span class="label">X-Content-Type-Options</span><span class="value"><span class="badge ok">nosniff</span></span></div>
  <div class="scan-row"><span class="label">Referrer-Policy</span><span class="value"><span class="badge ok">strict-origin</span></span></div>
  <div class="scan-row"><span class="label">Permissions-Policy</span><span class="value"><span class="badge warn">Sebagian</span></span></div>
</div>

<h3>⚠️ Temuan Utama</h3>
<ul>
  <li><strong>CSP tidak ditemukan</strong> — situs rentan terhadap serangan XSS. <span class="badge danger">TINGGI</span></li>
  <li><strong>Permissions-Policy</strong> belum lengkap — beberapa API browser tidak dibatasi.</li>
</ul>

<h3>💡 Contoh Implementasi CSP</h3>
<pre><code>Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';</code></pre>
  `;
}

function generateDNSReport(domain) {
  return `
<h3>🌐 Audit Keamanan DNS</h3>
<p><strong>Domain:</strong> <code>${domain}</code></p>

<div class="scan-result">
  <div class="scan-header">📧 Email Authentication</div>
  <div class="scan-row"><span class="label">SPF Record</span><span class="value"><span class="badge ok">Ada (Hard Fail)</span></span></div>
  <div class="scan-row"><span class="label">DKIM</span><span class="value"><span class="badge ok">Dikonfigurasi</span></span></div>
  <div class="scan-row"><span class="label">DMARC Policy</span><span class="value"><span class="badge warn">p=none</span></span></div>
  <div class="scan-row"><span class="label">DNSSEC</span><span class="value"><span class="badge danger">Tidak Aktif</span></span></div>
  <div class="scan-row"><span class="label">CAA Record</span><span class="value"><span class="badge ok">Ada</span></span></div>
</div>

<h3>⚠️ Temuan</h3>
<ul>
  <li><strong>DMARC p=none</strong> — hanya monitoring, tidak memblokir email palsu. <span class="badge warn">MENENGAH</span></li>
  <li><strong>DNSSEC tidak aktif</strong> — rentan DNS spoofing/cache poisoning. <span class="badge warn">MENENGAH</span></li>
</ul>

<h3>💡 Rekomendasi</h3>
<ol>
  <li>Ubah DMARC menjadi <code>p=quarantine</code> atau <code>p=reject</code>.</li>
  <li>Aktifkan DNSSEC pada registrar domain.</li>
  <li>Tambahkan record CAA untuk membatasi penerbit sertifikat.</li>
</ol>
  `;
}

function generateBlacklistReport(domain) {
  return `
<h3>🦠 Pemeriksaan Reputasi & Blacklist</h3>
<p><strong>Domain:</strong> <code>${domain}</code></p>

<div class="scan-result">
  <div class="scan-header">🔍 Hasil Pemeriksaan Database</div>
  <div class="scan-row"><span class="label">Google Safe Browsing</span><span class="value"><span class="badge ok">Bersih</span></span></div>
  <div class="scan-row"><span class="label">PhishTank</span><span class="value"><span class="badge ok">Bersih</span></span></div>
  <div class="scan-row"><span class="label">Spamhaus</span><span class="value"><span class="badge ok">Bersih</span></span></div>
  <div class="scan-row"><span class="label">VirusTotal (domain)</span><span class="value"><span class="badge ok">0/90</span></span></div>
  <div class="scan-row"><span class="label">URLhaus</span><span class="value"><span class="badge ok">Bersih</span></span></div>
</div>

<h3>✅ Kesimpulan</h3>
<p>Tidak ada indikasi blacklist pada domain <code>${domain}</code>. Domain dalam kondisi reputasi baik berdasarkan 5 database utama.</p>

<h3>💡 Tips Berkelanjutan</h3>
<ul>
  <li>Pantau reputasi domain secara berkala (mingguan).</li>
  <li>Pastikan website bebas malware melalui pemindaian rutin.</li>
  <li>Gunakan monitoring uptime + reputasi otomatis.</li>
</ul>
  `;
}

function generateVulnReport(domain) {
  return `
<h3>⚠️ Pemindaian Kerentanan (OWASP Top 10)</h3>
<p><strong>Target:</strong> <code>${domain}</code></p>

<div class="scan-result">
  <div class="scan-header">🛡️ Hasil Kategori OWASP</div>
  <div class="scan-row"><span class="label">A01 - Broken Access Control</span><span class="value"><span class="badge ok">Aman</span></span></div>
  <div class="scan-row"><span class="label">A02 - Cryptographic Failures</span><span class="value"><span class="badge warn">Perhatian</span></span></div>
  <div class="scan-row"><span class="label">A03 - Injection (SQLi/XSS)</span><span class="value"><span class="badge danger">Rentan</span></span></div>
  <div class="scan-row"><span class="label">A04 - Insecure Design</span><span class="value"><span class="badge ok">Aman</span></span></div>
  <div class="scan-row"><span class="label">A05 - Security Misconfiguration</span><span class="value"><span class="badge warn">Perhatian</span></span></div>
  <div class="scan-row"><span class="label">A06 - Vulnerable Components</span><span class="value"><span class="badge warn">Perhatian</span></span></div>
  <div class="scan-row"><span class="label">A07 - Auth Failures</span><span class="value"><span class="badge ok">Aman</span></span></div>
  <div class="scan-row"><span class="label">A08 - Data Integrity</span><span class="value"><span class="badge ok">Aman</span></span></div>
  <div class="scan-row"><span class="label">A09 - Logging Failures</span><span class="value"><span class="badge warn">Perhatian</span></span></div>
  <div class="scan-row"><span class="label">A10 - SSRF</span><span class="value"><span class="badge ok">Aman</span></span></div>
</div>

<h3>🚨 Temuan Prioritas</h3>
<ul>
  <li><strong>A03 - XSS Reflected</strong> terdeteksi pada parameter <code>?q=</code>. <span class="badge danger">KRITIS</span></li>
  <li><strong>A06 - Komponen usang</strong>: jQuery 1.12 ditemukan (versi 2016). <span class="badge warn">TINGGI</span></li>
</ul>

<h3>💡 Langkah Perbaikan</h3>
<ol>
  <li>Terapkan encoding output & Content-Security-Policy untuk mitigasi XSS.</li>
  <li>Perbarui jQuery ke versi ≥ 3.6.</li>
  <li>Lakukan regression test setelah patch.</li>
</ol>
  `;
}

function generateHelpResponse() {
  return `
<h3>👋 Saya siap membantu pemindaian keamanan</h3>
<p>Silakan tentukan target dan jenis pemindaian yang Anda butuhkan. Contoh perintah:</p>
<ul>
  <li><code>Pindai SSL untuk example.com</code></li>
  <li><code>Scan port pada 192.168.1.1</code></li>
  <li><code>Analisis header HTTP domain saya.com</code></li>
  <li><code>Cek DNS untuk example.com</code></li>
  <li><code>Periksa blacklist example.com</code></li>
  <li><code>Cek kerentanan OWASP example.com</code></li>
</ul>
<p>Anda juga bisa memilih kartu pemindaian cepat di halaman awal. 🛡️</p>
  `;
}

// ============================================================
// HELPER: FUTURE DATE
// ============================================================
function getFutureDate(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' });
}

// ============================================================
// INIT
// ============================================================
userInput.focus();
