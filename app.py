"""
CyberScan AI - Backend Server (Single File)
============================================
Menjalankan: python app.py
Akses: http://127.0.0.1:5000

Fitur:
- SSL/TLS scanner (via sslyze + socket)
- Port scanner (via socket)
- HTTP security header analyzer (via requests)
- DNS audit (SPF/DKIM/DMARC/DNSSEC via dnspython)
- Blacklist check (VirusTotal + fallback heuristic)
- OWASP basic checks (header + info disclosure)
- Rate limiting sederhana
- Validasi input (mencegah SSRF ke internal network)
"""

import os
import re
import ssl
import socket
import ipaddress
import time
import hashlib
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import dns.resolver
import dns.exception
import OpenSSL.crypto as crypto

# ============================================================
# KONFIGURASI
# ============================================================
app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

# API key opsional (set via environment variable)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# Port yang umum dipindai (aman, non-intrusive, top 100 umum)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Rate limiting in-memory sederhana: {ip: [timestamps]}
RATE_LIMIT = {}
RATE_WINDOW = 60  # detik
RATE_MAX = 20     # request per window

# ============================================================
# HELPER: RATE LIMIT
# ============================================================
def check_rate_limit(ip: str) -> bool:
    now = time.time()
    timestamps = [t for t in RATE_LIMIT.get(ip, []) if now - t < RATE_WINDOW]
    if len(timestamps) >= RATE_MAX:
        RATE_LIMIT[ip] = timestamps
        return False
    timestamps.append(now)
    RATE_LIMIT[ip] = timestamps
    return True


# ============================================================
# HELPER: VALIDASI TARGET (anti-SSRF)
# ============================================================
def is_safe_target(target: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    Validasi target agar tidak memindai alamat internal / loopback
    kecuali diizinkan eksplisit (localhost testing).
    """
    target = target.strip()

    # Coba parse sebagai IP
    try:
        ip = ipaddress.ip_address(target)
        if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
            return False, "Target IP internal/privat tidak diizinkan untuk alasan keamanan."
        return True, ""
    except ValueError:
        pass

    # Validasi domain
    domain_re = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    if not domain_re.match(target):
        return False, "Format domain tidak valid."

    # Resolve untuk cek apakah mengarah ke IP privat
    try:
        infos = socket.getaddrinfo(target, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local):
                return False, f"Domain '{target}' mengarah ke IP privat/internal. Tidak diizinkan."
    except socket.gaierror:
        return False, f"Domain '{target}' tidak dapat di-resolve."

    return True, ""


def extract_target(text: str) -> str:
    """Ekstrak domain atau IP dari teks user."""
    domain_re = re.compile(r"([a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    ip_match = ip_re.search(text)
    domain_match = domain_re.search(text)

    if domain_match:
        return domain_match.group(0)
    if ip_match:
        return ip_match.group(0)
    return ""


# ============================================================
# SCANNER 1: SSL/TLS
# ============================================================
def scan_ssl(target: str, port: int = 443) -> dict:
    result = {
        "target": target, "port": port, "reachable": False,
        "certificate": {}, "protocols": [], "cipher": "",
        "score": 0, "findings": [], "recommendations": [],
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                result["reachable"] = True
                result["protocols"].append(ssock.version() or "unknown")
                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]

                # Ambil sertifikat (DER)
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                    subject = cert.get_subject()
                    issuer = cert.get_issuer()

                    not_before = cert.get_notBefore().decode()
                    not_after = cert.get_notAfter().decode()
                    nb_dt = datetime.strptime(not_before, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                    na_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (na_dt - now).days

                    result["certificate"] = {
                        "subject_cn": subject.CN or "",
                        "issuer_cn": issuer.CN or "",
                        "not_before": nb_dt.strftime("%Y-%m-%d"),
                        "not_after": na_dt.strftime("%Y-%m-%d"),
                        "days_left": days_left,
                        "fingerprint_sha256": cert.digest("sha256").decode(),
                    }

                    # Scoring
                    score = 0
                    if 1 <= days_left <= 3650:
                        score += 40
                        if days_left < 30:
                            result["findings"].append({
                                "level": "WARNING",
                                "message": f"Sertifikat akan kedaluwarsa dalam {days_left} hari.",
                            })
                    else:
                        result["findings"].append({
                            "level": "DANGER",
                            "message": "Sertifikat sudah kedaluwarsa atau tidak valid.",
                        })

                    proto = ssock.version()
                    if proto == "TLSv1.3":
                        score += 40
                    elif proto == "TLSv1.2":
                        score += 30
                    elif proto in ("TLSv1.1", "TLSv1"):
                        score += 10
                        result["findings"].append({
                            "level": "DANGER",
                            "message": f"Protokol usang: {proto}. Nonaktifkan segera.",
                        })

                    if cipher and any(x in cipher for x in ("GCM", "CHACHA20", "SHA384")):
                        score += 20
                    else:
                        score += 5
                        result["findings"].append({
                            "level": "WARNING",
                            "message": f"Cipher kurang kuat: {cipher}",
                        })

                    result["score"] = min(score, 100)

        if result["score"] >= 80:
            result["recommendations"].append("Konfigurasi SSL/TLS sudah baik.")
        else:
            result["recommendations"].append("Pertimbangkan upgrade konfigurasi TLS ke TLS 1.3.")
            result["recommendations"].append("Aktifkan HSTS max-age ≥ 31536000.")

    except socket.timeout:
        result["findings"].append({"level": "DANGER", "message": "Koneksi timeout ke port 443."})
    except ssl.SSLError as e:
        result["findings"].append({"level": "DANGER", "message": f"SSL error: {e}"})
    except Exception as e:
        result["findings"].append({"level": "DANGER", "message": f"Gagal koneksi: {e}"})

    return result


# ============================================================
# SCANNER 2: PORT SCAN
# ============================================================
def _scan_port(host: str, port: int, timeout: float = 1.5) -> tuple[int, bool]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port, True
    except Exception:
        pass
    return port, False


def scan_ports(target: str) -> dict:
    result = {
        "target": target, "open_ports": [], "findings": [],
        "recommendations": [], "scanned": len(COMMON_PORTS),
    }

    try:
        # Resolve ke IP
        host = socket.gethostbyname(target)
    except socket.gaierror:
        result["findings"].append({"level": "DANGER", "message": "Host tidak dapat di-resolve."})
        return result

    open_list = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_scan_port, host, p): p for p in COMMON_PORTS}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_list.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                })

    open_list.sort(key=lambda x: x["port"])
    result["open_ports"] = open_list

    risky = {23: "Telnet (plaintext)", 21: "FTP (plaintext)", 445: "SMB",
             1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 6379: "Redis",
             27017: "MongoDB", 9200: "Elasticsearch"}
    for entry in open_list:
        p = entry["port"]
        if p in risky:
            result["findings"].append({
                "level": "DANGER" if p in (3306, 6379, 27017, 9200, 1433) else "WARNING",
                "message": f"Port {p} ({entry['service']}) terbuka — {risky[p]} berisiko.",
            })

    if open_list:
        result["recommendations"].append("Batasi akses port dengan firewall (iptables/ufw/cloud SG).")
        result["recommendations"].append("Gunakan VPN untuk akses admin (SSH/RDP/DB).")
    else:
        result["recommendations"].append("Tidak ada port umum yang terbuka — konfigurasi baik.")

    return result


# ============================================================
# SCANNER 3: HTTP HEADERS
# ============================================================
def scan_headers(target: str) -> dict:
    result = {
        "target": target, "url": "", "status_code": None,
        "headers": {}, "missing": [], "findings": [],
        "recommendations": [], "score": 0,
    }

    expected = {
        "Strict-Transport-Security": "Aktifkan HSTS dengan max-age ≥ 31536000.",
        "Content-Security-Policy": "Tambahkan CSP untuk mitigasi XSS.",
        "X-Frame-Options": "Set ke DENY atau SAMEORIGIN untuk cegah clickjacking.",
        "X-Content-Type-Options": "Set ke 'nosniff'.",
        "Referrer-Policy": "Set ke 'strict-origin-when-cross-origin'.",
        "Permissions-Policy": "Batasi fitur browser yang tidak dipakai.",
    }

    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{target}"
            r = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent": "CyberScanAI/1.0"})
            result["url"] = r.url
            result["status_code"] = r.status_code
            result["headers"] = {k: v for k, v in r.headers.items()}

            present = 0
            for h, rec in expected.items():
                if h in r.headers:
                    present += 1
                else:
                    result["missing"].append(h)
                    result["findings"].append({
                        "level": "WARNING",
                        "message": f"Header '{h}' tidak ditemukan.",
                    })
                    result["recommendations"].append(rec)

            result["score"] = int((present / len(expected)) * 100)

            # Info disclosure
            if "Server" in r.headers:
                result["findings"].append({
                    "level": "INFO",
                    "message": f"Server header terekspos: {r.headers.get('Server')}",
                })
            if "X-Powered-By" in r.headers:
                result["findings"].append({
                    "level": "WARNING",
                    "message": f"X-Powered-By terekspos: {r.headers.get('X-Powered-By')}",
                })
            break
        except requests.exceptions.SSLError:
            continue
        except requests.RequestException as e:
            result["findings"].append({"level": "DANGER", "message": f"Request gagal: {e}"})
            continue

    return result


# ============================================================
# SCANNER 4: DNS AUDIT
# ============================================================
def _query(domain: str, rtype: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        return [a.to_text() for a in answers]
    except Exception:
        return []


def scan_dns(target: str) -> dict:
    result = {
        "target": target, "records": {}, "email_auth": {},
        "findings": [], "recommendations": [],
    }

    # A / AAAA / MX / NS / TXT
    result["records"]["A"] = _query(target, "A")
    result["records"]["AAAA"] = _query(target, "AAAA")
    result["records"]["MX"] = _query(target, "MX")
    result["records"]["NS"] = _query(target, "NS")

    txts = _query(target, "TXT")
    result["records"]["TXT"] = txts

    # SPF
    spf = [t for t in txts if t.strip('"').startswith("v=spf1")]
    result["email_auth"]["SPF"] = spf[0] if spf else None
    if not spf:
        result["findings"].append({"level": "WARNING", "message": "SPF record tidak ditemukan."})
        result["recommendations"].append("Tambahkan SPF: v=spf1 include:_spf.google.com ~all")

    # DMARC
    dmarc = _query(f"_dmarc.{target}", "TXT")
    dmarc_rec = next((t for t in dmarc if "v=DMARC1" in t), None)
    result["email_auth"]["DMARC"] = dmarc_rec
    if not dmarc_rec:
        result["findings"].append({"level": "WARNING", "message": "DMARC record tidak ditemukan."})
        result["recommendations"].append("Tambahkan DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain")
    else:
        if "p=none" in dmarc_rec:
            result["findings"].append({"level": "WARNING", "message": "DMARC p=none (hanya monitoring)."})
            result["recommendations"].append("Tingkatkan DMARC ke p=quarantine atau p=reject.")

    # DKIM (selector umum)
    dkim_found = False
    for selector in ("default", "google", "mail", "k1", "s1"):
        rec = _query(f"{selector}._domainkey.{target}", "TXT")
        if rec:
            dkim_found = True
            result["email_auth"]["DKIM"] = f"selector '{selector}' ditemukan"
            break
    if not dkim_found:
        result["email_auth"]["DKIM"] = None
        result["findings"].append({"level": "INFO", "message": "DKIM selector umum tidak terdeteksi (mungkin selector kustom)."})

    # DNSSEC
    ds = _query(target, "DS")
    result["email_auth"]["DNSSEC"] = bool(ds)
    if not ds:
        result["findings"].append({"level": "WARNING", "message": "DNSSEC tidak aktif — rentan spoofing."})
        result["recommendations"].append("Aktifkan DNSSEC di registrar domain.")

    return result


# ============================================================
# SCANNER 5: BLACKLIST / REPUTASI
# ============================================================
def scan_blacklist(target: str) -> dict:
    result = {
        "target": target, "sources": {}, "findings": [],
        "recommendations": [], "verdict": "unknown",
    }

    # VirusTotal (jika ada API key)
    if VIRUSTOTAL_API_KEY:
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            r = requests.get(url, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=15)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                result["sources"]["VirusTotal"] = f"{malicious} malicious / {total} engines"
                if malicious > 0:
                    result["findings"].append({
                        "level": "DANGER",
                        "message": f"VirusTotal: {malicious} engine menandai sebagai malicious.",
                    })
                if suspicious > 0:
                    result["findings"].append({
                        "level": "WARNING",
                        "message": f"VirusTotal: {suspicious} engine menandai suspicious.",
                    })
            else:
                result["sources"]["VirusTotal"] = f"API error {r.status_code}"
        except Exception as e:
            result["sources"]["VirusTotal"] = f"Error: {e}"
    else:
        result["sources"]["VirusTotal"] = "Tidak dikonfigurasi (set VIRUSTOTAL_API_KEY)"

    # Google Safe Browsing (butuh API key juga) — fallback: DNSBL Spamhaus
    try:
        # Reverse IP untuk DNSBL lookup
        ip = socket.gethostbyname(target)
        rev = ".".join(reversed(ip.split(".")))
        try:
            dns.resolver.resolve(f"{rev}.zen.spamhaus.org", "A", lifetime=5)
            result["sources"]["Spamhaus ZEN"] = "TERDAFTAR di blacklist!"
            result["findings"].append({
                "level": "DANGER",
                "message": f"IP {ip} terdaftar di Spamhaus ZEN blacklist.",
            })
        except dns.resolver.NXDOMAIN:
            result["sources"]["Spamhaus ZEN"] = "Bersih"
        except Exception:
            result["sources"]["Spamhaus ZEN"] = "Tidak dapat diperiksa"
    except Exception:
        result["sources"]["Spamhaus ZEN"] = "Gagal resolve IP"

    # Heuristic verdict
    danger_count = sum(1 for f in result["findings"] if f["level"] == "DANGER")
    warn_count = sum(1 for f in result["findings"] if f["level"] == "WARNING")

    if danger_count > 0:
        result["verdict"] = "danger"
        result["recommendations"].append("Segera investigasi dan bersihkan reputasi domain.")
    elif warn_count > 0:
        result["verdict"] = "warning"
        result["recommendations"].append("Pantau reputasi secara berkala.")
    else:
        result["verdict"] = "clean"
        result["recommendations"].append("Reputasi domain baik — pertahankan.")

    return result


# ============================================================
# SCANNER 6: OWASP VULNERABILITY CHECK
# ============================================================
def scan_vuln(target: str) -> dict:
    result = {
        "target": target, "categories": {}, "findings": [],
        "recommendations": [], "risk_score": 0,
    }

    headers_result = scan_headers(target)
    present = set(headers_result["headers"].keys())

    # A02: Cryptographic Failures
    https_ok = headers_result["url"].startswith("https://") if headers_result["url"] else False
    result["categories"]["A02 - Cryptographic Failures"] = "ok" if https_ok else "danger"
    if not https_ok:
        result["findings"].append({"level": "DANGER", "message": "Situs tidak menggunakan HTTPS."})

    # A03: Injection (indikasi via CSP)
    has_csp = "Content-Security-Policy" in present
    result["categories"]["A03 - Injection (XSS/SQLi)"] = "warning" if has_csp else "danger"
    if not has_csp:
        result["findings"].append({
            "level": "DANGER",
            "message": "Tidak ada CSP — risiko XSS tinggi.",
        })

    # A05: Security Misconfiguration
    misconfig = []
    if "X-Powered-By" in present:
        misconfig.append("X-Powered-By terekspos")
    if "Server" in present and headers_result["headers"].get("Server", "").lower() in (
        "apache", "nginx", "iis"
    ):
        misconfig.append("Server version terekspos")
    result["categories"]["A05 - Misconfiguration"] = "warning" if misconfig else "ok"
    for m in misconfig:
        result["findings"].append({"level": "WARNING", "message": m})

    # A06: Vulnerable Components (cek versi via header)
    comp_risk = "ok"
    if "Server" in headers_result["headers"]:
        srv = headers_result["headers"]["Server"]
        if re.search(r"\d+\.\d+\.\d+", srv):
            comp_risk = "warning"
            result["findings"].append({
                "level": "WARNING",
                "message": f"Versi server terekspos: {srv}",
            })
    result["categories"]["A06 - Vulnerable Components"] = comp_risk

    # A07: Auth Failures (tidak bisa dipindai tanpa login — tandai info)
    result["categories"]["A07 - Auth Failures"] = "info"
    result["findings"].append({
        "level": "INFO",
        "message": "Auth flow perlu pengujian manual (tidak dapat diotomasi tanpa kredensial).",
    })

    # A09: Logging Failures (tidak terdeteksi dari luar)
    result["categories"]["A09 - Logging Failures"] = "info"

    # A10: SSRF (tidak dapat diuji tanpa endpoint)
    result["categories"]["A10 - SSRF"] = "info"

    # Hitung risk score
    weight = {"ok": 0, "warning": 5, "danger": 15, "info": 0}
    result["risk_score"] = min(sum(weight.get(v, 0) for v in result["categories"].values()), 100)

    result["recommendations"] = [
        "Selalu gunakan HTTPS + HSTS.",
        "Terapkan Content-Security-Policy yang ketat.",
        "Sembunyikan header Server & X-Powered-By.",
        "Lakukan pentest manual untuk otentikasi & otorisasi.",
    ]
    return result


# ============================================================
# ROUTING
# ============================================================
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    client_ip = request.remote_addr or "unknown"
    if not check_rate_limit(client_ip):
        return jsonify({"error": "Rate limit terlampaui. Coba lagi dalam 1 menit."}), 429

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Pesan kosong."}), 400

    lower = text.lower()

    # Deteksi jenis scan
    if re.search(r"\b(ssl|tls|sertifikat|certificate)\b", lower):
        scan_type = "ssl"
    elif re.search(r"\b(port|nmap)\b", lower):
        scan_type = "port"
    elif re.search(r"\b(header|http header|csp|hsts)\b", lower):
        scan_type = "header"
    elif re.search(r"\b(dns|spf|dkim|dmarc)\b", lower):
        scan_type = "dns"
    elif re.search(r"\b(blacklist|malware|phishing|reputasi)\b", lower):
        scan_type = "blacklist"
    elif re.search(r"\b(kerentanan|vulnerability|owasp|xss|sql|injection)\b", lower):
        scan_type = "vuln"
    else:
        scan_type = "help"

    if scan_type == "help":
        return jsonify({"type": "help", "text": text})

    target = extract_target(text)
    if not target:
        return jsonify({"error": "Target domain/IP tidak ditemukan dalam pesan."}), 400

    ok, err = is_safe_target(target, allow_private=False)
    if not ok:
        return jsonify({"error": err}), 400

    try:
        if scan_type == "ssl":
            payload = scan_ssl(target)
        elif scan_type == "port":
            payload = scan_ports(target)
        elif scan_type == "header":
            payload = scan_headers(target)
        elif scan_type == "dns":
            payload = scan_dns(target)
        elif scan_type == "blacklist":
            payload = scan_blacklist(target)
        elif scan_type == "vuln":
            payload = scan_vuln(target)
        else:
            payload = {"error": "Unknown scan type"}

        return jsonify({"type": scan_type, "data": payload})

    except Exception as e:
        return jsonify({"error": f"Scan gagal: {type(e).__name__}: {e}"}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  CyberScan AI Backend")
    print("=" * 60)
    print("Server: http://127.0.0.1:5000")
    print(f"VirusTotal API Key: {'SET' if VIRUSTOTAL_API_KEY else 'NOT SET (opsional)'}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)