# 🔐 SecureVault — Secure File Sharing System

A cybersecurity-focused file sharing platform built with end-to-end
encryption, multi-factor authentication, and real-time threat detection.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-red)
![MFA](https://img.shields.io/badge/MFA-TOTP-orange)

---

## 🛡️ Security Features

| Feature | Implementation |
|---|---|
| File Encryption | AES-256-GCM (authenticated encryption) |
| Key Derivation | PBKDF2-SHA256 (600,000 iterations) |
| Password Hashing | Argon2id (64MB memory cost) |
| Authentication | JWT (15-min expiry) + Refresh Tokens |
| Multi-Factor Auth | TOTP via RFC 6238 (Google Authenticator) |
| Malware Scanning | VirusTotal API (70+ AV engines) |
| File Validation | libmagic MIME detection + blocklist |
| Rate Limiting | Per-IP limits on all auth endpoints |
| Integrity Checks | SHA-256 hash verification on download |
| Audit Logging | JSON audit trail for all events |
| Anomaly Detection | Brute force, bulk exfil, tamper alerts |
| Secure Headers | HSTS, CSP, X-Frame-Options, nosniff |

---

## 🏗️ Architecture

┌─────────────────────────────────────────────────────────┐
│ SecureVault API │
│ (FastAPI + Python) │
├──────────────┬──────────────┬──────────────┬────────────┤
│ Auth Module │ File Module │ Audit Module │ Core Lib │
│ JWT + MFA │ Upload/DL │ Dashboard │ Crypto │
│ Argon2id │ AES-256-GCM │ Anomaly │ Scanner │
├──────────────┴──────────────┴──────────────┴────────────┤
│ SQLite Database (SQLAlchemy ORM) │
├─────────────────────────────────────────────────────────┤
│ Encrypted File Storage (uploads/*.enc) │
└─────────────────────────────────────────────────────────┘

text

---

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/yourusername/securevault.git
cd securevault
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo apt install libmagic1 -y

# Configure environment
cp .env.example .env
# Edit .env — generate SECRET_KEY with:
# python3 -c "import secrets; print(secrets.token_hex(32))"

# Run
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Visit `http://localhost:8000/docs` for the interactive API.
Visit `http://localhost:8000/audit/dashboard` for the security dashboard.

---

## 🔒 Encryption Design

User uploads file.pdf
↓
SHA-256 hash computed (integrity fingerprint)
↓
AES-256-GCM encryption
Key = PBKDF2(user_id, random_salt, 600000 iterations)
Nonce = os.urandom(12) [never reused]
↓
Stored as: [salt(16)][nonce(12)][ciphertext+tag] → uuid.enc
↓
Original filename never touches disk

text

On download, the GCM authentication tag is verified before
decryption — any tampering raises `InvalidTag` and the
download is rejected.

---

## 📁 Project Structure

securevault/
├── app/
│ ├── core/
│ │ ├── crypto.py # AES-256-GCM, PBKDF2, SHA-256
│ │ ├── security.py # JWT, Argon2id, TOTP/MFA
│ │ ├── audit.py # Audit logging + stats
│ │ ├── anomaly.py # Anomaly detection engine
│ │ └── scanner.py # VirusTotal integration
│ ├── models/ # SQLAlchemy DB models
│ ├── routers/ # FastAPI route handlers
│ ├── schemas/ # Pydantic validation models
│ ├── config.py # Settings management
│ ├── database.py # DB session handling
│ └── main.py # App entry point
├── uploads/ # Encrypted file storage
├── logs/ # Audit trail
├── .env.example # Environment template
└── requirements.txt

text

---

## 🚨 Anomaly Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Brute Force | 5+ failed logins in 10 min | HIGH |
| Bulk Download | 20+ downloads in 5 min | HIGH |
| Malware Probe | 3+ blocked uploads in 30 min | MEDIUM |
| File Tampering | Any integrity check failure | CRITICAL |
| MFA Bypass | 5+ MFA failures in 10 min | HIGH |

---

## 🛡️ OWASP Top 10 Coverage

| OWASP Risk | Mitigation |
|---|---|
| A01 Broken Access Control | RBAC, owner-only file access |
| A02 Cryptographic Failures | AES-256-GCM, Argon2id, PBKDF2 |
| A03 Injection | Pydantic validation, SQLAlchemy ORM |
| A04 Insecure Design | Threat model, zero-knowledge storage |
| A07 Auth Failures | JWT expiry, MFA, rate limiting |
| A08 Software Integrity | SHA-256 integrity checks |
| A09 Logging Failures | Full audit trail + anomaly detection |

---

## ⚠️ Security Notes

- Never commit `.env` to version control
- Rotate `SECRET_KEY` regularly in production
- Set `ACCESS_TOKEN_EXPIRE_MINUTES=15` in production
- Add HTTPS/TLS reverse proxy (nginx) before deploying
- Replace SQLite with PostgreSQL for production use