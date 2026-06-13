# 🛡️ NeuroVirus — Advanced Threat Intelligence Platform

A full-stack virus / malware scanner with a cyberpunk UI built on:

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Recharts, Axios |
| Backend | Python 3.12 + Flask |
| AV Engine | ClamAV (via `clamd`) |
| Rule Engine | YARA 4.x |
| Threat Intel | VirusTotal API v3 |
| Container | Docker + Docker Compose |
| Web Server | Nginx (production) |

---

## 📐 Architecture

```
Browser (React)
     │  HTTP  (upload + results)
     ▼
  Nginx :80
     │  /api/*  proxied to Flask
     ▼
Flask Backend :5000
     ├── Magic-byte detection
     ├── Shannon entropy analysis
     ├── Suspicious string extraction
     ├── Network indicator extraction
     ├── PE header parser (Windows EXE/DLL)
     ├── ClamAV  ──────────────► clamd :3310
     ├── YARA rule engine
     └── VirusTotal API v3  ───► cloud
```

---

## 🚀 Quick Start — Docker (Recommended)

### Prerequisites
- Docker Desktop ≥ 24
- Docker Compose v2

### 1. Clone & configure

```bash
git clone <repo-url> neurovirus
cd neurovirus

# Create your env file
cp .env.example .env
```

Edit `.env` and add your **VirusTotal API key** (free at https://www.virustotal.com/gui/join-us).

### 2. Launch all services

```bash
docker compose up --build
```

> ⚠️ **First run takes 3–5 minutes.** ClamAV downloads its signature database (~350 MB) on startup.

### 3. Open the UI

```
http://localhost:3000
```

The backend API is available at `http://localhost:5000/api`.

---

## 🛠️ Local Development (without Docker)

### Backend

#### Requirements
- Python 3.10+
- ClamAV installed and `clamd` running (`brew install clamav` on macOS, `apt install clamav clamav-daemon` on Ubuntu)
- YARA installed (`pip install yara-python` requires `yara` system lib)

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and edit env
cp ../.env.example .env

# Start ClamAV daemon (if not already running)
# macOS:  brew services start clamav
# Ubuntu: sudo systemctl start clamav-daemon

# Run Flask dev server
python run.py
# → http://localhost:5000
```

#### ClamAV setup (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install clamav clamav-daemon

# Update signature database
sudo freshclam

# Start daemon
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Verify
clamdscan --ping
```

#### ClamAV setup (macOS)

```bash
brew install clamav
sudo cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
# Edit freshclam.conf: remove the "Example" line

sudo freshclam
brew services start clamav
```

### Frontend

```bash
cd frontend
npm install
npm start
# → http://localhost:3000  (proxies /api to localhost:5000)
```

---

## 🔌 API Reference

All endpoints are prefixed with `/api`.

### `POST /api/scan`

Upload one or more files for analysis.

**Request:** `multipart/form-data` with field `files` (one or many).

**Response:**
```json
{
  "scanned": 1,
  "results": [
    {
      "scan_id": "abc123def456",
      "timestamp": "2026-03-19T10:00:00Z",
      "filename": "suspicious.exe",
      "file_size": 204800,
      "file_type_magic": "PE Executable",
      "file_extension": "exe",
      "hashes": {
        "md5": "...",
        "sha1": "...",
        "sha256": "..."
      },
      "entropy": 7.432,
      "threat_score": 85,
      "threat_level": "CRITICAL",
      "findings": [
        {
          "name": "ClamAV: Win.Trojan.GenericKD",
          "detail": "ClamAV signature match",
          "severity": "critical",
          "category": "MALWARE"
        }
      ],
      "clamav": { "status": "FOUND", "signature": "Win.Trojan.GenericKD" },
      "yara_matches": [...],
      "virustotal": { "status": "FOUND", "detections": 42, "total_engines": 72 },
      "suspicious_strings": [...],
      "network_indicators": [...],
      "pe_info": { "architecture": "x64 (64-bit)", "num_sections": 6, ... },
      "scan_duration_ms": 1243,
      "errors": []
    }
  ]
}
```

### `GET /api/scan/<scan_id>`

Retrieve a previous scan result by ID.

### `DELETE /api/scan/<scan_id>`

Delete a scan result and its uploaded file from disk.

### `GET /api/history?limit=50`

List recent scans (lightweight summaries, no full detail).

### `POST /api/quarantine`

Move a scanned file to the quarantine folder.

**Body:** `{ "scan_id": "abc123def456" }`

### `GET /api/status`

Returns the health/availability of all scan engines.

```json
{
  "engine": "NeuroVirus v3.14.1",
  "clamav":      { "available": true, "version": "ClamAV 1.3.0" },
  "yara":        { "available": true, "rule_files": 2, "yara_version": "4.5.1" },
  "virustotal":  { "available": true, "key_configured": true }
}
```

---

## 🧬 YARA Rules

Custom YARA rules live in `backend/yara_rules/`. Add `.yar` or `.yara` files there and restart the backend — they are loaded automatically.

Included rule sets:
- `malware_generic.yar` — Ransomware, Keyloggers, Process Injection, Anti-Debug, Crypto Miners, Backdoors, PowerShell abuse, Packers, PHP Webshells, Mimikatz
- `network_threats.yar` — C2 patterns, DNS tunneling, Tor hidden services, Data exfiltration

Rule metadata fields recognised by the engine:

```yara
rule My_Rule {
    meta:
        description = "Human-readable description shown in UI"
        severity     = "critical"   // critical | high | medium | low
        category     = "MALWARE"
    strings:
        ...
    condition:
        ...
}
```

---

## 🔍 Scan Capabilities

| Check | Method | What it detects |
|-------|--------|-----------------|
| File type | Magic bytes | Real file type vs declared extension |
| Hashing | MD5 / SHA-1 / SHA-256 | Identity, deduplication, VT lookup |
| Entropy | Shannon algorithm | Packed / encrypted / obfuscated content |
| Strings | Regex on printable bytes | 23 suspicious API / command patterns |
| PE headers | Struct parsing | Architecture, sections, WX pages, packers |
| Network IOCs | Regex | URLs, IPs, suspicious TLDs (.onion, .tk …) |
| AV signatures | ClamAV clamd | Millions of known malware signatures |
| Custom rules | YARA 4.x | Behavioural & structural pattern matching |
| Cloud Intel | VirusTotal API v3 | 70+ AV engines, hash lookup + file upload |
| Quarantine | File system | Isolate flagged files from uploads/ to quarantine/ |

---

## 📁 Project Structure

```
neurovirus/
├── docker-compose.yml
├── .env.example
├── .gitignore
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── run.py                  ← Flask entry point
│   ├── app/
│   │   ├── __init__.py         ← App factory
│   │   ├── config.py           ← All configuration
│   │   ├── routes.py           ← REST API endpoints
│   │   └── scanner.py          ← Core scan engine (900 lines)
│   ├── yara_rules/
│   │   ├── malware_generic.yar
│   │   └── network_threats.yar
│   ├── uploads/                ← Temporary scan storage (git-ignored)
│   └── quarantine/             ← Quarantined files (git-ignored)
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    └── src/
        ├── index.js
        ├── App.js              ← Main UI (cyberpunk React)
        ├── App.css             ← Cyberpunk stylesheet
        └── api.js              ← Axios API client
```

---

## 🔒 Security Notes

- **Never run this on production infrastructure without a proper secrets manager** — use environment variables or Docker secrets, never hardcode API keys.
- The `uploads/` folder is auto-cleaned on `DELETE /api/scan/<id>`. Consider adding a cron job to purge old files.
- ClamAV's database updates automatically via `freshclamd`. In Docker it updates on container start.
- VirusTotal free tier: **4 requests/minute, 500/day**. Throttle if scanning many files.
- The quarantine folder stores files with `.quarantine` extension — they are NOT executed, but treat them as live malware.
- For production, add authentication middleware to the Flask API (JWT / API key).

---

## 📦 Dependencies Summary

### Backend Python packages
| Package | Purpose |
|---------|---------|
| `flask` | Web framework |
| `flask-cors` | Cross-origin headers |
| `clamd` | ClamAV TCP socket client |
| `yara-python` | YARA rule engine bindings |
| `requests` | VirusTotal HTTP calls |
| `python-magic` | libmagic MIME detection (optional) |

### Frontend npm packages
| Package | Purpose |
|---------|---------|
| `react` | UI framework |
| `axios` | HTTP client |
| `recharts` | Radial gauge + bar charts |

---

## 🐛 Troubleshooting

**ClamAV says "Connection refused"**
→ Make sure `clamd` is running: `sudo systemctl status clamav-daemon`
→ In Docker: wait for the health check to pass (up to 2 min on first run)

**YARA import error**
→ `pip install yara-python` requires the YARA C library. On Ubuntu: `sudo apt install yara`

**VirusTotal returns 404**
→ The file hash isn't in VT's database. If the file is ≤32 MB it will be automatically uploaded for analysis.

**"No module named clamd"**
→ Run `pip install -r requirements.txt` inside the `backend/` directory with your virtualenv active.

---

## 📜 License

MIT — use freely, but **never use this to scan files you do not own or have permission to scan**.
