# 🔍 OSINT Surface Analyzer

> Dockerized OSINT platform for exposed attack surface analysis — subdomains, emails, ports, SSL, data leaks & cybersquatting. Encrypted key storage, automated evidence capture, and professional PDF/Excel reporting.

<div align="center">

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-USDT%20TRC20-yellow?style=for-the-badge&logo=buymeacoffee)](https://tronscan.org/#/address/TM3hVY5QNz4TJGemtBw4EfZb2nDHqB9Zkz)

**USDT (TRC20):** `TM3hVY5QNz4TJGemtBw4EfZb2nDHqB9Zkz`

*If this tool saves you time, a coffee keeps the project alive ☕*

</div>

---

## Features

### 🔎 Automated Recon Modules

| Module | Tools | Auto |
|---|---|---|
| Subdomains | subfinder, amass, dnsenum, crt.sh, DNSDumpster | ✅ |
| Emails | theHarvester, Google Dorks, Hunter.io, crt.sh | ✅ |
| WHOIS | whois CLI, python-whois | ✅ |
| Ports | nmap (all 65535 TCP/UDP) | ✅ |
| SSL/TLS | Live socket + crt.sh | ✅ |
| DMARC / SPF | dig + DNS analysis | ✅ |
| DNS & MX | dig, dnsenum | ✅ |
| Technologies | whatweb, wafw00f, HTTP headers | ✅ |
| Robots.txt | HTTP fetch + dork search | ✅ |
| Sitemap | XML parsing | ✅ |
| ASN / IP Blocks | BGP.he.net, BGPView, HackerTarget | ✅ |
| Data Leaks | HaveIBeenPwned API | ✅ |
| Cloud Infrastructure | DNS CNAME detection | ✅ |
| Cybersquatting | dnstwist (local + API) | ✅ |
| FAVICON Hash | mmh3 + Shodan | ✅ |
| Credentials Leaked | IntelligenceX API | ✅ |

### 🔌 API Integrations

| API | Usage | Tier |
|---|---|---|
| **Shodan** | IoT devices, open ports, FAVICON hash search | Free |
| **VirusTotal** | Domain reputation, subdomains, malicious IPs | Free (500 req/day) |
| **SecurityTrails** | Historical DNS, premium subdomain enum | Free (50 req/mo) |
| **IntelligenceX** | Dark web, data leaks, credential dumps | Free |
| **Hunter.io** | Email discovery by domain | Free (25/mo) |
| **HaveIBeenPwned** | Breach detection by domain/email | Paid (~$3.50/mo) |
| **Snov.io** | Email enrichment | Free (50 credits/mo) |

### 📸 Automatic Evidence Capture

After every scan, the platform automatically captures:

- **Screenshots** of all active subdomains, cybersquatting domains, and Disallow paths
- **HTTP security headers** analysis per subdomain
- **Full SSL/TLS certificate** dumps (subject, SANs, expiry, cipher, SHA-256 fingerprint)
- **WHOIS dumps** and **DMARC analysis** saved as structured text
- **ASN/IP block tables** per domain

Evidence is linked to individual findings and included in PDF/Excel exports.

### 📊 Reporting

- **PDF Report** — professional executive report with all findings, severity classification, and evidence
- **Excel Workbook** — one sheet per module, findings cross-referenced with captured evidence
- **Scan History** — all past scans stored locally with full data retention

---

## Architecture

```
Internet ──▶ Traefik (80/443) ──▶ osint-analyzer  (Python/FastAPI :8080)
                                        │
                              osint-internal network
                                   │            │
                            osint-tools     osint-puppeteer
                          (CLI tools :4000)  (Chromium :3000)
```

### Containers

| Container | Role | Network |
|---|---|---|
| `osint-analyzer` | Backend API + Frontend | `traefik` + `osint-internal` |
| `osint-tools` | CLI tools + API integrations | `osint-internal` only |
| `osint-puppeteer` | Headless Chromium screenshots | `osint-internal` only |

`osint-tools` and `osint-puppeteer` are **never exposed to the internet** — they only communicate with `osint-analyzer` over the isolated internal Docker network.

### CLI Tools in `osint-tools`

- **Go 1.22 (official tarball):** `subfinder`, `amass`, `httpx`, `dnsx`
- **Ruby:** `whatweb`
- **Perl:** `dnsenum`
- **Python (isolated venv):** `theHarvester`, `wafw00f`, `dnstwist`
- **System:** `nmap`, `whois`, `dig`

---

## Security

### API Key Storage

API keys are **never stored in plaintext**.

```
User enters key in UI
       ↓
PBKDF2-HMAC-SHA256 (600,000 iterations)
  + per-installation random salt (16 bytes, CSPRNG)
  + OSINT_DEPLOY_SECRET (machine-specific)
       ↓
AES-128-CBC (Fernet) encryption
       ↓
/app/data/keys/apikeys.enc  ←  persisted in Docker named volume
```

- Keys are **never passed as environment variables** to child containers
- During scans, decrypted keys travel **only in runtime HTTP requests** over the internal network, never to disk in child containers
- Every key operation (`get`, `set`, `delete`) is written to an **audit log** (timestamps only, no values)
- Bootstrap: if a key is provided via `.env` at first start, it is imported to the encrypted store and **immediately cleared from the process environment**

### Network Isolation

- `osint-puppeteer` has **SSRF protection** — blocks all private IP ranges (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `169.254.x`, `.local`, `.internal`)
- `osint-tools` has no Traefik labels — **zero external exposure**
- Rate limiting: 30 screenshots/min, 5 concurrent

### Container Hardening

- All containers: `no-new-privileges: true`
- `osint-puppeteer`: runs as non-root user (`pptruser`)
- No secrets in container images or `docker-compose.yml`

---

## Deployment Modes

Choose the mode that fits your setup:

| Mode | File | Access | HTTPS | Best For |
|---|---|---|---|---|
| **Traefik + Domain** | `docker-compose.yml` | `https://your-domain.com` | ✅ Auto | Production servers |
| **IP:Port** | `docker-compose.no-domain.yml` | `http://IP:8080` | ❌ | LAN / trusted network |
| **Localhost** | `docker-compose.localhost.yml` | `http://localhost:8080` | ❌ | Personal laptop |
| **Cloudflare Tunnel** | `docker-compose.cf-tunnel.yml` | `https://xxxx.trycloudflare.com` | ✅ Free | No domain, remote access |
| **Ngrok** | `docker-compose.ngrok.yml` | `https://xxxx.ngrok-free.app` | ✅ Free | Quick demos |

### Traefik + Domain (default)
```bash
docker compose up -d --build
```

### IP:Port — no domain, no Traefik
```bash
docker compose -f docker-compose.no-domain.yml up -d --build
# Access at: http://YOUR_IP:8080
```

### Localhost — your machine only
```bash
docker compose -f docker-compose.localhost.yml up -d --build
# Access at: http://localhost:8080
```

### Cloudflare Tunnel — free HTTPS without a domain

**Option A — Temporary URL** (no account needed, changes on restart):
```bash
docker compose -f docker-compose.cf-tunnel.yml up -d --build
docker logs osint-cloudflared  # get the assigned URL
```

**Option B — Permanent URL** (free Cloudflare account):
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → Zero Trust → Networks → Tunnels
2. Create tunnel → copy the token
3. In the dashboard set route to: `http://osint-analyzer:8080`
4. Add to `.env`:
```env
CLOUDFLARE_TUNNEL_TOKEN=your_token_here
```
```bash
docker compose -f docker-compose.cf-tunnel.yml up -d --build
```

### Ngrok — temporary public tunnel
1. Sign up at [ngrok.com](https://ngrok.com) and copy your auth token
2. Add to `.env`:
```env
NGROK_AUTHTOKEN=your_token_here
```
```bash
docker compose -f docker-compose.ngrok.yml up -d --build
docker logs osint-ngrok  # get the public URL
```

---

## Getting Started

### Prerequisites

- Docker + Docker Compose v2
- `openssl` for generating the deploy secret

### 1. Clone

```bash
git clone https://github.com/yourusername/osint-surface-analyzer.git
cd osint-surface-analyzer
```

### 2. Configure

```bash
cp .env.example .env
```

Generate a unique deploy secret — **do this once and never change it**:

```bash
openssl rand -hex 32
```

Paste the result into `.env`:

```env
OSINT_DEPLOY_SECRET=paste_your_generated_secret_here
```

> ⚠️ Rotating `OSINT_DEPLOY_SECRET` after the first deploy will invalidate all stored API keys.

### 3. Deploy

```bash
docker compose up -d --build
```

> **First build takes 5–8 minutes** — `osint-tools` compiles Go 1.22 and installs all CLI tools from source.

### 4. Configure API Keys

Open the platform → **⚙ AJUSTES** and enter your API keys via the UI.
Keys are encrypted immediately on save — no need to touch `.env` for this.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OSINT_DEPLOY_SECRET` | **Yes** | Master secret for PBKDF2 key derivation. Generate with `openssl rand -hex 32`. Set once, never rotate. |

All API keys are managed through the UI. They can optionally be bootstrapped via `.env` on first start and will be auto-imported and cleared from the environment automatically.

---

## Data Persistence

| Volume | Mount | Contents |
|---|---|---|
| `osint-keys` | `/app/data/keys` | Encrypted API keys, PBKDF2 salt, audit log |
| `osint-scans` | `/app/data/scans` | Scan results (JSON) |
| `osint-evidence` | `/app/data/evidence` | Screenshots, certificates, header dumps |
| `osint-results` | `/app/results` | Exported reports |

```bash
# Safe — rebuilds image, all volumes untouched
docker compose down && docker compose up -d --build

# ⚠️ Destroys ALL data including API keys — use only for full reset
docker compose down -v
```

---

## Usage

### Running a Scan

1. Enter a target domain (e.g., `example.com`)
2. Select which modules to run (or run all)
3. Click **INICIAR ANÁLISIS**
4. Watch the live log stream — evidence captures appear in purple
5. Export as **PDF** or **Excel** when complete

### Manual Findings

Each module has a **+ AGREGAR MANUAL** button for findings from external tools (Maltego, Shodan web UI, etc.) that require human verification.

### Per-Finding Evidence

Each finding row has three inline buttons:

| Button | Action |
|---|---|
| **📎 EVIDENCIA** | Attach screenshots or files with drag & drop |
| **🔗 URL** | Link to an external reference |
| **✎ NOTA** | Add analyst notes |

All evidence is embedded in the exported PDF and Excel reports.

---

## API Reference

```
GET    /api/scans                      List all scans
GET    /api/scans/{id}                 Full scan data
DELETE /api/scans/{id}                 Delete scan
POST   /api/scans/{id}/rename          Rename scan
GET    /api/scans/{id}/pdf             Download PDF report
GET    /api/scans/{id}/xlsx            Download Excel report
POST   /api/scans/{id}/manual          Add manual findings
GET    /api/scans/{id}/evidence        List evidence items
POST   /api/scans/{id}/evidence        Upload evidence file
PATCH  /api/scans/{id}/evidence/{eid}  Update evidence caption
DELETE /api/scans/{id}/evidence/{eid}  Delete evidence item
GET    /api/keys                       List key status (no values exposed)
POST   /api/keys/{service_id}          Set API key
DELETE /api/keys/{service_id}          Remove API key
GET    /api/keys/audit                 Key access audit log
WS     /ws/scan                        Live scan log stream
```

---

## Updating

```bash
git pull
docker compose down
docker compose up -d --build
# Keys and scan history are preserved
```

---

## Roadmap

- [ ] Multi-user authentication
- [ ] Scheduled / recurring scans
- [ ] Slack / email alerts on critical findings
- [ ] Scan delta comparison (track changes over time)
- [ ] Dark web monitoring module

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

**If this tool is useful to you, consider supporting its development:**

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-USDT%20TRC20-yellow?style=for-the-badge)](https://tronscan.org/#/address/TM3hVY5QNz4TJGemtBw4EfZb2nDHqB9Zkz)

`TM3hVY5QNz4TJGemtBw4EfZb2nDHqB9Zkz`

<sub>Built with FastAPI · Puppeteer · Go 1.22 · Ruby · Docker</sub>

</div>
