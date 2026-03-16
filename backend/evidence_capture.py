"""
evidence_capture.py
Auto-capture evidence during OSINT scan:
  1. Screenshots via puppeteer-server (port 3000)
  2. HTTP headers + status for every active URL
  3. SSL certificate details (text export)
  4. Tool raw outputs (already handled in main.py, referenced here for completeness)
"""

import asyncio
import aiohttp
import json
import ssl
import socket
import uuid
import os
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

# ── Puppeteer screenshot service ─────────────────────────────────────────────
# Reads from env var set in docker-compose; falls back to service name default.
PUPPETEER_URL      = os.environ.get("PUPPETEER_SERVICE_URL", "http://osint-puppeteer:3000") + "/screenshot"
SCREENSHOT_TIMEOUT = 20          # seconds per screenshot
MAX_SCREENSHOTS    = 20          # cap per scan to avoid flooding
SCREENSHOT_WIDTH   = 1280
SCREENSHOT_HEIGHT  = 720

# ── HTTP headers capture ──────────────────────────────────────────────────────
HEADERS_TIMEOUT = 8
MAX_HEADER_CAPTURES = 50

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"


# ─────────────────────────────────────────────────────────────────────────────
# Public API  — called from main.py after each module finishes
# ─────────────────────────────────────────────────────────────────────────────

async def auto_capture_module(
    scan_id: str,
    module_id: str,
    module_result: dict,
    ev_dir: Path,
    ev_idx: list,
    log_fn=None,
) -> list:
    """
    Dispatch automatic evidence capture based on module type.
    Returns list of new evidence entries (already appended to ev_idx).
    """
    new_entries = []

    async def _log(msg):
        if log_fn:
            await log_fn(msg)

    if module_id == "subdomains":
        new_entries += await _capture_subdomains(scan_id, module_result, ev_dir, ev_idx, _log)

    elif module_id == "ssl":
        new_entries += await _capture_ssl(scan_id, module_result, ev_dir, ev_idx, _log)

    elif module_id == "ports":
        new_entries += await _capture_port_headers(scan_id, module_result, ev_dir, ev_idx, _log)

    elif module_id == "technologies":
        new_entries += await _capture_tech_headers(scan_id, module_result, ev_dir, ev_idx, _log)

    elif module_id in ("whois", "dmarc", "dns", "asn"):
        new_entries += _capture_structured_output(scan_id, module_id, module_result, ev_dir, ev_idx)

    elif module_id == "robots":
        new_entries += await _capture_robots(scan_id, module_result, ev_dir, ev_idx, _log)

    elif module_id == "cybersquatting":
        new_entries += await _capture_squatting(scan_id, module_result, ev_dir, ev_idx, _log)

    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 1. SCREENSHOTS  (puppeteer-server)
# ─────────────────────────────────────────────────────────────────────────────

async def take_screenshot(url: str) -> Optional[bytes]:
    """
    Call puppeteer-server REST API to get a PNG screenshot.
    Expected API: POST /screenshot  { url, width, height, fullPage }
    Returns PNG bytes or None on failure.
    """
    payload = {
        "url": url,
        "width": SCREENSHOT_WIDTH,
        "height": SCREENSHOT_HEIGHT,
        "fullPage": False,
        "waitUntil": "networkidle2",
        "timeout": (SCREENSHOT_TIMEOUT - 3) * 1000,  # ms
    }
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                PUPPETEER_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=SCREENSHOT_TIMEOUT),
            ) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("content-type", "")
                    if "image" in ct or "octet" in ct:
                        return await resp.read()
                    # Some puppeteer servers return JSON with base64
                    data = await resp.json()
                    if "screenshot" in data:
                        import base64 as b64
                        return b64.b64decode(data["screenshot"])
                    if "image" in data:
                        import base64 as b64
                        return b64.b64decode(data["image"])
    except Exception:
        pass
    return None


def _make_ev_entry(scan_id, module_id, fname, caption, finding_ref="",
                   media_type="text/plain", size=0, source="auto",
                   tool="", is_image=False):
    return {
        "id":           str(uuid.uuid4()),
        "scan_id":      scan_id,
        "module":       module_id,
        "finding_ref":  finding_ref,
        "caption":      caption,
        "source":       source,
        "filename":     fname,
        "stored_name":  fname,
        "media_type":   media_type,
        "size":         size,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "is_image":     is_image,
        "is_text":      not is_image,
        "tool":         tool,
    }


def _save_entry(ev_dir: Path, ev_idx: list, entry: dict, data: bytes) -> dict:
    """Write file to disk, append to index, return entry."""
    (ev_dir / entry["stored_name"]).write_bytes(data)
    entry["id"] = str(uuid.uuid4())  # ensure unique after copy
    entry["stored_name"] = entry["stored_name"].replace(
        entry["stored_name"].split(".")[0], entry["id"]
    )
    # Re-write with correct stored_name
    final_path = ev_dir / entry["stored_name"]
    (ev_dir / list(ev_dir.glob(f'*{Path(entry["filename"]).suffix}'))[-1].name
     if False else ev_dir / entry["stored_name"]).write_bytes(data)
    ev_idx.append(entry)
    return entry


def _write_evidence(ev_dir: Path, ev_idx: list, entry: dict, data: bytes) -> dict:
    """Simpler write helper."""
    fpath = ev_dir / entry["stored_name"]
    fpath.write_bytes(data)
    ev_idx.append(entry)
    return entry


# ─────────────────────────────────────────────────────────────────────────────
# 2. SUBDOMAINS: screenshot + HTTP headers for each active subdomain
# ─────────────────────────────────────────────────────────────────────────────

async def _capture_subdomains(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    active = result.get("active_subdomains", [])
    if not active:
        return new_entries

    await log(f"[EVIDENCE] Capturando evidencia de {len(active)} subdominio(s) activo(s)...")

    # Screenshot cap
    screenshot_count = 0
    tasks_ss = []
    for item in active[:MAX_SCREENSHOTS]:
        sub = item.get("subdomain", "")
        url = f"https://{sub}" if not sub.startswith("http") else sub
        tasks_ss.append((sub, url, asyncio.create_task(take_screenshot(url))))

    for sub, url, task in tasks_ss:
        try:
            png = await asyncio.wait_for(task, timeout=SCREENSHOT_TIMEOUT + 2)
        except Exception:
            png = None

        if png:
            ev_id  = str(uuid.uuid4())
            fname  = f"{ev_id}.png"
            entry  = {
                "id": ev_id, "scan_id": scan_id, "module": "subdomains",
                "finding_ref": sub, "caption": f"Screenshot: {sub}",
                "source": "auto", "filename": f"screenshot_{sub}.png",
                "stored_name": fname, "media_type": "image/png",
                "size": len(png), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": True, "is_text": False, "tool": "puppeteer",
            }
            _write_evidence(ev_dir, ev_idx, entry, png)
            new_entries.append(entry)
            screenshot_count += 1
            await log(f"[EVIDENCE] 📸 Screenshot: {sub}")

    # HTTP headers for ALL active (no screenshot cap)
    header_tasks = []
    for item in active[:MAX_HEADER_CAPTURES]:
        sub = item.get("subdomain", "")
        url = f"https://{sub}" if not sub.startswith("http") else sub
        header_tasks.append((sub, url, asyncio.create_task(_fetch_headers(url))))

    for sub, url, task in header_tasks:
        try:
            headers_text = await asyncio.wait_for(task, timeout=HEADERS_TIMEOUT + 2)
        except Exception:
            headers_text = None
        if headers_text:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = headers_text.encode("utf-8")
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "subdomains",
                "finding_ref": sub,
                "caption": f"HTTP Headers: {sub}",
                "source": "auto", "filename": f"headers_{sub}.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "aiohttp",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    await log(f"[EVIDENCE] ✔ Subdomains: {screenshot_count} screenshots + {len(new_entries)-screenshot_count} headers")
    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 3. HTTP HEADERS FETCH
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_headers(url: str) -> Optional[str]:
    """Return formatted headers string for a URL."""
    try:
        headers_req = {"User-Agent": USER_AGENT}
        async with aiohttp.ClientSession() as s:
            async with s.get(
                url,
                headers=headers_req,
                timeout=aiohttp.ClientTimeout(total=HEADERS_TIMEOUT),
                ssl=False,
                allow_redirects=True,
                max_redirects=5,
            ) as resp:
                lines = [
                    f"REQUEST URL : {url}",
                    f"FINAL URL   : {str(resp.url)}",
                    f"STATUS      : {resp.status} {resp.reason}",
                    f"CAPTURED AT : {datetime.now(timezone.utc).isoformat()}",
                    "",
                    "── RESPONSE HEADERS ──────────────────────────────────────",
                ]
                for k, v in resp.headers.items():
                    lines.append(f"{k:<40} {v}")
                # Security-relevant headers check
                sec_hdrs = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                    "x-xss-protection",
                    "server",
                    "x-powered-by",
                ]
                missing = [h for h in sec_hdrs if h not in {k.lower() for k in resp.headers}]
                if missing:
                    lines += ["", "── MISSING SECURITY HEADERS ──────────────────────────────"]
                    for m in missing:
                        lines.append(f"  ✖ {m}")
                return "\n".join(lines)
    except Exception as e:
        return f"ERROR fetching {url}: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. SSL CERTIFICATE export
# ─────────────────────────────────────────────────────────────────────────────

async def _capture_ssl(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    certs = result.get("certificates", [])
    if not certs:
        return new_entries

    await log(f"[EVIDENCE] Exportando {len(certs)} certificado(s) SSL...")

    for cert_info in certs:
        domain = cert_info.get("domain", "")
        if not domain:
            continue
        cert_text = await _fetch_ssl_cert(domain)
        if not cert_text:
            # Fall back to already-collected data
            cert_text = _format_ssl_data(cert_info)

        ev_id = str(uuid.uuid4())
        fname = f"{ev_id}.txt"
        data  = cert_text.encode("utf-8")
        entry = {
            "id": ev_id, "scan_id": scan_id, "module": "ssl",
            "finding_ref": domain,
            "caption": f"Certificado SSL: {domain}",
            "source": "auto", "filename": f"ssl_cert_{domain}.txt",
            "stored_name": fname, "media_type": "text/plain",
            "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_image": False, "is_text": True, "tool": "ssl_socket",
        }
        _write_evidence(ev_dir, ev_idx, entry, data)
        new_entries.append(entry)

    await log(f"[EVIDENCE] ✔ SSL: {len(new_entries)} certificado(s) exportados")
    return new_entries


async def _fetch_ssl_cert(domain: str, port: int = 443) -> Optional[str]:
    """Connect via SSL and extract the full certificate details."""
    try:
        loop = asyncio.get_event_loop()

        def _blocking_ssl():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert    = ssock.getpeercert()
                    der     = ssock.getpeercert(binary_form=True)
                    version = ssock.version()
                    cipher  = ssock.cipher()
                    return cert, der, version, cipher

        cert, der, version, cipher = await loop.run_in_executor(None, _blocking_ssl)

        # Build human-readable output
        lines = [
            f"DOMAIN      : {domain}",
            f"CAPTURED AT : {datetime.now(timezone.utc).isoformat()}",
            f"TLS VERSION : {version}",
            f"CIPHER      : {cipher[0] if cipher else 'unknown'}",
            "",
            "── CERTIFICATE DETAILS ───────────────────────────────────────",
        ]

        def _dn(dn_tuples):
            return ", ".join(f"{k}={v}" for item in (dn_tuples or []) for k, v in item)

        lines.append(f"Subject     : {_dn(cert.get('subject'))}")
        lines.append(f"Issuer      : {_dn(cert.get('issuer'))}")
        lines.append(f"Valid From  : {cert.get('notBefore','')}")
        lines.append(f"Valid Until : {cert.get('notAfter','')}")
        lines.append(f"Serial No.  : {cert.get('serialNumber','')}")
        lines.append(f"Version     : {cert.get('version','')}")

        sans = cert.get("subjectAltName", [])
        if sans:
            lines.append("")
            lines.append("── SUBJECT ALTERNATIVE NAMES ─────────────────────────────")
            for typ, val in sans:
                lines.append(f"  {typ:<6} {val}")

        # SHA-256 fingerprint
        import hashlib
        fp = hashlib.sha256(der).hexdigest()
        fp_fmt = ":".join(fp[i:i+2].upper() for i in range(0, len(fp), 2))
        lines.append("")
        lines.append(f"SHA-256 FP  : {fp_fmt}")

        return "\n".join(lines)

    except Exception as e:
        return None


def _format_ssl_data(cert_info: dict) -> str:
    """Format already-collected SSL data as evidence text."""
    lines = [
        f"DOMAIN      : {cert_info.get('domain','')}",
        f"ISSUER      : {cert_info.get('issuer','')}",
        f"VALID UNTIL : {cert_info.get('valid_until','')}",
        f"DAYS LEFT   : {cert_info.get('days_left','')}",
        f"TLS VERSION : {cert_info.get('tls_version','')}",
        f"STATUS      : {cert_info.get('status','')}",
        f"CAPTURED AT : {datetime.now(timezone.utc).isoformat()}",
    ]
    if cert_info.get("sans"):
        lines.append("")
        lines.append("── SUBJECT ALTERNATIVE NAMES ─────────────────────────────")
        for san in cert_info["sans"]:
            lines.append(f"  {san}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 5. PORT SCAN: capture HTTP headers for open web ports
# ─────────────────────────────────────────────────────────────────────────────

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 4443}

async def _capture_port_headers(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    all_ports = result.get("all_open_ports", [])
    web_ports = [p for p in all_ports if p.get("port") in WEB_PORTS]
    if not web_ports:
        return new_entries

    await log(f"[EVIDENCE] Capturando headers HTTP de {len(web_ports)} puerto(s) web...")

    tasks = []
    for p in web_ports[:20]:
        domain = p.get("domain", "")
        port   = p.get("port", 80)
        scheme = "https" if port in (443, 8443, 4443) else "http"
        url    = f"{scheme}://{domain}:{port}" if port not in (80, 443) else f"{scheme}://{domain}"
        tasks.append((domain, port, url, asyncio.create_task(_fetch_headers(url))))

    for domain, port, url, task in tasks:
        try:
            headers_text = await asyncio.wait_for(task, timeout=HEADERS_TIMEOUT + 2)
        except Exception:
            headers_text = None
        if headers_text:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = headers_text.encode("utf-8")
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "ports",
                "finding_ref": f"{domain}:{port}",
                "caption": f"HTTP Headers: {domain}:{port}",
                "source": "auto", "filename": f"headers_{domain}_{port}.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "aiohttp",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    await log(f"[EVIDENCE] ✔ Ports: {len(new_entries)} header(s) capturados")
    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 6. TECHNOLOGY detection: screenshot of main domain + headers
# ─────────────────────────────────────────────────────────────────────────────

async def _capture_tech_headers(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    scans = result.get("technology_scans", [])
    if not scans:
        return new_entries

    await log(f"[EVIDENCE] Capturando screenshots de dominio(s) principal(es)...")

    done_domains = set()
    for ts in scans[:10]:
        domain = ts.get("domain", "")
        if not domain or domain in done_domains:
            continue
        done_domains.add(domain)
        url = f"https://{domain}" if not domain.startswith("http") else domain

        # Screenshot
        png = await take_screenshot(url)
        if png:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.png"
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "technologies",
                "finding_ref": domain,
                "caption": f"Screenshot principal: {domain}",
                "source": "auto", "filename": f"screenshot_{domain}.png",
                "stored_name": fname, "media_type": "image/png",
                "size": len(png), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": True, "is_text": False, "tool": "puppeteer",
            }
            _write_evidence(ev_dir, ev_idx, entry, png)
            new_entries.append(entry)
            await log(f"[EVIDENCE] 📸 Screenshot principal: {domain}")

        # Headers
        headers_text = await _fetch_headers(url)
        if headers_text:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = headers_text.encode("utf-8")
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "technologies",
                "finding_ref": domain,
                "caption": f"HTTP Headers: {domain}",
                "source": "auto", "filename": f"headers_{domain}.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "aiohttp",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    await log(f"[EVIDENCE] ✔ Technologies: {len(new_entries)} evidencia(s)")
    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 7. STRUCTURED output capture (whois, dmarc, dns, asn)
# ─────────────────────────────────────────────────────────────────────────────

def _capture_structured_output(scan_id, module_id, result, ev_dir, ev_idx):
    new_entries = []

    # Build a readable text from the structured data
    if module_id == "whois":
        records = result.get("whois_data", [])
        for rec in records:
            domain = rec.get("domain", "")
            lines  = [f"WHOIS — {domain}", f"Captured: {datetime.now(timezone.utc).isoformat()}", ""]
            for k, v in rec.items():
                if k != "domain":
                    lines.append(f"{k:<20} {v}")
            text = "\n".join(lines)
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = text.encode()
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "whois",
                "finding_ref": domain, "caption": f"WHOIS: {domain}",
                "source": "auto", "filename": f"whois_{domain}.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "whois",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    elif module_id == "dmarc":
        dmarc_records = result.get("dmarc_records", [])
        spf_records   = result.get("spf_records", [])
        all_domains   = set()
        for r in dmarc_records + spf_records:
            all_domains.add(r.get("domain", ""))
        for domain in all_domains:
            if not domain:
                continue
            d_rec = next((r for r in dmarc_records if r.get("domain") == domain), {})
            s_rec = next((r for r in spf_records   if r.get("domain") == domain), {})
            lines = [
                f"DMARC/SPF ANALYSIS — {domain}",
                f"Captured: {datetime.now(timezone.utc).isoformat()}",
                "",
                "── DMARC ──────────────────────────────────────────────────",
                f"Has DMARC  : {d_rec.get('has_dmarc', 'unknown')}",
                f"Policy     : {d_rec.get('policy', 'none')}",
                f"Record     : {d_rec.get('record', '')}",
                f"Issues     : {', '.join(d_rec.get('issues', [])) or 'none'}",
                "",
                "── SPF ────────────────────────────────────────────────────",
                f"Has SPF    : {s_rec.get('has_spf', 'unknown')}",
                f"Record     : {s_rec.get('record', '')}",
                f"Issues     : {', '.join(s_rec.get('issues', [])) or 'none'}",
            ]
            text  = "\n".join(lines)
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = text.encode()
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "dmarc",
                "finding_ref": domain, "caption": f"DMARC/SPF: {domain}",
                "source": "auto", "filename": f"dmarc_{domain}.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "dns_query",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    elif module_id == "dns":
        lines = [
            f"DNS SERVERS — {datetime.now(timezone.utc).isoformat()}",
            "",
            json.dumps(result, indent=2, default=str),
        ]
        text  = "\n".join(lines)
        ev_id = str(uuid.uuid4())
        fname = f"{ev_id}.txt"
        data  = text.encode()
        entry = {
            "id": ev_id, "scan_id": scan_id, "module": "dns",
            "finding_ref": "", "caption": "DNS Servers dump",
            "source": "auto", "filename": "dns_servers.txt",
            "stored_name": fname, "media_type": "text/plain",
            "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_image": False, "is_text": True, "tool": "dns_query",
        }
        _write_evidence(ev_dir, ev_idx, entry, data)
        new_entries.append(entry)

    elif module_id == "asn":
        ip_blocks = result.get("ip_blocks", [])
        if ip_blocks:
            lines = [
                f"ASN / IP BLOCKS — {datetime.now(timezone.utc).isoformat()}",
                "",
                f"{'Domain':<30} {'IP':<18} {'ASN':<10} {'Organization'}",
                "-" * 80,
            ]
            for b in ip_blocks:
                lines.append(
                    f"{b.get('domain',''):<30} {b.get('ip',''):<18} "
                    f"{b.get('asn',''):<10} {b.get('name','')}"
                )
            text  = "\n".join(lines)
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.txt"
            data  = text.encode()
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "asn",
                "finding_ref": "", "caption": "ASN / IP Blocks",
                "source": "auto", "filename": "asn_ip_blocks.txt",
                "stored_name": fname, "media_type": "text/plain",
                "size": len(data), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": False, "is_text": True, "tool": "BGP lookup",
            }
            _write_evidence(ev_dir, ev_idx, entry, data)
            new_entries.append(entry)

    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 8. ROBOTS.TXT: capture screenshot of disallowed paths
# ─────────────────────────────────────────────────────────────────────────────

async def _capture_robots(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    findings = result.get("findings", [])
    disallowed = [f for f in findings if f.get("type") == "disallow_path"]
    if not disallowed:
        return new_entries

    await log(f"[EVIDENCE] Capturando paths de robots.txt ({len(disallowed)})...")
    count = 0
    for f in disallowed[:10]:
        domain = f.get("domain", "")
        path   = f.get("value") or f.get("path", "")
        if not domain or not path:
            continue
        url = f"https://{domain}{path}"
        png = await take_screenshot(url)
        if png:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.png"
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "robots",
                "finding_ref": path,
                "caption": f"robots.txt Disallow: {path}",
                "source": "auto", "filename": f"robots_path_{count}.png",
                "stored_name": fname, "media_type": "image/png",
                "size": len(png), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": True, "is_text": False, "tool": "puppeteer",
            }
            _write_evidence(ev_dir, ev_idx, entry, png)
            new_entries.append(entry)
            count += 1
            await log(f"[EVIDENCE] 📸 robots path: {path}")

    return new_entries


# ─────────────────────────────────────────────────────────────────────────────
# 9. CYBERSQUATTING: screenshot of active squatting domains
# ─────────────────────────────────────────────────────────────────────────────

async def _capture_squatting(scan_id, result, ev_dir, ev_idx, log):
    new_entries = []
    variants = result.get("active_variants", [])
    if not variants:
        return new_entries

    await log(f"[EVIDENCE] Capturando screenshots de dominios de cybersquatting activos...")
    count = 0
    for v in variants[:8]:
        domain = v.get("domain", "")
        if not domain:
            continue
        url = f"https://{domain}"
        png = await take_screenshot(url)
        if not png:
            url = f"http://{domain}"
            png = await take_screenshot(url)
        if png:
            ev_id = str(uuid.uuid4())
            fname = f"{ev_id}.png"
            entry = {
                "id": ev_id, "scan_id": scan_id, "module": "cybersquatting",
                "finding_ref": domain,
                "caption": f"Squatting activo: {domain}",
                "source": "auto", "filename": f"squatting_{domain}.png",
                "stored_name": fname, "media_type": "image/png",
                "size": len(png), "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_image": True, "is_text": False, "tool": "puppeteer",
            }
            _write_evidence(ev_dir, ev_idx, entry, png)
            new_entries.append(entry)
            count += 1
            await log(f"[EVIDENCE] 📸 Squatting: {domain}")

    return new_entries
