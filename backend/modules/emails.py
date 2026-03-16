"""
Módulo: Recolección de Correos Electrónicos — v2
Técnicas:
  1. theHarvester (CLI)
  2. Google Dorks scraping
  3. Bing Dorks scraping
  4. crt.sh — Certificate Transparency logs
  5. WHOIS / DNS TXT
  6. Hunter.io API (si hay key)
  7. Snov.io API   (si hay key)
  8. Have I Been Pwned (si hay key)
  9. IntelligenceX  (si hay key)
 10. Links manuales
"""
import asyncio
import re
import json
import urllib.parse
from typing import List, Dict, Any, Set

from .utils import run_command, http_get, extract_emails, clean_domain

def _keys():
    try:
        import sys, os
        sys.path.insert(0, '/app')
        from keys_manager import get_key
        return get_key
    except ImportError:
        return lambda _: None

EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

def _scrub(emails: Set[str], domain: str) -> Set[str]:
    return {e.lower() for e in emails if domain.lower() in e.lower().split('@')[-1]}

# ── 1. theHarvester ────────────────────────────────────────────────────────────
async def _harvester(domain: str) -> Dict:
    cmd = ["theHarvester", "-d", domain, "-b", "bing,google,yahoo,linkedin", "-l", "200"]
    res = await run_command(cmd, timeout=90)
    emails: Set[str] = set()
    if res["success"] or res["stdout"]:
        emails = set(extract_emails(res["stdout"]))
        return {"status": "ok", "emails": emails}
    return {"status": "unavailable", "emails": emails, "note": "theHarvester no instalado"}

# ── 2 & 3. Google / Bing Dorks ────────────────────────────────────────────────
DORKS = [
    '"{domain}" email',
    '"{domain}" correo',
    '"{domain}" contact',
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xlsx',
    'site:{domain} filetype:docx',
    '"@{domain}"',
]

async def _dork_engine(domain: str, engine: str) -> Dict:
    emails: Set[str] = set()
    base = "https://www.bing.com/search?q={q}&count=50" if engine == "bing" else "https://www.google.com/search?q={q}&num=50&hl=en"

    async def fetch_one(tmpl):
        q = tmpl.format(domain=domain)
        url = base.format(q=urllib.parse.quote(q))
        resp = await http_get(url, timeout=15)
        if resp["success"] and resp["status"] == 200:
            text = re.sub(r'<[^>]+>', ' ', resp["text"])
            text = urllib.parse.unquote(text)
            found = set(EMAIL_RE.findall(text))
            return _scrub(found, domain)
        return set()

    results = await asyncio.gather(*[fetch_one(d) for d in DORKS], return_exceptions=True)
    for r in results:
        if isinstance(r, set):
            emails.update(r)

    return {"status": "ok", "emails": emails, "dorks_run": len(DORKS)}

# ── 4. crt.sh ─────────────────────────────────────────────────────────────────
async def _crtsh(domain: str) -> Dict:
    emails: Set[str] = set()
    url = f"https://crt.sh/?q=%25%40{urllib.parse.quote(domain)}&output=json"
    resp = await http_get(url, timeout=20)
    if resp["success"] and resp["status"] == 200:
        try:
            data = json.loads(resp["text"])
            for entry in data:
                name_value = entry.get("name_value", "")
                for part in name_value.replace('\n', ' ').split():
                    if '@' in part:
                        emails.update(_scrub(set(EMAIL_RE.findall(part)), domain))
            return {"status": "ok", "emails": emails, "certs_checked": len(data)}
        except:
            pass
    # Fallback HTML
    resp2 = await http_get(f"https://crt.sh/?q=%25%40{urllib.parse.quote(domain)}", timeout=20)
    if resp2["success"]:
        raw = re.sub(r'<[^>]+>', ' ', resp2["text"])
        emails = _scrub(set(EMAIL_RE.findall(raw)), domain)
    return {"status": "partial", "emails": emails, "certs_checked": 0}

# ── 5. WHOIS / DNS TXT ────────────────────────────────────────────────────────
async def _whois_dns(domain: str) -> Dict:
    emails: Set[str] = set()

    whois_resp = await http_get(f"https://whois.domaintools.com/{domain}", timeout=15)
    if whois_resp["success"]:
        text = re.sub(r'<[^>]+>', ' ', whois_resp["text"])
        emails.update(_scrub(set(EMAIL_RE.findall(text)), domain))

    cmd_res = await run_command(["dig", "TXT", domain, "+short"], timeout=10)
    if cmd_res["success"]:
        emails.update(set(EMAIL_RE.findall(cmd_res["stdout"])))

    guessed = {f"{p}@{domain}" for p in ["postmaster","abuse","admin","info","contact","security","hostmaster","noreply","support"]}
    return {"status": "ok", "emails": emails, "guessed": guessed}

# ── 6. Hunter.io ──────────────────────────────────────────────────────────────
async def _hunter(domain: str, api_key: str) -> Dict:
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=100"
    resp = await http_get(url, timeout=20)
    emails: Set[str] = set()
    if not resp["success"] or resp["status"] != 200:
        return {"status": "api_error", "emails": emails, "error": f"HTTP {resp['status']}"}
    try:
        data = json.loads(resp["text"])
        if "errors" in data:
            return {"status": "api_error", "emails": emails, "error": str(data["errors"])}
        for e in data.get("data", {}).get("emails", []):
            val = e.get("value", "")
            if val: emails.add(val.lower())
        return {"status": "ok", "emails": emails,
                "pattern": data.get("data", {}).get("pattern", ""),
                "total_known": data.get("meta", {}).get("total", 0)}
    except Exception as e:
        return {"status": "parse_error", "emails": emails, "error": str(e)}

# ── 7. Snov.io ────────────────────────────────────────────────────────────────
async def _snov(domain: str, client_id: str, client_secret: str) -> Dict:
    import aiohttp
    emails: Set[str] = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.snov.io/v1/oauth/access_token",
                data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
                timeout=aiohttp.ClientTimeout(total=15), ssl=False
            ) as r:
                if r.status != 200:
                    return {"status": "api_error", "emails": emails, "error": "Token fallido"}
                token_data = await r.json()
                access_token = token_data.get("access_token")
            if not access_token:
                return {"status": "api_error", "emails": emails, "error": "Token inválido"}
            async with session.get(
                f"https://api.snov.io/v2/domain-emails-with-info?domain={domain}&type=all&limit=100&access_token={access_token}",
                timeout=aiohttp.ClientTimeout(total=20), ssl=False
            ) as r2:
                if r2.status != 200:
                    return {"status": "api_error", "emails": emails, "error": f"HTTP {r2.status}"}
                data = await r2.json()
                for e in data.get("emails", []):
                    val = e.get("email", "")
                    if val: emails.add(val.lower())
        return {"status": "ok", "emails": emails}
    except Exception as e:
        return {"status": "error", "emails": emails, "error": str(e)}

# ── 8. Have I Been Pwned ──────────────────────────────────────────────────────
async def _hibp(domain: str, api_key: str) -> Dict:
    import aiohttp
    emails: Set[str] = set()
    breaches = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key": api_key, "User-Agent": "OSINT-Analyzer/2.0"},
                timeout=aiohttp.ClientTimeout(total=20), ssl=False
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    for email_addr, breach_list in data.items():
                        emails.add(email_addr.lower())
                        for b in breach_list:
                            breaches.append({"email": email_addr, "breach": b})
                    return {"status": "ok", "emails": emails, "breaches": breaches[:50]}
                elif r.status == 404:
                    return {"status": "ok", "emails": emails, "note": "Sin brechas conocidas"}
                else:
                    return {"status": "api_error", "emails": emails, "error": f"HTTP {r.status}"}
    except Exception as e:
        return {"status": "error", "emails": emails, "error": str(e)}

# ── 9. IntelligenceX ──────────────────────────────────────────────────────────
async def _intelx(domain: str, api_key: str) -> Dict:
    import aiohttp
    emails: Set[str] = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://2.intelx.io/intelligent/search",
                json={"term": f"@{domain}", "buckets": [], "lookuplevel": 0,
                      "maxresults": 100, "timeout": 0, "datefrom": "", "dateto": "",
                      "sort": 4, "media": 0, "terminate": []},
                headers={"x-key": api_key, "User-Agent": "OSINT-Analyzer/2.0"},
                timeout=aiohttp.ClientTimeout(total=20), ssl=False
            ) as r:
                if r.status != 200:
                    return {"status": "api_error", "emails": emails, "error": f"HTTP {r.status}"}
                data = await r.json()
                search_id = data.get("id")
            if not search_id:
                return {"status": "api_error", "emails": emails, "error": "No search ID"}
            await asyncio.sleep(2)
            async with session.get(
                f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=100&offset=0",
                headers={"x-key": api_key},
                timeout=aiohttp.ClientTimeout(total=20), ssl=False
            ) as r2:
                if r2.status == 200:
                    rdata = await r2.json()
                    for record in rdata.get("records", []):
                        found = set(EMAIL_RE.findall(record.get("name", "")))
                        emails.update(_scrub(found, domain))
        return {"status": "ok", "emails": emails}
    except Exception as e:
        return {"status": "error", "emails": emails, "error": str(e)}

# ── MAIN RUN ───────────────────────────────────────────────────────────────────
async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    get_key = _keys()
    hunter_key     = get_key("hunter_io")
    hibp_key       = get_key("hibp")
    snov_id        = get_key("snov_io_client")
    snov_sec       = get_key("snov_io_secret")
    intelx_key     = get_key("intelx")

    results = {"summary": "", "findings": [], "emails": [], "breaches": [],
               "guessed": [], "tools": [], "severity": "info"}

    all_emails:   Set[str] = set()
    all_breaches: list     = []
    all_guessed:  Set[str] = set()

    for domain in domains:
        d = clean_domain(domain)

        # 1. theHarvester
        r1 = await _harvester(d)
        all_emails.update(r1["emails"])
        results["tools"].append({"tool": "theHarvester", "status": r1["status"],
            "found": len(r1["emails"]), "note": r1.get("note", f"{len(r1['emails'])} emails")})

        # 2. Google Dorks
        r2 = await _dork_engine(d, "google")
        all_emails.update(r2["emails"])
        results["tools"].append({"tool": "Google Dorks", "status": r2["status"],
            "found": len(r2["emails"]), "note": f"{len(r2['emails'])} emails vía {r2['dorks_run']} dorks"})

        # 3. Bing Dorks
        r3 = await _dork_engine(d, "bing")
        all_emails.update(r3["emails"])
        results["tools"].append({"tool": "Bing Dorks", "status": r3["status"],
            "found": len(r3["emails"]), "note": f"{len(r3['emails'])} emails vía Bing"})

        # 4. crt.sh
        r4 = await _crtsh(d)
        all_emails.update(r4["emails"])
        results["tools"].append({"tool": "crt.sh (CT Logs)", "status": r4["status"],
            "found": len(r4["emails"]), "certs_checked": r4.get("certs_checked", 0),
            "note": f"{len(r4['emails'])} emails en certificados · {r4.get('certs_checked',0)} certs revisados",
            "url": f"https://crt.sh/?q=%25%40{d}"})

        # 5. WHOIS / DNS TXT
        r5 = await _whois_dns(d)
        all_emails.update(r5["emails"])
        all_guessed.update(r5.get("guessed", set()))
        results["tools"].append({"tool": "WHOIS / DNS TXT", "status": r5["status"],
            "found": len(r5["emails"]), "guessed": len(r5.get("guessed", set())),
            "note": f"{len(r5['emails'])} emails reales · {len(r5.get('guessed',set()))} patrones inferidos"})

        # 6. Hunter.io
        if hunter_key:
            r6 = await _hunter(d, hunter_key)
            all_emails.update(r6["emails"])
            results["tools"].append({"tool": "Hunter.io API ✓", "status": r6["status"],
                "found": len(r6["emails"]), "total_known": r6.get("total_known", 0),
                "note": f"Patrón: {r6.get('pattern') or 'N/A'} · Total conocidos: {r6.get('total_known',0)}"})
        else:
            results["tools"].append({"tool": "Hunter.io API", "status": "no_key",
                "url": "https://hunter.io/api-keys", "note": "⚙ Configura API key en Ajustes"})

        # 7. Snov.io
        if snov_id and snov_sec:
            r7 = await _snov(d, snov_id, snov_sec)
            all_emails.update(r7["emails"])
            results["tools"].append({"tool": "Snov.io API ✓", "status": r7["status"],
                "found": len(r7["emails"]), "note": f"{len(r7['emails'])} emails"})
        else:
            results["tools"].append({"tool": "Snov.io API", "status": "no_key",
                "url": "https://app.snov.io/account?type=api", "note": "⚙ Configura API keys en Ajustes"})

        # 8. HIBP
        if hibp_key:
            r8 = await _hibp(d, hibp_key)
            all_emails.update(r8["emails"])
            all_breaches.extend(r8.get("breaches", []))
            results["tools"].append({"tool": "Have I Been Pwned ✓", "status": r8["status"],
                "found": len(r8["emails"]), "breaches": len(r8.get("breaches",[])),
                "note": r8.get("note", f"{len(r8['emails'])} emails · {len(r8.get('breaches',[]))} brechas")})
        else:
            results["tools"].append({"tool": "Have I Been Pwned", "status": "no_key",
                "url": "https://haveibeenpwned.com/API/Key", "note": "⚙ Configura API key en Ajustes"})

        # 9. IntelligenceX
        if intelx_key:
            r9 = await _intelx(d, intelx_key)
            all_emails.update(r9["emails"])
            results["tools"].append({"tool": "IntelligenceX API ✓", "status": r9["status"],
                "found": len(r9["emails"]), "note": f"{len(r9['emails'])} emails"})
        else:
            results["tools"].append({"tool": "IntelligenceX API", "status": "no_key",
                "url": "https://intelx.io/account?tab=developer", "note": "⚙ Configura API key en Ajustes"})

        # 10. Manual refs
        for svc in [
            {"tool": "Phonebook.cz",  "url": f"https://phonebook.cz/?q={d}"},
            {"tool": "Mailshunt",     "url": f"https://mailshunt.com/domain-search?domain={d}"},
            {"tool": "MagicLeaks",    "url": f"https://magicleaks.info/?q={d}"},
        ]:
            results["tools"].append({**svc, "status": "manual_required",
                                     "note": "Ejecutar manualmente en el navegador"})

    # ── build output ──────────────────────────────────────────────────────────
    all_emails_list  = sorted(all_emails)
    all_guessed_list = sorted(all_guessed - all_emails)

    results["emails"]   = all_emails_list
    results["breaches"] = all_breaches
    results["guessed"]  = all_guessed_list

    for email in all_emails_list:
        in_breach = any(b["email"].lower() == email.lower() for b in all_breaches)
        results["findings"].append({
            "type": "email_confirmed", "value": email,
            "severity": "high" if in_breach else "medium",
            "description": "⚠ Encontrado en brecha de datos" if in_breach else "Email corporativo expuesto públicamente",
        })
    for email in all_guessed_list:
        results["findings"].append({
            "type": "email_pattern", "value": email, "severity": "low",
            "description": "Patrón común inferido — verificar manualmente",
        })
    for breach in all_breaches[:20]:
        results["findings"].append({
            "type": "data_breach", "value": f"{breach['email']} → {breach['breach']}",
            "severity": "critical",
            "description": "Email corporativo encontrado en brecha de datos conocida",
        })

    count = len(all_emails_list)
    if all_breaches:         results["severity"] = "critical"
    elif count > 10:         results["severity"] = "high"
    elif count > 0:          results["severity"] = "medium"

    results["summary"] = (
        f"{count} email(s) confirmados · "
        f"{len(all_guessed_list)} patrones inferidos · "
        f"{len(all_breaches)} breach(es) detectados"
    )
    return results
