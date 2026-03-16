"""
Módulo: WHOIS
Herramientas: whois (CLI), whois.domaintools.com, lookup.icann.org
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import run_command, http_get, clean_domain

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "whois_data": [],
        "tools": [],
        "severity": "info"
    }

    for domain in domains:
        d = clean_domain(domain)
        entry = {"domain": d, "data": {}, "raw": "", "emails": [], "registrar": "", "expiry": ""}

        # CLI whois
        res = await run_command(["whois", d], timeout=20)
        if res["success"] and res["stdout"]:
            raw = res["stdout"]
            entry["raw"] = raw[:3000]
            
            # Extract key fields
            registrar = re.search(r'(?i)registrar:\s*(.+)', raw)
            if registrar:
                entry["registrar"] = registrar.group(1).strip()
            
            expiry = re.search(r'(?i)(expir[yed\s]+date|registry expiry):\s*(.+)', raw)
            if expiry:
                entry["expiry"] = expiry.group(2).strip()
            
            created = re.search(r'(?i)(creation date|created):\s*(.+)', raw)
            if created:
                entry["created"] = created.group(2).strip()
            
            org = re.search(r'(?i)(org|organization|registrant organization):\s*(.+)', raw)
            if org:
                entry["org"] = org.group(2).strip()
            
            country = re.search(r'(?i)(registrant country|country):\s*(.+)', raw)
            if country:
                entry["country"] = country.group(2).strip()

            # Extract emails
            email_pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
            emails = list(set(re.findall(email_pattern, raw)))
            entry["emails"] = emails
            
            if emails:
                results["findings"].extend([{"type": "whois_email", "domain": d, "value": e} for e in emails])

            entry["status"] = "ok"
        else:
            entry["status"] = "unavailable"
            entry["note"] = "whois CLI no disponible"

        # ICANN Lookup reference
        entry["icann_url"] = f"https://lookup.icann.org/lookup?name={d}"
        entry["domaintools_url"] = f"https://whois.domaintools.com/{d}"

        results["whois_data"].append(entry)
        results["tools"].append({"tool": "whois CLI", "domain": d, "status": entry["status"]})
        results["tools"].append({
            "tool": "ICANN Lookup", "domain": d, "status": "manual_required",
            "url": f"https://lookup.icann.org/lookup?name={d}"
        })
        results["tools"].append({
            "tool": "DomainTools", "domain": d, "status": "manual_required",
            "url": f"https://whois.domaintools.com/{d}"
        })

    # Assess severity
    all_emails = []
    for w in results["whois_data"]:
        all_emails.extend(w.get("emails", []))
    
    if all_emails:
        results["severity"] = "medium"
        results["summary"] = f"WHOIS analizado para {len(domains)} dominio(s). Se encontraron {len(all_emails)} email(s) expuesto(s) en registros WHOIS."
    else:
        results["summary"] = f"WHOIS analizado para {len(domains)} dominio(s). Sin información de contacto expuesta."

    return results
