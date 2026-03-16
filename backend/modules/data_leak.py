"""
Módulo: Data Leak
Herramientas: HaveIBeenPwned API, IntelligenceX, referencias manuales
"""
import asyncio
import json
import re
from typing import List, Dict, Any
from .utils import http_get, clean_domain

BREACH_RISK_KEYWORDS = {
    "critical": ["passwords","password","credentials","credit cards","financial data","bank account","ssn","social security","passport"],
    "high": ["email addresses","usernames","phone numbers","physical addresses","dates of birth","security questions","auth tokens"],
    "medium": ["names","geographic locations","ip addresses","device information","browser info"],
    "low": ["website activity","user agent strings","search history"],
}

def classify_breach_severity(data_classes: List[str], pwn_count: int) -> str:
    lower = [d.lower() for d in data_classes]
    joined = " ".join(lower)
    for kw in BREACH_RISK_KEYWORDS["critical"]:
        if kw in joined: return "critical"
    if pwn_count and pwn_count > 1_000_000:
        for kw in BREACH_RISK_KEYWORDS["high"]:
            if kw in joined: return "critical"
        return "high"
    for kw in BREACH_RISK_KEYWORDS["high"]:
        if kw in joined: return "high"
    if pwn_count and pwn_count > 100_000:
        return "high"
    for kw in BREACH_RISK_KEYWORDS["medium"]:
        if kw in joined: return "medium"
    return "low"

def strip_html(text: str) -> str:
    return re.sub(r'<[^>]+>', '', text or '')

async def check_hibp_domain(domain: str) -> Dict[str, Any]:
    """Check HaveIBeenPwned breach list for breaches matching domain."""
    resp = await http_get("https://haveibeenpwned.com/api/v3/breaches", timeout=20)

    if resp["success"] and resp["status"] == 200:
        try:
            all_breaches = json.loads(resp["text"])
            relevant = []
            domain_clean = domain.lower()
            base = domain_clean.split(".")[0]
            for breach in all_breaches:
                breach_domain = breach.get("Domain", "").lower()
                breach_name   = breach.get("Name", "").lower()
                if (domain_clean in breach_domain or breach_domain in domain_clean
                        or base in breach_name):
                    data_classes = breach.get("DataClasses", [])
                    pwn_count    = breach.get("PwnCount", 0)
                    is_verified  = breach.get("IsVerified", False)
                    is_sensitive = breach.get("IsSensitive", False)
                    is_fabricated= breach.get("IsFabricated", False)
                    logo_url     = breach.get("LogoPath", "")
                    desc_raw     = breach.get("Description", "")
                    desc_clean   = strip_html(desc_raw)[:400]

                    severity = classify_breach_severity(data_classes, pwn_count)
                    if is_sensitive: severity = "critical"

                    relevant.append({
                        "name":         breach.get("Name"),
                        "title":        breach.get("Title", breach.get("Name")),
                        "date":         breach.get("BreachDate"),
                        "added_date":   breach.get("AddedDate", ""),
                        "modified_date":breach.get("ModifiedDate", ""),
                        "pwn_count":    pwn_count,
                        "data_classes": data_classes,
                        "description":  desc_clean,
                        "is_verified":  is_verified,
                        "is_sensitive": is_sensitive,
                        "is_fabricated":is_fabricated,
                        "is_spam_list": breach.get("IsSpamList", False),
                        "logo_url":     logo_url,
                        "breach_domain":breach.get("Domain", ""),
                        "severity":     severity,
                        "risk_reason":  f"Exposes: {', '.join(data_classes[:5])}" if data_classes else "Unknown data types",
                    })
            return {"domain": domain, "breaches": relevant, "status": "ok", "total_checked": len(all_breaches)}
        except Exception as e:
            pass

    return {
        "domain": domain,
        "status": "api_key_required",
        "note": "HIBP requiere API key para búsqueda por dominio",
        "manual_url": f"https://haveibeenpwned.com/DomainSearch",
        "breaches": []
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "breach_data": [],
        "tools": [],
        "severity": "info"
    }

    total_breaches = 0
    max_severity = "info"
    sev_order = ["info", "low", "medium", "high", "critical"]

    for domain in domains:
        d = clean_domain(domain)
        hibp_result = await check_hibp_domain(d)
        results["breach_data"].append(hibp_result)

        breaches = hibp_result.get("breaches", [])
        if breaches:
            total_breaches += len(breaches)
            for breach in breaches:
                sev = breach.get("severity", "medium")
                if sev_order.index(sev) > sev_order.index(max_severity):
                    max_severity = sev

                pwn_count = breach.get("pwn_count", 0)
                pwn_fmt = f"{pwn_count:,}" if pwn_count else "Unknown"

                results["findings"].append({
                    "type":        "data_breach",
                    "domain":      d,
                    "value":       breach.get("title") or breach.get("name"),
                    "breach_name": breach.get("name"),
                    "breach_title":breach.get("title"),
                    "date":        breach.get("date"),
                    "added_date":  breach.get("added_date"),
                    "records":     pwn_count,
                    "records_fmt": pwn_fmt,
                    "data_types":  breach.get("data_classes", []),
                    "description": breach.get("description"),
                    "is_verified": breach.get("is_verified"),
                    "is_sensitive":breach.get("is_sensitive"),
                    "is_fabricated":breach.get("is_fabricated"),
                    "risk_reason": breach.get("risk_reason"),
                    "breach_domain": breach.get("breach_domain"),
                    "severity":    sev,
                })

        tool_refs = [
            ("HaveIBeenPwned Domain Search", f"https://haveibeenpwned.com/DomainSearch"),
            ("IntelligenceX",                f"https://intelx.io/?s={d}"),
            ("Databreaches.net",             "https://www.databreaches.net/"),
            ("CSE Google Leaks",             f"https://cse.google.com/cse?cx=013305635491195529773:0ufpuq-fpt0&q={d}+breach"),
            ("Cracking Drift",               f"https://www.crackingdrift.to/search?q={d}"),
            ("Information is Beautiful",     "https://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/"),
        ]
        for tool_name, url in tool_refs:
            results["tools"].append({
                "tool": tool_name, "domain": d,
                "status": "manual_required", "url": url
            })

    if total_breaches > 5 or max_severity == "critical":
        results["severity"] = "critical"
    elif total_breaches > 0 or max_severity in ("high", "medium"):
        results["severity"] = max_severity if max_severity != "info" else "high"

    results["summary"] = (
        f"{total_breaches} brecha(s) de datos identificada(s) para {len(domains)} dominio(s). "
        + (f"Severidad máxima: {max_severity.upper()}. " if total_breaches > 0 else "")
        + "Verificar manualmente en HIBP, IntelligenceX y CSE Google para resultados completos."
    )
    return results
