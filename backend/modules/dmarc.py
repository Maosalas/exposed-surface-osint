"""
Módulo: Registros DMARC
Herramientas: dnscan, mxtoolbox, análisis DNS directo
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import run_command, http_get, clean_domain

async def query_dmarc(domain: str) -> Dict[str, Any]:
    """Query DMARC record via dig."""
    dmarc_domain = f"_dmarc.{domain}"
    res = await run_command(["dig", "TXT", dmarc_domain, "+short"], timeout=10)
    
    if res["success"] and res["stdout"].strip():
        raw = res["stdout"].strip().replace('"', '')
        
        if "v=DMARC1" not in raw.upper():
            return {"domain": domain, "has_dmarc": False, "raw": raw}
        
        # Parse DMARC tags
        policy = re.search(r'p=(\w+)', raw, re.IGNORECASE)
        sp = re.search(r'sp=(\w+)', raw, re.IGNORECASE)
        pct = re.search(r'pct=(\d+)', raw, re.IGNORECASE)
        rua = re.search(r'rua=([^;]+)', raw, re.IGNORECASE)
        ruf = re.search(r'ruf=([^;]+)', raw, re.IGNORECASE)
        adkim = re.search(r'adkim=([rs])', raw, re.IGNORECASE)
        aspf = re.search(r'aspf=([rs])', raw, re.IGNORECASE)

        p_val = policy.group(1).lower() if policy else "none"
        pct_val = int(pct.group(1)) if pct else 100

        issues = []
        if p_val == "none":
            issues.append("Política DMARC en 'none' - solo monitoreo, sin protección activa")
        elif p_val == "quarantine":
            issues.append("Política en 'quarantine' - considerar 'reject' para mayor seguridad")
        if pct_val < 100:
            issues.append(f"pct={pct_val}% - no se aplica a todos los correos")
        if not rua:
            issues.append("Sin dirección rua configurada - no se reciben reportes agregados")

        return {
            "domain": domain,
            "has_dmarc": True,
            "raw": raw,
            "policy": p_val,
            "subdomain_policy": sp.group(1) if sp else p_val,
            "pct": pct_val,
            "rua": rua.group(1) if rua else None,
            "ruf": ruf.group(1) if ruf else None,
            "adkim": adkim.group(1) if adkim else "r",
            "aspf": aspf.group(1) if aspf else "r",
            "issues": issues,
            "status": "ok"
        }
    else:
        return {
            "domain": domain,
            "has_dmarc": False,
            "status": "not_found",
            "issues": ["No se encontró registro DMARC - dominio vulnerable a spoofing"]
        }

async def query_spf(domain: str) -> Dict[str, Any]:
    """Query SPF record."""
    res = await run_command(["dig", "TXT", domain, "+short"], timeout=10)
    if res["success"] and res["stdout"]:
        lines = res["stdout"].strip().split("\n")
        for line in lines:
            if "v=spf1" in line.lower():
                spf_raw = line.replace('"', '')
                issues = []
                if "+all" in spf_raw:
                    issues.append("CRÍTICO: '+all' permite cualquier servidor enviar correo en nombre del dominio")
                elif "~all" in spf_raw:
                    issues.append("SPF softfail (~all) - considerar usar '-all'")
                elif "-all" not in spf_raw:
                    issues.append("Sin mecanismo 'all' definido correctamente")
                return {"domain": domain, "has_spf": True, "raw": spf_raw, "issues": issues}
    return {"domain": domain, "has_spf": False, "issues": ["No se encontró registro SPF"]}

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "dmarc_records": [],
        "spf_records": [],
        "tools": [],
        "severity": "info"
    }

    critical_issues = []
    all_issues = []

    for domain in domains:
        d = clean_domain(domain)

        dmarc_info = await query_dmarc(d)
        results["dmarc_records"].append(dmarc_info)

        spf_info = await query_spf(d)
        results["spf_records"].append(spf_info)

        if not dmarc_info.get("has_dmarc"):
            critical_issues.append(f"{d}: Sin DMARC")
            results["findings"].append({
                "type": "no_dmarc", "domain": d, 
                "severity": "high",
                "description": "Dominio sin registro DMARC - vulnerable a email spoofing"
            })
        else:
            for issue in dmarc_info.get("issues", []):
                all_issues.append(f"{d}: {issue}")
                results["findings"].append({
                    "type": "dmarc_issue", "domain": d,
                    "severity": "medium" if dmarc_info.get("policy") == "none" else "low",
                    "description": issue
                })

        if not spf_info.get("has_spf"):
            critical_issues.append(f"{d}: Sin SPF")
            results["findings"].append({
                "type": "no_spf", "domain": d,
                "severity": "high",
                "description": "Dominio sin registro SPF"
            })
        else:
            for issue in spf_info.get("issues", []):
                results["findings"].append({
                    "type": "spf_issue", "domain": d,
                    "severity": "critical" if "+all" in issue else "medium",
                    "description": issue
                })

        # Reference tools
        for tool_name, url in [
            ("Mxtoolbox DMARC", f"https://mxtoolbox.com/dmarc.aspx"),
            ("DMARCIAN", f"https://dmarcian.com/"),
            ("DMARCMonitor", f"https://analyzer.dmarcmonitor.net/check-domain"),
            ("DNSChecker", f"https://dnschecker.org/dmarc-record-validation.php"),
        ]:
            results["tools"].append({
                "tool": tool_name, "domain": d,
                "status": "manual_required", "url": url
            })

    # Severity
    has_critical = any(f.get("severity") in ["critical", "high"] for f in results["findings"])
    has_medium = any(f.get("severity") == "medium" for f in results["findings"])
    
    if has_critical:
        results["severity"] = "high"
    elif has_medium:
        results["severity"] = "medium"
    else:
        results["severity"] = "low"

    no_dmarc_count = sum(1 for d in results["dmarc_records"] if not d.get("has_dmarc"))
    results["summary"] = (
        f"DMARC/SPF analizado para {len(domains)} dominio(s). "
        f"{no_dmarc_count} dominio(s) sin DMARC configurado. "
        f"{len(critical_issues)} problema(s) crítico(s) encontrado(s)."
    )

    return results
