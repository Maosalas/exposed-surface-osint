"""
Módulo: Cybersquatting
Herramientas: dnstwist, phishydomains, urlcrazy, dnstwister
"""
import asyncio
import json
import re
from typing import List, Dict, Any
from .utils import run_command, http_get, clean_domain, resolve_domain, check_url_alive
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools_client import run_tool as _ext_tool, is_available as _tools_up

async def run_dnstwist(domain: str) -> Dict[str, Any]:
    """Run dnstwist to find cybersquatting domains."""
    res = await run_command(
        ["dnstwist", "--registered", "--format", "json", domain],
        timeout=120
    )
    
    if res["success"] and res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            variants = []
            for entry in data:
                fuzzer = entry.get("fuzzer", "")
                dom = entry.get("domain", "")
                dns_a = entry.get("dns_a", [])
                mx = entry.get("dns_mx", [])
                
                if dom and dom != domain:
                    variants.append({
                        "domain": dom,
                        "fuzzer": fuzzer,
                        "ips": dns_a,
                        "has_mx": bool(mx),
                        "alive": bool(dns_a),
                        "risk": assess_squatting_risk(dom, domain, dns_a, mx)
                    })
            return {"status": "ok", "variants": variants}
        except json.JSONDecodeError:
            # Try parsing plain text output
            pass
    
    # If not available, generate common variants manually
    return await generate_manual_variants(domain)

async def generate_manual_variants(domain: str) -> Dict[str, Any]:
    """Generate common typosquatting variants manually."""
    parts = domain.rsplit(".", 1)
    name = parts[0] if len(parts) > 1 else domain
    tld = parts[1] if len(parts) > 1 else "com"
    
    variants = []
    
    # TLD variations
    alt_tlds = ["com", "net", "org", "co", "info", "biz", "io", "co.cr", "com.mx"]
    for alt_tld in alt_tlds:
        if alt_tld != tld:
            variants.append({"domain": f"{name}.{alt_tld}", "fuzzer": "tld-swap"})
    
    # Common typos
    typos = []
    for i in range(len(name)):
        # Character omission
        typo = name[:i] + name[i+1:]
        if typo:
            typos.append(f"{typo}.{tld}")
        # Repeated character
        typos.append(f"{name[:i]}{name[i]}{name[i:]}.{tld}")
    
    for t in typos[:10]:
        variants.append({"domain": t, "fuzzer": "typo"})
    
    # Prefix/suffix variations
    for affix in ["www", "mail", "secure", "login", "my", "account"]:
        variants.append({"domain": f"{affix}-{name}.{tld}", "fuzzer": "prefix"})
        variants.append({"domain": f"{name}-{affix}.{tld}", "fuzzer": "suffix"})
    
    # Check which are registered
    check_tasks = []
    unique_variants = list({v["domain"] for v in variants[:30]})
    for var_domain in unique_variants:
        check_tasks.append(resolve_domain(var_domain))
    
    ips = await asyncio.gather(*check_tasks, return_exceptions=True)
    
    results_variants = []
    for var_domain, ip in zip(unique_variants, ips):
        if isinstance(ip, str) and ip:
            fuzzer_type = next((v["fuzzer"] for v in variants if v["domain"] == var_domain), "unknown")
            results_variants.append({
                "domain": var_domain,
                "fuzzer": fuzzer_type,
                "ips": [ip],
                "alive": True,
                "has_mx": False,
                "risk": "medium"
            })
    
    return {"status": "manual_variants", "variants": results_variants}

def assess_squatting_risk(variant: str, original: str, ips: list, mx: list) -> str:
    """Assess risk level of a cybersquatting domain."""
    if not ips:
        return "low"
    
    risky_keywords = ["login", "secure", "account", "bank", "pay", "signin", "verify"]
    if any(kw in variant.lower() for kw in risky_keywords):
        return "critical"
    
    if mx:  # Has email server - potential phishing
        return "high"
    
    return "medium"

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "cybersquatting_data": [],
        "active_variants": [],
        "tools": [],
        "severity": "info"
    }

    total_active = 0
    total_critical = 0

    for domain in domains:
        d = clean_domain(domain)

        twist_result = await run_dnstwist(d)

        # osint-tools dnstwist (more thorough, with --registered flag)
        if await _tools_up():
            ext_twist = await _ext_tool("dnstwist", {"domain": d}, timeout=150)
            for f in ext_twist.get("findings", []):
                results["findings"].append({**f, "source": "dnstwist_ext"})
            for v in ext_twist.get("active_variants", []):
                results.setdefault("active_variants", []).append(v)
        variants = twist_result.get("variants", [])
        
        entry = {
            "domain": d,
            "variants_found": len(variants),
            "active_variants": [v for v in variants if v.get("alive")],
            "all_variants": variants,
            "source": twist_result.get("status")
        }
        
        results["cybersquatting_data"].append(entry)
        
        for variant in variants:
            if variant.get("alive"):
                total_active += 1
                risk = variant.get("risk", "medium")
                
                if risk in ["critical", "high"]:
                    total_critical += 1
                
                results["active_variants"].append({
                    "original_domain": d,
                    **variant
                })
                
                results["findings"].append({
                    "type": "cybersquatting",
                    "original_domain": d,
                    "squatted_domain": variant["domain"],
                    "fuzzer": variant.get("fuzzer"),
                    "ips": variant.get("ips", []),
                    "has_mx": variant.get("has_mx", False),
                    "severity": risk
                })

        # Reference tools
        results["tools"].append({
            "tool": "DNSTwist",
            "domain": d,
            "status": "executed" if twist_result.get("status") == "ok" else "manual_required",
            "url": f"https://dnstwist.it/?d={d}"
        })
        results["tools"].append({
            "tool": "DNSTwister",
            "domain": d,
            "status": "manual_required",
            "url": f"https://dnstwister.report/search/?q={d}"
        })
        results["tools"].append({
            "tool": "Phishy Domains",
            "status": "manual_required",
            "url": f"https://phishydomains.com/"
        })
        results["tools"].append({
            "tool": "DomainTools",
            "status": "manual_required",
            "url": "https://www.domaintools.com/"
        })

    # Severity
    if total_critical > 0:
        results["severity"] = "critical"
    elif total_active > 5:
        results["severity"] = "high"
    elif total_active > 0:
        results["severity"] = "medium"

    results["summary"] = (
        f"Análisis de Cybersquatting completado. "
        f"{total_active} dominio(s) variante activo(s) encontrado(s). "
        f"{total_critical} con riesgo crítico/alto (posible phishing)."
    )

    return results
