"""
Módulo: Identificación de Servidores DNS & MX
Herramientas: dig, dnsmap, dnscan
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import run_command, clean_domain, resolve_domain

async def query_dns_records(domain: str, record_type: str) -> Dict[str, Any]:
    """Query DNS records using dig."""
    res = await run_command(["dig", record_type, domain, "+short", "+time=5"], timeout=15)
    records = []
    if res["success"] and res["stdout"].strip():
        records = [r.strip() for r in res["stdout"].strip().splitlines() if r.strip()]
    return {
        "type": record_type,
        "domain": domain,
        "records": records,
        "count": len(records)
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "dns_data": [],
        "tools": [],
        "severity": "info"
    }

    for domain in domains:
        d = clean_domain(domain)
        domain_dns = {"domain": d, "records": {}}

        # Query all important record types
        record_types = ["NS", "MX", "A", "AAAA", "TXT", "SOA", "CNAME", "PTR"]
        tasks = [query_dns_records(d, rt) for rt in record_types]
        dns_results = await asyncio.gather(*tasks, return_exceptions=True)

        for dr in dns_results:
            if isinstance(dr, dict):
                domain_dns["records"][dr["type"]] = dr["records"]

        # Zone transfer attempt (AXFR)
        ns_servers = domain_dns["records"].get("NS", [])
        axfr_results = []
        for ns in ns_servers[:3]:
            ns_clean = ns.rstrip(".")
            axfr_res = await run_command(["dig", "axfr", d, f"@{ns_clean}", "+time=10"], timeout=20)
            if axfr_res["success"] and axfr_res["stdout"]:
                if "Transfer failed" not in axfr_res["stdout"] and "connection refused" not in axfr_res["stdout"].lower():
                    # Successful zone transfer is a critical finding
                    lines = [l for l in axfr_res["stdout"].splitlines() if l.strip() and not l.startswith(";")]
                    if len(lines) > 5:
                        axfr_results.append({
                            "ns": ns_clean,
                            "success": True,
                            "records_count": len(lines),
                            "sample": lines[:10]
                        })
                        results["findings"].append({
                            "type": "zone_transfer",
                            "domain": d,
                            "ns": ns_clean,
                            "severity": "critical",
                            "description": f"Transferencia de zona exitosa desde {ns_clean} - expone todos los registros DNS"
                        })

        domain_dns["zone_transfer_attempts"] = axfr_results

        # Check for open DNS resolvers
        open_resolver_check = await run_command(
            ["dig", "+short", "test.openresolver.com", "TXT", f"@{d}", "+time=5"],
            timeout=10
        )
        domain_dns["open_resolver"] = (
            open_resolver_check["success"] and 
            "open-resolver" in open_resolver_check["stdout"].lower()
        )
        
        if domain_dns["open_resolver"]:
            results["findings"].append({
                "type": "open_dns_resolver",
                "domain": d,
                "severity": "high",
                "description": "El servidor DNS es un resolver abierto - puede ser usado en ataques DDoS de amplificación"
            })

        results["dns_data"].append(domain_dns)

        # Tools references
        results["tools"].append({"tool": "dig", "domain": d, "status": "executed"})
        results["tools"].append({
            "tool": "Dnsmap",
            "domain": d,
            "status": "manual_required",
            "note": f"dnsmap {d}"
        })

    # Severity
    if any(f.get("severity") == "critical" for f in results["findings"]):
        results["severity"] = "critical"
    elif any(f.get("severity") == "high" for f in results["findings"]):
        results["severity"] = "high"
    elif results["dns_data"]:
        results["severity"] = "info"

    zone_transfers = sum(1 for f in results["findings"] if f.get("type") == "zone_transfer")
    results["summary"] = (
        f"Registros DNS analizados para {len(domains)} dominio(s). "
        f"{zone_transfers} transferencia(s) de zona exitosa(s) detectada(s). "
        f"{len(results['findings'])} hallazgo(s) identificado(s)."
    )

    return results
