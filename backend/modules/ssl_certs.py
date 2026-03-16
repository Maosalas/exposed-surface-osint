"""
Módulo: Análisis de Certificados SSL/TLS
Herramientas: crt.sh, Google Transparency, Censys, análisis manual
"""
import asyncio
import json
import ssl
import socket
from datetime import datetime
from typing import List, Dict, Any
from .utils import http_get, clean_domain, run_command

async def get_cert_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate info directly from the domain."""
    try:
        loop = asyncio.get_event_loop()
        def _get_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cert, cipher, version
        cert, cipher, version = await loop.run_in_executor(None, _get_cert)
        
        # Parse expiry
        expiry_str = cert.get("notAfter", "")
        expiry_dt = None
        days_left = None
        if expiry_str:
            try:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_dt - datetime.utcnow()).days
            except:
                pass

        san = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                san.append(val)

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        return {
            "domain": domain,
            "subject_cn": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "valid_from": cert.get("notBefore", ""),
            "valid_until": expiry_str,
            "days_left": days_left,
            "san": san,
            "tls_version": version,
            "cipher": cipher[0] if cipher else "",
            "expired": days_left is not None and days_left < 0,
            "expiring_soon": days_left is not None and 0 <= days_left <= 30,
            "status": "ok"
        }
    except ssl.SSLError as e:
        return {"domain": domain, "status": "ssl_error", "error": str(e)}
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e)}

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "certificates": [],
        "subdomains_via_ct": [],
        "tools": [],
        "severity": "info"
    }

    all_ct_domains = set()
    issues = []

    for domain in domains:
        d = clean_domain(domain)

        # Direct SSL inspection
        cert_info = await get_cert_info(d)
        results["certificates"].append(cert_info)

        if cert_info.get("expired"):
            issues.append(f"Certificado EXPIRADO en {d}")
            results["findings"].append({"type": "ssl_expired", "domain": d, "severity": "high"})
        elif cert_info.get("expiring_soon"):
            issues.append(f"Certificado próximo a vencer ({cert_info.get('days_left')} días) en {d}")
            results["findings"].append({"type": "ssl_expiring", "domain": d, "days_left": cert_info.get("days_left"), "severity": "medium"})

        # crt.sh CT logs
        crt_result = {"tool": "crt.sh", "domain": d, "output": [], "status": ""}
        resp = await http_get(f"https://crt.sh/?q=%25.{d}&output=json", timeout=15)
        if resp["success"] and resp["status"] == 200:
            try:
                crt_data = json.loads(resp["text"])
                subs = set()
                for entry in crt_data[:200]:
                    name = entry.get("name_value", "")
                    issuer = entry.get("issuer_name", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub and d in sub:
                            subs.add(sub)
                all_ct_domains.update(subs)
                crt_result["output"] = list(subs)[:50]
                crt_result["count"] = len(subs)
                crt_result["status"] = "ok"
            except:
                crt_result["status"] = "parse_error"
        else:
            crt_result["status"] = "error"
        results["tools"].append(crt_result)

        # Reference tools
        results["tools"].append({
            "tool": "Google Transparency Report",
            "status": "manual_required",
            "url": f"https://transparencyreport.google.com/https/certificates?cert_search_auth=&cert_search_cert=&cert_search=include_subdomains:true;domain:{d}&include_subdomains:true;domain:{d}"
        })
        results["tools"].append({
            "tool": "Censys",
            "status": "manual_required",
            "url": f"https://censys.io/certificates?q={d}"
        })

    results["subdomains_via_ct"] = list(all_ct_domains)

    severity = "info"
    if any(f.get("severity") == "high" for f in results["findings"]):
        severity = "high"
    elif any(f.get("severity") == "medium" for f in results["findings"]):
        severity = "medium"
    elif all_ct_domains:
        severity = "low"
    
    results["severity"] = severity
    issue_text = ". ".join(issues) if issues else "Sin problemas críticos detectados"
    results["summary"] = f"Análisis SSL/TLS completado. {len(results['certificates'])} certificado(s) inspeccionado(s), {len(all_ct_domains)} dominio(s) en CT logs. {issue_text}"

    return results
