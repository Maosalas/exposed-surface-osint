"""
Módulo: ASN (Autonomous System Number)
Herramientas: BGP Toolkit, BGPView, HackerTarget, OWASP Amass
"""
import asyncio
import json
from typing import List, Dict, Any
from .utils import http_get, clean_domain, resolve_domain

async def lookup_asn_bgpview(ip: str) -> Dict[str, Any]:
    """Lookup ASN via BGPView API."""
    resp = await http_get(f"https://api.bgpview.io/ip/{ip}", timeout=15)
    if resp["success"] and resp["status"] == 200:
        try:
            data = json.loads(resp["text"])
            prefixes = data.get("data", {}).get("prefixes", [])
            if prefixes:
                asn_data = prefixes[0].get("asn", {})
                return {
                    "ip": ip,
                    "asn": asn_data.get("asn"),
                    "asn_name": asn_data.get("name", ""),
                    "asn_description": asn_data.get("description_short", ""),
                    "prefix": prefixes[0].get("prefix", ""),
                    "country": prefixes[0].get("country_code", ""),
                    "source": "bgpview",
                    "status": "ok"
                }
        except:
            pass
    return {"ip": ip, "status": "error", "source": "bgpview"}

async def lookup_asn_hackertarget(domain: str) -> Dict[str, Any]:
    """Lookup ASN via HackerTarget API."""
    resp = await http_get(f"https://api.hackertarget.com/aslookup/?q={domain}", timeout=15)
    if resp["success"] and resp["status"] == 200 and resp["text"]:
        text = resp["text"].strip()
        if "error" not in text.lower() and text:
            parts = text.split(",")
            if len(parts) >= 2:
                return {
                    "domain": domain,
                    "asn": parts[0].strip() if parts[0] else "",
                    "ip_range": parts[1].strip() if len(parts) > 1 else "",
                    "org": parts[2].strip() if len(parts) > 2 else "",
                    "country": parts[3].strip() if len(parts) > 3 else "",
                    "source": "hackertarget",
                    "status": "ok"
                }
    return {"domain": domain, "status": "error", "source": "hackertarget"}

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "asn_data": [],
        "ip_blocks": [],
        "tools": [],
        "severity": "info"
    }

    seen_asns = set()

    for domain in domains:
        d = clean_domain(domain)

        # Resolve IP
        ip = await resolve_domain(d)
        if not ip:
            results["asn_data"].append({"domain": d, "ip": None, "status": "unresolved"})
            continue

        # BGPView lookup
        bgpview_data = await lookup_asn_bgpview(ip)
        bgpview_data["domain"] = d
        
        # HackerTarget lookup
        ht_data = await lookup_asn_hackertarget(d)

        asn_entry = {
            "domain": d,
            "ip": ip,
            "bgpview": bgpview_data,
            "hackertarget": ht_data
        }

        # Consolidate ASN info
        asn_num = bgpview_data.get("asn") or ht_data.get("asn", "")
        asn_name = bgpview_data.get("asn_name") or ht_data.get("org", "")
        
        if asn_num:
            asn_entry["asn"] = asn_num
            asn_entry["asn_name"] = asn_name
            asn_entry["prefix"] = bgpview_data.get("prefix", ht_data.get("ip_range", ""))
            
            if asn_num not in seen_asns:
                seen_asns.add(asn_num)
                results["ip_blocks"].append({
                    "asn": asn_num,
                    "name": asn_name,
                    "prefix": asn_entry["prefix"],
                    "domain": d,
                    "ip": ip
                })

        results["asn_data"].append(asn_entry)

        # Reference tools
        results["tools"].append({
            "tool": "BGP.he.net",
            "status": "manual_required",
            "url": f"https://bgp.he.net/ip/{ip}#_prefixes"
        })
        results["tools"].append({
            "tool": "BGPView",
            "status": "manual_required",
            "url": f"https://bgpview.io/ip/{ip}"
        })
        results["tools"].append({
            "tool": "HackerTarget ASN",
            "status": "executed",
            "url": f"https://hackertarget.com/as-ip-lookup/?q={d}"
        })
        results["tools"].append({
            "tool": "OWASP Amass ASN",
            "status": "manual_required",
            "note": f"amass intel -asn <ASN_NUMBER>"
        })

    results["severity"] = "info"
    results["summary"] = (
        f"ASN identificado para {len(results['asn_data'])} dominio(s). "
        f"{len(seen_asns)} bloque(s) ASN único(s) encontrado(s): "
        f"{', '.join(str(a) for a in seen_asns) if seen_asns else 'Ninguno'}"
    )

    return results
