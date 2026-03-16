"""
Módulo: Análisis de FAVICON
Herramientas: MurmurHash, Shodan (manual)
"""
import asyncio
import hashlib
import struct
import base64
import mmh3
from typing import List, Dict, Any
from .utils import http_get, clean_domain

async def get_favicon_hash(domain: str) -> Dict[str, Any]:
    """Calculate favicon MurmurHash for Shodan search."""
    favicon_urls = [
        f"https://{domain}/favicon.ico",
        f"https://{domain}/images/favicon.ico",
        f"https://{domain}/static/favicon.ico",
    ]
    
    for url in favicon_urls:
        resp = await http_get(url, timeout=10)
        if resp.get("success") and resp.get("status") == 200:
            content = resp.get("text", "")
            if content:
                try:
                    # Calculate MurmurHash3 (used by Shodan)
                    favicon_b64 = base64.encodebytes(content.encode('latin-1', errors='replace'))
                    hash_value = mmh3.hash(favicon_b64)
                    return {
                        "domain": domain,
                        "favicon_url": url,
                        "murmurhash": hash_value,
                        "shodan_query": f"http.favicon.hash:{hash_value}",
                        "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash:{hash_value}",
                        "status": "ok"
                    }
                except Exception as e:
                    return {"domain": domain, "status": "hash_error", "error": str(e)}
    
    return {"domain": domain, "status": "no_favicon"}

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "favicon_data": [],
        "tools": [],
        "severity": "info"
    }

    for domain in domains:
        d = clean_domain(domain)
        fav_data = await get_favicon_hash(d)
        results["favicon_data"].append(fav_data)

        if fav_data.get("status") == "ok":
            hash_val = fav_data.get("murmurhash")
            results["findings"].append({
                "type": "favicon_hash",
                "domain": d,
                "hash": hash_val,
                "shodan_url": fav_data.get("shodan_url"),
                "description": "Usar hash en Shodan para encontrar infraestructura relacionada",
                "severity": "info"
            })
            results["tools"].append({
                "tool": "Shodan FAVICON",
                "domain": d,
                "status": "manual_required",
                "url": fav_data.get("shodan_url"),
                "hash": hash_val,
                "note": f"Buscar en Shodan: http.favicon.hash:{hash_val}"
            })

    results["summary"] = f"Análisis de FAVICON completado para {len(domains)} dominio(s)."
    return results
