"""
Módulo: Site Map
Herramientas: Análisis manual de /sitemap.xml
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import http_get, clean_domain

async def parse_sitemap(url: str, depth: int = 0) -> Dict[str, Any]:
    """Fetch and parse sitemap XML."""
    if depth > 2:
        return {"url": url, "urls": [], "status": "max_depth"}
    
    resp = await http_get(url, timeout=15)
    if not resp["success"] or resp["status"] != 200:
        return {"url": url, "urls": [], "status": "not_found"}
    
    content = resp.get("text", "")
    
    # Find nested sitemaps
    sitemap_refs = re.findall(r'<sitemap>.*?<loc>(.*?)</loc>.*?</sitemap>', content, re.DOTALL)
    
    # Find URLs
    url_entries = re.findall(r'<url>.*?<loc>(.*?)</loc>.*?</url>', content, re.DOTALL)
    
    # Also try simple loc tags
    all_locs = re.findall(r'<loc>(.*?)</loc>', content)
    
    # Categorize URLs
    sensitive_patterns = [
        (r'/admin', "Admin Panel", "high"),
        (r'/login|/signin|/auth', "Auth Page", "medium"),
        (r'/api/', "API Endpoint", "medium"),
        (r'/wp-admin|/wp-login', "WordPress Admin", "high"),
        (r'/backup|/bak', "Backup", "critical"),
        (r'/config', "Config", "high"),
        (r'/test|/dev|/staging', "Dev/Test", "medium"),
        (r'/upload', "Upload", "medium"),
        (r'\.pdf$|\.xls|\.doc', "Document", "low"),
        (r'/internal', "Internal", "high"),
    ]
    
    sensitive_urls = []
    for loc in all_locs:
        for pattern, desc, severity in sensitive_patterns:
            if re.search(pattern, loc, re.IGNORECASE):
                sensitive_urls.append({
                    "url": loc,
                    "type": desc,
                    "severity": severity
                })
                break
    
    return {
        "url": url,
        "total_urls": len(all_locs),
        "urls": all_locs[:100],
        "sensitive_urls": sensitive_urls,
        "nested_sitemaps": sitemap_refs,
        "status": "ok" if content else "empty",
        "has_sitemap": bool(content and ("xml" in content or "loc" in content))
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "sitemap_data": [],
        "tools": [],
        "severity": "info"
    }

    total_urls = 0
    total_sensitive = 0

    for domain in domains:
        d = clean_domain(domain)
        
        sitemap_paths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/", "/robots.txt"]
        
        for scheme in ["https", "http"]:
            sitemap_url = f"{scheme}://{d}/sitemap.xml"
            sitemap_data = await parse_sitemap(sitemap_url)
            sitemap_data["domain"] = d
            
            if sitemap_data.get("has_sitemap"):
                results["sitemap_data"].append(sitemap_data)
                total_urls += sitemap_data.get("total_urls", 0)
                
                for sensitive in sitemap_data.get("sensitive_urls", []):
                    total_sensitive += 1
                    results["findings"].append({
                        "type": "sitemap_sensitive_url",
                        "domain": d,
                        "url": sensitive["url"],
                        "url_type": sensitive["type"],
                        "severity": sensitive["severity"]
                    })
                break
        else:
            results["sitemap_data"].append({"domain": d, "status": "not_found", "has_sitemap": False})

        results["tools"].append({
            "tool": "Sitemap Manual",
            "domain": d,
            "status": "manual_required",
            "urls": [
                f"https://{d}/sitemap.xml",
                f"https://{d}/sitemap_index.xml"
            ]
        })

    # Severity
    if any(f.get("severity") in ["critical", "high"] for f in results["findings"]):
        results["severity"] = "high"
    elif total_sensitive > 0:
        results["severity"] = "medium"
    elif total_urls > 0:
        results["severity"] = "low"

    found_count = sum(1 for s in results["sitemap_data"] if s.get("has_sitemap"))
    results["summary"] = (
        f"Sitemap encontrado en {found_count}/{len(domains)} dominio(s). "
        f"{total_urls} URL(s) indexada(s). "
        f"{total_sensitive} URL(s) sensible(s) identificada(s)."
    )

    return results
