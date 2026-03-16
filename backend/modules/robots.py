"""
Módulo: Archivo ROBOTS.txt
Herramientas: Breacher, análisis manual, Google Dorks
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import http_get, clean_domain, check_url_alive

async def analyze_robots(domain: str) -> Dict[str, Any]:
    """Fetch and analyze robots.txt."""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}/robots.txt"
        resp = await http_get(url, timeout=10)
        
        if resp["success"] and resp["status"] == 200 and resp["text"]:
            content = resp["text"]
            
            # Check it's actually robots.txt content
            if "user-agent" not in content.lower() and "disallow" not in content.lower() and "allow" not in content.lower():
                continue
            
            disallowed = []
            allowed = []
            sitemaps = []
            user_agents = []
            
            for line in content.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line[9:].strip()
                    if path:
                        disallowed.append(path)
                elif line.lower().startswith("allow:"):
                    path = line[6:].strip()
                    if path:
                        allowed.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line[8:].strip()
                    if sitemap_url:
                        sitemaps.append(sitemap_url)
                elif line.lower().startswith("user-agent:"):
                    ua = line[11:].strip()
                    if ua:
                        user_agents.append(ua)
            
            # Check disallowed paths for sensitive content
            sensitive_patterns = [
                (r'/admin', "Panel administrativo", "high"),
                (r'/backup', "Directorio de backups", "critical"),
                (r'/config', "Directorio de configuración", "high"),
                (r'/api', "API endpoint", "medium"),
                (r'/private', "Directorio privado", "high"),
                (r'/db|/database', "Directorio de base de datos", "critical"),
                (r'/secret', "Directorio secreto", "high"),
                (r'/upload', "Directorio de uploads", "medium"),
                (r'/passwd|/password', "Archivo de contraseñas", "critical"),
                (r'/\.env', "Archivo .env", "critical"),
                (r'/wp-admin', "Admin WordPress", "high"),
                (r'/phpmyadmin', "phpMyAdmin", "critical"),
                (r'/login|/signin', "Página de login", "medium"),
            ]
            
            sensitive_findings = []
            for path in disallowed:
                for pattern, desc, severity in sensitive_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        sensitive_findings.append({
                            "path": path,
                            "description": desc,
                            "severity": severity,
                            "url": f"{scheme}://{domain}{path}"
                        })
                        break
            
            return {
                "domain": domain,
                "url": url,
                "found": True,
                "content": content[:3000],
                "disallowed": disallowed,
                "allowed": allowed,
                "sitemaps": sitemaps,
                "user_agents": user_agents,
                "sensitive_findings": sensitive_findings,
                "status": "ok"
            }
    
    return {
        "domain": domain,
        "found": False,
        "disallowed": [],
        "sensitive_findings": [],
        "status": "not_found"
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "robots_data": [],
        "tools": [],
        "severity": "info"
    }

    total_sensitive = 0

    for domain in domains:
        d = clean_domain(domain)
        
        robot_data = await analyze_robots(d)
        results["robots_data"].append(robot_data)

        if robot_data["found"]:
            for sf in robot_data.get("sensitive_findings", []):
                total_sensitive += 1
                results["findings"].append({
                    "type": "robots_sensitive_path",
                    "domain": d,
                    "path": sf["path"],
                    "description": sf["description"],
                    "url": sf["url"],
                    "severity": sf["severity"]
                })

        # Breacher reference
        results["tools"].append({
            "tool": "Breacher",
            "domain": d,
            "status": "manual_required",
            "note": "pip install breacher && python breacher.py -u " + d
        })

        # Google Dork references
        results["tools"].append({
            "tool": "Google Dorks - robots.txt",
            "domain": d,
            "status": "manual_required",
            "urls": [
                f"https://www.google.com/search?q=site:{d}+filetype:txt+robots",
                f"https://www.google.com/search?q=inurl:robots.txt+site:{d}"
            ]
        })

    # Severity
    if any(f.get("severity") == "critical" for f in results["findings"]):
        results["severity"] = "critical"
    elif any(f.get("severity") == "high" for f in results["findings"]):
        results["severity"] = "high"
    elif any(f.get("severity") == "medium" for f in results["findings"]):
        results["severity"] = "medium"
    elif total_sensitive > 0:
        results["severity"] = "low"

    found_count = sum(1 for r in results["robots_data"] if r.get("found"))
    results["summary"] = (
        f"robots.txt encontrado en {found_count}/{len(domains)} dominio(s). "
        f"{total_sensitive} ruta(s) sensible(s) identificada(s) en las directivas Disallow."
    )

    return results
