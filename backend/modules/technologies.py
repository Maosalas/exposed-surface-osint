"""
Módulo: Tecnologías utilizadas en el sitio principal
Herramientas: whatweb, wafw00f, builtwith (manual), wappalyzer (manual)
"""
import asyncio
import re
import json
from typing import List, Dict, Any
from .utils import run_command, http_get, clean_domain
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools_client import run_batch as _run_batch, is_available as _tools_up

async def detect_technologies(url: str) -> Dict[str, Any]:
    """Detect technologies from HTTP response headers and body."""
    resp = await http_get(url, timeout=15)
    if not resp["success"]:
        return {"url": url, "technologies": [], "headers": {}, "status": "unreachable"}

    headers = resp.get("headers", {})
    body = resp.get("text", "")
    techs = []

    # Server header
    server = headers.get("Server", headers.get("server", ""))
    if server:
        techs.append({"name": server, "category": "Web Server", "confidence": "high"})

    # X-Powered-By
    powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    if powered:
        techs.append({"name": powered, "category": "Backend", "confidence": "high"})

    # Technology fingerprints from body/headers
    fingerprints = [
        (r'wp-content|wp-includes|WordPress', "WordPress", "CMS"),
        (r'Drupal|drupal', "Drupal", "CMS"),
        (r'Joomla|joomla', "Joomla", "CMS"),
        (r'Magento|magento', "Magento", "E-Commerce"),
        (r'shopify', "Shopify", "E-Commerce"),
        (r'angular', "Angular", "JavaScript Framework"),
        (r'react|ReactDOM', "React", "JavaScript Framework"),
        (r'vue\.js|Vue\.js', "Vue.js", "JavaScript Framework"),
        (r'jquery', "jQuery", "JavaScript Library"),
        (r'bootstrap', "Bootstrap", "CSS Framework"),
        (r'nginx', "Nginx", "Web Server"),
        (r'apache', "Apache", "Web Server"),
        (r'IIS', "Microsoft IIS", "Web Server"),
        (r'cloudflare', "Cloudflare", "CDN/Security"),
        (r'google-analytics|gtag\(', "Google Analytics", "Analytics"),
        (r'laravel|Laravel', "Laravel", "PHP Framework"),
        (r'symfony', "Symfony", "PHP Framework"),
        (r'django', "Django", "Python Framework"),
        (r'spring', "Spring", "Java Framework"),
        (r'ASP\.NET', "ASP.NET", "Microsoft Framework"),
        (r'php', "PHP", "Backend Language"),
        (r'ruby on rails|rails', "Ruby on Rails", "Framework"),
        (r'node\.js|nodejs', "Node.js", "Runtime"),
        (r'woocommerce', "WooCommerce", "E-Commerce"),
        (r'recaptcha', "Google reCAPTCHA", "Security"),
        (r'cloudfront\.net', "Amazon CloudFront", "CDN"),
        (r'akamai', "Akamai", "CDN"),
        (r'fastly', "Fastly", "CDN"),
    ]

    combined = (body[:5000] + str(headers)).lower()
    seen = set()
    for pattern, name, category in fingerprints:
        if name not in seen and re.search(pattern, combined, re.IGNORECASE):
            seen.add(name)
            techs.append({"name": name, "category": category, "confidence": "medium"})

    # Security headers check
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Content-Security-Policy": "CSP",
        "X-XSS-Protection": "XSS Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
    }
    
    missing_headers = []
    present_headers = []
    for header, desc in security_headers.items():
        if header.lower() in {k.lower() for k in headers.keys()}:
            present_headers.append(desc)
        else:
            missing_headers.append({"header": header, "description": desc})

    return {
        "url": url,
        "status_code": resp.get("status", 0),
        "technologies": techs,
        "missing_security_headers": missing_headers,
        "present_security_headers": present_headers,
        "status": "ok"
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "technology_scans": [],
        "tools": [],
        "severity": "info"
    }

    all_techs = set()
    missing_headers_count = 0

    for domain in domains:
        d = clean_domain(domain)
        
        for scheme in ["https", "http"]:
            url = f"{scheme}://{d}"
            tech_info = await detect_technologies(url)
            if tech_info["status"] == "ok":
                results["technology_scans"].append(tech_info)
                for t in tech_info.get("technologies", []):
                    all_techs.add(t["name"])
                missing_headers_count += len(tech_info.get("missing_security_headers", []))
                
                for missing in tech_info.get("missing_security_headers", []):
                    results["findings"].append({
                        "type": "missing_security_header",
                        "domain": d,
                        "header": missing["header"],
                        "description": missing["description"],
                        "severity": "medium"
                    })
                break

        # whatweb CLI
        ww_result = {"tool": "whatweb", "domain": d, "output": [], "status": ""}
        res = await run_command(["whatweb", "--color=never", f"https://{d}"], timeout=20)

        # Also call osint-tools whatweb + wafw00f in parallel
        if await _tools_up():
            ext = await _run_batch([
                {"tool": "whatweb", "args": {"domain": d}},
                {"tool": "wafw00f", "args": {"domain": d}},
            ], timeout=60)
            for r in ext:
                for f in r.get("findings", []):
                    results["findings"].append({**f, "auto": True})
            # Merge waf info
            for r in ext:
                if r.get("waf_detected"):
                    ww_result.setdefault("waf", []).extend(r["waf_detected"])
        if res["success"] and res["stdout"]:
            ww_result["output"] = res["stdout"][:1000]
            ww_result["status"] = "ok"
        else:
            ww_result["status"] = "unavailable"
        results["tools"].append(ww_result)

        # wafw00f - WAF detection
        waf_result = {"tool": "wafw00f", "domain": d, "output": [], "status": ""}
        res = await run_command(["wafw00f", f"https://{d}"], timeout=20)
        if res["success"] and res["stdout"]:
            waf_result["output"] = res["stdout"][:500]
            waf_result["status"] = "ok"
            if "is behind" in res["stdout"].lower():
                import re
                waf_match = re.search(r'is behind (.+?) WAF', res["stdout"])
                if waf_match:
                    waf_result["waf_detected"] = waf_match.group(1)
        else:
            waf_result["status"] = "unavailable"
        results["tools"].append(waf_result)

        # Manual reference tools
        results["tools"].append({
            "tool": "BuiltWith",
            "status": "manual_required",
            "url": f"https://builtwith.com/{d}"
        })
        results["tools"].append({
            "tool": "Wappalyzer",
            "status": "manual_required",
            "url": f"https://www.wappalyzer.com/lookup/{d}"
        })
        results["tools"].append({
            "tool": "URLScan",
            "status": "manual_required",
            "url": f"https://urlscan.io/search/#domain:{d}"
        })

    # Severity
    if missing_headers_count > 3:
        results["severity"] = "medium"
    elif all_techs:
        results["severity"] = "low"

    results["summary"] = (
        f"Se identificaron {len(all_techs)} tecnología(s): {', '.join(list(all_techs)[:5])}. "
        f"{missing_headers_count} cabecera(s) de seguridad ausente(s)."
    )

    return results
