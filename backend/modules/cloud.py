"""
Módulo: Infraestructura Cloud
Herramientas: cloud_enum, Grayhat Warfare, ReconCloud
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import http_get, run_command, clean_domain, resolve_domain

CLOUD_PROVIDERS = {
    "AWS": [
        r'\.amazonaws\.com',
        r'\.s3\.amazonaws\.com',
        r'\.cloudfront\.net',
        r'\.elb\.amazonaws\.com',
        r'\.execute-api\.',
        r'\.lambda-url\.'
    ],
    "Azure": [
        r'\.azurewebsites\.net',
        r'\.blob\.core\.windows\.net',
        r'\.azure\.com',
        r'\.microsoftonline\.com',
        r'\.trafficmanager\.net',
        r'\.cloudapp\.azure\.com'
    ],
    "GCP": [
        r'\.appspot\.com',
        r'\.googleapis\.com',
        r'\.googleusercontent\.com',
        r'\.run\.app',
        r'storage\.googleapis\.com'
    ],
    "Cloudflare": [
        r'\.pages\.dev',
        r'workers\.dev'
    ],
    "Heroku": [r'\.herokuapp\.com'],
    "DigitalOcean": [r'\.digitaloceanspaces\.com'],
    "Fastly": [r'\.fastly\.net'],
}

async def check_s3_bucket(company: str) -> list:
    """Check common S3 bucket naming patterns."""
    company_clean = re.sub(r'[^a-z0-9]', '-', company.lower())
    patterns = [
        company_clean,
        f"{company_clean}-backup",
        f"{company_clean}-dev",
        f"{company_clean}-staging",
        f"{company_clean}-prod",
        f"{company_clean}-data",
        f"{company_clean}-assets",
        f"{company_clean}-files",
        f"{company_clean}-media",
        f"backup-{company_clean}",
        f"dev-{company_clean}",
    ]

    found_buckets = []
    tasks = []
    
    for pattern in patterns[:8]:  # Limit for performance
        tasks.append(http_get(f"https://{pattern}.s3.amazonaws.com", timeout=5))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for pattern, result in zip(patterns[:8], results):
        if isinstance(result, dict) and result.get("success"):
            status = result.get("status", 0)
            if status in [200, 403, 301]:  # 403 = exists but private, 200 = public!
                public = status == 200
                found_buckets.append({
                    "bucket": pattern,
                    "url": f"https://{pattern}.s3.amazonaws.com",
                    "status": status,
                    "public": public,
                    "severity": "critical" if public else "medium"
                })
    
    return found_buckets

async def detect_cloud_from_headers(domain: str) -> Dict[str, Any]:
    """Detect cloud providers from HTTP headers and CNAME records."""
    resp = await http_get(f"https://{domain}", timeout=10)
    cloud_indicators = []
    
    if resp["success"]:
        headers_str = str(resp.get("headers", {})).lower()
        final_url = resp.get("url", "")
        
        for provider, patterns in CLOUD_PROVIDERS.items():
            for pattern in patterns:
                if re.search(pattern, headers_str + final_url, re.IGNORECASE):
                    cloud_indicators.append({"provider": provider, "indicator": pattern})
                    break
    
    # Check CNAME
    cname_res = await run_command(["dig", "CNAME", domain, "+short"], timeout=10)
    if cname_res["success"] and cname_res["stdout"]:
        cname = cname_res["stdout"].strip().lower()
        for provider, patterns in CLOUD_PROVIDERS.items():
            for pattern in patterns:
                if re.search(pattern, cname, re.IGNORECASE):
                    cloud_indicators.append({"provider": provider, "indicator": f"CNAME: {cname}"})
                    break
    
    return {
        "domain": domain,
        "cloud_indicators": cloud_indicators,
        "detected_providers": list(set(c["provider"] for c in cloud_indicators))
    }

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "cloud_data": [],
        "exposed_buckets": [],
        "tools": [],
        "severity": "info"
    }

    all_providers = set()

    # S3 bucket enumeration
    s3_buckets = await check_s3_bucket(company)
    for bucket in s3_buckets:
        results["exposed_buckets"].append(bucket)
        if bucket.get("public"):
            results["findings"].append({
                "type": "public_s3_bucket",
                "bucket": bucket["bucket"],
                "url": bucket["url"],
                "severity": "critical",
                "description": "Bucket S3 público - datos potencialmente expuestos"
            })
        else:
            results["findings"].append({
                "type": "s3_bucket_exists",
                "bucket": bucket["bucket"],
                "url": bucket["url"],
                "severity": "medium",
                "description": "Bucket S3 existe (acceso restringido)"
            })

    for domain in domains:
        d = clean_domain(domain)
        
        cloud_info = await detect_cloud_from_headers(d)
        results["cloud_data"].append(cloud_info)
        all_providers.update(cloud_info.get("detected_providers", []))

        # Reference tools
        results["tools"].append({
            "tool": "Grayhat Warfare",
            "status": "manual_required",
            "url": f"https://buckets.grayhatwarfare.com/?keywords={company}"
        })
        results["tools"].append({
            "tool": "ReconCloud",
            "status": "manual_required",
            "url": "https://recon.cloud/"
        })
        results["tools"].append({
            "tool": "cloud_enum",
            "status": "manual_required",
            "note": f"python3 cloud_enum.py -k {company}"
        })

    # Severity
    if any(f.get("severity") == "critical" for f in results["findings"]):
        results["severity"] = "critical"
    elif any(f.get("severity") == "medium" for f in results["findings"]):
        results["severity"] = "medium"
    elif all_providers:
        results["severity"] = "info"

    results["summary"] = (
        f"Infraestructura cloud detectada: {', '.join(all_providers) if all_providers else 'No detectada'}. "
        f"{len(s3_buckets)} bucket(s) S3 encontrado(s), "
        f"{sum(1 for b in s3_buckets if b.get('public'))} público(s)."
    )

    return results
