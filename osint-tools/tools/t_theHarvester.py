import re, os
from ._base import run_cmd, extract_emails

# Uses wrapper at /usr/local/bin/theHarvester (calls venv python + script)
async def run(args: dict, api_keys: dict) -> dict:
    domain  = args.get("domain", "")
    sources = args.get("sources", "google,bing,duckduckgo,crtsh")
    limit   = args.get("limit", 200)
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", str(limit)]
    res = await run_cmd(cmd, timeout=120)

    output = res["stdout"] + res["stderr"]
    emails     = extract_emails(output)
    subdomains = list(set(re.findall(
        rf'(?:[a-zA-Z0-9\-]+\.)+{re.escape(domain)}', output
    )))

    findings = []
    for e in emails:
        findings.append({"type": "email", "value": e, "source": "theHarvester", "domain": domain})
    for s in subdomains:
        findings.append({"type": "subdomain", "value": s, "source": "theHarvester", "domain": domain})

    return {
        "ok":         res["success"] or len(findings) > 0,
        "findings":   findings,
        "raw":        output[:20000],
        "emails":     emails,
        "subdomains": subdomains,
    }
