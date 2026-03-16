from ._base import run_cmd, extract_domains

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    cmd = ["subfinder", "-d", domain, "-silent", "-t", "20", "-timeout", "15"]
    res = await run_cmd(cmd, timeout=90)

    subdomains = [s.strip() for s in res["stdout"].splitlines() if s.strip()]
    findings = [{"type": "subdomain", "value": s, "source": "subfinder", "domain": domain} for s in subdomains]

    return {
        "ok":       res["success"] or len(subdomains) > 0,
        "findings": findings,
        "raw":      res["stdout"],
        "count":    len(subdomains),
    }
