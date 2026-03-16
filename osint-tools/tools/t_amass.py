from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    # Passive only — no active scanning
    cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "3"]
    res = await run_cmd(cmd, timeout=200)

    subdomains = [s.strip() for s in res["stdout"].splitlines() if s.strip() and domain in s]
    findings = [{"type": "subdomain", "value": s, "source": "amass", "domain": domain} for s in subdomains]

    return {
        "ok":       len(subdomains) > 0,
        "findings": findings,
        "raw":      res["stdout"],
        "count":    len(subdomains),
    }
