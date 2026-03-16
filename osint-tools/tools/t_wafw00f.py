import re
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    url = f"https://{domain}" if not domain.startswith("http") else domain
    cmd = ["wafw00f", url, "-a"]  # -a: check all WAFs
    res = await run_cmd(cmd, timeout=30)

    output = res["stdout"] + res["stderr"]
    findings = []

    # Parse wafw00f output
    waf_detected = re.findall(r'is behind (.+?)(?:\s*WAF|\s*\()', output, re.IGNORECASE)
    no_waf = "No WAF detected" in output or "not behind a WAF" in output.lower()

    if waf_detected:
        for waf in waf_detected:
            findings.append({
                "type":     "waf_detected",
                "value":    waf.strip(),
                "source":   "wafw00f",
                "domain":   domain,
                "severity": "info",
            })
    elif no_waf:
        findings.append({
            "type":     "no_waf",
            "value":    "No WAF detected",
            "source":   "wafw00f",
            "domain":   domain,
            "severity": "medium",
            "note":     "Site may be directly exposed without WAF protection",
        })

    return {
        "ok":          res["success"] or True,
        "findings":    findings,
        "raw":         output[:5000],
        "waf_detected": waf_detected,
        "no_waf":      no_waf,
    }
