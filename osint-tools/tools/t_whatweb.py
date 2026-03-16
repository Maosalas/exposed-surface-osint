import re, json
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    url = f"https://{domain}" if not domain.startswith("http") else domain
    cmd = ["whatweb", "--color=never", "--log-brief=/dev/stdout", url]
    res = await run_cmd(cmd, timeout=30)

    output = res["stdout"] + res["stderr"]
    findings = []

    # Parse whatweb brief output: URL [status] TechName[version] ...
    tech_pattern = re.compile(r'(\w[\w\-\.]+)\[([^\]]+)\]')
    status_match = re.search(r'\[(\d{3})\]', output)
    status_code  = int(status_match.group(1)) if status_match else None

    for m in tech_pattern.finditer(output):
        name, detail = m.group(1), m.group(2)
        # Skip noise
        if name in ("http", "https", "IP", "Country", "Email"):
            continue
        findings.append({
            "type":    "technology",
            "value":   name,
            "detail":  detail,
            "source":  "whatweb",
            "domain":  domain,
            "version": detail if re.search(r'\d', detail) else None,
        })

    return {
        "ok":          res["success"] or len(findings) > 0,
        "findings":    findings,
        "raw":         output[:10000],
        "status_code": status_code,
        "technologies": [f["value"] for f in findings],
    }
