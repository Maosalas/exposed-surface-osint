import re
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    cmd = ["dnsenum", "--noreverse", "--nocolor", "--timeout", "10", domain]
    res = await run_cmd(cmd, timeout=90)

    output = res["stdout"] + res["stderr"]
    findings = []

    # Parse subdomains
    sub_pattern = re.compile(
        rf'((?:[a-zA-Z0-9\-]+\.)+{re.escape(domain)})\s+\d+\s+\w+\s+\w+\s+([\d\.]+)'
    )
    for m in sub_pattern.finditer(output):
        findings.append({
            "type":   "subdomain",
            "value":  m.group(1),
            "ip":     m.group(2),
            "source": "dnsenum",
            "domain": domain,
        })

    # Parse nameservers
    ns_section = re.search(r'Name Servers:(.*?)(?:\n\n|\Z)', output, re.DOTALL)
    if ns_section:
        for line in ns_section.group(1).splitlines():
            ns_match = re.search(r'([\w\.\-]+)\s+\d+\s+IN\s+A\s+([\d\.]+)', line)
            if ns_match:
                findings.append({
                    "type":   "nameserver",
                    "value":  ns_match.group(1),
                    "ip":     ns_match.group(2),
                    "source": "dnsenum",
                    "domain": domain,
                })

    # Parse MX records
    mx_section = re.search(r'Mail.*?Servers:(.*?)(?:\n\n|\Z)', output, re.DOTALL)
    if mx_section:
        for line in mx_section.group(1).splitlines():
            mx_match = re.search(r'([\w\.\-]+)\s+\d+\s+IN\s+A\s+([\d\.]+)', line)
            if mx_match:
                findings.append({
                    "type":   "mx_record",
                    "value":  mx_match.group(1),
                    "ip":     mx_match.group(2),
                    "source": "dnsenum",
                    "domain": domain,
                })

    subdomains = [f["value"] for f in findings if f["type"] == "subdomain"]
    return {
        "ok":         res["success"] or len(findings) > 0,
        "findings":   findings,
        "raw":        output[:20000],
        "subdomains": subdomains,
        "count":      len(subdomains),
    }
