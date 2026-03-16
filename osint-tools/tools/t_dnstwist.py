import json
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    cmd = ["dnstwist", "--format", "json", "--registered", domain]
    res = await run_cmd(cmd, timeout=120)

    findings = []
    variants = []

    if res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            for entry in data:
                d = entry.get("domain", "")
                fuzzer = entry.get("fuzzer", "")
                ips    = entry.get("dns_a", []) or []
                mx     = entry.get("dns_mx", []) or []
                ns     = entry.get("dns_ns", []) or []

                if d and d != domain:
                    severity = "high" if ips else "low"
                    finding = {
                        "type":           "squatting",
                        "value":          d,
                        "squatted_domain": d,
                        "source":         "dnstwist",
                        "domain":         domain,
                        "fuzzer":         fuzzer,
                        "ips":            ips,
                        "has_mx":         bool(mx),
                        "severity":       severity,
                    }
                    findings.append(finding)
                    if ips:
                        variants.append({
                            "domain":  d,
                            "fuzzer":  fuzzer,
                            "ips":     ips,
                            "has_mx":  bool(mx),
                            "risk":    severity,
                        })
        except json.JSONDecodeError:
            # Fallback: plain text parsing
            for line in res["stdout"].splitlines():
                if domain not in line and "." in line:
                    parts = line.split()
                    if parts:
                        findings.append({
                            "type":           "squatting",
                            "value":          parts[0],
                            "squatted_domain": parts[0],
                            "source":         "dnstwist",
                            "domain":         domain,
                            "severity":       "medium",
                        })

    return {
        "ok":              res["success"] or len(findings) > 0,
        "findings":        findings,
        "raw":             res["stdout"][:20000],
        "active_variants": variants,
        "count":           len(findings),
    }
