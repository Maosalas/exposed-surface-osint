import aiohttp, json

ST_BASE = "https://api.securitytrails.com/v1"

async def run(args: dict, api_keys: dict) -> dict:
    api_key = api_keys.get("securitytrails") or ""
    if not api_key:
        return {"ok": False, "findings": [], "raw": "", "error": "SecurityTrails API key required", "needs_key": "securitytrails"}

    domain = args.get("domain", "")
    mode   = args.get("mode", "subdomains")  # subdomains | dns_history | associated
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    findings = []
    raw_data = {}
    headers  = {"APIKEY": api_key, "Content-Type": "application/json"}

    async with aiohttp.ClientSession(headers=headers) as s:
        try:
            if mode == "subdomains":
                async with s.get(f"{ST_BASE}/domain/{domain}/subdomains?children_only=false&include_inactive=false",
                                  timeout=aiohttp.ClientTimeout(total=20)) as r:
                    data = await r.json()
                    raw_data["subdomains"] = data
                    for sub in data.get("subdomains", [])[:100]:
                        full = f"{sub}.{domain}"
                        findings.append({
                            "type":     "subdomain",
                            "value":    full,
                            "domain":   domain,
                            "source":   "securitytrails",
                            "severity": "info",
                        })

            elif mode == "dns_history":
                for record_type in ("a", "mx", "ns"):
                    async with s.get(f"{ST_BASE}/history/{domain}/dns/{record_type}",
                                      timeout=aiohttp.ClientTimeout(total=15)) as r:
                        data = await r.json()
                        raw_data[f"history_{record_type}"] = data
                        for record in data.get("records", [])[:10]:
                            for val in record.get("values", []):
                                findings.append({
                                    "type":       f"historical_{record_type}_record",
                                    "value":      val.get("ip") or val.get("hostname") or val.get("value", ""),
                                    "domain":     domain,
                                    "source":     "securitytrails_history",
                                    "severity":   "info",
                                    "first_seen": record.get("first_seen", ""),
                                    "last_seen":  record.get("last_seen", ""),
                                })

            elif mode == "associated":
                async with s.post(f"{ST_BASE}/domains/list",
                                   json={"filter": {"apex_domain": domain}},
                                   timeout=aiohttp.ClientTimeout(total=20)) as r:
                    data = await r.json()
                    raw_data["associated"] = data
                    for record in data.get("records", [])[:20]:
                        d = record.get("hostname", "")
                        if d and d != domain:
                            findings.append({
                                "type":     "associated_domain",
                                "value":    d,
                                "domain":   domain,
                                "source":   "securitytrails",
                                "severity": "info",
                            })

        except aiohttp.ClientResponseError as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": f"SecurityTrails API error: {e.status}"}
        except Exception as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": str(e)}

    return {
        "ok":       True,
        "findings": findings,
        "raw":      json.dumps(raw_data, indent=2)[:20000],
        "count":    len(findings),
    }
