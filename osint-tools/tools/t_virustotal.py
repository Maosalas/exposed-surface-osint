import aiohttp, json

VT_BASE = "https://www.virustotal.com/api/v3"

async def run(args: dict, api_keys: dict) -> dict:
    api_key = api_keys.get("virustotal") or ""
    if not api_key:
        return {"ok": False, "findings": [], "raw": "", "error": "VirusTotal API key required", "needs_key": "virustotal"}

    domain = args.get("domain", "")
    ip     = args.get("ip", "")
    mode   = args.get("mode", "domain")

    findings = []
    raw_data = {}
    headers  = {"x-apikey": api_key}

    async with aiohttp.ClientSession(headers=headers) as s:
        try:
            if mode == "domain" and domain:
                # Domain report
                async with s.get(f"{VT_BASE}/domains/{domain}", timeout=aiohttp.ClientTimeout(total=15)) as r:
                    data = await r.json()
                    raw_data["domain"] = data
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    reputation = attrs.get("reputation", 0)

                    severity = "critical" if malicious > 5 else "high" if malicious > 0 else "medium" if suspicious > 0 else "info"

                    if malicious > 0 or suspicious > 0:
                        findings.append({
                            "type":        "malicious_domain",
                            "value":       domain,
                            "domain":      domain,
                            "source":      "virustotal",
                            "severity":    severity,
                            "malicious":   malicious,
                            "suspicious":  suspicious,
                            "reputation":  reputation,
                            "categories":  attrs.get("categories", {}),
                        })

                    # Subdomains from VT
                    async with s.get(f"{VT_BASE}/domains/{domain}/subdomains?limit=40", timeout=aiohttp.ClientTimeout(total=15)) as rs:
                        sub_data = await rs.json()
                        for item in sub_data.get("data", []):
                            sub = item.get("id", "")
                            if sub and sub != domain:
                                findings.append({
                                    "type":     "subdomain",
                                    "value":    sub,
                                    "domain":   domain,
                                    "source":   "virustotal",
                                    "severity": "info",
                                })

                    # Related IPs
                    async with s.get(f"{VT_BASE}/domains/{domain}/resolutions?limit=20", timeout=aiohttp.ClientTimeout(total=15)) as ri:
                        ip_data = await ri.json()
                        for item in ip_data.get("data", []):
                            res_attr = item.get("attributes", {})
                            ip_addr  = res_attr.get("ip_address", "")
                            if ip_addr:
                                findings.append({
                                    "type":     "resolved_ip",
                                    "value":    ip_addr,
                                    "domain":   domain,
                                    "source":   "virustotal",
                                    "severity": "info",
                                    "date":     res_attr.get("date", ""),
                                })

            elif mode == "ip" and ip:
                async with s.get(f"{VT_BASE}/ip_addresses/{ip}", timeout=aiohttp.ClientTimeout(total=15)) as r:
                    data = await r.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        findings.append({
                            "type":      "malicious_ip",
                            "value":     ip,
                            "domain":    domain,
                            "source":    "virustotal",
                            "severity":  "critical" if malicious > 5 else "high",
                            "malicious": malicious,
                            "country":   attrs.get("country", ""),
                            "asn":       attrs.get("asn", ""),
                            "as_owner":  attrs.get("as_owner", ""),
                        })

        except aiohttp.ClientResponseError as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": f"VT API error: {e.status}"}
        except Exception as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": str(e)}

    return {
        "ok":       True,
        "findings": findings,
        "raw":      json.dumps(raw_data, indent=2, default=str)[:20000],
        "count":    len(findings),
    }
