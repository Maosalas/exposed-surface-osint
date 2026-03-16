import aiohttp, json
from ._base import extract_domains

SHODAN_BASE = "https://api.shodan.io"

async def run(args: dict, api_keys: dict) -> dict:
    api_key = api_keys.get("shodan") or ""
    if not api_key:
        return {"ok": False, "findings": [], "raw": "", "error": "Shodan API key required", "needs_key": "shodan"}

    domain    = args.get("domain", "")
    favicon_hash = args.get("favicon_hash", "")
    query     = args.get("query", "")
    mode      = args.get("mode", "domain")  # domain | favicon | query

    findings = []
    raw_data = {}

    async with aiohttp.ClientSession() as s:
        try:
            if mode == "domain" and domain:
                # DNS resolve via Shodan
                url = f"{SHODAN_BASE}/dns/domain/{domain}?key={api_key}"
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    data = await r.json()
                    raw_data["dns"] = data
                    for entry in data.get("data", []):
                        subdomain = entry.get("subdomain", "")
                        rec_type  = entry.get("type", "")
                        value     = entry.get("value", "")
                        if subdomain:
                            full = f"{subdomain}.{domain}"
                            findings.append({
                                "type":     "subdomain",
                                "value":    full,
                                "domain":   domain,
                                "source":   "shodan_dns",
                                "severity": "info",
                                "rec_type": rec_type,
                                "ip":       value if rec_type == "A" else "",
                            })

                # Host search
                search_url = f"{SHODAN_BASE}/shodan/host/search?key={api_key}&query=hostname:{domain}&facets=port,org"
                async with s.get(search_url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    sdata = await r.json()
                    raw_data["search"] = {"total": sdata.get("total", 0)}
                    for match in sdata.get("matches", [])[:20]:
                        ip       = match.get("ip_str", "")
                        port     = match.get("port", "")
                        product  = match.get("product", "")
                        version  = match.get("version", "")
                        hostnames = match.get("hostnames", [])
                        findings.append({
                            "type":     "exposed_service",
                            "value":    f"{ip}:{port}",
                            "domain":   domain,
                            "source":   "shodan",
                            "severity": "high" if port in (22, 3389, 5900, 1433, 3306) else "medium",
                            "ip":       ip,
                            "port":     port,
                            "product":  product,
                            "version":  version,
                            "hostnames": hostnames,
                        })

            elif mode == "favicon" and favicon_hash:
                url = f"{SHODAN_BASE}/shodan/host/search?key={api_key}&query=http.favicon.hash:{favicon_hash}"
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    data = await r.json()
                    raw_data["favicon"] = {"total": data.get("total", 0)}
                    for match in data.get("matches", [])[:15]:
                        ip = match.get("ip_str", "")
                        findings.append({
                            "type":     "favicon_match",
                            "value":    ip,
                            "domain":   domain,
                            "source":   "shodan_favicon",
                            "severity": "medium",
                            "ip":       ip,
                            "port":     match.get("port"),
                            "hostnames": match.get("hostnames", []),
                        })

        except aiohttp.ClientResponseError as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": f"Shodan API error: {e.status}"}
        except Exception as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": str(e)}

    return {
        "ok":       True,
        "findings": findings,
        "raw":      json.dumps(raw_data, indent=2)[:20000],
        "count":    len(findings),
    }
