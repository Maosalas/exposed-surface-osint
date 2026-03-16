import aiohttp, json, asyncio

INTELX_BASE = "https://2.intelx.io"

async def run(args: dict, api_keys: dict) -> dict:
    api_key = api_keys.get("intelx") or ""
    if not api_key:
        return {"ok": False, "findings": [], "raw": "", "error": "IntelligenceX API key required", "needs_key": "intelx"}

    domain     = args.get("domain", "")
    search_term = args.get("search_term", domain)
    max_results = args.get("max_results", 20)
    if not search_term:
        return {"ok": False, "findings": [], "raw": "", "error": "domain or search_term required"}

    findings = []
    raw_data = {}
    headers  = {"x-key": api_key}

    async with aiohttp.ClientSession(headers=headers) as s:
        try:
            # Step 1: Start search
            search_payload = {
                "term": search_term,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": max_results,
                "timeout": 0,
                "datefrom": "",
                "dateto": "",
                "sort": 4,       # date desc
                "media": 0,
                "terminate": [],
            }
            async with s.post(f"{INTELX_BASE}/intelligent/search",
                               json=search_payload,
                               timeout=aiohttp.ClientTimeout(total=20)) as r:
                search_resp = await r.json()
                search_id   = search_resp.get("id", "")
                raw_data["search_id"] = search_id

            if not search_id:
                return {"ok": False, "findings": [], "raw": json.dumps(raw_data), "error": "No search ID returned"}

            # Step 2: Fetch results (poll once after brief wait)
            await asyncio.sleep(3)
            async with s.get(
                f"{INTELX_BASE}/intelligent/search/result?id={search_id}&limit={max_results}&offset=0",
                timeout=aiohttp.ClientTimeout(total=20)
            ) as r:
                results = await r.json()
                raw_data["results_count"] = results.get("found", 0)

                for record in results.get("records", [])[:max_results]:
                    media_type = record.get("mediah", "")
                    name       = record.get("name", "")
                    bucket     = record.get("bucket", "")
                    date       = record.get("date", "")
                    systemid   = record.get("systemid", "")

                    # Classify severity by bucket
                    sev = "critical" if bucket in ("pastes", "leaks.private") else \
                          "high"     if "leak" in bucket.lower() else \
                          "medium"   if "darkweb" in bucket.lower() else "info"

                    findings.append({
                        "type":      "data_leak_record",
                        "value":     name or search_term,
                        "domain":    domain,
                        "source":    "intelx",
                        "severity":  sev,
                        "bucket":    bucket,
                        "date":      date[:10] if date else "",
                        "media_type": media_type,
                        "record_id": systemid,
                        "preview_url": f"https://intelx.io/?did={systemid}" if systemid else "",
                    })

        except aiohttp.ClientResponseError as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": f"IntelX API error: {e.status}"}
        except Exception as e:
            return {"ok": False, "findings": [], "raw": str(e), "error": str(e)}

    return {
        "ok":       True,
        "findings": findings,
        "raw":      json.dumps(raw_data, indent=2),
        "count":    len(findings),
    }
