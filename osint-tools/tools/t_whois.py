import whois as pywhois
import asyncio
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    domain = args.get("domain", "")
    if not domain:
        return {"ok": False, "findings": [], "raw": "", "error": "domain required"}

    findings = []
    whois_data = {}
    raw = ""

    # Try python-whois first (structured)
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, lambda: pywhois.whois(domain))
        if w:
            def _str(v):
                if isinstance(v, list): return str(v[0]) if v else ""
                return str(v) if v else ""

            whois_data = {
                "domain":     domain,
                "registrar":  _str(w.registrar),
                "registrant": _str(w.get("registrant_name") or w.get("org") or ""),
                "country":    _str(w.country),
                "emails":     list(set(w.emails or [])),
                "created":    _str(w.creation_date),
                "updated":    _str(w.updated_date),
                "expiry":     _str(w.expiration_date),
                "nameservers": [str(ns).lower() for ns in (w.name_servers or [])],
                "status":     _str(w.status),
            }
            raw = str(w.text or "")

            # Flag if domain expires soon
            from datetime import datetime, timezone
            if w.expiration_date:
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if hasattr(exp, "replace"):
                    exp = exp.replace(tzinfo=timezone.utc) if exp.tzinfo is None else exp
                    days_left = (exp - datetime.now(timezone.utc)).days
                    whois_data["days_until_expiry"] = days_left
                    if days_left < 30:
                        findings.append({
                            "type": "domain_expiry_soon",
                            "value": domain,
                            "domain": domain,
                            "severity": "high" if days_left < 7 else "medium",
                            "note": f"Domain expires in {days_left} days",
                        })

            # Expose emails found in WHOIS
            for email in whois_data.get("emails", []):
                findings.append({
                    "type": "whois_email",
                    "value": email,
                    "domain": domain,
                    "source": "whois",
                    "severity": "info",
                })

    except Exception as e:
        raw = f"python-whois error: {e}"

    # Also run CLI whois for raw evidence
    cli_res = await run_cmd(["whois", domain], timeout=20)
    if cli_res["stdout"]:
        raw = cli_res["stdout"]

    return {
        "ok":        bool(whois_data),
        "findings":  findings,
        "raw":       raw[:20000],
        "whois_data": whois_data,
    }
