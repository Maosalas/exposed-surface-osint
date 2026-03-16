"""
Módulo: Dominios y Sub-dominios
Herramientas: subfinder, amass, dnsenum, dnsx, theHarvester
"""
import asyncio
import json
from typing import List, Dict, Any
from .utils import run_command, http_get, clean_domain, check_url_alive, resolve_domain
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from tools_client import run_tool as _ext_tool, is_available as _tools_up

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "subdomains": [],
        "active_subdomains": [],
        "tools": [],
        "severity": "info"
    }

    all_subdomains = set()

    for domain in domains:
        d = clean_domain(domain)

        # subfinder
        sf_result = {"tool": "subfinder", "domain": d, "output": [], "status": ""}
        res = await run_command(["subfinder", "-d", d, "-silent", "-t", "20"], timeout=60)
        if res["success"] and res["stdout"].strip():
            subs = [s.strip() for s in res["stdout"].splitlines() if s.strip()]
            all_subdomains.update(subs)
            sf_result["output"] = subs
            sf_result["status"] = "ok"
        else:
            sf_result["status"] = "unavailable"
        results["tools"].append(sf_result)

        # amass (passive)
        amass_result = {"tool": "amass", "domain": d, "output": [], "status": ""}
        res = await run_command(["amass", "enum", "-passive", "-d", d, "-timeout", "2"], timeout=120)
        if res["success"] and res["stdout"].strip():
            subs = [s.strip() for s in res["stdout"].splitlines() if s.strip() and d in s]
            all_subdomains.update(subs)
            amass_result["output"] = subs
            amass_result["status"] = "ok"
        else:
            amass_result["status"] = "unavailable"
        results["tools"].append(amass_result)

        # dnsenum
        dnsenum_result = {"tool": "dnsenum", "domain": d, "output": [], "status": ""}
        res = await run_command(["dnsenum", "--noreverse", "--nocolor", d], timeout=60)
        if res["success"] and res["stdout"].strip():
            import re
            found = re.findall(r'[\w\-\.]+\.' + re.escape(d), res["stdout"])
            all_subdomains.update(found)
            dnsenum_result["output"] = list(set(found))
            dnsenum_result["status"] = "ok"
        else:
            dnsenum_result["status"] = "unavailable"
        results["tools"].append(dnsenum_result)

        # crt.sh - Certificate Transparency (free, no auth needed)
        crt_result = {"tool": "crt.sh", "domain": d, "output": [], "status": ""}
        resp = await http_get(f"https://crt.sh/?q=%25.{d}&output=json", timeout=15)
        if resp["success"] and resp["status"] == 200:
            try:
                crt_data = json.loads(resp["text"])
                subs = set()
                for entry in crt_data:
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(d) and sub != d:
                            subs.add(sub)
                all_subdomains.update(subs)
                crt_result["output"] = list(subs)
                crt_result["status"] = "ok"
            except:
                crt_result["status"] = "parse_error"
        else:
            crt_result["status"] = "error"
        results["tools"].append(crt_result)

        # DNSDumpster reference
        results["tools"].append({
            "tool": "DNSDumpster",
            "domain": d,
            "status": "manual_required",
            "url": f"https://dnsdumpster.com/",
            "note": f"Buscar '{d}' manualmente"
        })

        # SYNAPSINT
        results["tools"].append({
            "tool": "SYNAPSINT",
            "domain": d,
            "status": "manual_required",
            "url": f"https://synapsint.com/index.php",
            "note": f"Buscar '{d}' manualmente"
        })

    # ── osint-tools: amass + dnsenum + theHarvester (if service available) ──
    if await _tools_up():
        batch_tasks = []
        for d in domains:
            batch_tasks.append({"tool": "amass",        "args": {"domain": d}})
            batch_tasks.append({"tool": "dnsenum",      "args": {"domain": d}})
            batch_tasks.append({"tool": "theHarvester", "args": {"domain": d, "sources": "google,bing,duckduckgo,crtsh"}})
        from tools_client import run_batch as _run_batch
        ext_results = await _run_batch(batch_tasks, timeout=300)
        for r in ext_results:
            for f in r.get("findings", []):
                if f.get("type") == "subdomain":
                    all_subdomains.add(f["value"])

    # Check which subdomains are active
    unique_subs = list(all_subdomains)
    active = []
    
    if unique_subs:
        tasks = []
        for sub in unique_subs[:50]:  # limit for performance
            tasks.append(check_url_alive(f"https://{sub}", timeout=5))
        
        check_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for sub, chk in zip(unique_subs[:50], check_results):
            if isinstance(chk, dict) and chk.get("alive"):
                ip = await resolve_domain(sub)
                active.append({
                    "subdomain": sub,
                    "status_code": chk.get("status_code"),
                    "ip": ip,
                    "https": True
                })

    results["subdomains"] = unique_subs
    results["active_subdomains"] = active
    results["findings"] = [{"type": "subdomain", "value": s} for s in unique_subs]
    
    count = len(unique_subs)
    active_count = len(active)
    results["summary"] = f"Se identificaron {count} subdominio(s), {active_count} activo(s)."
    if count > 0:
        results["severity"] = "medium" if active_count > 0 else "low"
    
    return results
