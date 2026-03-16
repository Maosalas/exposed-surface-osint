import json, tempfile, os
from ._base import run_cmd

async def run(args: dict, api_keys: dict) -> dict:
    """
    Probe a list of subdomains/hosts for HTTP/HTTPS response.
    args: { "hosts": ["sub1.domain.com", ...] }  OR  { "domain": "domain.com" }
    """
    hosts = args.get("hosts", [])
    domain = args.get("domain", "")

    if not hosts and domain:
        hosts = [domain]
    if not hosts:
        return {"ok": False, "findings": [], "raw": "", "error": "hosts or domain required"}

    # Write hosts to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(hosts))
    tmp.close()

    cmd = [
        "httpx", "-l", tmp.name,
        "-json",
        "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-timeout", "8",
        "-threads", "20",
        "-silent",
    ]
    res = await run_cmd(cmd, timeout=120)
    os.unlink(tmp.name)

    findings = []
    active_hosts = []

    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            host  = entry.get("input", "")
            url   = entry.get("url", "")
            sc    = entry.get("status_code", 0)
            title = entry.get("title", "")
            tech  = entry.get("tech", [])

            active_hosts.append({
                "host":        host,
                "url":         url,
                "status_code": sc,
                "title":       title,
                "technologies": tech,
            })

            findings.append({
                "type":     "active_host",
                "value":    url or host,
                "domain":   host,
                "source":   "httpx",
                "severity": "info",
                "status_code": sc,
                "title":    title,
            })
        except json.JSONDecodeError:
            pass

    return {
        "ok":          True,
        "findings":    findings,
        "raw":         res["stdout"][:20000],
        "active_hosts": active_hosts,
        "count":       len(active_hosts),
    }
