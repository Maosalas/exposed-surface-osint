"""
tool_server.py  —  Internal REST API for OSINT CLI tools
Listens on :4000, only reachable from osint-internal network.

Endpoints:
  GET  /health
  POST /run          { tool, args: {...} }   → { ok, findings, raw, elapsed }
  GET  /tools        list available tools + status
"""

import asyncio, json, os, time, traceback
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="OSINT Tools Service", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Tool registry ─────────────────────────────────────────────────────────────
# Each handler is imported from tools/
from tools.t_subfinder    import run as run_subfinder
from tools.t_amass        import run as run_amass
from tools.t_theHarvester import run as run_theharvester
from tools.t_whatweb      import run as run_whatweb
from tools.t_wafw00f      import run as run_wafw00f
from tools.t_dnsenum      import run as run_dnsenum
from tools.t_dnstwist     import run as run_dnstwist
from tools.t_whois        import run as run_whois
from tools.t_httpx        import run as run_httpx
from tools.t_shodan       import run as run_shodan
from tools.t_virustotal   import run as run_virustotal
from tools.t_securitytrails import run as run_securitytrails
from tools.t_intelx       import run as run_intelx

TOOL_MAP = {
    "subfinder":      run_subfinder,
    "amass":          run_amass,
    "theHarvester":   run_theharvester,
    "whatweb":        run_whatweb,
    "wafw00f":        run_wafw00f,
    "dnsenum":        run_dnsenum,
    "dnstwist":       run_dnstwist,
    "whois":          run_whois,
    "httpx":          run_httpx,
    "shodan":         run_shodan,
    "virustotal":     run_virustotal,
    "securitytrails": run_securitytrails,
    "intelx":         run_intelx,
}

# Cache availability at startup
_tool_available: dict[str, bool] = {}

async def _check_bin(cmd: list[str]) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.wait(), timeout=5)
        return True
    except Exception:
        return False

@app.on_event("startup")
async def _startup():
    checks = {
        "subfinder":    ["subfinder", "--version"],
        "amass":        ["amass", "enum", "-version"],
        "theHarvester": ["theHarvester", "-h"],
        "whatweb":      ["whatweb", "--version"],
        "wafw00f":      ["wafw00f", "--version"],
        "dnsenum":      ["dnsenum", "--version"],
        "dnstwist":     ["dnstwist", "--version"],
        "whois":        ["whois", "--version"],
        "httpx":        ["httpx", "-version"],
    }
    for name, cmd in checks.items():
        _tool_available[name] = await _check_bin(cmd)
        status = "✔" if _tool_available[name] else "✖"
        print(f"  {status} {name}")

    # API tools availability (require keys)
    for api_tool in ("shodan", "virustotal", "securitytrails", "intelx"):
        _tool_available[api_tool] = True  # availability checked at runtime

    print("[tool_server] Ready on :4000")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "tools": _tool_available}

@app.get("/tools")
def list_tools():
    return {"tools": _tool_available}

@app.post("/run")
async def run_tool(body: dict):
    """
    body = { "tool": "subfinder", "args": { "domain": "example.com", ... }, "api_keys": {...} }
    Returns { "ok": bool, "findings": [...], "raw": str, "elapsed": float, "error": str|null }
    """
    tool_name = body.get("tool", "").lower()
    args      = body.get("args", {})
    api_keys  = body.get("api_keys", {})

    if tool_name not in TOOL_MAP:
        raise HTTPException(400, f"Unknown tool: {tool_name}. Available: {list(TOOL_MAP)}")

    t0 = time.time()
    try:
        handler = TOOL_MAP[tool_name]
        result  = await handler(args, api_keys)
        result["elapsed"] = round(time.time() - t0, 2)
        result.setdefault("ok", True)
        result.setdefault("error", None)
        return result
    except Exception as e:
        return {
            "ok":       False,
            "findings": [],
            "raw":      traceback.format_exc(),
            "elapsed":  round(time.time() - t0, 2),
            "error":    str(e),
        }

@app.post("/run/batch")
async def run_batch(body: dict):
    """
    Run multiple tools in parallel.
    body = { "tasks": [ {tool, args, api_keys}, ... ] }
    Returns list of results in same order.
    """
    tasks = body.get("tasks", [])
    if not tasks or len(tasks) > 10:
        raise HTTPException(400, "1-10 tasks required")

    async def _one(task):
        return await run_tool(task)

    results = await asyncio.gather(*[_one(t) for t in tasks], return_exceptions=True)
    return {"results": [r if not isinstance(r, Exception) else {"ok": False, "error": str(r)} for r in results]}


if __name__ == "__main__":
    uvicorn.run("tool_server:app", host="0.0.0.0", port=4000, workers=1, log_level="info")
