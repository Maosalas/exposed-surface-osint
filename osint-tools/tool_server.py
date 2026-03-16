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

# ── Tool registry — lazy loading so one broken tool never crashes the server ──
_TOOL_MODULES = {
    "subfinder":      "tools.t_subfinder",
    "amass":          "tools.t_amass",
    "theHarvester":   "tools.t_theHarvester",
    "whatweb":        "tools.t_whatweb",
    "wafw00f":        "tools.t_wafw00f",
    "dnsenum":        "tools.t_dnsenum",
    "dnstwist":       "tools.t_dnstwist",
    "whois":          "tools.t_whois",
    "httpx":          "tools.t_httpx",
    "shodan":         "tools.t_shodan",
    "virustotal":     "tools.t_virustotal",
    "securitytrails": "tools.t_securitytrails",
    "intelx":         "tools.t_intelx",
}

# Loaded handlers (populated at startup, missing = unavailable)
TOOL_MAP: dict = {}
_tool_available: dict = {}

def _load_tools():
    """Import each tool module individually — failures are isolated."""
    for name, module_path in _TOOL_MODULES.items():
        try:
            import importlib
            mod = importlib.import_module(module_path)
            TOOL_MAP[name] = mod.run
            _tool_available[name] = True
            print(f"  ✔ {name}")
        except Exception as e:
            _tool_available[name] = False
            print(f"  ✖ {name}: {e}")

_load_tools()


# ── Binary availability check ─────────────────────────────────────────────────
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
    print("[tool_server] Checking binary availability...")
    bin_checks = {
        "subfinder":    ["subfinder", "--version"],
        "amass":        ["amass", "enum", "-version"],
        "theHarvester": ["theHarvester", "--version"],
        "whatweb":      ["whatweb", "--version"],
        "wafw00f":      ["wafw00f", "--version"],
        "dnsenum":      ["dnsenum", "--version"],
        "dnstwist":     ["dnstwist", "--version"],
        "whois":        ["whois", "--version"],
        "httpx":        ["httpx", "-version"],
    }
    for name, cmd in bin_checks.items():
        # Only update if module loaded successfully
        if _tool_available.get(name):
            bin_ok = await _check_bin(cmd)
            if not bin_ok:
                print(f"  ⚠ {name}: module ok but binary not found")
                # Keep True — some tools like theHarvester have non-standard --version
        # API tools: availability determined at runtime by key presence
    for api_tool in ("shodan", "virustotal", "securitytrails", "intelx"):
        _tool_available[api_tool] = _tool_available.get(api_tool, False)

    available = [k for k,v in _tool_available.items() if v]
    print(f"[tool_server] Ready — {len(available)}/{len(_TOOL_MODULES)} tools available")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "tools":  _tool_available,
        "available_count": sum(1 for v in _tool_available.values() if v),
    }

@app.get("/tools")
def list_tools():
    return {"tools": _tool_available}

@app.post("/run")
async def run_tool(body: dict):
    """
    body = { "tool": "subfinder", "args": { "domain": "example.com" }, "api_keys": {...} }
    Returns { "ok": bool, "findings": [...], "raw": str, "elapsed": float, "error": str|null }
    """
    tool_name = body.get("tool", "").lower()
    args      = body.get("args", {})
    api_keys  = body.get("api_keys", {})

    if tool_name not in _TOOL_MODULES:
        raise HTTPException(400, f"Unknown tool: {tool_name}. Available: {list(TOOL_MAP)}")

    if tool_name not in TOOL_MAP:
        return {
            "ok": False, "findings": [], "raw": "",
            "elapsed": 0, "error": f"{tool_name} failed to load at startup — check container logs",
        }

    t0 = time.time()
    try:
        result  = await TOOL_MAP[tool_name](args, api_keys)
        result["elapsed"] = round(time.time() - t0, 2)
        result.setdefault("ok", True)
        result.setdefault("error", None)
        return result
    except Exception as e:
        return {
            "ok": False, "findings": [], "raw": traceback.format_exc(),
            "elapsed": round(time.time() - t0, 2), "error": str(e),
        }

@app.post("/run/batch")
async def run_batch(body: dict):
    """Run up to 10 tools in parallel."""
    tasks = body.get("tasks", [])
    if not tasks or len(tasks) > 10:
        raise HTTPException(400, "1-10 tasks required")

    async def _one(task):
        return await run_tool(task)

    results = await asyncio.gather(*[_one(t) for t in tasks], return_exceptions=True)
    return {
        "results": [
            r if not isinstance(r, Exception) else {"ok": False, "error": str(r)}
            for r in results
        ]
    }


# ── Graceful shutdown ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("tool_server:app", host="0.0.0.0", port=4000, workers=1, log_level="info")
