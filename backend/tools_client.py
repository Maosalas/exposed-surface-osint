"""
tools_client.py  —  Called from osint-analyzer backend modules.
Talks to osint-tools container REST API on http://osint-tools:4000.
Falls back gracefully if service is unavailable.
"""

import os, aiohttp, asyncio, json
from typing import Optional

TOOLS_URL = os.environ.get("TOOLS_SERVICE_URL", "http://osint-tools:4000")
_available: Optional[bool] = None  # cached at first call


async def is_available() -> bool:
    global _available
    if _available is not None:
        return _available
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{TOOLS_URL}/health", timeout=aiohttp.ClientTimeout(total=4)) as r:
                _available = r.status == 200
    except Exception:
        _available = False
    return _available


# Per-scan API keys injected by main.py before each scan
_scan_api_keys: dict = {}

async def run_tool(tool: str, args: dict, api_keys: dict = None, timeout: int = 180) -> dict:
    """
    Call a single tool on the osint-tools service.
    Returns the JSON result dict or a graceful error dict.
    """
    if not await is_available():
        return {"ok": False, "findings": [], "raw": "", "error": "osint-tools service unavailable", "skipped": True}

    # Merge: explicit api_keys > scan-level keys
    merged_keys = {**_scan_api_keys, **(api_keys or {})}
    payload = {"tool": tool, "args": args, "api_keys": merged_keys}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{TOOLS_URL}/run",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                return await r.json()
    except asyncio.TimeoutError:
        return {"ok": False, "findings": [], "raw": "", "error": f"{tool} timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "findings": [], "raw": "", "error": str(e)}


async def run_batch(tasks: list, timeout: int = 300) -> list:
    """
    Run up to 10 tools in parallel via the batch endpoint.
    tasks = [{"tool": ..., "args": ..., "api_keys": ...}, ...]
    """
    if not await is_available():
        return [{"ok": False, "findings": [], "raw": "", "skipped": True}] * len(tasks)

    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{TOOLS_URL}/run/batch",
                json={"tasks": tasks},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                data = await r.json()
                return data.get("results", [])
    except Exception as e:
        return [{"ok": False, "findings": [], "raw": "", "error": str(e)}] * len(tasks)


async def get_available_tools() -> dict:
    """Return dict of tool_name -> available bool."""
    if not await is_available():
        return {}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{TOOLS_URL}/tools", timeout=aiohttp.ClientTimeout(total=5)) as r:
                data = await r.json()
                return data.get("tools", {})
    except Exception:
        return {}
