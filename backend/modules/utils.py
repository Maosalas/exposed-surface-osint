import asyncio
import subprocess
import aiohttp
import socket
import ssl
import re
from typing import List, Dict, Any

async def run_command(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a shell command asynchronously and return output."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "returncode": proc.returncode
            }
        except asyncio.TimeoutError:
            proc.kill()
            return {"success": False, "stdout": "", "stderr": "Timeout", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": "Tool not found", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

async def http_get(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Perform an async HTTP GET request."""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; OSINT-Analyzer/1.0)"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), 
                                   headers=headers, ssl=False, allow_redirects=True) as resp:
                text = await resp.text(errors="replace")
                return {
                    "success": True,
                    "status": resp.status,
                    "text": text,
                    "headers": dict(resp.headers),
                    "url": str(resp.url)
                }
    except Exception as e:
        return {"success": False, "status": 0, "text": "", "headers": {}, "error": str(e)}

def extract_emails(text: str) -> List[str]:
    """Extract emails from a text."""
    pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    return list(set(re.findall(pattern, text)))

def is_valid_domain(domain: str) -> bool:
    """Basic domain validation."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain.strip()))

async def check_url_alive(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Check if URL responds."""
    result = await http_get(url, timeout)
    return {
        "url": url,
        "alive": result.get("success", False) and result.get("status", 0) > 0,
        "status_code": result.get("status", 0),
        "final_url": result.get("url", url)
    }

async def resolve_domain(domain: str) -> str:
    """Resolve domain to IP."""
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return ip
    except:
        return ""

def clean_domain(domain: str) -> str:
    """Remove protocol and trailing slashes."""
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    domain = domain.split('/')[0]
    return domain
