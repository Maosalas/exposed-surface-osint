"""Shared utilities for tool handlers."""
import asyncio, re
from typing import Optional

async def run_cmd(cmd: list, timeout: int = 120) -> dict:
    """Run a CLI command, return {success, stdout, stderr, returncode}."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "success":    proc.returncode == 0,
            "stdout":     stdout.decode("utf-8", errors="replace"),
            "stderr":     stderr.decode("utf-8", errors="replace"),
            "returncode": proc.returncode,
        }
    except asyncio.TimeoutError:
        try: proc.kill()
        except: pass
        return {"success": False, "stdout": "", "stderr": "Timeout", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": "Tool not found", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

def extract_domains(text: str) -> list:
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    return list(set(re.findall(pattern, text)))

def extract_emails(text: str) -> list:
    pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    return list(set(re.findall(pattern, text)))
