"""
Módulo: Puertos Abiertos
Herramientas: nmap
Nota: Se escanean los puertos más comunes. Para todos 65535 se debe ejecutar manualmente.
"""
import asyncio
import re
from typing import List, Dict, Any
from .utils import run_command, clean_domain, resolve_domain

# Common ports to scan (subset for speed - full scan via manual nmap)
COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888"

async def nmap_scan(target: str, ports: str = COMMON_PORTS) -> Dict[str, Any]:
    """Run nmap scan on a target."""
    cmd = [
        "nmap", "-sV", "--open", "-T4",
        "--script", "banner",
        "-p", ports,
        "-oN", "-",
        target
    ]
    res = await run_command(cmd, timeout=120)
    
    if not res["success"] and not res["stdout"]:
        # Try basic scan without scripts
        cmd2 = ["nmap", "-T4", "--open", "-p", ports, target]
        res = await run_command(cmd2, timeout=60)

    services = []
    if res["stdout"]:
        # Parse nmap output
        for line in res["stdout"].splitlines():
            # Match port lines like: 80/tcp   open  http    Apache httpd 2.4.41
            m = re.match(r'\s*(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                port, proto, service, version = m.groups()
                risk = assess_port_risk(int(port), service)
                services.append({
                    "port": int(port),
                    "protocol": proto,
                    "service": service,
                    "version": version.strip(),
                    "risk": risk
                })

    return {
        "target": target,
        "open_ports": services,
        "raw": res["stdout"][:3000] if res["stdout"] else "",
        "available": res["success"] or bool(res["stdout"]),
        "status": "ok" if services else ("no_ports" if res["success"] else "error")
    }

def assess_port_risk(port: int, service: str) -> str:
    """Assess risk level for an open port."""
    critical_ports = {21, 23, 3389, 5900, 445, 135, 139}  # FTP, Telnet, RDP, VNC, SMB
    high_ports = {22, 3306, 5432, 1521, 27017, 6379}  # SSH, databases
    medium_ports = {80, 8080, 8888, 25, 110, 143}  # HTTP, mail
    
    if port in critical_ports:
        return "critical"
    elif port in high_ports:
        return "high"
    elif port in medium_ports:
        return "medium"
    else:
        return "low"

async def run(company: str, domains: List[str]) -> Dict[str, Any]:
    results = {
        "summary": "",
        "findings": [],
        "scans": [],
        "all_open_ports": [],
        "tools": [],
        "severity": "info"
    }

    total_ports = 0
    critical_services = []

    for domain in domains:
        d = clean_domain(domain)
        
        # Resolve to IP first
        ip = await resolve_domain(d)
        
        # Scan domain
        scan = await nmap_scan(d)
        scan["domain"] = d
        scan["ip"] = ip
        results["scans"].append(scan)
        
        for port_info in scan.get("open_ports", []):
            port_info["domain"] = d
            results["all_open_ports"].append(port_info)
            total_ports += 1
            
            if port_info["risk"] in ["critical", "high"]:
                critical_services.append(f"{d}:{port_info['port']}/{port_info['service']}")
                results["findings"].append({
                    "type": "open_port",
                    "domain": d,
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "version": port_info["version"],
                    "severity": port_info["risk"]
                })
    
    results["tools"].append({
        "tool": "nmap",
        "status": "executed",
        "note": f"Scan de puertos comunes ({COMMON_PORTS}). Para escaneo completo (65535 puertos) ejecutar: nmap -sV -p- <target>"
    })

    # Severity
    if any(f.get("severity") == "critical" for f in results["findings"]):
        results["severity"] = "critical"
    elif any(f.get("severity") == "high" for f in results["findings"]):
        results["severity"] = "high"
    elif any(f.get("severity") == "medium" for f in results["findings"]):
        results["severity"] = "medium"
    elif total_ports > 0:
        results["severity"] = "low"

    results["summary"] = (
        f"Se detectaron {total_ports} puerto(s) abierto(s) en {len(domains)} dominio(s). "
        f"{len(critical_services)} servicio(s) de alto riesgo encontrado(s). "
        "NOTA: Ejecutar nmap -p- para escaneo completo de 65535 puertos."
    )

    return results
