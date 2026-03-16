from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
import json, os, uuid, shutil, mimetypes, base64
from datetime import datetime
from pathlib import Path

from modules import (
    emails, subdomains, whois_module, ssl_certs,
    ports, dmarc, technologies, robots,
    dns_servers, asn, data_leak, cloud,
    cybersquatting, favicons, credentials, sitemap
)
from pdf_report import generate_pdf
import keys_manager
from evidence_capture import auto_capture_module
from tools_client import is_available as _tools_available

app = FastAPI(title="OSINT Surface Analyzer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

SCANS_DIR = Path("/app/data/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR = Path("/app/data/evidence")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

def load_index():
    p = SCANS_DIR / "index.json"
    if p.exists():
        try: return json.loads(p.read_text())
        except: pass
    return []

def save_index(idx):
    (SCANS_DIR / "index.json").write_text(json.dumps(idx, indent=2))

def save_scan(scan_id, data):
    (SCANS_DIR / f"{scan_id}.json").write_text(json.dumps(data, indent=2))

def load_scan(scan_id):
    p = SCANS_DIR / f"{scan_id}.json"
    if not p.exists(): raise HTTPException(404, "Scan not found")
    return json.loads(p.read_text())

app.mount("/static", StaticFiles(directory="/app/frontend/dist"), name="static")

@app.get("/")
async def root(): return FileResponse("/app/frontend/dist/index.html")

@app.get("/health")
async def health(): return {"status": "ok"}

# ── SCAN HISTORY ───────────────────────────────────────────────────────────
@app.get("/api/scans")
async def list_scans(): return load_index()

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str): return load_scan(scan_id)

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    p = SCANS_DIR / f"{scan_id}.json"
    if p.exists(): p.unlink()
    save_index([s for s in load_index() if s["id"] != scan_id])
    return {"deleted": scan_id}

@app.post("/api/scans/{scan_id}/rename")
async def rename_scan(scan_id: str, body: dict):
    name = body.get("name","").strip()
    if not name: raise HTTPException(400, "Name required")
    idx = load_index()
    for s in idx:
        if s["id"] == scan_id: s["name"] = name; break
    save_index(idx)
    return {"ok": True}

# ── IMPORT ────────────────────────────────────────────────────────────────
@app.post("/api/scans/import")
async def import_scan(body: dict):
    """Import a scan from a JSON file. Accepts both full scan format and active-scan export."""
    # Normalize: handle both formats
    meta    = body.get("meta", {})
    stats   = body.get("stats", {})
    modules = body.get("modules", {})

    # Minimal validation
    if not modules:
        raise HTTPException(400, "Invalid scan: missing 'modules' field")

    company = meta.get("company") or body.get("company", "Importado")
    domains = meta.get("domains") or body.get("domains", [])

    # Always assign a fresh ID to avoid collisions
    new_id = str(uuid.uuid4())
    ts     = meta.get("timestamp") or datetime.utcnow().isoformat() + "Z"

    # Rebuild clean meta
    scan_record = {
        "meta": {
            "id":          new_id,
            "company":     company,
            "domains":     domains,
            "timestamp":   ts,
            "modules_run": list(modules.keys()),
            "name":        meta.get("name") or company,
            "imported":    True,
            "imported_at": datetime.utcnow().isoformat() + "Z",
        },
        "stats":   stats,
        "modules": modules,
    }

    # Recompute stats if empty/missing
    if not any(stats.values()):
        computed = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for md in modules.values():
            if isinstance(md, dict):
                sev = md.get("severity","info")
                if sev in computed: computed[sev] += 1
        scan_record["stats"] = computed
        stats = computed

    save_scan(new_id, scan_record)
    idx = load_index()
    idx.insert(0, {
        "id":            new_id,
        "name":          scan_record["meta"]["name"],
        "company":       company,
        "domains":       domains,
        "timestamp":     ts,
        "stats":         scan_record["stats"],
        "modules_count": len(modules),
        "imported":      True,
    })
    save_index(idx)
    return {"id": new_id, "company": company, "modules": len(modules)}

# ── PDF ────────────────────────────────────────────────────────────────────
@app.get("/api/scans/{scan_id}/pdf")
async def pdf_from_id(scan_id: str):
    data = load_scan(scan_id)
    ev_items = _load_evidence_index(scan_id)
    for ev in ev_items:
        ev.setdefault("scan_id", scan_id)
    try: pdf_bytes = generate_pdf(data, evidence_items=ev_items, evidence_dir=str(EVIDENCE_DIR))
    except Exception as e: raise HTTPException(500, str(e))
    company = data.get("meta",{}).get("company","report").replace(" ","_")
    date    = data.get("meta",{}).get("timestamp","")[:10]
    return Response(content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="osint_{company}_{date}.pdf"'})

@app.post("/api/pdf")
async def pdf_from_body(body: dict):
    scan_id = body.get("meta",{}).get("id","")
    ev_items = _load_evidence_index(scan_id) if scan_id else []
    for ev in ev_items:
        ev.setdefault("scan_id", scan_id)
    try: pdf_bytes = generate_pdf(body, evidence_items=ev_items, evidence_dir=str(EVIDENCE_DIR))
    except Exception as e: raise HTTPException(500, str(e))
    company = body.get("meta",{}).get("company",body.get("company","report")).replace(" ","_")
    date    = datetime.now().strftime("%Y-%m-%d")
    return Response(content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="osint_{company}_{date}.pdf"'})

# ── WEBSOCKET SCAN ─────────────────────────────────────────────────────────
@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    scan_id = str(uuid.uuid4())
    collected = {}

    try:
        data     = await websocket.receive_json()
        company  = data.get("company","")
        domains  = data.get("domains",[])
        selected = data.get("modules",[])

        if not company or not domains:
            await websocket.send_json({"type":"error","message":"Company and domains required"})
            return

        module_map = {
            "emails":        (emails.run,         "Correos Electronicos"),
            "subdomains":    (subdomains.run,      "Subdominios"),
            "whois":         (whois_module.run,    "WHOIS"),
            "ssl":           (ssl_certs.run,       "Certificados SSL/TLS"),
            "ports":         (ports.run,           "Puertos Abiertos"),
            "dmarc":         (dmarc.run,           "Registros DMARC"),
            "technologies":  (technologies.run,    "Tecnologias"),
            "robots":        (robots.run,          "ROBOTS.txt"),
            "dns":           (dns_servers.run,     "Servidores DNS & MX"),
            "asn":           (asn.run,             "ASN"),
            "data_leak":     (data_leak.run,       "Data Leak"),
            "cloud":         (cloud.run,           "Infraestructura Cloud"),
            "cybersquatting":(cybersquatting.run,  "Cybersquatting"),
            "favicons":      (favicons.run,        "Analisis FAVICON"),
            "credentials":   (credentials.run,     "Credenciales Exfiltradas"),
            "sitemap":       (sitemap.run,         "Site Map"),
        }

        active = selected if selected else list(module_map.keys())

        # Module subtitles shown during scan
        module_subtitles = {
            "emails":        "Enumerating emails via dorks, APIs & WHOIS",
            "subdomains":    "Resolving subdomains via DNS & cert transparency",
            "whois":         "Querying WHOIS & domain registration records",
            "ssl":           "Checking SSL/TLS certificates & expiry dates",
            "ports":         "Scanning open TCP/UDP ports with Nmap",
            "dmarc":         "Checking DMARC, SPF & DKIM records",
            "technologies":  "Fingerprinting web technologies & CMS",
            "robots":        "Fetching robots.txt & sitemap directives",
            "dns":           "Resolving DNS, NS & MX records",
            "asn":           "Looking up Autonomous System Numbers & IP blocks",
            "data_leak":     "Searching breach databases & leak indexes",
            "cloud":         "Discovering exposed cloud buckets & assets",
            "cybersquatting":"Detecting typosquatting & lookalike domains",
            "favicons":      "Hashing favicons to find related assets",
            "credentials":   "Searching exfiltrated credential dumps",
            "sitemap":       "Crawling sitemap.xml & exposed endpoints",
        }

        await websocket.send_json({
            "type": "start",
            "company": company,
            "domains": domains,
            "scan_id": scan_id,
            "total_modules": len(active),
            "active_modules": active,
        })

        async def send(module, status, message, result=None, progress=None, partial_count=None, log_event=None, elapsed=None):
            p = {"type":"update","module":module,"status":status,"message":message}
            if result is not None: p["data"] = result
            if progress is not None: p["progress"] = progress
            if partial_count is not None: p["partial_count"] = partial_count
            if log_event is not None: p["log_event"] = log_event
            if elapsed is not None: p["elapsed"] = elapsed
            await websocket.send_json(p)

        async def send_log(module, text):
            await websocket.send_json({"type":"log","module":module,"text":text})

        stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        completed_count = 0
        import time as _time

        # Build API keys dict — passed to osint-tools service
        _api_keys = {
            svc: keys_manager.get_key(svc) or ""
            for svc in ("shodan","virustotal","securitytrails","intelx","hunter_io","hibp")
        }
        # Inject into tools_client for this scan (stored in a context var)
        import tools_client as _tc
        _tc._scan_api_keys = _api_keys

        # Log osint-tools availability
        if await _tools_available():
            await send_log("system", "[osint-tools] ✔ Servicio de herramientas CLI disponible")
        else:
            await send_log("system", "[osint-tools] ⚠ Servicio osint-tools no disponible — usando solo herramientas locales")

        for key in active:
            if key not in module_map: continue
            func, label = module_map[key]
            subtitle = module_subtitles.get(key, "")
            t_start = _time.time()

            await send(key, "running", f"Ejecutando: {label}...", progress=0, elapsed=0)
            await send_log(key, f"▶ Starting {label}")

            try:
                result = await func(company, domains)
                elapsed = round(_time.time() - t_start, 1)
                collected[key] = result
                sev = result.get("severity","info")
                if sev in stats: stats[sev] += 1
                findings_count = len(result.get("findings", []))
                completed_count += 1
                await send(key, "done", f"{label} completado",
                           result=result, progress=100,
                           partial_count=findings_count,
                           elapsed=elapsed)
                await websocket.send_json({
                    "type": "progress",
                    "completed": completed_count,
                    "total": len(active),
                    "current_module": key,
                    "current_label": label,
                })
                await send_log(key, f"✔ {label}: {findings_count} findings [{elapsed}s]")

                # ── Auto-capture raw tool outputs as evidence ──────────────
                for tool_entry in result.get("tools", []):
                    raw = tool_entry.get("raw") or tool_entry.get("output")
                    tool_name = tool_entry.get("tool", key)
                    if raw:
                        raw_text = "\n".join(raw) if isinstance(raw, list) else str(raw)
                        if raw_text.strip():
                            ev_id_auto = str(uuid.uuid4())
                            fname_auto = f"{ev_id_auto}.txt"
                            fpath_auto = _evidence_dir(scan_id) / fname_auto
                            fpath_auto.write_text(raw_text, encoding="utf-8")
                            auto_entry = {
                                "id": ev_id_auto, "scan_id": scan_id,
                                "module": key, "finding_ref": "",
                                "caption": f"[AUTO] {tool_name} output",
                                "source": "auto",
                                "filename": f"{tool_name.lower().replace(' ','_')}_output.txt",
                                "stored_name": fname_auto,
                                "media_type": "text/plain",
                                "size": len(raw_text.encode()),
                                "timestamp": datetime.utcnow().isoformat()+"Z",
                                "is_image": False, "is_text": True,
                                "tool": tool_name,
                            }
                            ev_idx = _load_evidence_index(scan_id)
                            ev_idx.append(auto_entry)
                            _save_evidence_index(scan_id, ev_idx)
                # Also capture module-level raw if present
                if result.get("raw"):
                    raw_text = str(result["raw"])[:100000]
                    ev_id_auto = str(uuid.uuid4())
                    fname_auto = f"{ev_id_auto}.txt"
                    (_evidence_dir(scan_id) / fname_auto).write_text(raw_text, encoding="utf-8")
                    ev_idx = _load_evidence_index(scan_id)
                    ev_idx.append({
                        "id": ev_id_auto, "scan_id": scan_id, "module": key,
                        "finding_ref": "", "caption": f"[AUTO] {label} raw output",
                        "source": "auto", "filename": f"{key}_raw.txt",
                        "stored_name": fname_auto, "media_type": "text/plain",
                        "size": len(raw_text.encode()),
                        "timestamp": datetime.utcnow().isoformat()+"Z",
                        "is_image": False, "is_text": True, "tool": label,
                    })
                    _save_evidence_index(scan_id, ev_idx)

                # ── Auto-capture: screenshots, HTTP headers, SSL certs ─────
                try:
                    await send_log(key, f"[EVIDENCE] Auto-capturando evidencia para {label}...")
                    ev_idx = _load_evidence_index(scan_id)

                    async def _ev_log(msg):
                        await send_log(key, msg)

                    new_ev = await auto_capture_module(
                        scan_id=scan_id,
                        module_id=key,
                        module_result=result,
                        ev_dir=_evidence_dir(scan_id),
                        ev_idx=ev_idx,
                        log_fn=_ev_log,
                    )
                    if new_ev:
                        _save_evidence_index(scan_id, ev_idx)
                        await send_log(key, f"[EVIDENCE] ✔ {len(new_ev)} evidencia(s) auto-capturada(s)")
                except Exception as _ev_err:
                    await send_log(key, f"[EVIDENCE] ⚠ Error en auto-captura: {_ev_err}")

            except Exception as e:
                elapsed = round(_time.time() - t_start, 1)
                err = {"severity":"info","findings":[],"tools":[],"summary":str(e)}
                collected[key] = err
                completed_count += 1
                await send(key, "error", f"Error en {label}: {str(e)}", elapsed=elapsed)
                await websocket.send_json({
                    "type": "progress",
                    "completed": completed_count,
                    "total": len(active),
                    "current_module": key,
                    "current_label": label,
                })
                await send_log(key, f"✖ {label} error: {str(e)[:80]}")

        scan_record = {
            "meta": {
                "id": scan_id, "company": company, "domains": domains,
                "timestamp": datetime.utcnow().isoformat()+"Z",
                "modules_run": active, "name": company,
            },
            "stats": stats,
            "modules": collected,
        }

        save_scan(scan_id, scan_record)
        idx = load_index()
        idx.insert(0, {
            "id": scan_id, "name": company, "company": company,
            "domains": domains, "timestamp": scan_record["meta"]["timestamp"],
            "stats": stats, "modules_count": len(collected),
        })
        save_index(idx)

        await websocket.send_json({"type":"complete","scan_id":scan_id,"stats":stats})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try: await websocket.send_json({"type":"error","message":str(e)})
        except: pass

# ── API KEYS MANAGEMENT ────────────────────────────────────────────────────────
@app.get("/api/keys")
async def list_keys():
    """Return all services with configured status (values never exposed)."""
    return keys_manager.get_status()

@app.post("/api/keys/{service_id}")
async def set_key(service_id: str, body: dict):
    """Save or delete an API key."""
    if service_id not in keys_manager.SERVICES:
        raise HTTPException(400, f"Unknown service: {service_id}")
    value = body.get("value", "").strip()
    keys_manager.set_key(service_id, value)
    return {"ok": True, "service": service_id, "configured": bool(value)}

@app.delete("/api/keys/{service_id}")
async def delete_key(service_id: str):
    """Remove a stored API key."""
    keys_manager.set_key(service_id, "")
    return {"ok": True, "deleted": service_id}

@app.get("/api/keys/audit")
async def get_key_audit():
    """Return audit log of key access (no values exposed)."""
    return {"entries": keys_manager.get_audit_log(100)}

# ── EXCEL EXPORT ────────────────────────────────────────────────────────────────
from fastapi.responses import StreamingResponse
import io

@app.get("/api/scans/{scan_id}/xlsx")
async def export_scan_xlsx(scan_id: str):
    """Export full scan as multi-sheet Excel workbook including evidence."""
    from excel_report import generate_excel
    data = load_scan(scan_id)
    # Load evidence index for this scan
    ev_items = _load_evidence_index(scan_id)
    # Inject scan_id into each item (needed by _build_evidence to locate files)
    for ev in ev_items:
        ev.setdefault("scan_id", scan_id)
    buf = generate_excel(data, evidence_items=ev_items,
                         evidence_dir=str(EVIDENCE_DIR))
    company  = data.get("meta", {}).get("company", scan_id).replace(" ", "_")
    date_str = (data.get("meta", {}).get("timestamp", "")[:10])
    fname = f"osint_{company}_{date_str}.xlsx"
    return StreamingResponse(
        io.BytesIO(buf),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )

# ── MANUAL FINDINGS ─────────────────────────────────────────────────────────────
@app.post("/api/scans/{scan_id}/manual")
async def add_manual_findings(scan_id: str, body: dict):
    """
    Add manual findings to a specific module of a saved scan.
    Body: { "module": "data_leak", "findings": [...] }
    """
    module  = body.get("module", "").strip()
    new_fnd = body.get("findings", [])
    if not module:
        raise HTTPException(400, "module required")

    scan = load_scan(scan_id)
    mod_data = scan.get("modules", {}).get(module)
    if mod_data is None:
        # Create empty module entry if not present
        scan.setdefault("modules", {})[module] = {
            "findings": [], "tools": [], "summary": "", "severity": "info"
        }
        mod_data = scan["modules"][module]

    # Tag each finding as manually added
    for f in new_fnd:
        f["manual"] = True
        f.setdefault("severity", "medium")
    mod_data.setdefault("findings", []).extend(new_fnd)

    # Recalc severity
    sevs = [f.get("severity","info") for f in mod_data["findings"]]
    sev_order = ["info","low","medium","high","critical"]
    top = max(sevs, key=lambda s: sev_order.index(s) if s in sev_order else 0, default="info")
    mod_data["severity"] = top

    # Rebuild stats
    stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for m in scan["modules"].values():
        s = m.get("severity","info")
        if s in stats: stats[s] += 1
    scan["stats"] = stats

    save_scan(scan_id, scan)
    # Update index stats
    idx = load_index()
    for entry in idx:
        if entry["id"] == scan_id:
            entry["stats"] = stats; break
    save_index(idx)

    return {"ok": True, "module": module, "added": len(new_fnd),
            "total_findings": len(mod_data["findings"])}

@app.get("/api/scans/{scan_id}/manual/{module}")
async def get_manual_findings(scan_id: str, module: str):
    """Get all manual findings for a module."""
    scan = load_scan(scan_id)
    mod_data = scan.get("modules", {}).get(module, {})
    manual = [f for f in mod_data.get("findings", []) if f.get("manual")]
    return {"module": module, "findings": manual}

# ── EVIDENCE SYSTEM ─────────────────────────────────────────────────────────────
ALLOWED_EVIDENCE_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "text/plain", "application/json", "text/csv",
    "application/pdf",
}
MAX_EVIDENCE_SIZE = 15 * 1024 * 1024  # 15MB

def _evidence_dir(scan_id: str) -> Path:
    d = EVIDENCE_DIR / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d

def _evidence_index_path(scan_id: str) -> Path:
    return _evidence_dir(scan_id) / "_index.json"

def _load_evidence_index(scan_id: str) -> list:
    p = _evidence_index_path(scan_id)
    if p.exists():
        try: return json.loads(p.read_text())
        except: pass
    return []

def _save_evidence_index(scan_id: str, idx: list):
    _evidence_index_path(scan_id).write_text(json.dumps(idx, indent=2))

@app.get("/api/scans/{scan_id}/evidence")
async def list_evidence(scan_id: str, module: str = None):
    """List all evidence files for a scan, optionally filtered by module."""
    idx = _load_evidence_index(scan_id)
    if module:
        idx = [e for e in idx if e.get("module") == module]
    # Add inline preview for small text/json files
    for e in idx:
        e["preview_url"] = f"/api/scans/{scan_id}/evidence/{e['id']}/file"
    return idx

@app.post("/api/scans/{scan_id}/evidence")
async def upload_evidence(
    scan_id: str,
    file: UploadFile = File(...),
    module: str = Form(...),
    finding_ref: str = Form(""),   # optional: link to a specific finding value
    caption: str = Form(""),
    source: str = Form("manual"),  # manual | auto
):
    """Upload a file as evidence for a scan module."""
    # Validate scan exists
    scan_path = SCANS_DIR / f"{scan_id}.json"
    if not scan_path.exists():
        raise HTTPException(404, "Scan not found")

    # Read and validate
    content = await file.read()
    if len(content) > MAX_EVIDENCE_SIZE:
        raise HTTPException(413, f"File too large (max {MAX_EVIDENCE_SIZE//1024//1024}MB)")

    media_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if media_type not in ALLOWED_EVIDENCE_TYPES:
        raise HTTPException(415, f"Unsupported file type: {media_type}. Allowed: images, text, json, csv, pdf")

    # Save file
    ev_id  = str(uuid.uuid4())
    suffix = Path(file.filename or "file").suffix or _ext_for_mime(media_type)
    fname  = f"{ev_id}{suffix}"
    fpath  = _evidence_dir(scan_id) / fname
    fpath.write_bytes(content)

    entry = {
        "id":          ev_id,
        "scan_id":     scan_id,
        "module":      module,
        "finding_ref": finding_ref,
        "caption":     caption,
        "source":      source,
        "filename":    file.filename or fname,
        "stored_name": fname,
        "media_type":  media_type,
        "size":        len(content),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "is_image":    media_type.startswith("image/"),
        "is_text":     media_type.startswith("text/") or media_type == "application/json",
    }
    idx = _load_evidence_index(scan_id)
    idx.append(entry)
    _save_evidence_index(scan_id, idx)
    return entry

@app.get("/api/scans/{scan_id}/evidence/{ev_id}/file")
async def get_evidence_file(scan_id: str, ev_id: str):
    """Serve the evidence file."""
    idx = _load_evidence_index(scan_id)
    entry = next((e for e in idx if e["id"] == ev_id), None)
    if not entry:
        raise HTTPException(404, "Evidence not found")
    fpath = _evidence_dir(scan_id) / entry["stored_name"]
    if not fpath.exists():
        raise HTTPException(404, "File not found on disk")
    return FileResponse(str(fpath), media_type=entry["media_type"],
                        filename=entry["filename"])

@app.get("/api/scans/{scan_id}/evidence/{ev_id}/preview")
async def get_evidence_preview(scan_id: str, ev_id: str):
    """Return text/json evidence as inline content (max 50KB)."""
    idx = _load_evidence_index(scan_id)
    entry = next((e for e in idx if e["id"] == ev_id), None)
    if not entry:
        raise HTTPException(404, "Evidence not found")
    if not entry.get("is_text"):
        raise HTTPException(400, "Preview only available for text files")
    fpath = _evidence_dir(scan_id) / entry["stored_name"]
    if not fpath.exists():
        raise HTTPException(404, "File not found on disk")
    content = fpath.read_bytes()[:50*1024].decode("utf-8", errors="replace")
    return {"content": content, "truncated": fpath.stat().st_size > 50*1024}

@app.delete("/api/scans/{scan_id}/evidence/{ev_id}")
async def delete_evidence(scan_id: str, ev_id: str):
    """Delete an evidence file."""
    idx = _load_evidence_index(scan_id)
    entry = next((e for e in idx if e["id"] == ev_id), None)
    if not entry:
        raise HTTPException(404, "Evidence not found")
    fpath = _evidence_dir(scan_id) / entry["stored_name"]
    if fpath.exists():
        fpath.unlink()
    idx = [e for e in idx if e["id"] != ev_id]
    _save_evidence_index(scan_id, idx)
    return {"ok": True, "deleted": ev_id}

@app.patch("/api/scans/{scan_id}/evidence/{ev_id}")
async def update_evidence_meta(scan_id: str, ev_id: str, body: dict):
    """Update caption or finding_ref of an evidence entry."""
    idx = _load_evidence_index(scan_id)
    for e in idx:
        if e["id"] == ev_id:
            if "caption"     in body: e["caption"]     = body["caption"]
            if "finding_ref" in body: e["finding_ref"] = body["finding_ref"]
            break
    else:
        raise HTTPException(404, "Evidence not found")
    _save_evidence_index(scan_id, idx)
    return {"ok": True}

@app.post("/api/scans/{scan_id}/evidence/auto")
async def add_auto_evidence(scan_id: str, body: dict):
    """
    Store raw tool output as text evidence automatically during scan.
    body: { module, tool_name, content, finding_ref? }
    """
    scan_path = SCANS_DIR / f"{scan_id}.json"
    if not scan_path.exists():
        raise HTTPException(404, "Scan not found")
    module   = body.get("module", "")
    tool     = body.get("tool_name", "auto")
    content  = body.get("content", "")
    if not content or not module:
        raise HTTPException(400, "module and content required")

    ev_id  = str(uuid.uuid4())
    fname  = f"{ev_id}.txt"
    fpath  = _evidence_dir(scan_id) / fname
    fpath.write_text(content, encoding="utf-8")

    entry = {
        "id":          ev_id,
        "scan_id":     scan_id,
        "module":      module,
        "finding_ref": body.get("finding_ref", ""),
        "caption":     f"[AUTO] {tool}",
        "source":      "auto",
        "filename":    f"{tool}_output.txt",
        "stored_name": fname,
        "media_type":  "text/plain",
        "size":        len(content.encode()),
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "is_image":    False,
        "is_text":     True,
        "tool":        tool,
    }
    idx = _load_evidence_index(scan_id)
    idx.append(entry)
    _save_evidence_index(scan_id, idx)
    return entry

def _ext_for_mime(mime: str) -> str:
    return {
        "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
        "image/webp": ".webp", "text/plain": ".txt", "application/json": ".json",
        "text/csv": ".csv", "application/pdf": ".pdf",
    }.get(mime, ".bin")
