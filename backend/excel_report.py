"""
Generador de Reportes Excel - Análisis de Información Expuesta

"""
import io
import os
from datetime import datetime
from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import (
    Font, PatternFill, Alignment, Border, Side, GradientFill
)
from openpyxl.utils import get_column_letter

# ── Palette ──────────────────────────────────────────────────────────────────
BG_DARK   = "05080D"
BG_MID    = "0C1420"
BG_CARD   = "0F1A28"
BG_ROW    = "111E2D"
C_CYAN    = "00D4FF"
C_GREEN   = "00E676"
C_RED     = "FF1744"
C_ORANGE  = "FF9100"
C_YELLOW  = "FFD740"
C_BLUE    = "448AFF"
C_PURPLE  = "B388FF"
C_T1      = "DDE8F5"
C_T2      = "8AABB5"
C_T3      = "3A5570"
C_WHITE   = "FFFFFF"

SEV_COLOR = {
    "critical": (C_RED,    "FF1744"),
    "high":     (C_ORANGE, "FF9100"),
    "medium":   (C_YELLOW, "FFD740"),
    "low":      (C_GREEN,  "00E676"),
    "info":     (C_BLUE,   "448AFF"),
}

MOD_LABELS = {
    'emails':'Correos Electronicos','subdomains':'Subdominios','whois':'WHOIS',
    'ssl':'Certificados SSL-TLS','dmarc':'Registros DMARC-SPF','ports':'Puertos Abiertos',
    'technologies':'Tecnologias','robots':'ROBOTS.txt','dns':'Servidores DNS y MX',
    'asn':'ASN','data_leak':'Data Leak','cloud':'Infraestructura Cloud',
    'cybersquatting':'Cybersquatting','favicons':'Analisis FAVICON',
    'credentials':'Credenciales Exfiltradas','sitemap':'Site Map',
}

# Excel sheet names: max 31 chars, no /\?*[]:
def _safe_title(s: str, max_len: int = 31) -> str:
    for ch in '/\\?*[]:'  :
        s = s.replace(ch, '-')
    return s[:max_len]

# ── Style helpers ─────────────────────────────────────────────────────────────
def _fill(hex_color: str):
    return PatternFill("solid", fgColor=hex_color)

def _font(hex_color: str = C_T1, bold=False, size=10, name="Arial"):
    return Font(color=hex_color, bold=bold, size=size, name=name)

def _border_thin(color=C_T3):
    s = Side(style="thin", color=color)
    return Border(left=s, right=s, top=s, bottom=s)

def _center():
    return Alignment(horizontal="center", vertical="center", wrap_text=True)

def _left(wrap=True):
    return Alignment(horizontal="left", vertical="center", wrap_text=wrap)

def _right():
    return Alignment(horizontal="right", vertical="center")

def _hdr(ws, row, col, value, width_hint=None):
    cell = ws.cell(row=row, column=col, value=value)
    cell.fill = _fill(BG_CARD)
    cell.font = _font(C_CYAN, bold=True, size=9)
    cell.alignment = _center()
    cell.border = _border_thin(C_T3)
    if width_hint:
        ws.column_dimensions[get_column_letter(col)].width = width_hint
    return cell

def _row_data(ws, row, col, value, sev="info", manual=False, center=False):
    cell = ws.cell(row=row, column=col, value=value)
    row_bg = BG_ROW if row % 2 == 0 else BG_MID
    cell.fill = _fill(row_bg)
    txt_color = C_T1 if not manual else C_PURPLE
    cell.font = _font(txt_color, size=9)
    cell.alignment = _center() if center else _left()
    cell.border = _border_thin(C_T3)
    return cell

def _sev_cell(ws, row, col, sev: str):
    cell = ws.cell(row=row, column=col, value=sev.upper())
    color = SEV_COLOR.get(sev, (C_BLUE, C_BLUE))[0]
    cell.fill = _fill(BG_ROW if row % 2 == 0 else BG_MID)
    cell.font = Font(color=color, bold=True, size=9, name="Arial")
    cell.alignment = _center()
    cell.border = _border_thin(C_T3)
    return cell

def _section_title(ws, row, col, text, span=1):
    cell = ws.cell(row=row, column=col, value=text)
    cell.fill = _fill(BG_DARK)
    cell.font = _font(C_CYAN, bold=True, size=10)
    cell.alignment = _left(wrap=False)
    cell.border = _border_thin(C_T3)
    if span > 1:
        ws.merge_cells(start_row=row, start_column=col,
                       end_row=row, end_column=col + span - 1)
    return cell

def _set_col_widths(ws, widths: dict):
    for col_letter, w in widths.items():
        ws.column_dimensions[col_letter].width = w

def _freeze(ws, cell="A2"):
    ws.freeze_panes = ws[cell]

def _tab_color(ws, hex_color: str):
    ws.sheet_properties.tabColor = hex_color


# ── SHEET BUILDERS ────────────────────────────────────────────────────────────

def _build_cover(wb: Workbook, meta: dict, stats: dict):
    ws = wb.active
    ws.title = "Portada"
    _tab_color(ws, C_CYAN)
    ws.sheet_view.showGridLines = False

    company  = meta.get("company", "N/A")
    domains  = ", ".join(meta.get("domains", []))
    ts       = meta.get("timestamp", "")[:19].replace("T", " ")
    mod_count= meta.get("modules_count", len(meta.get("modules_run", [])))

    # Title block
    ws.row_dimensions[1].height = 10
    ws.row_dimensions[2].height = 45
    c = ws.cell(row=2, column=2, value="ANÁLISIS DE INFORMACIÓN EXPUESTA")
    c.fill = _fill(BG_DARK)
    c.font = Font(color=C_CYAN, bold=True, size=18, name="Arial")
    c.alignment = Alignment(horizontal="left", vertical="center")
    ws.merge_cells("B2:H2")

    ws.row_dimensions[3].height = 20
    c = ws.cell(row=3, column=2, value="OSINT Surface Analyzer")
    c.fill = _fill(BG_DARK)
    c.font = Font(color=C_T3, bold=False, size=10, name="Arial")
    c.alignment = Alignment(horizontal="left", vertical="center")
    ws.merge_cells("B3:H3")

    ws.row_dimensions[4].height = 8

    # Info grid
    info_rows = [
        ("EMPRESA / CLIENTE", company),
        ("DOMINIOS ANALIZADOS", domains),
        ("FECHA DEL ESCANEO", ts),
        ("MÓDULOS EJECUTADOS", mod_count),
    ]
    for i, (lbl, val) in enumerate(info_rows, start=5):
        ws.row_dimensions[i].height = 22
        lc = ws.cell(row=i, column=2, value=lbl)
        lc.fill = _fill(BG_CARD); lc.font = _font(C_T2, bold=True, size=9)
        lc.alignment = _right(); lc.border = _border_thin()
        ws.merge_cells(start_row=i, start_column=2, end_row=i, end_column=3)
        vc = ws.cell(row=i, column=4, value=val)
        vc.fill = _fill(BG_MID); vc.font = _font(C_T1, size=9)
        vc.alignment = _left(); vc.border = _border_thin()
        ws.merge_cells(start_row=i, start_column=4, end_row=i, end_column=8)

    ws.row_dimensions[9].height = 8

    # Severity summary
    sev_labels = [("CRÍTICO", "critical", C_RED),("ALTO","high",C_ORANGE),
                  ("MEDIO","medium",C_YELLOW),("BAJO","low",C_GREEN),("INFO","info",C_BLUE)]
    ws.row_dimensions[10].height = 18
    c = ws.cell(row=10, column=2, value="RESUMEN DE HALLAZGOS")
    c.fill = _fill(BG_DARK); c.font = _font(C_CYAN, bold=True, size=11)
    c.alignment = _left(); ws.merge_cells("B10:H10")

    ws.row_dimensions[11].height = 28
    for j, (lbl, key, color) in enumerate(sev_labels):
        col = 2 + j
        cnt = stats.get(key, 0)
        ws.cell(row=11, column=col, value=lbl).fill = _fill(BG_CARD)
        ws.cell(row=11, column=col).font = Font(color=color, bold=True, size=9, name="Arial")
        ws.cell(row=11, column=col).alignment = _center()
        ws.cell(row=11, column=col).border = _border_thin(color)
        ws.row_dimensions[12].height = 32
        nc = ws.cell(row=12, column=col, value=cnt)
        nc.fill = _fill(BG_MID)
        nc.font = Font(color=color, bold=True, size=20, name="Arial")
        nc.alignment = _center(); nc.border = _border_thin(color)

    ws.row_dimensions[13].height = 8

    # Note about manual findings
    ws.row_dimensions[14].height = 18
    note = ws.cell(row=14, column=2,
        value="⚠  Los hallazgos marcados con [MANUAL] fueron ingresados manualmente por el analista.")
    note.fill = _fill(BG_DARK)
    note.font = Font(color=C_YELLOW, size=9, name="Arial", italic=True)
    note.alignment = _left()
    ws.merge_cells("B14:H14")

    #  footer-ish
    ws.row_dimensions[16].height = 14
    foot = ws.cell(row=16, column=2, value="Generado por: Análisis de Información Expuesta  |  ")
    foot.fill = _fill(BG_DARK); foot.font = Font(color=C_T3, size=8, name="Arial", italic=True)
    foot.alignment = _left(); ws.merge_cells("B16:H16")

    for col in range(1, 10):
        ws.column_dimensions[get_column_letter(col)].width = \
            [3, 18, 18, 20, 20, 20, 20, 20, 3][col-1] if col <= 9 else 10

    # Fill background for all visible rows
    for r in range(1, 20):
        for col in range(1, 12):
            cell = ws.cell(row=r, column=col)
            if cell.fill.fgColor.type == "none" or cell.fill.patternType == "none":
                cell.fill = _fill(BG_DARK)


def _build_summary(wb: Workbook, modules: dict):
    ws = wb.create_sheet("Resumen")
    _tab_color(ws, C_GREEN)
    ws.sheet_view.showGridLines = False

    hdrs = ["Módulo","Etiqueta","Hallazgos","Severidad","Manual?","Resumen"]
    widths = {"A":4,"B":18,"C":22,"D":10,"E":10,"F":9,"G":55}

    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// RESUMEN DE MÓDULOS", span=6)

    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    sev_order = ["critical","high","medium","low","info"]
    rows = []
    for mod_id, mod_data in modules.items():
        if not isinstance(mod_data, dict): continue
        findings = mod_data.get("findings", [])
        manual_count = sum(1 for f in findings if f.get("manual"))
        rows.append((mod_id, mod_data, findings, manual_count))

    rows.sort(key=lambda x: sev_order.index(x[1].get("severity","info"))
                             if x[1].get("severity","info") in sev_order else 99)

    for r_idx, (mod_id, mod_data, findings, manual_count) in enumerate(rows, start=3):
        ws.row_dimensions[r_idx].height = 18
        sev = mod_data.get("severity","info")
        label = MOD_LABELS.get(mod_id, mod_id)
        has_manual = "✓" if manual_count > 0 else ""
        _row_data(ws, r_idx, 2, mod_id)
        _row_data(ws, r_idx, 3, label)
        _row_data(ws, r_idx, 4, len(findings), center=True)
        _sev_cell(ws, r_idx, 5, sev)
        _row_data(ws, r_idx, 6, has_manual, center=True)
        _row_data(ws, r_idx, 7, mod_data.get("summary",""))

    _set_col_widths(ws, widths)
    _freeze(ws, "B3")


def _build_findings(wb: Workbook, modules: dict, evidence_items: list = None):
    ws = wb.create_sheet("Todos los Hallazgos")
    _tab_color(ws, C_RED)
    ws.sheet_view.showGridLines = False

    hdrs = ["Módulo","Tipo","Valor / Descripción","Dominio","Severidad","Manual?","Detalles Adicionales","Evidencias"]
    widths = {"A":4,"B":18,"C":18,"D":40,"E":22,"F":12,"G":9,"H":45,"I":50}

    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// TODOS LOS HALLAZGOS", span=7)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    r = 3
    sev_order = ["critical","high","medium","low","info"]
    all_findings = []
    for mod_id, mod_data in modules.items():
        if not isinstance(mod_data, dict): continue
        for f in mod_data.get("findings", []):
            f["_module"] = mod_id
            all_findings.append(f)

    all_findings.sort(key=lambda x: sev_order.index(x.get("severity","info"))
                                    if x.get("severity","info") in sev_order else 99)

    for f in all_findings:
        ws.row_dimensions[r].height = 18
        mod_id = f.get("_module","")
        sev    = f.get("severity","info")
        manual = f.get("manual", False)
        val    = (f.get("value") or f.get("url") or f.get("domain") or
                  f.get("breach_title") or f.get("breach_name") or
                  f.get("squatted_domain") or f.get("path") or "")
        ftype  = (f.get("type","") or "").replace("_"," ").upper()
        domain = f.get("domain","")
        # Extra details
        extras = []
        if f.get("description"): extras.append(f.get("description","")[:150])
        if f.get("records_fmt"): extras.append(f"Records: {f['records_fmt']}")
        if f.get("data_types"):  extras.append("Data: " + ", ".join(f["data_types"][:5]))
        if f.get("risk_reason"): extras.append(f.get("risk_reason",""))
        if f.get("port"):        extras.append(f"Port: {f['port']}/{f.get('service','')} {f.get('version','')}")
        if f.get("date"):        extras.append(f"Date: {f['date']}")
        if f.get("is_verified") is not None:
            extras.append("Verified: YES" if f["is_verified"] else "Verified: NO")
        if f.get("is_sensitive"):extras.append("⚠ SENSITIVE BREACH")
        extra_str = " | ".join(extras)

        _row_data(ws, r, 2, MOD_LABELS.get(mod_id, mod_id))
        _row_data(ws, r, 3, ftype)
        _row_data(ws, r, 4, str(val))
        _row_data(ws, r, 5, domain)
        _sev_cell(ws, r, 6, sev)
        _row_data(ws, r, 7, "MANUAL" if manual else "", center=True)
        _row_data(ws, r, 8, extra_str)
        # Evidence references for this finding
        ev_for_finding = []
        if evidence_items:
            ref_val = str(val)
            for ev in evidence_items:
                if ev.get("module") == mod_id and ev.get("finding_ref") == ref_val:
                    cap = ev.get("caption") or ev.get("filename","")
                    ev_for_finding.append(cap)
        if ev_for_finding:
            ev_cell = ws.cell(r, 9, " | ".join(ev_for_finding[:5]))
            ev_cell.font = Font(color="00D4FF", size=9, name="Consolas")
            ev_cell.alignment = Alignment(wrap_text=True, vertical="top")
        r += 1

    _set_col_widths(ws, widths)
    _freeze(ws, "B3")


def _build_data_leak(wb: Workbook, mod_data: dict):
    if not mod_data or not isinstance(mod_data, dict): return
    findings = mod_data.get("findings", [])
    if not findings and not mod_data.get("breach_data"): return

    ws = wb.create_sheet("Data Leak")
    _tab_color(ws, C_RED)
    ws.sheet_view.showGridLines = False

    hdrs = ["Breach Name","Dominio","Fecha","Registros Expuestos",
            "Tipos de Datos","Severidad","Verificado","Sensible","Descripción","Fuente"]

    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// DATA LEAK — BRECHAS DE DATOS IDENTIFICADAS", span=10)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    r = 3
    for f in findings:
        ws.row_dimensions[r].height = 20
        sev  = f.get("severity","high")
        manual = f.get("manual", False)
        data_types_str = ", ".join(f.get("data_types", [])[:8])
        records = f.get("records_fmt") or (f"{f['records']:,}" if f.get("records") else "—")

        _row_data(ws, r, 2, f.get("breach_title") or f.get("breach_name") or f.get("value",""))
        _row_data(ws, r, 3, f.get("domain",""))
        _row_data(ws, r, 4, f.get("date",""))
        _row_data(ws, r, 5, records, center=True)
        _row_data(ws, r, 6, data_types_str)
        _sev_cell(ws, r, 7, sev)
        _row_data(ws, r, 8, "✓" if f.get("is_verified") else "—", center=True)
        _row_data(ws, r, 9, "⚠ SÍ" if f.get("is_sensitive") else "—", center=True)
        desc = f.get("description","")
        if manual: desc = "[MANUAL] " + desc
        _row_data(ws, r, 10, desc[:200])
        _row_data(ws, r, 11, f.get("breach_domain",""))
        r += 1

    _set_col_widths(ws, {"A":4,"B":22,"C":18,"D":12,"E":16,"F":45,"G":11,
                         "H":10,"I":9,"J":60,"K":18})
    _freeze(ws, "B3")


def _build_emails(wb: Workbook, mod_data: dict):
    if not mod_data or not isinstance(mod_data, dict): return
    findings = [f for f in mod_data.get("findings",[]) if f.get("type") in ("email","email_found")]
    if not findings: return

    ws = wb.create_sheet("Emails")
    _tab_color(ws, C_BLUE)
    ws.sheet_view.showGridLines = False

    hdrs = ["Email","Dominio","Tipo","Fuente","Severidad","Manual?"]
    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// CORREOS ELECTRÓNICOS IDENTIFICADOS", span=6)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    for r, f in enumerate(findings, start=3):
        ws.row_dimensions[r].height = 16
        _row_data(ws, r, 2, f.get("value",""))
        _row_data(ws, r, 3, f.get("domain",""))
        _row_data(ws, r, 4, f.get("type",""))
        _row_data(ws, r, 5, f.get("source",""))
        _sev_cell(ws, r, 6, f.get("severity","info"))
        _row_data(ws, r, 7, "MANUAL" if f.get("manual") else "", center=True)

    _set_col_widths(ws, {"A":4,"B":38,"C":22,"D":16,"E":22,"F":11,"G":9})
    _freeze(ws, "B3")


def _build_subdomains(wb: Workbook, mod_data: dict):
    if not mod_data or not isinstance(mod_data, dict): return
    subs = mod_data.get("active_subdomains",[])
    findings = mod_data.get("findings",[])
    if not subs and not findings: return

    ws = wb.create_sheet("Subdominios")
    _tab_color(ws, C_GREEN)
    ws.sheet_view.showGridLines = False

    hdrs = ["Subdominio","IP","Código HTTP","HTTPS","Tecnología","Severidad","Manual?"]
    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// SUBDOMINIOS ACTIVOS", span=7)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    rows = subs or [{"subdomain": f.get("value",f.get("domain","")),
                     "ip": f.get("ip",""), "status_code": f.get("status_code",""),
                     "severity": f.get("severity","info"), "manual": f.get("manual",False)}
                    for f in findings]

    for r, s in enumerate(rows, start=3):
        ws.row_dimensions[r].height = 16
        _row_data(ws, r, 2, s.get("subdomain",""))
        _row_data(ws, r, 3, s.get("ip",""))
        _row_data(ws, r, 4, s.get("status_code",""), center=True)
        _row_data(ws, r, 5, "✓" if str(s.get("status_code","")).startswith("2") else "")
        _row_data(ws, r, 6, s.get("server",""))
        _sev_cell(ws, r, 7, s.get("severity","info"))
        _row_data(ws, r, 8, "MANUAL" if s.get("manual") else "", center=True)

    _set_col_widths(ws, {"A":4,"B":38,"C":18,"D":12,"E":8,"F":18,"G":11,"H":9})
    _freeze(ws, "B3")


def _build_ports(wb: Workbook, mod_data: dict):
    if not mod_data or not isinstance(mod_data, dict): return
    ports = mod_data.get("all_open_ports",[]) or mod_data.get("findings",[])
    if not ports: return

    ws = wb.create_sheet("Puertos")
    _tab_color(ws, C_ORANGE)
    ws.sheet_view.showGridLines = False

    hdrs = ["Dominio/IP","Puerto","Servicio","Versión","Estado","Riesgo","Severidad","Manual?"]
    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// PUERTOS ABIERTOS", span=8)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    for r, p in enumerate(ports, start=3):
        ws.row_dimensions[r].height = 16
        _row_data(ws, r, 2, p.get("domain",""))
        _row_data(ws, r, 3, str(p.get("port",p.get("value",""))), center=True)
        _row_data(ws, r, 4, p.get("service",""))
        _row_data(ws, r, 5, p.get("version",""))
        _row_data(ws, r, 6, p.get("state","open"))
        _row_data(ws, r, 7, (p.get("risk","") or "").upper())
        _sev_cell(ws, r, 8, p.get("severity","info"))
        _row_data(ws, r, 9, "MANUAL" if p.get("manual") else "", center=True)

    _set_col_widths(ws, {"A":4,"B":28,"C":8,"D":16,"E":22,"F":10,"G":14,"H":11,"I":9})
    _freeze(ws, "B3")


def _build_generic(wb: Workbook, mod_id: str, mod_data: dict):
    """Generic sheet for any module with findings."""
    if not mod_data or not isinstance(mod_data, dict): return
    findings = mod_data.get("findings", [])
    if not findings: return

    label = _safe_title(MOD_LABELS.get(mod_id, mod_id), 31)
    # Avoid duplicate sheet names
    existing = {s.title for s in wb.worksheets}
    title = label
    i = 2
    while title in existing:
        title = label[:28] + str(i); i += 1
    ws = wb.create_sheet(title)
    _tab_color(ws, C_BLUE)
    ws.sheet_view.showGridLines = False

    hdrs = ["Tipo","Valor","Dominio","Severidad","Manual?","Descripción"]
    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, f"// {label.upper()}", span=6)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    for r, f in enumerate(findings, start=3):
        ws.row_dimensions[r].height = 16
        val = (f.get("value") or f.get("url") or f.get("domain") or
               f.get("squatted_domain") or f.get("path") or "")
        desc = f.get("description","")
        if f.get("port"):
            desc = f"Port {f['port']}/{f.get('service','')} {f.get('version','')} | " + desc
        if f.get("manual"):
            desc = "[MANUAL] " + desc
        _row_data(ws, r, 2, (f.get("type","") or "").replace("_"," ").upper())
        _row_data(ws, r, 3, str(val))
        _row_data(ws, r, 4, f.get("domain",""))
        _sev_cell(ws, r, 5, f.get("severity","info"))
        _row_data(ws, r, 6, "MANUAL" if f.get("manual") else "", center=True)
        _row_data(ws, r, 7, desc[:200])

    _set_col_widths(ws, {"A":4,"B":20,"C":38,"D":22,"E":11,"F":9,"G":55})
    _freeze(ws, "B3")


def _build_tools(wb: Workbook, modules: dict):
    """Sheet listing all tools, categorized by auto/manual."""
    ws = wb.create_sheet("Herramientas")
    _tab_color(ws, C_T2)
    ws.sheet_view.showGridLines = False

    hdrs = ["Módulo","Herramienta","Dominio","Estado","URL","Notas"]
    ws.row_dimensions[1].height = 20
    _section_title(ws, 1, 2, "// HERRAMIENTAS REFERENCIADAS", span=6)
    ws.row_dimensions[2].height = 16
    for i, h in enumerate(hdrs, start=2):
        _hdr(ws, 2, i, h)

    r = 3
    for mod_id, mod_data in modules.items():
        if not isinstance(mod_data, dict): continue
        for tool in mod_data.get("tools", []):
            ws.row_dimensions[r].height = 16
            status = tool.get("status","")
            is_manual = status == "manual_required"
            _row_data(ws, r, 2, MOD_LABELS.get(mod_id, mod_id))
            _row_data(ws, r, 3, tool.get("tool",""))
            _row_data(ws, r, 4, tool.get("domain",""))
            cell_s = ws.cell(row=r, column=6,
                value="MANUAL" if is_manual else "AUTO")
            cell_s.fill = _fill(BG_ROW if r%2==0 else BG_MID)
            cell_s.font = Font(color=C_YELLOW if is_manual else C_GREEN,
                               bold=True, size=9, name="Arial")
            cell_s.alignment = _center()
            cell_s.border = _border_thin()
            _row_data(ws, r, 7, tool.get("url",""))
            _row_data(ws, r, 8, tool.get("note","") or tool.get("query",""))
            r += 1

    _set_col_widths(ws, {"A":4,"B":22,"C":22,"D":22,"E":4,"F":9,"G":55,"H":35})
    _freeze(ws, "B3")


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

MOD_LABELS_ES = MOD_LABELS  # alias for evidence sheet

def _build_evidence(wb: Workbook, evidence_items: list, evidence_dir: str = "/app/data/evidence"):
    """Dedicated sheet with all evidence files: images embedded, text inline."""
    if not evidence_items:
        return

    from openpyxl.drawing.image import Image as XLImage
    from PIL import Image as PILImage

    ws = wb.create_sheet("Evidencias")
    _tab_color(ws, "FF8C00")
    ws.sheet_view.showGridLines = False

    # Title row
    ws.row_dimensions[1].height = 8
    ws.merge_cells("B2:K2")
    c = ws["B2"]
    c.value = "// EVIDENCIAS DEL ANÁLISIS"
    c.font  = Font(name="Consolas", size=14, bold=True, color="FF8C00")
    c.alignment = Alignment(horizontal="left", vertical="center")
    c.fill = _fill(BG_MID)
    ws.row_dimensions[2].height = 28

    # Group by module
    from collections import defaultdict
    by_module = defaultdict(list)
    for ev in evidence_items:
        by_module[ev.get("module", "otros")].append(ev)

    ROW = 4  # start writing from row 4
    col_widths = {"B":6, "C":32, "D":22, "E":14, "F":12, "G":12, "H":24, "I":20}
    for col, w in col_widths.items():
        ws.column_dimensions[col].width = w

    SEV_COLOR = {"critical": C_RED, "high": C_ORANGE, "medium": C_YELLOW,
                 "low": C_GREEN, "info": C_BLUE}

    for mod_id, items in by_module.items():
        mod_label = MOD_LABELS.get(mod_id, mod_id).upper()

        # Module header
        ws.row_dimensions[ROW].height = 6
        ROW += 1
        ws.merge_cells(f"B{ROW}:K{ROW}")
        c = ws[f"B{ROW}"]
        c.value = f"▸ {mod_label}"
        c.font  = Font(name="Consolas", size=10, bold=True, color="FF8C00")
        c.fill  = _fill("0F1E2E")
        c.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[ROW].height = 18
        ROW += 1

        # Column headers
        hdrs = ["Archivo", "Caption / Descripción", "Tipo", "Fuente", "Tamaño", "Fecha", "Finding ref."]
        for ci, h in enumerate(hdrs, start=2):
            c = ws.cell(row=ROW, column=ci)
            c.value = h
            c.font  = Font(name="Consolas", size=8, bold=True, color=C_T2)
            c.fill  = _fill(BG_MID)
            c.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[ROW].height = 16
        ROW += 1

        for ev in items:
            fname      = ev.get("stored_name", "")
            caption    = ev.get("caption", ev.get("filename", fname))
            media_type = ev.get("media_type", "")
            source     = ev.get("source", "manual")
            size_bytes = ev.get("size", 0)
            ts         = (ev.get("timestamp", "")[:16] or "").replace("T", " ")
            finding_ref= ev.get("finding_ref", "")
            is_image   = ev.get("is_image", False)
            is_text    = ev.get("is_text", False)
            fpath      = Path(evidence_dir) / ev.get("scan_id", "") / fname

            size_str = (f"{size_bytes/1024:.1f} KB" if size_bytes < 1024*1024
                        else f"{size_bytes/1024/1024:.1f} MB") if size_bytes else ""
            type_str = media_type.split("/")[-1].upper()
            source_str = "AUTO" if source == "auto" else "MANUAL"

            # Row for metadata
            ws.row_dimensions[ROW].height = 15
            vals = [ev.get("filename", fname), caption, type_str, source_str, size_str, ts, finding_ref]
            for ci, v in enumerate(vals, start=2):
                c = ws.cell(row=ROW, column=ci)
                c.value = str(v) if v else ""
                c.font  = Font(name="Consolas", size=8,
                               color="00D4FF" if source == "auto" else "FF9100")
                c.fill  = _fill(BG_DARK)
                c.alignment = Alignment(horizontal="left", vertical="center",
                                        wrap_text=(ci == 3))
            ROW += 1

            # For images: embed the image
            if is_image and fpath.exists():
                try:
                    img_io = io.BytesIO(fpath.read_bytes())
                    pil = PILImage.open(img_io)
                    # Scale to max 600x400
                    max_w, max_h = 600, 400
                    w, h = pil.size
                    scale = min(max_w/w, max_h/h, 1.0)
                    new_w, new_h = int(w*scale), int(h*scale)
                    pil = pil.resize((new_w, new_h), PILImage.LANCZOS)
                    out = io.BytesIO()
                    fmt = "PNG" if media_type=="image/png" else "JPEG"
                    pil.save(out, format=fmt, optimize=True, quality=85)
                    out.seek(0)
                    xl_img = XLImage(out)
                    xl_img.width  = new_w
                    xl_img.height = new_h
                    # Set row height proportionally (pixels ≈ points * 0.75)
                    img_rows = max(1, new_h // 15 + 2)
                    for r in range(ROW, ROW + img_rows):
                        ws.row_dimensions[r].height = 15
                    ws.add_image(xl_img, f"C{ROW}")
                    ROW += img_rows
                except Exception as exc:
                    c = ws.cell(row=ROW, column=3)
                    c.value = f"[Error embebiendo imagen: {exc}]"
                    c.font  = Font(name="Consolas", size=8, color="FF1744")
                    c.fill  = _fill(BG_DARK)
                    ws.row_dimensions[ROW].height = 14
                    ROW += 1

            # For text/json: include content inline (max 80 lines)
            elif is_text and fpath.exists():
                try:
                    raw_content = fpath.read_text(encoding="utf-8", errors="replace")
                    lines = raw_content.splitlines()
                    truncated = len(lines) > 80
                    if truncated:
                        lines = lines[:80]
                    content_str = "\n".join(lines)
                    if truncated:
                        content_str += f"\n... [truncado — {len(raw_content.splitlines())} líneas total]"

                    # One merged cell with pre-formatted text
                    ws.merge_cells(f"C{ROW}:K{ROW}")
                    c = ws[f"C{ROW}"]
                    c.value = content_str
                    c.font  = Font(name="Consolas", size=7.5, color="A0B4C8")
                    c.fill  = _fill("030609")
                    c.alignment = Alignment(horizontal="left", vertical="top",
                                            wrap_text=True)
                    # Height: ~12pt per line, max 300
                    line_count = min(len(lines), 80)
                    ws.row_dimensions[ROW].height = min(max(line_count * 11, 20), 400)
                    ROW += 1
                except Exception as exc:
                    c = ws.cell(row=ROW, column=3)
                    c.value = f"[Error leyendo archivo: {exc}]"
                    c.font  = Font(name="Consolas", size=8, color="FF1744")
                    c.fill  = _fill(BG_DARK)
                    ws.row_dimensions[ROW].height = 14
                    ROW += 1

            # Spacer
            ws.row_dimensions[ROW].height = 4
            ROW += 1

        # Module spacer
        ws.row_dimensions[ROW].height = 6
        ROW += 1

    # Freeze top rows
    ws.freeze_panes = "B4"


def generate_excel(scan_data: dict, evidence_items: list = None,
                   evidence_dir: str = "/app/data/evidence") -> bytes:
    meta    = scan_data.get("meta", {})
    stats   = scan_data.get("stats", {})
    modules = scan_data.get("modules", {})
    if evidence_items is None:
        evidence_items = []

    wb = Workbook()

    # Cover sheet (uses wb.active)
    _build_cover(wb, meta, stats)

    # Summary
    _build_summary(wb, modules)

    # All findings combined
    _build_findings(wb, modules, evidence_items=evidence_items)

    # Data leak — dedicated detailed sheet
    if "data_leak" in modules:
        _build_data_leak(wb, modules["data_leak"])

    # Emails
    if "emails" in modules:
        _build_emails(wb, modules["emails"])

    # Subdomains
    if "subdomains" in modules:
        _build_subdomains(wb, modules["subdomains"])

    # Ports
    if "ports" in modules:
        _build_ports(wb, modules["ports"])

    # Generic sheets for remaining modules
    for mod_id in ["whois","ssl","dmarc","technologies","robots","dns",
                   "asn","cloud","cybersquatting","favicons","credentials","sitemap"]:
        if mod_id in modules:
            _build_generic(wb, mod_id, modules[mod_id])

    # Evidence sheet — images + raw text
    _build_evidence(wb, evidence_items, evidence_dir)

    # Tools reference sheet
    _build_tools(wb, modules)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()
