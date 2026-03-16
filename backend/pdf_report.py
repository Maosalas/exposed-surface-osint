"""
Generador de Reportes PDF - OSINT Surface Analyzer
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_RIGHT
from reportlab.platypus import Flowable

C_CARD = HexColor('#0c1420'); C_DARK = HexColor('#0f1a28'); C_D2 = HexColor('#1a2535')
C_BRD  = HexColor('#0f2035'); C_CYAN = HexColor('#00d4ff'); C_GREEN = HexColor('#00e676')
C_RED  = HexColor('#ff1744'); C_ORNG = HexColor('#ff9100'); C_YEL  = HexColor('#ffd740')
C_BLUE = HexColor('#448aff'); C_T1   = HexColor('#dde8f5'); C_T2   = HexColor('#6b8aaa')
C_T3   = HexColor('#2d4a62')

SEV_COL = {'critical':C_RED,'high':C_ORNG,'medium':C_YEL,'low':C_GREEN,'info':C_BLUE}
MOD_LABELS = {
    'emails':'Correos Electronicos','subdomains':'Subdominios','whois':'WHOIS',
    'ssl':'Certificados SSL/TLS','dmarc':'Registros DMARC/SPF','ports':'Puertos Abiertos',
    'technologies':'Tecnologias','robots':'ROBOTS.txt','dns':'Servidores DNS & MX',
    'asn':'ASN','data_leak':'Data Leak','cloud':'Infraestructura Cloud',
    'cybersquatting':'Cybersquatting','favicons':'Analisis FAVICON',
    'credentials':'Credenciales Exfiltradas','sitemap':'Site Map',
}
MOD_ICON = {
    'emails':'@','subdomains':'SUB','whois':'WHS','ssl':'SSL','dmarc':'MX',
    'ports':'TCP','technologies':'CMS','robots':'BOT','dns':'DNS','asn':'ASN',
    'data_leak':'DB','cloud':'S3','cybersquatting':'SQ','favicons':'ICO',
    'credentials':'KEY','sitemap':'MAP',
}

class FilledRect(Flowable):
    def __init__(self, w, h, color, r=2):
        super().__init__(); self.width,self.height,self.color,self.r = w,h,color,r
    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0,0,self.width,self.height,self.r,fill=1,stroke=0)

class SevBar(Flowable):
    def __init__(self, stats, width):
        super().__init__(); self.stats,self.width,self.height = stats,width,40
    def draw(self):
        c = self.canv
        keys = [('CRITICAL','critical',C_RED),('HIGH','high',C_ORNG),('MEDIUM','medium',C_YEL),('LOW','low',C_GREEN),('INFO','info',C_BLUE)]
        bw = self.width/len(keys)
        for i,(lbl,key,col) in enumerate(keys):
            x = i*bw
            c.setFillColor(C_D2); c.roundRect(x+2,2,bw-4,self.height-4,3,fill=1,stroke=0)
            c.setFillColor(col); c.setFont('Courier-Bold',18); c.drawCentredString(x+bw/2,16,str(self.stats.get(key,0)))
            c.setFillColor(C_T3); c.setFont('Courier',6); c.drawCentredString(x+bw/2,6,lbl)

def S():
    return {
        'h1':  ParagraphStyle('h1', fontName='Courier-Bold',fontSize=20,textColor=C_CYAN,spaceAfter=2),
        'h2':  ParagraphStyle('h2', fontName='Courier-Bold',fontSize=10,textColor=C_CYAN,spaceBefore=4,spaceAfter=4),
        'sub': ParagraphStyle('sub',fontName='Courier',fontSize=9,textColor=C_T2,spaceAfter=2),
        'body':ParagraphStyle('body',fontName='Courier',fontSize=7.5,textColor=C_T2,spaceAfter=2,leading=11),
        'lbl': ParagraphStyle('lbl',fontName='Courier-Bold',fontSize=7,textColor=C_T3,spaceAfter=1),
        'dim': ParagraphStyle('dim',fontName='Courier',fontSize=7,textColor=C_T3),
    }

def dtable(data, widths):
    t = Table(data,colWidths=widths,repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),C_D2),('TEXTCOLOR',(0,0),(-1,0),C_T3),
        ('FONTNAME',(0,0),(-1,0),'Courier-Bold'),('FONTSIZE',(0,0),(-1,-1),7),
        ('FONTNAME',(0,1),(-1,-1),'Courier'),('TEXTCOLOR',(0,1),(-1,-1),C_T2),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_CARD,C_DARK]),('GRID',(0,0),(-1,-1),0.3,C_BRD),
        ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
        ('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    return t

def generate_pdf(scan_data: dict, evidence_items: list = None,
                 evidence_dir: str = "/app/data/evidence") -> bytes:
    from pathlib import Path as _Path
    buf = io.BytesIO()
    W,H = A4; mg = 16*mm; cw = W-2*mg
    doc = SimpleDocTemplate(buf,pagesize=A4,leftMargin=mg,rightMargin=mg,topMargin=mg,bottomMargin=12*mm)
    st = S(); story = []
    if evidence_items is None:
        evidence_items = []

    meta    = scan_data.get('meta',{}); stats   = scan_data.get('stats',{})
    modules = scan_data.get('modules',{}); company = meta.get('company',scan_data.get('company','N/A'))
    domains = meta.get('domains',scan_data.get('domains',[])); ts = meta.get('timestamp',meta.get('scan_date',''))
    try:
        dstr = datetime.fromisoformat(ts.replace('Z','')).strftime('%Y-%m-%d %H:%M UTC')
    except:
        dstr = ts[:16] if ts else 'N/A'

    # Cover
    story += [FilledRect(cw,3,C_CYAN), Spacer(1,6*mm),
              Paragraph('OSINT SURFACE ANALYZER',st['h1']),
              Paragraph('OSINT Surface Analyzer',st['sub']),
              Spacer(1,2*mm), HRFlowable(width=cw,thickness=0.4,color=C_BRD), Spacer(1,5*mm)]
    story.append(dtable([['CLIENTE',company.upper()],['DOMINIOS',', '.join(domains) if domains else 'N/A'],
        ['FECHA',dstr],['MODULOS',str(len(modules))],['HALLAZGOS',str(sum(stats.values()))]],
        [48*mm,cw-48*mm]))
    story += [Spacer(1,5*mm), Paragraph('RESUMEN DE SEVERIDAD',st['lbl']), Spacer(1,2*mm), SevBar(stats,cw), Spacer(1,8*mm)]

    # Exec summary
    story += [Paragraph('// RESUMEN EJECUTIVO',st['h2']), HRFlowable(width=cw,thickness=0.3,color=C_BRD), Spacer(1,2*mm)]
    all_f = [{**f,'_mod':mid} for mid,md in modules.items() if isinstance(md,dict) for f in md.get('findings',[])]
    crit = [f for f in all_f if f.get('severity')=='critical']
    high = [f for f in all_f if f.get('severity')=='high']
    for line in [
        f"Se analizaron {len(domains)} dominio(s) para {company}.",
        f"Se ejecutaron {len(modules)} modulos. Total hallazgos: {len(all_f)} ({stats.get('critical',0)} criticos, {stats.get('high',0)} altos, {stats.get('medium',0)} medios, {stats.get('low',0)} bajos, {stats.get('info',0)} info).",
        *(([f"CRITICO: {len(crit)} hallazgo(s) requieren atencion inmediata."]) if crit else []),
        *(([f"ALTO: {len(high)} hallazgo(s) de severidad alta detectados."]) if high else []),
    ]:
        story.append(Paragraph(line, st['body']))
    story.append(Spacer(1,3*mm))

    top = (crit+high)[:15]
    if top:
        story += [Paragraph('HALLAZGOS PRIORITARIOS',st['lbl']), Spacer(1,1*mm)]
        rows = [['SEV','MODULO','TIPO','DETALLE']]
        for f in top:
            rows.append([f.get('severity','').upper()[:8],MOD_LABELS.get(f.get('_mod',''),f.get('_mod',''))[:14],
                (f.get('type','') or '').replace('_',' ').upper()[:20],
                str(f.get('description') or f.get('value') or f.get('domain') or '')[:60]])
        t = dtable(rows,[14*mm,30*mm,36*mm,cw-80*mm])
        for i,f in enumerate(top,1):
            col = SEV_COL.get(f.get('severity','info'),C_T2)
            t.setStyle(TableStyle([('TEXTCOLOR',(0,i),(0,i),col),('FONTNAME',(0,i),(0,i),'Courier-Bold')]))
        story.append(t)
    story.append(PageBreak())

    # TOC
    story += [Paragraph('// INDICE DE MODULOS',st['h2']), HRFlowable(width=cw,thickness=0.3,color=C_BRD), Spacer(1,2*mm)]
    toc = [['#','MODULO','HALLAZGOS','SEVERIDAD']]
    for i,(mid,md) in enumerate(modules.items(),1):
        toc.append([str(i),MOD_LABELS.get(mid,mid),str(len(md.get('findings',[])) if isinstance(md,dict) else 0),(md.get('severity','info').upper() if isinstance(md,dict) else 'INFO')])
    tt = dtable(toc,[10*mm,80*mm,25*mm,25*mm])
    for i,(mid,md) in enumerate(modules.items(),1):
        if isinstance(md,dict):
            col = SEV_COL.get(md.get('severity','info'),C_T2)
            tt.setStyle(TableStyle([('TEXTCOLOR',(3,i),(3,i),col),('FONTNAME',(3,i),(3,i),'Courier-Bold')]))
    story += [tt, PageBreak()]

    # Module details
    story += [Paragraph('// DETALLE POR MODULO',st['h2']), HRFlowable(width=cw,thickness=0.3,color=C_BRD)]
    for idx,(mid,md) in enumerate(modules.items(),1):
        if not isinstance(md,dict): continue
        lbl=MOD_LABELS.get(mid,mid); icon=MOD_ICON.get(mid,'?'); sev=md.get('severity','info')
        scol=SEV_COL.get(sev,C_T2); findings=md.get('findings',[]); tools=md.get('tools',[])
        story.append(Spacer(1,4*mm))
        hdr=Table([[
            Paragraph(f'[{icon}]',ParagraphStyle('ic',fontName='Courier-Bold',fontSize=8,textColor=C_CYAN)),
            Paragraph(f'{idx:02d}. {lbl.upper()}',ParagraphStyle('mh',fontName='Courier-Bold',fontSize=9,textColor=C_T1)),
            Paragraph(sev.upper(),ParagraphStyle('sv',fontName='Courier-Bold',fontSize=8,textColor=scol,alignment=TA_RIGHT)),
        ]],colWidths=[12*mm,cw-38*mm,22*mm])
        hdr.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),C_D2),('LINEBELOW',(0,0),(-1,0),1.2,scol),
            ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
            ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        story.append(KeepTogether([hdr]))
        if md.get('summary'): story += [Spacer(1,2*mm), Paragraph(md['summary'],st['body'])]
        if findings:
            story += [Spacer(1,2*mm), Paragraph(f'HALLAZGOS ({len(findings)})',st['lbl']), Spacer(1,1*mm)]
            rows = [['SEV','TIPO','VALOR / DESCRIPCION']]
            for f in findings[:25]:
                val = str(f.get('description') or f.get('value') or f.get('url') or f.get('domain') or f.get('path') or '')
                if f.get('port'): val = f"Port {f['port']}/{f.get('service','')} - {val}"
                rows.append([f.get('severity','').upper()[:8],(f.get('type','') or '').replace('_',' ').upper()[:22],val[:75]])
            ft = dtable(rows,[14*mm,38*mm,cw-52*mm])
            for i,f in enumerate(findings[:25],1):
                col = SEV_COL.get(f.get('severity','info'),C_T2)
                ft.setStyle(TableStyle([('TEXTCOLOR',(0,i),(0,i),col),('FONTNAME',(0,i),(0,i),'Courier-Bold')]))
            story.append(ft)
            if len(findings)>25: story.append(Paragraph(f'... y {len(findings)-25} hallazgos mas (ver JSON)',st['dim']))
        for tname,tobj in _mod_tables(mid,md,cw):
            story += [Spacer(1,2*mm), Paragraph(tname,st['lbl']), Spacer(1,1*mm), tobj]
        if tools:
            story += [Spacer(1,2*mm), Paragraph('HERRAMIENTAS',st['lbl'])]
            seen=set(); parts=[]
            for t in tools[:16]:
                n=t.get('tool','')
                if n and n not in seen:
                    seen.add(n); parts.append(f"{'[OK]' if t.get('status') in ('ok','executed') else '[M]'} {n}")
            story.append(Paragraph('  |  '.join(parts),st['body']))
        story += [Spacer(1,2*mm), HRFlowable(width=cw,thickness=0.3,color=C_BRD)]

    # ── EVIDENCE SECTION ────────────────────────────────────────────────────
    if evidence_items:
        from reportlab.platypus import Image as RLImage
        from collections import defaultdict as _dd

        story += [PageBreak(), FilledRect(cw,2,HexColor('#FF8C00')), Spacer(1,4*mm),
                  Paragraph('// EVIDENCIAS DEL ANALISIS',st['h2']),
                  HRFlowable(width=cw,thickness=0.3,color=HexColor('#FF8C00')), Spacer(1,2*mm),
                  Paragraph(f'Total de evidencias adjuntas: {len(evidence_items)}  '
                            f'({sum(1 for e in evidence_items if e.get("source")=="auto")} automaticas, '
                            f'{sum(1 for e in evidence_items if e.get("source")!="auto")} manuales)',
                            st['body']),
                  Spacer(1,4*mm)]

        by_mod = _dd(list)
        for ev in evidence_items:
            by_mod[ev.get('module','otros')].append(ev)

        for mod_id, evs in by_mod.items():
            mod_label = MOD_LABELS.get(mod_id, mod_id).upper()
            story += [Paragraph(f'  [{mod_label}]', st['lbl']), Spacer(1,2*mm)]

            for ev in evs:
                fname      = ev.get('stored_name','')
                scan_id    = ev.get('scan_id','')
                caption    = ev.get('caption', ev.get('filename', fname))
                source     = ev.get('source','manual')
                ts_ev      = (ev.get('timestamp','')[:16] or '').replace('T',' ')
                finding_ref= ev.get('finding_ref','')
                is_image   = ev.get('is_image', False)
                is_text    = ev.get('is_text', False)
                fpath      = _Path(evidence_dir) / scan_id / fname
                src_tag    = '[AUTO]' if source=='auto' else '[MANUAL]'

                meta_line = f"{src_tag}  {caption}  |  {ts_ev}"
                if finding_ref: meta_line += f"  |  ref: {finding_ref}"

                story.append(Paragraph(meta_line, st['dim']))
                story.append(Spacer(1,1*mm))

                if is_image and fpath.exists():
                    try:
                        from PIL import Image as PILImg
                        pil = PILImg.open(str(fpath))
                        w, h = pil.size
                        # Scale to fit page width (max cw x 100mm)
                        max_w = float(cw)
                        max_h = 100*mm
                        scale = min(max_w/w, max_h/h, 1.0)
                        rw, rh = w*scale, h*scale
                        img_elem = RLImage(str(fpath), width=rw, height=rh)
                        story.append(img_elem)
                    except Exception as exc:
                        story.append(Paragraph(f'[Error cargando imagen: {exc}]', st['dim']))
                elif is_text and fpath.exists():
                    try:
                        raw = fpath.read_text(encoding='utf-8', errors='replace')
                        lines = raw.splitlines()[:60]
                        truncated = len(raw.splitlines()) > 60
                        preview = '\n'.join(lines)
                        if truncated:
                            preview += f'\n... [{len(raw.splitlines())} lineas total — ver archivo completo]'
                        story.append(Paragraph(
                            preview.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\n','<br/>'),
                            ParagraphStyle('raw', fontName='Courier', fontSize=6.5,
                                           textColor=HexColor('#8AA4BE'),
                                           backColor=HexColor('#030609'),
                                           borderPad=4, leading=9,
                                           leftIndent=6, rightIndent=6)
                        ))
                    except Exception as exc:
                        story.append(Paragraph(f'[Error leyendo archivo: {exc}]', st['dim']))

                story.append(Spacer(1,3*mm))
            story += [HRFlowable(width=cw,thickness=0.2,color=C_BRD), Spacer(1,3*mm)]

    # Back cover
    story += [PageBreak(), Spacer(1,18*mm), FilledRect(cw,2,C_CYAN), Spacer(1,6*mm),
              Paragraph('FIN DEL REPORTE',st['h1']), Spacer(1,3*mm),
              Paragraph(f'OSINT Surface Analyzer  |  {dstr}  |  {company}',st['dim']), Spacer(1,2*mm),
              Paragraph('Este reporte contiene informacion confidencial de reconocimiento pasivo. Distribucion restringida.',
                        ParagraphStyle('disc',fontName='Courier',fontSize=7,textColor=C_T3))]

    def on_page(cv,doc):
        cv.saveState()
        cv.setFillColor(C_CARD); cv.rect(0,H-11*mm,W,11*mm,fill=1,stroke=0)
        cv.setFillColor(C_CYAN); cv.rect(0,H-11*mm,W,0.7,fill=1,stroke=0)
        cv.setFont('Courier-Bold',7); cv.setFillColor(C_CYAN); cv.drawString(mg,H-7*mm,'OSINT SURFACE ANALYZER')
        cv.setFont('Courier',7); cv.setFillColor(C_T3); cv.drawRightString(W-mg,H-7*mm,f'{company.upper()}  |  {dstr}')
        cv.setFillColor(C_CARD); cv.rect(0,0,W,9*mm,fill=1,stroke=0)
        cv.setFillColor(C_BRD); cv.rect(0,9*mm,W,0.4,fill=1,stroke=0)
        cv.setFont('Courier',6.5); cv.setFillColor(C_T3)
        cv.drawString(mg,3.5*mm,'CONFIDENCIAL'); cv.drawRightString(W-mg,3.5*mm,f'Pag. {doc.page}')
        cv.restoreState()

    doc.build(story,onFirstPage=on_page,onLaterPages=on_page)
    return buf.getvalue()

def _mod_tables(mid, data, cw):
    tables = []
    if mid=='subdomains' and data.get('active_subdomains'):
        subs=data['active_subdomains'][:20]; rows=[['SUBDOMINIO','IP','HTTP']]
        for s in subs: rows.append([s.get('subdomain',''),s.get('ip','-'),str(s.get('status_code','-'))])
        tables.append((f'SUBDOMINIOS ACTIVOS ({len(subs)})',dtable(rows,[90*mm,45*mm,20*mm])))
    if mid=='ports' and data.get('all_open_ports'):
        pts=data['all_open_ports'][:25]; rows=[['DOMINIO','PUERTO','SERVICIO','VERSION','RIESGO']]
        for p in pts: rows.append([p.get('domain','')[:20],str(p.get('port','')),p.get('service',''),p.get('version','')[:18],(p.get('risk') or '').upper()])
        t=dtable(rows,[40*mm,18*mm,22*mm,38*mm,20*mm])
        for i,p in enumerate(pts,1):
            col=SEV_COL.get(p.get('risk','info'),C_T2)
            t.setStyle(TableStyle([('TEXTCOLOR',(4,i),(4,i),col),('FONTNAME',(4,i),(4,i),'Courier-Bold')]))
        tables.append((f'PUERTOS ({len(pts)})',t))
    if mid=='ssl' and data.get('certificates'):
        certs=[c for c in data['certificates'] if c.get('status')=='ok'][:10]
        if certs:
            rows=[['DOMINIO','EMISOR','VENCE','DIAS','TLS']]
            for c in certs: rows.append([c.get('domain',''),c.get('issuer','')[:22],(c.get('valid_until') or '')[:14],str(c.get('days_left','-')),c.get('tls_version','-')])
            t=dtable(rows,[40*mm,42*mm,30*mm,15*mm,15*mm])
            for i,c in enumerate(certs,1):
                d=c.get('days_left'); col=C_RED if d is not None and d<30 else (C_YEL if d is not None and d<90 else C_GREEN)
                t.setStyle(TableStyle([('TEXTCOLOR',(3,i),(3,i),col)]))
            tables.append(('CERTIFICADOS',t))
    if mid=='whois' and data.get('whois_data'):
        rows=[['DOMINIO','REGISTRAR','PAIS','EXPIRA','EMAILS']]
        for w in data['whois_data']: rows.append([w.get('domain',''),(w.get('registrar') or '')[:22],w.get('country','-'),(w.get('expiry') or '-')[:10],str(len(w.get('emails',[])))])
        tables.append(('WHOIS',dtable(rows,[38*mm,42*mm,16*mm,28*mm,18*mm])))
    if mid=='dmarc':
        rows=[['DOMINIO','TIPO','ESTADO','POLITICA']]
        for d in (data.get('dmarc_records') or []): rows.append([d.get('domain',''),'DMARC','SI' if d.get('has_dmarc') else 'NO',(d.get('policy') or 'N/A').upper()])
        for d in (data.get('spf_records') or []): rows.append([d.get('domain',''),'SPF','SI' if d.get('has_spf') else 'NO','CONFIGURADO' if d.get('has_spf') else 'AUSENTE'])
        if len(rows)>1:
            t=dtable(rows,[48*mm,20*mm,22*mm,52*mm])
            for i in range(1,len(rows)):
                col=C_GREEN if rows[i][2]=='SI' else C_RED
                t.setStyle(TableStyle([('TEXTCOLOR',(2,i),(2,i),col)]))
            tables.append(('DMARC / SPF',t))
    if mid=='cybersquatting' and data.get('active_variants'):
        vv=data['active_variants'][:15]; rows=[['VARIANTE','TIPO','IPS','RIESGO']]
        for v in vv: rows.append([v.get('domain',''),v.get('fuzzer','-'),', '.join(v.get('ips',[]))[:28],(v.get('risk') or '-').upper()])
        t=dtable(rows,[55*mm,25*mm,38*mm,20*mm])
        for i,v in enumerate(vv,1):
            col=SEV_COL.get(v.get('risk','info'),C_T2)
            t.setStyle(TableStyle([('TEXTCOLOR',(3,i),(3,i),col),('FONTNAME',(3,i),(3,i),'Courier-Bold')]))
        tables.append((f'VARIANTES ({len(vv)})',t))
    if mid=='asn' and data.get('ip_blocks'):
        rows=[['DOMINIO','IP','ASN','ORGANIZACION','PREFIJO']]
        for b in data['ip_blocks']: rows.append([b.get('domain',''),b.get('ip','-'),f"AS{b['asn']}" if b.get('asn') else '-',(b.get('name') or '')[:28],b.get('prefix','-')])
        tables.append(('BLOQUES ASN',dtable(rows,[36*mm,26*mm,16*mm,38*mm,26*mm])))
    if mid=='technologies':
        techs=[t for sc in (data.get('technology_scans') or []) for t in (sc.get('technologies') or [])]
        if techs:
            rows=[['TECNOLOGIA','CATEGORIA','CONFIANZA']]
            for t in techs[:18]: rows.append([t.get('name',''),t.get('category','-'),(t.get('confidence') or '-').upper()])
            tables.append((f'TECNOLOGIAS ({len(techs)})',dtable(rows,[62*mm,58*mm,28*mm])))
    if mid=='cloud' and data.get('exposed_buckets'):
        rows=[['BUCKET','URL','ACCESO']]
        for b in data['exposed_buckets']: rows.append([b.get('bucket',''),b.get('url','')[:42],'PUBLICO' if b.get('public') else 'PRIVADO'])
        t=dtable(rows,[32*mm,82*mm,22*mm])
        for i,b in enumerate(data['exposed_buckets'],1):
            col=C_RED if b.get('public') else C_GREEN
            t.setStyle(TableStyle([('TEXTCOLOR',(2,i),(2,i),col),('FONTNAME',(2,i),(2,i),'Courier-Bold')]))
        tables.append(('S3 BUCKETS',t))
    return tables
