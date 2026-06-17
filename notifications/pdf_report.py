"""
notifications/pdf_report.py
-----------------------------
Professional PDF Security Report Generator.

Generates a complete security report including:
  - Executive summary with key stats
  - All alerts with AI explanations
  - Device inventory with baselines
  - Blocked IPs list
  - Traffic summary
"""

import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from db.database import get_connection, get_packet_count

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable, PageBreak)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── Colour palette ────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#0a0e17")
C_DARK      = colors.HexColor("#111827")
C_BORDER    = colors.HexColor("#1e2d45")
C_ACCENT    = colors.HexColor("#00e5ff")
C_PURPLE    = colors.HexColor("#7c3aed")
C_RED       = colors.HexColor("#ef4444")
C_ORANGE    = colors.HexColor("#f97316")
C_YELLOW    = colors.HexColor("#eab308")
C_GREEN     = colors.HexColor("#22c55e")
C_TEXT      = colors.HexColor("#e2e8f0")
C_MUTED     = colors.HexColor("#64748b")
C_WHITE     = colors.white

SEV_COLORS  = {"Critical": C_RED, "High": C_ORANGE,
               "Medium": C_YELLOW, "Low": C_GREEN}


def get_report_data(hours: int = 24) -> dict:
    """Pull all data needed for the report from the database."""
    since = time.time() - hours * 3600
    conn  = get_connection()

    alerts = conn.execute("""
        SELECT * FROM alerts WHERE timestamp >= ?
        ORDER BY timestamp DESC
    """, (since,)).fetchall()

    devices = conn.execute("""
        SELECT b.*, MAX(tw.window_end) as last_seen
        FROM device_baselines b
        LEFT JOIN traffic_windows tw ON b.src_ip = tw.src_ip
        GROUP BY b.src_ip ORDER BY last_seen DESC
    """).fetchall()

    windows = conn.execute("""
        SELECT COUNT(*) as count,
               SUM(total_bytes) as total_bytes,
               AVG(bytes_per_sec) as avg_bps,
               MAX(bytes_per_sec) as peak_bps
        FROM traffic_windows WHERE window_start >= ?
    """, (since,)).fetchone()

    try:
        conn.execute("SELECT 1 FROM blocked_ips LIMIT 1")
        blocked = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    except Exception:
        blocked = []

    sev_counts = conn.execute("""
        SELECT severity, COUNT(*) as cnt FROM alerts
        WHERE timestamp >= ? GROUP BY severity
    """, (since,)).fetchall()

    conn.close()

    return {
        "alerts"     : [dict(a) for a in alerts],
        "devices"    : [dict(d) for d in devices],
        "windows"    : dict(windows) if windows else {},
        "blocked"    : [dict(b) for b in blocked],
        "sev_counts" : {r["severity"]: r["cnt"] for r in sev_counts},
        "total_pkts" : get_packet_count(),
        "since"      : since,
        "hours"      : hours,
    }


def generate_pdf_report(output_path: str = None, hours: int = 24) -> str:
    """
    Generate the PDF report and save it to output_path.
    Returns the path to the generated file.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab not installed. Run: pip install reportlab")

    if output_path is None:
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(reports_dir, f"cybersentinel_report_{ts}.pdf")

    data  = get_report_data(hours)
    now   = datetime.now()
    since = datetime.fromtimestamp(data["since"])

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Style definitions ─────────────────────────────────────────────────────
    def sty(name, **kw):
        return ParagraphStyle(name, **{"fontName": "Helvetica", "textColor": C_TEXT, **kw})

    s_title    = sty("title",   fontSize=24, fontName="Helvetica-Bold", textColor=C_ACCENT,    spaceAfter=4)
    s_sub      = sty("sub",     fontSize=11, textColor=C_MUTED,         spaceAfter=2)
    s_h1       = sty("h1",      fontSize=14, fontName="Helvetica-Bold", textColor=C_WHITE,     spaceBefore=14, spaceAfter=6)
    s_h2       = sty("h2",      fontSize=11, fontName="Helvetica-Bold", textColor=C_ACCENT,    spaceBefore=8,  spaceAfter=4)
    s_body     = sty("body",    fontSize=9,  textColor=C_TEXT,          leading=14)
    s_muted    = sty("muted",   fontSize=8,  textColor=C_MUTED)
    s_center   = sty("center",  fontSize=9,  alignment=TA_CENTER)
    s_code     = sty("code",    fontSize=8,  fontName="Courier",        textColor=C_ACCENT)

    def hr():
        return HRFlowable(width="100%", thickness=0.5,
                          color=C_BORDER, spaceAfter=8, spaceBefore=4)

    def tbl(data_rows, col_widths, style_cmds):
        base = [
            ("BACKGROUND",  (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",   (0,0), (-1,0),  C_ACCENT),
            ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_DARK, C_BG]),
            ("TEXTCOLOR",   (0,1), (-1,-1), C_TEXT),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING",(0,0), (-1,-1), 6),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ] + style_cmds
        t = Table(data_rows, colWidths=col_widths)
        t.setStyle(TableStyle(base))
        return t

    # ── Cover page ────────────────────────────────────────────────────────────
    cover_data = [[
        Paragraph("🛡 CyberSentinel", s_title),
        "",
    ]]
    cover_tbl = Table([[
        Paragraph("🛡  CyberSentinel", s_title),
    ]], colWidths=["100%"])
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_BG),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))

    # Header block
    header_rows = [[
        Paragraph("<b>🛡 CyberSentinel</b><br/><font size='9' color='#64748b'>AI Network Threat Detector</font>", ParagraphStyle("hdr", fontSize=20, fontName="Helvetica-Bold", textColor=C_ACCENT, leading=26)),
        Paragraph(f"<font color='#64748b'>Generated</font><br/><b>{now.strftime('%Y-%m-%d %H:%M')}</b><br/><font color='#64748b'>Period</font><br/><b>Last {hours} hours</b>", ParagraphStyle("hdr2", fontSize=9, textColor=C_TEXT, leading=14, alignment=TA_RIGHT)),
    ]]
    hdr_tbl = Table(header_rows, colWidths=["70%","30%"])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), C_DARK),
        ("TOPPADDING",  (0,0),(-1,-1), 14),
        ("BOTTOMPADDING",(0,0),(-1,-1),14),
        ("LEFTPADDING", (0,0),(-1,-1), 16),
        ("RIGHTPADDING",(0,0),(-1,-1), 16),
        ("LINEBELOW",   (0,0),(-1,-1), 2, C_PURPLE),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(hdr_tbl)
    story.append(Spacer(1, 14))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", s_h1))
    story.append(hr())

    sc   = data["sev_counts"]
    crit = sc.get("Critical", 0)
    high = sc.get("High", 0)
    med  = sc.get("Medium", 0)
    low  = sc.get("Low", 0)
    wins = data["windows"]
    tb   = wins.get("total_bytes") or 0

    summary_rows = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total Packets",    f"{data['total_pkts']:,}",     "Devices Detected",  str(len(data['devices']))],
        ["Total Alerts",     str(len(data['alerts'])),      "Traffic Windows",   str(wins.get('count',0))],
        ["Critical Alerts",  str(crit),                     "Data Transferred",  f"{tb/1048576:.1f} MB" if tb>0 else "N/A"],
        ["High Alerts",      str(high),                     "Avg Bandwidth",     f"{(wins.get('avg_bps',0) or 0)/1024:.1f} KB/s"],
        ["Medium Alerts",    str(med),                      "Peak Bandwidth",    f"{(wins.get('peak_bps',0) or 0)/1024:.1f} KB/s"],
        ["Low Alerts",       str(low),                      "Blocked IPs",       str(len(data['blocked']))],
        ["Report Period",    f"Last {hours}h",              "Report Generated",  now.strftime("%H:%M:%S")],
    ]
    w = doc.width / 4
    story.append(tbl(summary_rows, [w,w,w,w], [
        ("TEXTCOLOR", (0,1),(0,-1), C_MUTED),
        ("TEXTCOLOR", (2,1),(2,-1), C_MUTED),
        ("TEXTCOLOR", (1,3),(1,3), C_RED    if crit>0 else C_TEXT),
        ("TEXTCOLOR", (1,4),(1,4), C_ORANGE if high>0 else C_TEXT),
        ("FONTNAME",  (1,1),(1,-1),"Helvetica-Bold"),
        ("FONTNAME",  (3,1),(3,-1),"Helvetica-Bold"),
    ]))
    story.append(Spacer(1, 16))

    # Overall status
    if crit > 0:
        status_text = f"⛔  CRITICAL — {crit} critical threat(s) detected. Immediate investigation required."
        status_color = C_RED
    elif high > 0:
        status_text = f"⚠  HIGH RISK — {high} high-severity threat(s) detected. Review recommended."
        status_color = C_ORANGE
    elif len(data['alerts']) > 0:
        status_text = f"ℹ  MODERATE — {len(data['alerts'])} alert(s) detected. No critical threats."
        status_color = C_YELLOW
    else:
        status_text = "✅  CLEAR — No threats detected in this period. Network appears normal."
        status_color = C_GREEN

    status_tbl = Table([[Paragraph(status_text, ParagraphStyle("st", fontSize=10, fontName="Helvetica-Bold", textColor=C_WHITE, leading=14))]], colWidths=["100%"])
    status_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), status_color),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("LEFTPADDING",   (0,0),(-1,-1), 14),
        ("RIGHTPADDING",  (0,0),(-1,-1), 14),
        ("ROUNDEDCORNERS",(0,0),(-1,-1), [4,4,4,4]),
    ]))
    story.append(status_tbl)
    story.append(Spacer(1, 18))

    # ── Alerts section ────────────────────────────────────────────────────────
    if data["alerts"]:
        story.append(Paragraph(f"Alerts ({len(data['alerts'])})", s_h1))
        story.append(hr())

        alert_rows = [["Time", "Device IP", "Severity", "Threat Type", "Score"]]
        for a in data["alerts"][:50]:   # cap at 50 for PDF length
            ts_str = datetime.fromtimestamp(a.get("timestamp", 0)).strftime("%H:%M:%S")
            alert_rows.append([
                ts_str,
                a.get("src_ip", "Unknown"),
                a.get("severity", "Unknown"),
                a.get("threat_type", "Unknown"),
                f"{a.get('anomaly_score', 0):.2f}",
            ])

        w = doc.width
        story.append(tbl(alert_rows, [w*.13, w*.20, w*.13, w*.40, w*.10], [
            ("TEXTCOLOR", (0,1),(-1,-1), C_TEXT),
            ("FONTNAME",  (1,1),(1,-1),  "Courier"),
            ("TEXTCOLOR", (1,1),(1,-1),  C_ACCENT),
        ]))

        # Detailed explanations for High/Critical
        story.append(Spacer(1, 14))
        story.append(Paragraph("High & Critical Alert Details", s_h2))
        important = [a for a in data["alerts"] if a.get("severity") in ("High","Critical")]
        if important:
            for a in important[:10]:
                sev   = a.get("severity","Unknown")
                color = SEV_COLORS.get(sev, C_MUTED)
                sev_tbl = Table([[
                    Paragraph(f"<b>{sev.upper()}</b>", ParagraphStyle("sb", fontSize=9, fontName="Helvetica-Bold", textColor=C_WHITE)),
                    Paragraph(f"<b>{a.get('threat_type','Unknown')}</b> — {a.get('src_ip','?')}", ParagraphStyle("sd", fontSize=9, textColor=C_WHITE)),
                    Paragraph(datetime.fromtimestamp(a.get("timestamp",0)).strftime("%H:%M:%S"), ParagraphStyle("st2", fontSize=8, textColor=C_WHITE, alignment=TA_RIGHT)),
                ]], colWidths=[w*.12, w*.68, w*.18])
                sev_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), color),
                    ("TOPPADDING",    (0,0),(-1,-1), 6),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                    ("LEFTPADDING",   (0,0),(-1,-1), 8),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                    ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ]))
                story.append(sev_tbl)
                if a.get("explanation"):
                    story.append(Paragraph(a["explanation"], ParagraphStyle("ex", fontSize=8, textColor=C_TEXT, leading=12, leftIndent=8, spaceBefore=4)))
                if a.get("recommended_action"):
                    story.append(Paragraph(f"→ {a['recommended_action']}", ParagraphStyle("ac", fontSize=8, textColor=C_ACCENT, leading=12, leftIndent=8, spaceAfter=8)))
        else:
            story.append(Paragraph("No High or Critical alerts in this period.", s_muted))

        story.append(Spacer(1, 12))

    # ── Devices section ───────────────────────────────────────────────────────
    if data["devices"]:
        story.append(Paragraph(f"Device Inventory ({len(data['devices'])})", s_h1))
        story.append(hr())

        dev_rows = [["IP Address", "Windows", "Avg KB/s", "Avg Ports", "AI Status", "Last Seen"]]
        for d in data["devices"]:
            last = datetime.fromtimestamp(d["last_seen"]).strftime("%H:%M") if d.get("last_seen") else "—"
            dev_rows.append([
                d.get("src_ip","?"),
                str(d.get("window_count",0)),
                f"{(d.get('avg_bytes_per_sec') or 0)/1024:.1f} KB/s",
                str(round(d.get("avg_unique_dst_ports") or 0, 1)),
                "Trained" if d.get("model_trained") else "Learning",
                last,
            ])
        w = doc.width
        story.append(tbl(dev_rows, [w*.25, w*.10, w*.15, w*.12, w*.15, w*.15], [
            ("FONTNAME", (0,1),(0,-1), "Courier"),
            ("TEXTCOLOR",(0,1),(0,-1), C_ACCENT),
        ]))
        story.append(Spacer(1, 12))

    # ── Blocked IPs ───────────────────────────────────────────────────────────
    if data["blocked"]:
        story.append(Paragraph(f"Blocked IP Addresses ({len(data['blocked'])})", s_h1))
        story.append(hr())
        bl_rows = [["IP Address", "Reason", "Blocked At", "Blocked By"]]
        for b in data["blocked"]:
            ts_str = datetime.fromtimestamp(b.get("blocked_at",0)).strftime("%Y-%m-%d %H:%M") if b.get("blocked_at") else "—"
            bl_rows.append([b.get("ip","?"), b.get("reason","—"), ts_str, b.get("blocked_by","—")])
        w = doc.width
        story.append(tbl(bl_rows, [w*.25, w*.35, w*.22, w*.15], [
            ("FONTNAME", (0,1),(0,-1), "Courier"),
            ("TEXTCOLOR",(0,1),(0,-1), C_RED),
        ]))
        story.append(Spacer(1, 12))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(hr())
    story.append(Paragraph(
        f"Report generated by CyberSentinel AI Network Threat Detector · {now.strftime('%Y-%m-%d %H:%M:%S')} · All data is from local network monitoring only.",
        s_muted
    ))

    doc.build(story)
    print(f"[PDF] Report saved: {output_path}")
    return output_path