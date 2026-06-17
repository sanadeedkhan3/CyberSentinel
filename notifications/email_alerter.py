"""
notifications/email_alerter.py
--------------------------------
Email notification system for CyberSentinel.

Sends a beautifully formatted HTML email immediately when a
High or Critical alert is detected — even when the dashboard
is not open.

Works with Gmail, Outlook, Yahoo, or any SMTP provider.
"""

import os
import sys
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from db.database import get_connection

# ── Config from .env ──────────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER",     "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL   = os.getenv("ALERT_EMAIL",   "")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:5000")
NOTIFY_SEVERITIES = {"High", "Critical"}


def is_email_configured() -> bool:
    return bool(SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL)


SEV_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#22c55e",
}


def build_email_html(alert: dict) -> str:
    sev     = alert.get("severity", "Unknown")
    color   = SEV_COLORS.get(sev, "#64748b")
    src_ip  = alert.get("src_ip", "Unknown")
    threat  = alert.get("threat_type", "Anomalous Behavior")
    explain = alert.get("explanation", "No explanation available.")
    action  = alert.get("recommended_action", "Monitor the device.")
    ts      = datetime.fromtimestamp(alert.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
    score   = alert.get("anomaly_score", 0)
    conf    = alert.get("confidence_pct", 0)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0e17;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e17;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">
  <tr><td style="background:linear-gradient(135deg,#7c3aed,#00e5ff);border-radius:12px 12px 0 0;padding:28px 32px;text-align:center">
    <div style="font-size:32px;margin-bottom:8px">🛡️</div>
    <div style="color:#fff;font-size:22px;font-weight:700;letter-spacing:.04em">CyberSentinel</div>
    <div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:4px">AI Network Threat Detector</div>
  </td></tr>
  <tr><td style="background:{color};padding:14px 32px;text-align:center">
    <div style="color:#fff;font-size:15px;font-weight:700;letter-spacing:.06em">⚠ {sev.upper()} SEVERITY ALERT DETECTED</div>
  </td></tr>
  <tr><td style="background:#111827;padding:32px;border-radius:0 0 12px 12px">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a2235;border:1px solid #1e2d45;border-radius:10px;margin-bottom:24px">
      <tr>
        <td style="padding:14px 16px;border-bottom:1px solid #1e2d45;border-right:1px solid #1e2d45">
          <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Device IP</div>
          <div style="font-size:18px;font-weight:700;color:#00e5ff;font-family:'Courier New',monospace">{src_ip}</div>
        </td>
        <td style="padding:14px 16px;border-bottom:1px solid #1e2d45">
          <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Threat Type</div>
          <div style="font-size:15px;font-weight:700;color:#e2e8f0">{threat}</div>
        </td>
      </tr>
      <tr>
        <td style="padding:14px 16px;border-right:1px solid #1e2d45">
          <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Anomaly Score</div>
          <div style="font-size:15px;font-weight:700;color:{color}">{score:.2f} / 1.0</div>
        </td>
        <td style="padding:14px 16px">
          <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Confidence</div>
          <div style="font-size:15px;font-weight:700;color:{color}">{conf}%</div>
        </td>
      </tr>
    </table>
    <div style="margin-bottom:20px">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#64748b;margin-bottom:10px">What Happened</div>
      <div style="background:#1a2235;border-left:3px solid {color};border-radius:0 8px 8px 0;padding:14px 16px;color:#e2e8f0;font-size:14px;line-height:1.6">{explain}</div>
    </div>
    <div style="margin-bottom:28px">
      <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#64748b;margin-bottom:10px">Recommended Action</div>
      <div style="background:#1a2235;border-left:3px solid #00e5ff;border-radius:0 8px 8px 0;padding:14px 16px;color:#00e5ff;font-size:14px;line-height:1.6">{action}</div>
    </div>
    <div style="text-align:center;margin-bottom:24px">
      <a href="{DASHBOARD_URL}" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#5b21b6);color:#fff;text-decoration:none;padding:13px 32px;border-radius:8px;font-size:14px;font-weight:600">Open Dashboard →</a>
    </div>
    <div style="border-top:1px solid #1e2d45;padding-top:16px;text-align:center">
      <div style="font-size:12px;color:#64748b">Alert generated at {ts}</div>
      <div style="font-size:11px;color:#334155;margin-top:4px">CyberSentinel · AI Network Threat Detector</div>
    </div>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def send_alert_email(alert: dict) -> bool:
    if not is_email_configured():
        return False
    if alert.get("severity") not in NOTIFY_SEVERITIES:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CyberSentinel] {alert.get('severity')} Alert — {alert.get('threat_type','Threat')} on {alert.get('src_ip','Unknown')}"
        msg["From"]    = f"CyberSentinel <{SMTP_USER}>"
        msg["To"]      = ALERT_EMAIL

        plain = f"CyberSentinel {alert.get('severity')} Alert\n\nDevice: {alert.get('src_ip')}\nThreat: {alert.get('threat_type')}\n\n{alert.get('explanation','')}\n\nAction: {alert.get('recommended_action','')}\n\nDashboard: {DASHBOARD_URL}"
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(build_email_html(alert), "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.ehlo(); s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())

        print(f"[EMAIL] ✓ Alert sent for {alert.get('src_ip')} → {ALERT_EMAIL}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("[EMAIL] ✗ Auth failed — check SMTP_USER and SMTP_PASSWORD in .env")
        return False
    except Exception as e:
        print(f"[EMAIL] ✗ {e}")
        return False


def init_email_tracking():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS emailed_alerts (
            alert_id   INTEGER PRIMARY KEY,
            emailed_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def process_new_alerts_for_email() -> int:
    if not is_email_configured():
        return 0
    init_email_tracking()
    conn = get_connection()
    pending = conn.execute("""
        SELECT a.* FROM alerts a
        LEFT JOIN emailed_alerts e ON a.id = e.alert_id
        WHERE e.alert_id IS NULL
          AND a.severity IN ('High','Critical')
          AND a.llm_processed = 1
        ORDER BY a.timestamp DESC LIMIT 5
    """).fetchall()
    conn.close()

    sent = 0
    for row in pending:
        alert = dict(row)
        if send_alert_email(alert):
            conn = get_connection()
            conn.execute("INSERT OR IGNORE INTO emailed_alerts (alert_id, emailed_at) VALUES (?,?)", (alert["id"], time.time()))
            conn.commit()
            conn.close()
            sent += 1
            time.sleep(2)
    return sent


def send_test_email() -> tuple:
    if not is_email_configured():
        return False, "Email not configured. Add SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL to .env"
    ok = send_alert_email({
        "id": 0, "src_ip": "192.168.1.99", "severity": "High",
        "threat_type": "Port Scan", "anomaly_score": 0.89, "confidence_pct": 100,
        "explanation": "This is a test alert from CyberSentinel. Your email notifications are configured correctly.",
        "recommended_action": "No action needed — this is a test.",
        "timestamp": time.time(),
    })
    return (True, f"Test email sent to {ALERT_EMAIL}") if ok else (False, "Failed. Check SMTP settings in .env")