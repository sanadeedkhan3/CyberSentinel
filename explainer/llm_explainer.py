"""
explainer/llm_explainer.py
---------------------------
Phase 5: LLM Explainability Engine — THE UNIQUE PART.

This is what separates CyberSentinel from every other
student cybersecurity project in the world.

Every time the Isolation Forest (Phase 4) flags an anomaly,
this engine takes all the context about that alert and sends
it to the Claude AI API. Claude reads the numbers, understands
what they mean in a security context, and writes a plain-English
explanation that ANY person can understand — not just experts.

WHAT THE LLM RECEIVES:
  - The device's normal baseline (what it usually does)
  - The suspicious window's exact numbers
  - The anomaly score and threat classification
  - How many times more than normal each metric was

WHAT THE LLM RETURNS (structured JSON):
  - threat_type     : what kind of attack this looks like
  - severity        : Low / Medium / High / Critical
  - explanation     : 2-3 sentence plain-English description
  - recommended_action : exactly what the user should do

EXAMPLE OUTPUT:
  "Device 192.168.1.4 sent 3,400 packets to a single external
   IP in 8 seconds — roughly 10x its normal rate. This pattern
   closely matches data exfiltration behavior. Recommended:
   isolate the device and check for unauthorized software."
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.database import get_connection, update_alert_explanation

# ── Check for API key ─────────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

def is_llm_available() -> bool:
    """Returns True if the API key is configured."""
    return bool(ANTHROPIC_API_KEY and ANTHROPIC_API_KEY != "your_api_key_here")


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_prompt(alert: dict, window: dict, baseline: dict) -> str:
    """
    Build a detailed prompt for Claude that gives it all the
    context it needs to write a meaningful security explanation.
    """

    # Calculate how far each metric is from normal
    def deviation(current, avg):
        if avg and avg > 0:
            return round(current / avg, 1)
        return "N/A"

    bps_dev   = deviation(window.get("bytes_per_sec", 0),    baseline.get("avg_bytes_per_sec", 1))
    pkt_dev   = deviation(window.get("packet_count", 0),     baseline.get("avg_packet_count", 1))
    port_dev  = deviation(window.get("unique_dst_ports", 0), baseline.get("avg_unique_dst_ports", 1))

    prompt = f"""You are a cybersecurity analyst AI embedded in a network monitoring tool called CyberSentinel.

An anomaly detection system has flagged suspicious network traffic. Your job is to:
1. Analyze the data below
2. Explain what is happening in plain English that a non-expert can understand
3. Classify the threat type accurately
4. Give a clear recommended action

--- DEVICE INFORMATION ---
Device IP: {alert.get("src_ip", "Unknown")}
Alert time: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.get("timestamp", time.time())))}
AI anomaly score: {alert.get("anomaly_score", 0)} out of 1.0 (higher = more suspicious)
Initial threat classification: {alert.get("threat_type", "Unknown")}

--- THIS DEVICE'S NORMAL BEHAVIOR (baseline) ---
Normal bytes per second   : {baseline.get("avg_bytes_per_sec", "unknown"):.1f} B/s
Normal packet count/window: {baseline.get("avg_packet_count", "unknown"):.1f} packets
Normal unique ports used  : {baseline.get("avg_unique_dst_ports", "unknown"):.1f}
Normal unique IPs contacted: {baseline.get("avg_unique_dst_ips", "unknown"):.1f}
Baseline built from       : {baseline.get("window_count", "?")} traffic windows

--- SUSPICIOUS WINDOW (what triggered the alert) ---
Bytes per second     : {window.get("bytes_per_sec", 0):,.1f} B/s  ({bps_dev}x normal)
Packet count         : {window.get("packet_count", 0):,}  ({pkt_dev}x normal)
Unique ports targeted: {window.get("unique_dst_ports", 0):,}  ({port_dev}x normal)
Unique IPs contacted : {window.get("unique_dst_ips", 0):,}
TCP packets          : {window.get("tcp_count", 0):,}
UDP packets          : {window.get("udp_count", 0):,}
ICMP packets         : {window.get("icmp_count", 0):,}
Average packet size  : {window.get("avg_packet_size", 0):,.0f} bytes
Time window          : 30 seconds

--- YOUR TASK ---
Respond ONLY with a valid JSON object in exactly this format (no extra text, no markdown):
{{
  "threat_type": "one of: Port Scan / Data Exfiltration / DDoS Attack / ICMP Flood / Lateral Movement / Malware C2 Communication / Anomalous Behavior",
  "severity": "one of: Low / Medium / High / Critical",
  "explanation": "2-3 sentences explaining what is happening in plain English. Mention specific numbers. Do not use jargon.",
  "recommended_action": "1-2 sentences telling the user exactly what to do right now."
}}"""

    return prompt


# ── API call ──────────────────────────────────────────────────────────────────

def call_claude_api(prompt: str) -> dict | None:
    """
    Send the prompt to the Claude API and return the parsed JSON response.
    Returns None if the call fails.
    """
    try:
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "model"     : "claude-sonnet-4-20250514",
            "max_tokens": 500,
            "messages"  : [{"role": "user", "content": prompt}]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type"      : "application/json",
                "x-api-key"         : ANTHROPIC_API_KEY,
                "anthropic-version" : "2023-06-01",
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        raw_text = body["content"][0]["text"].strip()

        # Strip markdown code fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        return json.loads(raw_text.strip())

    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[LLM] API HTTP error {e.code}: {error_body}")
        return None
    except json.JSONDecodeError as e:
        print(f"[LLM] Failed to parse Claude response as JSON: {e}")
        return None
    except Exception as e:
        print(f"[LLM] Unexpected error calling Claude API: {e}")
        return None


# ── Fallback explainer (no API key needed) ────────────────────────────────────

def generate_fallback_explanation(alert: dict, window: dict, baseline: dict) -> dict:
    """
    If no API key is set, generate a rule-based plain-English explanation.
    Less intelligent than Claude but still useful and human-readable.
    """
    threat = alert.get("threat_type") or "Anomalous Behavior"
    src_ip = alert.get("src_ip", "Unknown device")
    bps    = window.get("bytes_per_sec", 0)
    ports  = window.get("unique_dst_ports", 0)
    pkts   = window.get("packet_count", 0)
    score  = alert.get("anomaly_score", 0)

    avg_bps  = baseline.get("avg_bytes_per_sec", 1) or 1
    avg_pkts = baseline.get("avg_packet_count", 1) or 1

    bps_x = round(bps / avg_bps, 1)
    pkt_x = round(pkts / avg_pkts, 1)

    if threat == "Port Scan":
        explanation = (
            f"Device {src_ip} contacted {ports} different network ports in 30 seconds, "
            f"which is far outside its normal behavior. "
            f"Port scanning is commonly used by attackers to discover which services "
            f"are running on a target before launching an attack."
        )
        action = "Check if this device is running a security scanner intentionally. If not, isolate it and scan for malware."
        severity = "High"

    elif "Exfil" in threat:
        explanation = (
            f"Device {src_ip} transferred data at {bps:,.0f} bytes/sec — "
            f"approximately {bps_x}x its normal rate. "
            f"This sudden spike in outbound traffic to a small number of destinations "
            f"matches the pattern of data being stolen from the network."
        )
        action = "Immediately block outbound traffic from this device and check what data it has been sending and to where."
        severity = "Critical"

    elif "DDoS" in threat:
        explanation = (
            f"Device {src_ip} sent {pkts:,} packets in 30 seconds ({pkt_x}x normal), "
            f"targeting many different IP addresses. "
            f"This suggests the device may be part of a botnet being used to flood other systems."
        )
        action = "Disconnect this device from the network immediately and perform a full malware scan."
        severity = "Critical"

    elif "ICMP" in threat:
        explanation = (
            f"Device {src_ip} sent an unusually high number of ICMP (ping) packets. "
            f"This can indicate a ping sweep — an attempt to map which devices are "
            f"active on the network — or an ICMP flood attack."
        )
        action = "Investigate what is generating the ICMP traffic. Block if unauthorized."
        severity = "Medium"

    else:
        explanation = (
            f"Device {src_ip} showed unusual network behavior with an anomaly score of "
            f"{score:.2f} out of 1.0. Its traffic was {bps_x}x its normal data rate "
            f"with {pkts} packets sent in 30 seconds."
        )
        action = "Monitor this device closely and investigate any unusual processes running on it."
        severity = "Medium"

    return {
        "threat_type"        : threat,
        "severity"           : severity,
        "explanation"        : explanation,
        "recommended_action" : action,
    }


# ── Main explainer function ───────────────────────────────────────────────────

def explain_alert(alert: dict, window: dict, baseline: dict) -> dict:
    """
    Generate a plain-English explanation for an alert.
    Uses Claude API if available, falls back to rule-based if not.

    Returns dict with: threat_type, severity, explanation, recommended_action
    """
    if is_llm_available():
        print(f"[LLM] Explaining alert for {alert.get('src_ip')} via Claude API...")
        prompt   = build_prompt(alert, window, baseline)
        result   = call_claude_api(prompt)
        if result:
            print(f"[LLM] ✓ Explanation generated — Severity: {result.get('severity')}")
            return result
        else:
            print("[LLM] API call failed — using fallback explainer")

    print(f"[LLM] Using rule-based fallback for {alert.get('src_ip')}")
    return generate_fallback_explanation(alert, window, baseline)


def process_pending_alerts(verbose: bool = True) -> int:
    """
    Find all alerts that haven't been explained yet and explain them.
    Called periodically from main.py.
    Returns number of alerts processed.
    """
    conn = get_connection()
    pending = conn.execute("""
        SELECT a.*, tw.packet_count, tw.total_bytes, tw.bytes_per_sec,
               tw.unique_dst_ips, tw.unique_dst_ports,
               tw.tcp_count, tw.udp_count, tw.icmp_count, tw.avg_packet_size
        FROM alerts a
        LEFT JOIN traffic_windows tw ON a.window_id = tw.id
        WHERE a.llm_processed = 0
        ORDER BY a.timestamp DESC
        LIMIT 10
    """).fetchall()
    conn.close()

    if not pending:
        if verbose:
            print("[LLM] No pending alerts to explain.")
        return 0

    from engine.baseline_profiler import get_baseline_for_ip

    processed = 0
    for row in pending:
        alert = dict(row)
        window = {
            "packet_count"    : alert.get("packet_count", 0),
            "total_bytes"     : alert.get("total_bytes", 0),
            "bytes_per_sec"   : alert.get("bytes_per_sec", 0),
            "unique_dst_ips"  : alert.get("unique_dst_ips", 0),
            "unique_dst_ports": alert.get("unique_dst_ports", 0),
            "tcp_count"       : alert.get("tcp_count", 0),
            "udp_count"       : alert.get("udp_count", 0),
            "icmp_count"      : alert.get("icmp_count", 0),
            "avg_packet_size" : alert.get("avg_packet_size", 0),
        }

        baseline = get_baseline_for_ip(alert["src_ip"]) or {
            "avg_bytes_per_sec"   : 1000,
            "avg_packet_count"    : 20,
            "avg_unique_dst_ports": 3,
            "avg_unique_dst_ips"  : 5,
            "window_count"        : 0,
        }

        explanation = explain_alert(alert, window, baseline)

        update_alert_explanation(
            alert_id          = alert["id"],
            threat_type       = explanation.get("threat_type", "Unknown"),
            severity          = explanation.get("severity", "Medium"),
            explanation       = explanation.get("explanation", ""),
            recommended_action= explanation.get("recommended_action", ""),
        )
        processed += 1

        if verbose:
            print(f"\n{'─'*56}")
            print(f"  ALERT EXPLAINED")
            print(f"{'─'*56}")
            print(f"  Device  : {alert['src_ip']}")
            print(f"  Threat  : {explanation.get('threat_type')}")
            print(f"  Severity: {explanation.get('severity')}")
            print(f"\n  {explanation.get('explanation', '')}")
            print(f"\n  Action: {explanation.get('recommended_action', '')}")
            print(f"{'─'*56}\n")

    return processed