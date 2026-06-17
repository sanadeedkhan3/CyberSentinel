"""
test_phase5.py
--------------
Tests Phase 5 — LLM Explainability Engine.

Tests both the fallback explainer (no API key needed)
and the full Claude API explainer (if key is set).

Run with:  python test_phase5.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from db.database import initialize_database, insert_traffic_window, insert_alert, get_connection
from engine.baseline_profiler import save_baseline
from explainer.llm_explainer import (
    is_llm_available,
    build_prompt,
    generate_fallback_explanation,
    explain_alert,
    process_pending_alerts,
)

NOW = time.time()

def section(title):
    print(f"\n{'='*56}")
    print(f"  {title}")
    print(f"{'='*56}")

def ok(msg):   print(f"  PASS ✓  {msg}")
def fail(msg, e=None):
    print(f"  FAIL ✗  {msg}")
    if e: print(f"          {e}")
    sys.exit(1)

# ── Shared test data ──────────────────────────────────────────────────────────

SAMPLE_BASELINE = {
    "avg_bytes_per_sec"   : 1200.0,
    "std_bytes_per_sec"   : 300.0,
    "avg_packet_count"    : 20.0,
    "std_packet_count"    : 5.0,
    "avg_unique_dst_ips"  : 4.0,
    "avg_unique_dst_ports": 3.0,
    "window_count"        : 48,
}

PORT_SCAN_ALERT = {
    "id"           : 1,
    "src_ip"       : "192.168.1.99",
    "anomaly_score": 0.89,
    "confidence_pct": 100,
    "threat_type"  : "Port Scan",
    "timestamp"    : NOW,
}

PORT_SCAN_WINDOW = {
    "packet_count"    : 1500,
    "total_bytes"     : 90000,
    "bytes_per_sec"   : 3000,
    "unique_dst_ips"  : 1,
    "unique_dst_ports": 500,
    "tcp_count"       : 1500,
    "udp_count"       : 0,
    "icmp_count"      : 0,
    "avg_packet_size" : 60,
}

EXFIL_ALERT = {
    "id"           : 2,
    "src_ip"       : "192.168.1.55",
    "anomaly_score": 0.97,
    "confidence_pct": 100,
    "threat_type"  : "Possible Data Exfiltration",
    "timestamp"    : NOW,
}

EXFIL_WINDOW = {
    "packet_count"    : 4500,
    "total_bytes"     : 450_000_000,
    "bytes_per_sec"   : 15_000_000,
    "unique_dst_ips"  : 1,
    "unique_dst_ports": 1,
    "tcp_count"       : 4500,
    "udp_count"       : 0,
    "icmp_count"      : 0,
    "avg_packet_size" : 100_000,
}


def run_tests():
    section("CyberSentinel — Phase 5 LLM Explainability Tests")

    # ── Test 1: Init ──
    print("\n[TEST 1] Initializing database...")
    try:
        initialize_database()
        ok("Database ready")
    except Exception as e:
        fail("Database init", e)

    # ── Test 2: Check API key status ──
    print("\n[TEST 2] Checking API key configuration...")
    try:
        available = is_llm_available()
        if available:
            ok("Anthropic API key found — Claude API will be used")
        else:
            print("  INFO    No API key set — fallback explainer will be used")
            print("          (This is fine for testing. Add your key to .env for full AI explanations)")
            ok("Fallback explainer ready")
    except Exception as e:
        fail("API key check", e)

    # ── Test 3: Prompt builder ──
    print("\n[TEST 3] Testing prompt builder...")
    try:
        prompt = build_prompt(PORT_SCAN_ALERT, PORT_SCAN_WINDOW, SAMPLE_BASELINE)
        assert "192.168.1.99" in prompt, "IP missing from prompt"
        assert "500"          in prompt, "Port count missing"
        assert "baseline"     in prompt.lower(), "Baseline section missing"
        assert "JSON"         in prompt, "JSON instruction missing"
        ok(f"Prompt built successfully ({len(prompt)} characters)")
        print(f"\n  --- Prompt preview (first 300 chars) ---")
        print(f"  {prompt[:300].replace(chr(10), chr(10)+'  ')}")
        print(f"  ...")
    except Exception as e:
        fail("Prompt builder", e)

    # ── Test 4: Fallback explainer — port scan ──
    print("\n[TEST 4] Testing fallback explainer on port scan...")
    try:
        result = generate_fallback_explanation(
            PORT_SCAN_ALERT, PORT_SCAN_WINDOW, SAMPLE_BASELINE
        )
        assert result.get("threat_type"),         "Missing threat_type"
        assert result.get("severity"),            "Missing severity"
        assert result.get("explanation"),         "Missing explanation"
        assert result.get("recommended_action"),  "Missing recommended_action"
        assert "500" in result["explanation"] or "port" in result["explanation"].lower()

        print(f"\n  Threat   : {result['threat_type']}")
        print(f"  Severity : {result['severity']}")
        print(f"  Explain  : {result['explanation']}")
        print(f"  Action   : {result['recommended_action']}")
        ok("Port scan fallback explanation generated correctly")
    except Exception as e:
        fail("Fallback port scan", e)

    # ── Test 5: Fallback explainer — data exfiltration ──
    print("\n[TEST 5] Testing fallback explainer on data exfiltration...")
    try:
        result = generate_fallback_explanation(
            EXFIL_ALERT, EXFIL_WINDOW, SAMPLE_BASELINE
        )
        assert result.get("severity") in ("High", "Critical"), \
            f"Exfil should be High/Critical, got: {result.get('severity')}"

        print(f"\n  Threat   : {result['threat_type']}")
        print(f"  Severity : {result['severity']}")
        print(f"  Explain  : {result['explanation']}")
        print(f"  Action   : {result['recommended_action']}")
        ok(f"Exfiltration severity correctly set to: {result['severity']}")
    except Exception as e:
        fail("Fallback exfiltration", e)

    # ── Test 6: Full explain_alert (uses Claude if key available) ──
    print("\n[TEST 6] Testing full explain_alert pipeline...")
    try:
        result = explain_alert(PORT_SCAN_ALERT, PORT_SCAN_WINDOW, SAMPLE_BASELINE)
        assert result.get("threat_type")
        assert result.get("severity")
        assert result.get("explanation")
        assert result.get("recommended_action")

        source = "Claude API" if is_llm_available() else "Rule-based fallback"
        print(f"\n  Source   : {source}")
        print(f"  Threat   : {result['threat_type']}")
        print(f"  Severity : {result['severity']}")
        print(f"  Explain  : {result['explanation']}")
        print(f"  Action   : {result['recommended_action']}")
        ok(f"Full explain_alert works via {source}")
    except Exception as e:
        fail("Full explain_alert", e)

    # ── Test 7: End-to-end pipeline ──
    print("\n[TEST 7] Testing end-to-end pipeline (alert → explanation → database)...")
    try:
        # Save a baseline for the test IP
        save_baseline("10.0.0.77", SAMPLE_BASELINE, 48)

        # Insert a traffic window
        window_id = insert_traffic_window({
            "window_start"    : NOW - 60,
            "window_end"      : NOW - 30,
            "src_ip"          : "10.0.0.77",
            **PORT_SCAN_WINDOW
        })

        # Insert a raw alert
        alert_id = insert_alert({
            "timestamp"     : NOW,
            "src_ip"        : "10.0.0.77",
            "anomaly_score" : 0.91,
            "confidence_pct": 100,
            "window_id"     : window_id,
        })

        # Update with threat type so process_pending_alerts can use it
        conn = get_connection()
        conn.execute(
            "UPDATE alerts SET threat_type = 'Port Scan' WHERE id = ?", (alert_id,)
        )
        conn.commit()
        conn.close()

        # Process it
        count = process_pending_alerts(verbose=True)
        assert count >= 1, f"Expected at least 1 alert processed, got {count}"

        # Verify it was saved to DB
        conn = get_connection()
        saved = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        conn.close()

        assert saved is not None,               "Alert not found in database"
        assert saved["llm_processed"] == 1,     "Alert not marked as processed"
        assert saved["explanation"] is not None, "Explanation not saved to DB"
        assert saved["severity"] is not None,    "Severity not saved to DB"

        ok(f"End-to-end pipeline complete — explanation saved to database")
    except Exception as e:
        fail("End-to-end pipeline", e)

    # ── Summary ──
    section("All Phase 5 tests passed!")
    print(f"""
  What Phase 5 built:
  ──────────────────────────────────────────────────
  ✓ Prompt builder packages all alert context for AI
  ✓ Claude API integration (with JSON parsing)
  ✓ Rule-based fallback (works without API key)
  ✓ Plain-English explanations for every threat type
  ✓ Severity classification (Low/Medium/High/Critical)
  ✓ Recommended actions generated automatically
  ✓ Explanations saved to database
  ✓ Full end-to-end pipeline tested

  {'✓ USING CLAUDE API — full AI explanations active!' if is_llm_available() else '⚠  Using fallback — add API key to .env for full AI'}
  ──────────────────────────────────────────────────

  Next: say "ready for Phase 6" to build the live
  web dashboard — where you see everything in one
  beautiful real-time interface.
    """)


if __name__ == "__main__":
    run_tests()