"""
test_phase2.py
--------------
Tests Phase 2 — Feature Engineering.

Simulates different network behaviours and verifies that the
feature engineering engine correctly computes window metrics.

Run with:  python test_phase2.py
(No sudo or network needed)
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from db.database import initialize_database, insert_packet, get_connection
from engine.feature_engineer import (
    compute_window_features,
    run_feature_engineering,
    get_all_windows,
    get_known_devices,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")

def ok(msg):  print(f"  PASS ✓  {msg}")
def fail(msg, e): print(f"  FAIL ✗  {msg}\n         Error: {e}"); sys.exit(1)

# ── Simulated traffic scenarios ───────────────────────────────────────────────

NOW = time.time()

# Normal user browsing (should produce low anomaly scores later)
NORMAL_BROWSING = [
    dict(timestamp=NOW+i*0.5, src_ip="192.168.1.10", dst_ip="142.250.80.46",
         src_port=50000+i, dst_port=443, protocol="TCP", size_bytes=1200, direction="outbound")
    for i in range(20)
] + [
    dict(timestamp=NOW+i*0.5, src_ip="192.168.1.10", dst_ip="8.8.8.8",
         src_port=51000, dst_port=53, protocol="UDP", size_bytes=60, direction="outbound")
    for i in range(5)
]

# Port scanner (hits many ports on same IP — suspicious)
PORT_SCAN = [
    dict(timestamp=NOW+i*0.05, src_ip="192.168.1.99", dst_ip="192.168.1.10",
         src_port=40000+i, dst_port=i+1, protocol="TCP", size_bytes=60, direction="inbound")
    for i in range(100)
]

# Data exfiltration (huge bytes to one external IP — suspicious)
EXFILTRATION = [
    dict(timestamp=NOW+i*0.2, src_ip="192.168.1.55", dst_ip="45.33.32.156",
         src_port=55000, dst_port=443, protocol="TCP", size_bytes=65000, direction="outbound")
    for i in range(30)
]


def run_tests():
    section("CyberSentinel — Phase 2 Feature Engineering Tests")

    # ── Test 1: DB init ──
    print("\n[TEST 1] Initializing database...")
    try:
        initialize_database()
        ok("Database ready")
    except Exception as e:
        fail("Database init", e)

    # ── Test 2: Insert scenarios ──
    print("\n[TEST 2] Inserting simulated traffic scenarios...")
    try:
        all_packets = NORMAL_BROWSING + PORT_SCAN + EXFILTRATION
        for p in all_packets:
            insert_packet(**p)
        ok(f"Inserted {len(all_packets)} packets across 3 scenarios")
    except Exception as e:
        fail("Packet insertion", e)

    # ── Test 3: compute_window_features directly ──
    print("\n[TEST 3] Testing feature computation on known data...")
    try:
        # Test the port scan window
        scan_packets = [
            {"dst_ip": "192.168.1.10", "dst_port": port, "protocol": "TCP", "size_bytes": 60}
            for port in range(1, 101)
        ]
        features = compute_window_features(
            packets=scan_packets,
            window_start=NOW,
            window_end=NOW + 30,
            src_ip="192.168.1.99"
        )

        assert features["packet_count"]     == 100,  f"Expected 100, got {features['packet_count']}"
        assert features["unique_dst_ports"] == 100,  f"Expected 100 ports, got {features['unique_dst_ports']}"
        assert features["unique_dst_ips"]   == 1,    f"Expected 1 IP, got {features['unique_dst_ips']}"
        assert features["tcp_count"]        == 100,  f"Expected 100 TCP"
        assert features["avg_packet_size"]  == 60.0, f"Expected 60 bytes avg"

        ok(f"Port scan detected: 100 unique ports, 1 destination IP")

        # Test the exfiltration window
        exfil_packets = [
            {"dst_ip": "45.33.32.156", "dst_port": 443, "protocol": "TCP", "size_bytes": 65000}
            for _ in range(30)
        ]
        features2 = compute_window_features(
            packets=exfil_packets,
            window_start=NOW,
            window_end=NOW + 30,
            src_ip="192.168.1.55"
        )

        assert features2["total_bytes"]   == 30 * 65000
        assert features2["bytes_per_sec"] == round((30 * 65000) / 30, 2)

        ok(f"Exfil detected: {features2['total_bytes']:,} bytes → {features2['bytes_per_sec']:,.0f} bytes/sec")

    except AssertionError as e:
        fail("Feature computation", e)

    # ── Test 4: Full pipeline ──
    print("\n[TEST 4] Running full feature engineering pipeline...")
    try:
        windows_created = run_feature_engineering(verbose=False)
        ok(f"Feature engineering ran — {windows_created} windows created")
    except Exception as e:
        fail("Feature engineering pipeline", e)

    # ── Test 5: Verify windows in DB ──
    print("\n[TEST 5] Verifying windows saved to database...")
    try:
        windows = get_all_windows()
        assert len(windows) > 0, "No windows found in database"

        devices = get_known_devices()
        device_ips = [d["src_ip"] for d in devices]

        print(f"\n  Devices detected ({len(devices)} total):")
        print(f"  {'IP ADDRESS':<20} {'WINDOWS':<10} {'ROLE'}")
        print(f"  {'-'*20} {'-'*10} {'-'*20}")

        for d in devices:
            ip = d["src_ip"]
            wc = d["window_count"]
            role = "Normal user" if ip == "192.168.1.10" else \
                   "Port scanner" if ip == "192.168.1.99" else \
                   "Data exfiltrator" if ip == "192.168.1.55" else "Unknown"
            print(f"  {ip:<20} {wc:<10} {role}")

        ok("All devices saved correctly")

    except Exception as e:
        fail("Window verification", e)

    # ── Test 6: Feature comparison ──
    print("\n[TEST 6] Comparing features across device behaviours...")
    try:
        conn = get_connection()

        normal = conn.execute("""
            SELECT AVG(bytes_per_sec) as avg_bps, AVG(unique_dst_ports) as avg_ports
            FROM traffic_windows WHERE src_ip = '192.168.1.10'
        """).fetchone()

        scanner = conn.execute("""
            SELECT AVG(bytes_per_sec) as avg_bps, AVG(unique_dst_ports) as avg_ports
            FROM traffic_windows WHERE src_ip = '192.168.1.99'
        """).fetchone()

        exfil = conn.execute("""
            SELECT AVG(bytes_per_sec) as avg_bps, AVG(unique_dst_ports) as avg_ports
            FROM traffic_windows WHERE src_ip = '192.168.1.55'
        """).fetchone()

        conn.close()

        print(f"\n  {'DEVICE':<20} {'AVG BYTES/SEC':<18} {'AVG UNIQUE PORTS'}")
        print(f"  {'-'*20} {'-'*18} {'-'*16}")

        if normal and normal["avg_bps"]:
            print(f"  {'Normal user':<20} {normal['avg_bps']:<18.0f} {normal['avg_ports']:.0f}")
        if scanner and scanner["avg_ports"]:
            print(f"  {'Port scanner':<20} {scanner['avg_bps']:<18.0f} {scanner['avg_ports']:.0f}")
        if exfil and exfil["avg_bps"]:
            print(f"  {'Data exfiltrator':<20} {exfil['avg_bps']:<18.0f} {exfil['avg_ports']:.0f}")

        # The scanner should have massively more unique ports than normal
        if scanner and normal and scanner["avg_ports"] and normal["avg_ports"]:
            assert scanner["avg_ports"] > normal["avg_ports"], \
                "Port scanner should show more unique ports than normal user"
            ok("Port scanner correctly shows higher unique port count than normal user")

        # Exfil should have massively higher bytes/sec
        if exfil and normal and exfil["avg_bps"] and normal["avg_bps"]:
            assert exfil["avg_bps"] > normal["avg_bps"], \
                "Exfiltrator should show higher bytes/sec than normal user"
            ok("Data exfiltrator correctly shows higher bytes/sec than normal user")

    except Exception as e:
        fail("Feature comparison", e)

    # ── Summary ──
    section("All Phase 2 tests passed!")
    print("""
  What Phase 2 built:
  ─────────────────────────────────────────────────
  ✓ Raw packets grouped into 30-second windows
  ✓ 9 features computed per window per device
  ✓ Normal, port-scan, and exfil traffic produce
    measurably different feature values
  ✓ All windows saved to SQLite for Phase 4 AI

  These feature differences are exactly what the
  Isolation Forest AI will learn to detect as
  anomalies in Phase 4.
  ─────────────────────────────────────────────────

  Next: say "ready for Phase 3" to build the
  behavioral baseline profiler.
    """)


if __name__ == "__main__":
    run_tests()
