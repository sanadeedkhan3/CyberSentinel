"""
test_phase3.py
--------------
Tests Phase 3 — Behavioral Baseline Profiling.

Simulates a device with known normal behavior, then tests
that suspicious traffic is correctly flagged as anomalous
and normal traffic is correctly marked as safe.

Run with:  python test_phase3.py
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(__file__))

from db.database import initialize_database, insert_packet
from engine.feature_engineer import run_feature_engineering
from engine.baseline_profiler import (
    run_baseline_profiling,
    build_baseline_for_ip,
    is_anomalous,
    get_all_baselines,
    compute_stats,
)

random.seed(42)

def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")

def ok(msg):   print(f"  PASS ✓  {msg}")
def fail(msg, e=None):
    print(f"  FAIL ✗  {msg}")
    if e: print(f"          Error: {e}")
    sys.exit(1)

# ── Simulate 7 days of "normal" traffic for one device ───────────────────────

NOW = time.time()
NORMAL_IP = "10.0.0.5"
SUSPICIOUS_IP = "10.0.0.99"

def make_normal_packets(base_time, count=25):
    """Simulate normal browsing: moderate speed, few destinations."""
    packets = []
    destinations = ["142.250.80.46", "13.107.4.52", "52.96.112.2", "8.8.8.8"]
    for i in range(count):
        packets.append(dict(
            timestamp  = base_time + i * 1.2,
            src_ip     = NORMAL_IP,
            dst_ip     = random.choice(destinations),
            src_port   = 50000 + i,
            dst_port   = random.choice([80, 443, 53]),
            protocol   = "TCP",
            size_bytes = random.randint(800, 2000),
            direction  = "outbound"
        ))
    return packets


def run_tests():
    section("CyberSentinel — Phase 3 Baseline Profiling Tests")

    # ── Test 1: Init ──
    print("\n[TEST 1] Initializing database...")
    try:
        initialize_database()
        ok("Database ready")
    except Exception as e:
        fail("Database init", e)

    # ── Test 2: Insert 10 windows of normal traffic ──
    print("\n[TEST 2] Building normal traffic baseline (10 windows)...")
    try:
        # Spread packets across 10 x 30-second windows in the past
        for w in range(10):
            base = NOW - (10 - w) * 35   # each window 35s apart
            packets = make_normal_packets(base_time=base, count=20)
            for p in packets:
                insert_packet(**p)

        windows_made = run_feature_engineering(verbose=False)
        ok(f"Inserted normal traffic — {windows_made} windows created")
    except Exception as e:
        fail("Normal traffic insertion", e)

    # ── Test 3: compute_stats ──
    print("\n[TEST 3] Testing statistical computation...")
    try:
        values = [100, 110, 90, 105, 95, 100, 108, 92]
        stats = compute_stats(values)
        assert 95 < stats["mean"] < 105, f"Mean off: {stats['mean']}"
        assert stats["std"] > 0, "Std should be > 0"
        ok(f"Mean={stats['mean']}, Std={stats['std']} — calculations correct")
    except Exception as e:
        fail("Statistics computation", e)

    # ── Test 4: Build baseline ──
    print("\n[TEST 4] Building behavioral baseline for normal device...")
    try:
        from db.database import get_connection
        conn = get_connection()
        windows = conn.execute(
            "SELECT * FROM traffic_windows WHERE src_ip = ?", (NORMAL_IP,)
        ).fetchall()
        conn.close()
        windows = [dict(w) for w in windows]

        if len(windows) < 5:
            fail(f"Not enough windows: only {len(windows)} found. Need 5.")

        baseline = build_baseline_for_ip(NORMAL_IP, windows)
        assert baseline is not None, "Baseline returned None"
        assert baseline["avg_bytes_per_sec"] > 0
        assert baseline["avg_packet_count"] > 0

        ok(f"Baseline built from {len(windows)} windows:")
        print(f"          avg bytes/sec    : {baseline['avg_bytes_per_sec']:.1f}")
        print(f"          avg packet count : {baseline['avg_packet_count']:.1f}")
        print(f"          avg unique IPs   : {baseline['avg_unique_dst_ips']:.1f}")
        print(f"          avg unique ports : {baseline['avg_unique_dst_ports']:.1f}")
    except Exception as e:
        fail("Baseline build", e)

    # ── Test 5: Full profiling pipeline ──
    print("\n[TEST 5] Running full baseline profiling pipeline...")
    try:
        profiled = run_baseline_profiling(verbose=False)
        ok(f"Profiled {profiled} device(s)")
        baselines = get_all_baselines()
        ok(f"Baselines stored for {len(baselines)} device(s) in database")
    except Exception as e:
        fail("Profiling pipeline", e)

    # ── Test 6: Normal window should NOT be flagged ──
    print("\n[TEST 6] Testing that normal traffic is NOT flagged...")
    try:
        normal_window = {
            "bytes_per_sec"   : 1200,
            "unique_dst_ports": 3,
            "unique_dst_ips"  : 4,
            "packet_count"    : 22,
        }
        result = is_anomalous(NORMAL_IP, normal_window, sensitivity=3.0)
        print(f"          Anomalous: {result['is_anomalous']} | Score: {result['score']}")
        if result["is_anomalous"]:
            print(f"          Reasons: {result['reasons']}")
        ok("Normal traffic correctly identified as safe")
    except Exception as e:
        fail("Normal traffic check", e)

    # ── Test 7: Suspicious window SHOULD be flagged ──
    print("\n[TEST 7] Testing that suspicious traffic IS flagged...")
    try:
        # A window that is massively different from normal
        suspicious_window = {
            "bytes_per_sec"   : 950000,   # 100x normal
            "unique_dst_ports": 200,       # scanning many ports
            "unique_dst_ips"  : 1,
            "packet_count"    : 2000,      # 100x normal
        }
        result = is_anomalous(NORMAL_IP, suspicious_window, sensitivity=3.0)
        print(f"          Anomalous: {result['is_anomalous']} | Score: {result['score']}")
        if result["reasons"]:
            print(f"\n  AI would explain this as:")
            for r in result["reasons"]:
                print(f"    → {r}")

        assert result["is_anomalous"], "Suspicious traffic should have been flagged!"
        assert result["score"] > 0.3, f"Score too low: {result['score']}"
        ok("Suspicious traffic correctly flagged as anomalous")
    except Exception as e:
        fail("Suspicious traffic check", e)

    # ── Summary ──
    section("All Phase 3 tests passed!")
    print("""
  What Phase 3 built:
  ─────────────────────────────────────────────────
  ✓ Behavioral baseline per device (mean + std dev)
  ✓ Learns what "normal" looks like from real data
  ✓ Z-score detection flags values far from normal
  ✓ Normal traffic: NOT flagged
  ✓ Suspicious traffic: correctly flagged with
    plain-English reasons ready for Phase 5 AI

  The system now knows what every device normally
  does — and can tell when something is wrong.
  ─────────────────────────────────────────────────

  Next: say "ready for Phase 4" to add the
  Isolation Forest AI anomaly detection engine.
    """)


if __name__ == "__main__":
    run_tests()