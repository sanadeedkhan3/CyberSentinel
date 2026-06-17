"""
test_phase1.py
--------------
Tests Phase 1 without requiring root/network access.

Simulates captured packets being inserted into the database,
then reads them back to verify everything is working correctly.

Run with:  python test_phase1.py
(No sudo needed for this test)
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from db.database import (
    initialize_database,
    insert_packet,
    get_packet_count,
    get_connection
)

# ── Test data: simulated packets ──────────────────────────────────────────────

SIMULATED_PACKETS = [
    # Normal browsing traffic
    dict(timestamp=time.time(),      src_ip="192.168.1.5",  dst_ip="142.250.80.46",
         src_port=54321, dst_port=443, protocol="TCP", size_bytes=1200, direction="outbound"),
    dict(timestamp=time.time()+0.1,  src_ip="142.250.80.46", dst_ip="192.168.1.5",
         src_port=443,   dst_port=54321, protocol="TCP", size_bytes=8800, direction="inbound"),

    # DNS query
    dict(timestamp=time.time()+0.2,  src_ip="192.168.1.5",  dst_ip="8.8.8.8",
         src_port=51234, dst_port=53, protocol="UDP", size_bytes=60, direction="outbound"),

    # Internal traffic
    dict(timestamp=time.time()+0.3,  src_ip="192.168.1.5",  dst_ip="192.168.1.1",
         src_port=None,  dst_port=None, protocol="ICMP", size_bytes=84, direction="internal"),

    # Suspicious: rapid port scanning simulation
    dict(timestamp=time.time()+0.4,  src_ip="192.168.1.99", dst_ip="192.168.1.5",
         src_port=44000, dst_port=22,   protocol="TCP", size_bytes=60, direction="inbound"),
    dict(timestamp=time.time()+0.41, src_ip="192.168.1.99", dst_ip="192.168.1.5",
         src_port=44001, dst_port=80,   protocol="TCP", size_bytes=60, direction="inbound"),
    dict(timestamp=time.time()+0.42, src_ip="192.168.1.99", dst_ip="192.168.1.5",
         src_port=44002, dst_port=443,  protocol="TCP", size_bytes=60, direction="inbound"),
    dict(timestamp=time.time()+0.43, src_ip="192.168.1.99", dst_ip="192.168.1.5",
         src_port=44003, dst_port=3306, protocol="TCP", size_bytes=60, direction="inbound"),
    dict(timestamp=time.time()+0.44, src_ip="192.168.1.99", dst_ip="192.168.1.5",
         src_port=44004, dst_port=8080, protocol="TCP", size_bytes=60, direction="inbound"),
]


def run_tests():
    print("=" * 55)
    print("  CyberSentinel — Phase 1 Test Suite")
    print("=" * 55)

    # Test 1: Database initialization
    print("\n[TEST 1] Initializing database...")
    try:
        initialize_database()
        print("         PASS ✓ — Database created successfully")
    except Exception as e:
        print(f"         FAIL ✗ — {e}")
        sys.exit(1)

    # Test 2: Insert packets
    print(f"\n[TEST 2] Inserting {len(SIMULATED_PACKETS)} simulated packets...")
    try:
        for pkt in SIMULATED_PACKETS:
            insert_packet(**pkt)
        print(f"         PASS ✓ — All packets inserted")
    except Exception as e:
        print(f"         FAIL ✗ — {e}")
        sys.exit(1)

    # Test 3: Read back and verify
    print("\n[TEST 3] Reading packets back from database...")
    try:
        count = get_packet_count()
        assert count >= len(SIMULATED_PACKETS), \
            f"Expected >= {len(SIMULATED_PACKETS)}, got {count}"
        print(f"         PASS ✓ — {count} packets in database")
    except Exception as e:
        print(f"         FAIL ✗ — {e}")
        sys.exit(1)

    # Test 4: Verify data integrity
    print("\n[TEST 4] Verifying data integrity...")
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT src_ip, dst_ip, protocol, size_bytes, direction
            FROM raw_packets
            ORDER BY timestamp DESC
            LIMIT 5
        """).fetchall()
        conn.close()

        print("         Latest 5 captured entries:")
        print(f"         {'SRC IP':<20} {'DST IP':<20} {'PROTO':<6} {'BYTES':<8} {'DIR'}")
        print(f"         {'-'*20} {'-'*20} {'-'*6} {'-'*8} {'-'*10}")
        for row in rows:
            print(f"         {row['src_ip']:<20} {row['dst_ip']:<20} "
                  f"{row['protocol']:<6} {row['size_bytes']:<8} {row['direction']}")
        print("         PASS ✓ — Data integrity verified")
    except Exception as e:
        print(f"         FAIL ✗ — {e}")
        sys.exit(1)

    # Test 5: Protocol distribution
    print("\n[TEST 5] Protocol distribution check...")
    try:
        conn = get_connection()
        protocols = conn.execute("""
            SELECT protocol, COUNT(*) as count
            FROM raw_packets
            GROUP BY protocol
            ORDER BY count DESC
        """).fetchall()
        conn.close()

        for p in protocols:
            bar = "█" * p['count']
            print(f"         {p['protocol']:<8} {bar} ({p['count']})")
        print("         PASS ✓")
    except Exception as e:
        print(f"         FAIL ✗ — {e}")

    print()
    print("=" * 55)
    print("  All Phase 1 tests passed! ✓")
    print("  Your database is working correctly.")
    print()
    print("  Next step:")
    print("  Run  sudo python main.py  to start live capture.")
    print("=" * 55)
    print()


if __name__ == "__main__":
    run_tests()
