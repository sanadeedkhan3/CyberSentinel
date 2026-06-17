"""
engine/feature_engineer.py
---------------------------
Phase 2: Feature Engineering Engine.

Takes raw packets from the database and groups them into
30-second time windows per device (IP address).

For each window it computes:
  - packet_count       : how many packets the device sent
  - total_bytes        : total data transferred
  - bytes_per_sec      : transfer speed
  - unique_dst_ips     : how many different destinations contacted
  - unique_dst_ports   : how many different ports contacted
  - tcp_count          : number of TCP packets
  - udp_count          : number of UDP packets
  - icmp_count         : number of ICMP packets
  - avg_packet_size    : average size of each packet

WHY THIS MATTERS:
  A normal device browsing the web might contact 5-10 unique IPs
  and send ~50KB in 30 seconds. A device doing a port scan might
  contact 1 IP but hit 500 different ports. A device exfiltrating
  data might send 10x its normal bytes. These numbers are what the
  AI learns from in Phase 4.
"""

import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.database import get_connection, insert_traffic_window

# ── Configuration ─────────────────────────────────────────────────────────────

WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "30"))

# Only process IPs that sent at least this many packets in a window.
# Filters out one-off background noise.
MIN_PACKETS_PER_WINDOW = 3

# ── Core feature extraction ───────────────────────────────────────────────────

def compute_window_features(packets: list, window_start: float, window_end: float, src_ip: str) -> dict:
    """
    Given a list of packet dicts for one IP in one time window,
    compute all the features the ML model needs.

    Args:
        packets     : list of dicts with keys: dst_ip, dst_port, protocol, size_bytes
        window_start: unix timestamp start of window
        window_end  : unix timestamp end of window
        src_ip      : the device IP being analysed

    Returns:
        dict of features ready to insert into traffic_windows table
    """
    duration = window_end - window_start
    if duration <= 0:
        duration = WINDOW_SECONDS

    packet_count   = len(packets)
    total_bytes    = sum(p["size_bytes"] for p in packets)
    bytes_per_sec  = round(total_bytes / duration, 2)

    dst_ips   = set(p["dst_ip"]   for p in packets if p["dst_ip"])
    dst_ports = set(p["dst_port"] for p in packets if p["dst_port"])

    tcp_count  = sum(1 for p in packets if p["protocol"] == "TCP")
    udp_count  = sum(1 for p in packets if p["protocol"] == "UDP")
    icmp_count = sum(1 for p in packets if p["protocol"] == "ICMP")

    avg_packet_size = round(total_bytes / packet_count, 2) if packet_count > 0 else 0

    return {
        "window_start"     : window_start,
        "window_end"       : window_end,
        "src_ip"           : src_ip,
        "packet_count"     : packet_count,
        "total_bytes"      : total_bytes,
        "bytes_per_sec"    : bytes_per_sec,
        "unique_dst_ips"   : len(dst_ips),
        "unique_dst_ports" : len(dst_ports),
        "tcp_count"        : tcp_count,
        "udp_count"        : udp_count,
        "icmp_count"       : icmp_count,
        "avg_packet_size"  : avg_packet_size,
    }


def get_unprocessed_packets(since_timestamp: float) -> list:
    """
    Fetch raw packets from the database that haven't been windowed yet.
    Returns packets as a list of dicts.
    """
    conn = get_connection()
    rows = conn.execute("""
        SELECT src_ip, dst_ip, dst_port, protocol, size_bytes, timestamp
        FROM raw_packets
        WHERE timestamp >= ?
        ORDER BY timestamp ASC
    """, (since_timestamp,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_last_processed_timestamp() -> float:
    """
    Find the end timestamp of the most recent window we already computed.
    If none exist, go back 10 minutes to catch recent packets.
    """
    conn = get_connection()
    row = conn.execute("""
        SELECT MAX(window_end) as last_end FROM traffic_windows
    """).fetchone()
    conn.close()

    if row and row["last_end"]:
        return float(row["last_end"])
    else:
        # First run — process packets from the last 10 minutes
        return time.time() - 600


def process_packets_into_windows(packets: list) -> int:
    """
    Takes a flat list of packets and groups them into
    30-second windows per source IP.

    Returns the number of windows created.
    """
    if not packets:
        return 0

    # Find the overall time range
    earliest = min(p["timestamp"] for p in packets)
    latest   = max(p["timestamp"] for p in packets)

    # Build a list of window boundaries
    windows_created = 0
    window_start = earliest

    while window_start < latest:
        window_end = window_start + WINDOW_SECONDS

        # Get all packets in this time window
        window_packets = [
            p for p in packets
            if window_start <= p["timestamp"] < window_end
        ]

        if not window_packets:
            window_start = window_end
            continue

        # Group by source IP within this window
        ips_in_window = set(p["src_ip"] for p in window_packets)

        for src_ip in ips_in_window:
            ip_packets = [p for p in window_packets if p["src_ip"] == src_ip]

            # Skip IPs with very few packets (likely background noise)
            if len(ip_packets) < MIN_PACKETS_PER_WINDOW:
                continue

            features = compute_window_features(
                packets=ip_packets,
                window_start=window_start,
                window_end=window_end,
                src_ip=src_ip
            )

            insert_traffic_window(features)
            windows_created += 1

        window_start = window_end

    return windows_created


def run_feature_engineering(verbose: bool = True) -> int:
    """
    Main function: fetch unprocessed packets, compute windows, save them.
    Returns number of windows created this run.
    """
    since = get_last_processed_timestamp()
    packets = get_unprocessed_packets(since_timestamp=since)

    if not packets:
        if verbose:
            print("[FE] No new packets to process.")
        return 0

    if verbose:
        print(f"[FE] Processing {len(packets)} packets into {WINDOW_SECONDS}s windows...")

    count = process_packets_into_windows(packets)

    if verbose:
        print(f"[FE] Created {count} traffic windows.")

    return count


def get_all_windows() -> list:
    """Fetch all computed windows — used by the anomaly detector in Phase 4."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM traffic_windows ORDER BY window_start ASC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_windows_for_ip(src_ip: str) -> list:
    """Fetch all windows for a specific IP — used for baseline profiling."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM traffic_windows
        WHERE src_ip = ?
        ORDER BY window_start ASC
    """, (src_ip,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_known_devices() -> list:
    """Return list of all unique IPs that have been windowed."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT DISTINCT src_ip, COUNT(*) as window_count
        FROM traffic_windows
        GROUP BY src_ip
        ORDER BY window_count DESC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]
