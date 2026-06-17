"""
engine/baseline_profiler.py
----------------------------
Phase 3: Behavioral Baseline Profiler.

This is the "learning" phase of CyberSentinel.

For each device on your network, it looks at all the traffic
windows collected in Phase 2 and builds a profile of what
"normal" looks like for that specific device.

Example:
  Your laptop normally sends 50-200 KB/s, contacts 5-15
  unique IPs, and uses ports 80, 443, 53.

  If suddenly it sends 5,000 KB/s to 1 unknown IP on port 4444
  — that is a massive deviation from its baseline.
  That is what Phase 4 will flag as an anomaly.

The baseline is stored per device in the device_baselines table.
"""

import os
import sys
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.database import get_connection

# Minimum number of windows needed before we trust the baseline.
# Less than this = not enough data to know what "normal" is yet.
MIN_WINDOWS_FOR_BASELINE = 5


# ── Database helpers ──────────────────────────────────────────────────────────

def save_baseline(src_ip: str, stats: dict, window_count: int):
    """Save or update a device's baseline profile in the database."""
    conn = get_connection()
    now = time.time()

    # Check if this device already has a baseline
    existing = conn.execute(
        "SELECT id FROM device_baselines WHERE src_ip = ?", (src_ip,)
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE device_baselines SET
                last_updated        = ?,
                window_count        = ?,
                avg_bytes_per_sec   = ?,
                std_bytes_per_sec   = ?,
                avg_packet_count    = ?,
                std_packet_count    = ?,
                avg_unique_dst_ips  = ?,
                avg_unique_dst_ports= ?,
                model_trained       = 1
            WHERE src_ip = ?
        """, (
            now,
            window_count,
            stats["avg_bytes_per_sec"],
            stats["std_bytes_per_sec"],
            stats["avg_packet_count"],
            stats["std_packet_count"],
            stats["avg_unique_dst_ips"],
            stats["avg_unique_dst_ports"],
            src_ip
        ))
    else:
        conn.execute("""
            INSERT INTO device_baselines (
                src_ip, first_seen, last_updated, window_count,
                avg_bytes_per_sec, std_bytes_per_sec,
                avg_packet_count, std_packet_count,
                avg_unique_dst_ips, avg_unique_dst_ports,
                model_trained
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            src_ip, now, now, window_count,
            stats["avg_bytes_per_sec"],
            stats["std_bytes_per_sec"],
            stats["avg_packet_count"],
            stats["std_packet_count"],
            stats["avg_unique_dst_ips"],
            stats["avg_unique_dst_ports"],
        ))

    conn.commit()
    conn.close()


def get_baseline_for_ip(src_ip: str) -> dict:
    """Fetch the stored baseline for a specific device. Returns None if not trained yet."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM device_baselines WHERE src_ip = ?", (src_ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_baselines() -> list:
    """Fetch baselines for all known devices."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM device_baselines ORDER BY last_updated DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ── Core profiling logic ──────────────────────────────────────────────────────

def compute_stats(values: list) -> dict:
    """
    Compute mean and standard deviation for a list of numbers.
    Standard deviation tells us how much the values normally vary —
    a small std means very consistent, a large std means varies a lot.
    """
    if not values:
        return {"mean": 0.0, "std": 0.0}

    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance ** 0.5

    return {"mean": round(mean, 4), "std": round(std, 4)}


def build_baseline_for_ip(src_ip: str, windows: list) -> dict | None:
    """
    Given a list of traffic windows for one device,
    compute its behavioral baseline.

    Returns None if there are not enough windows yet.
    """
    if len(windows) < MIN_WINDOWS_FOR_BASELINE:
        return None

    # Extract each feature across all windows into a list
    bytes_per_sec    = [w["bytes_per_sec"]    for w in windows]
    packet_counts    = [w["packet_count"]     for w in windows]
    unique_dst_ips   = [w["unique_dst_ips"]   for w in windows]
    unique_dst_ports = [w["unique_dst_ports"] for w in windows]

    bps_stats   = compute_stats(bytes_per_sec)
    pkt_stats   = compute_stats(packet_counts)
    ip_stats    = compute_stats(unique_dst_ips)
    port_stats  = compute_stats(unique_dst_ports)

    return {
        "avg_bytes_per_sec"   : bps_stats["mean"],
        "std_bytes_per_sec"   : bps_stats["std"],
        "avg_packet_count"    : pkt_stats["mean"],
        "std_packet_count"    : pkt_stats["std"],
        "avg_unique_dst_ips"  : ip_stats["mean"],
        "avg_unique_dst_ports": port_stats["mean"],
    }


def run_baseline_profiling(verbose: bool = True) -> int:
    """
    Main function: build/update baselines for all devices.
    Called periodically from main.py.
    Returns the number of devices profiled.
    """
    conn = get_connection()

    # Get all unique devices that have traffic windows
    devices = conn.execute("""
        SELECT DISTINCT src_ip FROM traffic_windows
    """).fetchall()
    conn.close()

    if not devices:
        if verbose:
            print("[BASELINE] No devices found yet. Waiting for traffic windows...")
        return 0

    profiled = 0

    for row in devices:
        src_ip = row["src_ip"]

        # Fetch all windows for this device
        conn = get_connection()
        windows = conn.execute("""
            SELECT * FROM traffic_windows
            WHERE src_ip = ?
            ORDER BY window_start ASC
        """, (src_ip,)).fetchall()
        conn.close()

        windows = [dict(w) for w in windows]

        if len(windows) < MIN_WINDOWS_FOR_BASELINE:
            if verbose:
                print(f"[BASELINE] {src_ip}: only {len(windows)} windows "
                      f"(need {MIN_WINDOWS_FOR_BASELINE}) — skipping")
            continue

        stats = build_baseline_for_ip(src_ip, windows)
        if stats is None:
            continue

        save_baseline(src_ip, stats, len(windows))
        profiled += 1

        if verbose:
            print(f"[BASELINE] {src_ip}: baseline updated "
                  f"({len(windows)} windows | "
                  f"avg {stats['avg_bytes_per_sec']:.0f} B/s | "
                  f"avg {stats['avg_unique_dst_ports']:.1f} ports)")

    return profiled


def is_anomalous(src_ip: str, window: dict, sensitivity: float = 3.0) -> dict:
    """
    Compare a single traffic window against the device's stored baseline.
    Uses the 'Z-score' method: if a value is more than N standard deviations
    away from the mean, it is considered anomalous.

    sensitivity = 3.0 means "flag if more than 3x the normal variation"

    Returns a dict with:
      - is_anomalous: True/False
      - reasons: list of plain-English reasons why it was flagged
      - score: how anomalous overall (0.0 = normal, 1.0 = very suspicious)
    """
    baseline = get_baseline_for_ip(src_ip)

    if not baseline or not baseline.get("model_trained"):
        return {"is_anomalous": False, "reasons": [], "score": 0.0}

    reasons = []
    deviations = []

    def check(label, current_val, avg, std, direction="high"):
        """Check if a value deviates significantly from its baseline."""
        if std == 0:
            std = 1  # avoid division by zero
        z_score = (current_val - avg) / std
        abs_z = abs(z_score)
        deviations.append(abs_z)

        # Only flag in the suspicious direction
        if direction == "high" and z_score > sensitivity:
            reasons.append(
                f"{label} is {current_val:,.0f} — "
                f"{abs_z:.1f}x higher than this device normally sends "
                f"(usual average: {avg:,.0f})"
            )
        elif direction == "any" and abs_z > sensitivity:
            reasons.append(
                f"{label} is {current_val:,.0f} — "
                f"{abs_z:.1f}x away from normal "
                f"(usual average: {avg:,.0f})"
            )

    check("Bytes per second",
          window["bytes_per_sec"],
          baseline["avg_bytes_per_sec"],
          baseline["std_bytes_per_sec"],
          direction="high")

    check("Unique destination ports",
          window["unique_dst_ports"],
          baseline["avg_unique_dst_ports"],
          baseline["std_bytes_per_sec"] or 1,
          direction="high")

    check("Unique destination IPs",
          window["unique_dst_ips"],
          baseline["avg_unique_dst_ips"],
          baseline["std_bytes_per_sec"] or 1,
          direction="high")

    check("Packet count",
          window["packet_count"],
          baseline["avg_packet_count"],
          baseline["std_packet_count"],
          direction="high")

    # Overall anomaly score: average of top deviations, capped at 1.0
    if deviations:
        top = sorted(deviations, reverse=True)[:3]
        raw_score = (sum(top) / len(top)) / (sensitivity * 3)
        score = min(round(raw_score, 3), 1.0)
    else:
        score = 0.0

    return {
        "is_anomalous": len(reasons) > 0,
        "reasons"     : reasons,
        "score"       : score,
    }