"""
db/database.py
--------------
Initializes and manages the SQLite database.
All captured packets, feature windows, baselines, and alerts are stored here.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'cybersentinel.db')


def get_connection():
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows dict-like row access
    return conn


def initialize_database():
    """
    Create all tables if they don't exist.
    Called once at startup.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── Table 1: raw_packets ──────────────────────────────────────────────────
    # Stores every captured packet's metadata (not the payload — privacy matters)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,           -- Unix time (float)
            src_ip      TEXT    NOT NULL,           -- Source IP address
            dst_ip      TEXT    NOT NULL,           -- Destination IP address
            src_port    INTEGER,                    -- Source port (NULL for non-TCP/UDP)
            dst_port    INTEGER,                    -- Destination port
            protocol    TEXT    NOT NULL,           -- TCP / UDP / ICMP / Other
            size_bytes  INTEGER NOT NULL,           -- Packet size in bytes
            direction   TEXT    NOT NULL DEFAULT 'unknown'  -- inbound / outbound / internal
        )
    """)

    # ── Table 2: traffic_windows ──────────────────────────────────────────────
    # Aggregated 30-second windows of features per source IP
    # This is what the ML model actually sees
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_windows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start    REAL    NOT NULL,       -- Unix time start of window
            window_end      REAL    NOT NULL,       -- Unix time end of window
            src_ip          TEXT    NOT NULL,       -- Device being profiled
            packet_count    INTEGER NOT NULL,       -- Total packets in window
            total_bytes     INTEGER NOT NULL,       -- Total bytes transferred
            bytes_per_sec   REAL    NOT NULL,       -- Transfer rate
            unique_dst_ips  INTEGER NOT NULL,       -- Number of distinct destinations
            unique_dst_ports INTEGER NOT NULL,      -- Number of distinct ports contacted
            tcp_count       INTEGER NOT NULL,       -- TCP packets
            udp_count       INTEGER NOT NULL,       -- UDP packets
            icmp_count      INTEGER NOT NULL,       -- ICMP packets
            avg_packet_size REAL    NOT NULL        -- Mean packet size in bytes
        )
    """)

    # ── Table 3: device_baselines ─────────────────────────────────────────────
    # Stores the learned "normal" ranges per device
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_baselines (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip                  TEXT    NOT NULL UNIQUE,
            first_seen              REAL    NOT NULL,
            last_updated            REAL    NOT NULL,
            window_count            INTEGER NOT NULL DEFAULT 0,   -- how many windows trained on
            avg_bytes_per_sec       REAL,
            std_bytes_per_sec       REAL,
            avg_packet_count        REAL,
            std_packet_count        REAL,
            avg_unique_dst_ips      REAL,
            avg_unique_dst_ports    REAL,
            model_trained           INTEGER NOT NULL DEFAULT 0    -- 0=no, 1=yes
        )
    """)

    # ── Table 4: alerts ───────────────────────────────────────────────────────
    # Every detected anomaly with its AI-generated explanation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp           REAL    NOT NULL,
            src_ip              TEXT    NOT NULL,
            anomaly_score       REAL    NOT NULL,       -- Isolation Forest score
            confidence_pct      INTEGER NOT NULL,       -- 0–100
            window_id           INTEGER REFERENCES traffic_windows(id),
            -- LLM-generated fields
            threat_type         TEXT,                   -- e.g. "Data exfiltration"
            severity            TEXT,                   -- Low / Medium / High / Critical
            explanation         TEXT,                   -- Plain-English explanation
            recommended_action  TEXT,                   -- What to do
            llm_processed       INTEGER NOT NULL DEFAULT 0,  -- 0=pending, 1=done
            acknowledged        INTEGER NOT NULL DEFAULT 0   -- 0=new, 1=seen
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at: {os.path.abspath(DB_PATH)}")


def insert_packet(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size_bytes, direction):
    """Insert a single captured packet into raw_packets."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO raw_packets
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size_bytes, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size_bytes, direction))
    conn.commit()
    conn.close()


def insert_traffic_window(window_data: dict) -> int:
    """Insert a computed traffic window. Returns the new row id."""
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO traffic_windows
            (window_start, window_end, src_ip, packet_count, total_bytes,
             bytes_per_sec, unique_dst_ips, unique_dst_ports,
             tcp_count, udp_count, icmp_count, avg_packet_size)
        VALUES
            (:window_start, :window_end, :src_ip, :packet_count, :total_bytes,
             :bytes_per_sec, :unique_dst_ips, :unique_dst_ports,
             :tcp_count, :udp_count, :icmp_count, :avg_packet_size)
    """, window_data)
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def insert_alert(alert_data: dict) -> int:
    """Insert a new alert. Returns the new row id."""
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO alerts
            (timestamp, src_ip, anomaly_score, confidence_pct, window_id)
        VALUES
            (:timestamp, :src_ip, :anomaly_score, :confidence_pct, :window_id)
    """, alert_data)
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def update_alert_explanation(alert_id: int, threat_type: str, severity: str,
                              explanation: str, recommended_action: str):
    """Called after LLM processes an alert — fills in the plain-English fields."""
    conn = get_connection()
    conn.execute("""
        UPDATE alerts
        SET threat_type        = ?,
            severity           = ?,
            explanation        = ?,
            recommended_action = ?,
            llm_processed      = 1
        WHERE id = ?
    """, (threat_type, severity, explanation, recommended_action, alert_id))
    conn.commit()
    conn.close()


def get_recent_alerts(limit: int = 50) -> list:
    """Fetch the most recent alerts for the dashboard."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_packet_count() -> int:
    """Return total number of packets captured so far."""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM raw_packets").fetchone()[0]
    conn.close()
    return count
