"""
engine/anomaly_detector.py
---------------------------
Phase 4: Isolation Forest Anomaly Detection Engine.
 
This is the core AI of CyberSentinel.
 
HOW ISOLATION FOREST WORKS (simply):
  Imagine you have 1000 dots on a page. Most are clustered
  together (normal traffic). A few are far away (anomalies).
 
  The algorithm draws random lines across the page over and
  over. Normal points take MANY cuts to isolate because they
  are surrounded by other points. Anomalous points take VERY
  FEW cuts because they are already alone.
 
  The "anomaly score" = how few cuts it took to isolate a point.
  Low cuts = anomalous. Many cuts = normal.
 
WHY THIS IS BETTER THAN PHASE 3 ALONE:
  Phase 3 checks each feature individually (bytes, ports etc).
  Phase 4 looks at ALL features TOGETHER as a pattern.
  A device sending 500 bytes/s is normal. Contacting 200 ports
  is suspicious. But sending 500 bytes/s TO 200 ports at 3am
  with all-TCP traffic is a very specific pattern — and the
  Isolation Forest catches that combination even if each
  number alone seems fine.
"""
 
import os
import sys
import time
import pickle
from datetime import datetime
 
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
 
from db.database import get_connection, insert_alert, update_alert_explanation
 
# ── Configuration ─────────────────────────────────────────────────────────────
 
# How sensitive the detector is.
# 0.05 = expects 5% of traffic to be anomalous (recommended)
# Lower = more sensitive (more alerts), Higher = less sensitive
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.05"))
 
# Minimum windows needed before we trust the model
MIN_TRAINING_WINDOWS = 10
 
# Where we save the trained model so we don't retrain every time
MODEL_DIR  = os.path.join(os.path.dirname(__file__), '..', 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
 
# The 9 features we feed into the model (same as Phase 2)
FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "bytes_per_sec",
    "unique_dst_ips",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "avg_packet_size",
]
 
 
# ── Model persistence ─────────────────────────────────────────────────────────
 
def ensure_model_dir():
    os.makedirs(MODEL_DIR, exist_ok=True)
 
 
def save_model(model, scaler):
    """Save the trained model and scaler to disk."""
    ensure_model_dir()
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
 
 
def load_model():
    """Load a previously trained model. Returns (model, scaler) or (None, None)."""
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        return model, scaler
    return None, None
 
 
# ── Feature matrix builder ────────────────────────────────────────────────────
 
def windows_to_matrix(windows: list) -> np.ndarray:
    """
    Convert a list of window dicts into a numpy matrix
    that scikit-learn can use for training/prediction.
    Each row = one time window. Each column = one feature.
    """
    matrix = []
    for w in windows:
        row = [float(w.get(col, 0) or 0) for col in FEATURE_COLUMNS]
        matrix.append(row)
    return np.array(matrix)
 
 
# ── Training ──────────────────────────────────────────────────────────────────
 
def train_model(windows: list) -> tuple:
    """
    Train the Isolation Forest on a list of traffic windows.
 
    Steps:
    1. Convert windows to a number matrix
    2. Scale all features to similar ranges (StandardScaler)
    3. Train Isolation Forest on scaled data
    4. Save model to disk
 
    Returns (model, scaler)
    """
    if len(windows) < MIN_TRAINING_WINDOWS:
        raise ValueError(
            f"Need at least {MIN_TRAINING_WINDOWS} windows to train. "
            f"Currently have {len(windows)}."
        )
 
    X = windows_to_matrix(windows)
 
    # Scale features so no single feature dominates
    # e.g. bytes (0-1,000,000) vs ports (0-65535) need scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    # Train the Isolation Forest
    model = IsolationForest(
        contamination=CONTAMINATION,
        random_state=42,       # makes results reproducible
        n_estimators=100,      # number of trees in the forest
        max_samples='auto',
    )
    model.fit(X_scaled)
 
    save_model(model, scaler)
    print(f"[AI] Model trained on {len(windows)} windows and saved.")
    return model, scaler
 
 
def get_trained_model():
    """
    Returns a trained model, loading from disk if available,
    otherwise training fresh from the database.
    """
    model, scaler = load_model()
    if model is not None:
        return model, scaler
 
    # No saved model — train fresh
    conn = get_connection()
    rows = conn.execute("SELECT * FROM traffic_windows ORDER BY window_start").fetchall()
    conn.close()
    windows = [dict(r) for r in rows]
 
    if len(windows) < MIN_TRAINING_WINDOWS:
        return None, None
 
    return train_model(windows)
 
 
# ── Scoring ───────────────────────────────────────────────────────────────────
 
def score_window(window: dict, model, scaler) -> float:
    """
    Score a single traffic window.
    Returns anomaly score between 0.0 (normal) and 1.0 (very anomalous).
 
    Isolation Forest returns negative scores for anomalies internally.
    We convert to a 0-1 scale where higher = more suspicious.
    """
    X = windows_to_matrix([window])
    X_scaled = scaler.transform(X)
 
    # Raw score: negative means anomalous in sklearn's convention
    raw_score = model.score_samples(X_scaled)[0]
 
    # Convert to 0-1 where 1.0 = most anomalous
    # Typical range is roughly -0.8 to 0.2
    normalized = max(0.0, min(1.0, (0.2 - raw_score) / 1.0))
    return round(normalized, 4)
 
 
def is_anomaly(score: float, threshold: float = 0.6) -> bool:
    """Returns True if the score exceeds our alert threshold."""
    return score >= threshold
 
 
# ── Alert pipeline ────────────────────────────────────────────────────────────
 
def classify_threat_type(window: dict, baseline: dict) -> str:
    """
    Given a suspicious window, make an educated guess at the
    attack type based on which features are most abnormal.
    This classification is passed to the LLM in Phase 5.
    """
    bps   = window.get("bytes_per_sec", 0)
    ports = window.get("unique_dst_ports", 0)
    ips   = window.get("unique_dst_ips", 0)
    icmp  = window.get("icmp_count", 0)
    pkts  = window.get("packet_count", 0)
 
    avg_bps   = baseline.get("avg_bytes_per_sec", 0) if baseline else 0
    avg_ports = baseline.get("avg_unique_dst_ports", 0) if baseline else 0
 
    # Port scan: many unique ports regardless of destination count
    if ports > 50:
        return "Port Scan"
 
    # Data exfiltration: massive bytes to few destinations
    if bps > max(500_000, avg_bps * 20) and ips <= 3:
        return "Possible Data Exfiltration"
 
    # DDoS / flood: huge packet count, many IPs
    if pkts > 1000 and ips > 20:
        return "Possible DDoS / Flood"
 
    # ICMP flood / ping sweep
    if icmp > 200:
        return "ICMP Flood / Ping Sweep"
 
    # Lateral movement: many internal IPs contacted
    if ips > 30:
        return "Lateral Movement / Network Scan"
 
    # High packet rate with elevated bytes
    if pkts > 500 and bps > max(100_000, avg_bps * 5):
        return "Possible Data Exfiltration"
 
    # Generic
    return "Anomalous Behavior"
 
 
def run_detection(verbose: bool = True) -> list:
    """
    Main detection function. Scores all recent unscored windows,
    flags anomalies, and saves alerts to the database.
 
    Returns list of new alert dicts.
    """
    model, scaler = get_trained_model()
    if model is None:
        if verbose:
            print("[AI] Not enough data to run detection yet. "
                  f"Need {MIN_TRAINING_WINDOWS} windows.")
        return []
 
    # Get windows that haven't been scored yet
    conn = get_connection()
    scored_ids = set(
        row[0] for row in
        conn.execute("SELECT window_id FROM alerts WHERE window_id IS NOT NULL").fetchall()
    )
 
    recent_windows = conn.execute("""
        SELECT * FROM traffic_windows
        ORDER BY window_start DESC
        LIMIT 200
    """).fetchall()
    conn.close()
 
    recent_windows = [dict(w) for w in recent_windows]
    new_alerts = []
 
    from engine.baseline_profiler import get_baseline_for_ip
 
    for window in recent_windows:
        if window["id"] in scored_ids:
            continue
 
        score = score_window(window, model, scaler)
 
        if is_anomaly(score):
            src_ip   = window["src_ip"]
            baseline = get_baseline_for_ip(src_ip)
            threat   = classify_threat_type(window, baseline)
 
            confidence = min(100, int(score * 120))
 
            alert_data = {
                "timestamp"     : time.time(),
                "src_ip"        : src_ip,
                "anomaly_score" : score,
                "confidence_pct": confidence,
                "window_id"     : window["id"],
            }
 
            alert_id = insert_alert(alert_data)
            alert_data["id"]          = alert_id
            alert_data["threat_type"] = threat
            alert_data["window"]      = window
            new_alerts.append(alert_data)
 
            if verbose:
                print(f"[ALERT] {threat} detected on {src_ip} "
                      f"| Score: {score} | Confidence: {confidence}%")
 
    if verbose and not new_alerts:
        print("[AI] Detection complete — no new anomalies found.")
 
    return new_alerts
 
 
def retrain_model():
    """Force a full model retrain from all stored windows."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM traffic_windows ORDER BY window_start").fetchall()
    conn.close()
    windows = [dict(r) for r in rows]
 
    if len(windows) < MIN_TRAINING_WINDOWS:
        print(f"[AI] Cannot retrain: only {len(windows)} windows available.")
        return None, None
 
    # Delete old model so it gets rebuilt
    for path in [MODEL_PATH, SCALER_PATH]:
        if os.path.exists(path):
            os.remove(path)
 
    return train_model(windows)