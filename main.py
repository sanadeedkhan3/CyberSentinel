"""
main.py — CyberSentinel — All 6 phases + notifications
"""
import os, sys, time, threading
from dotenv import load_dotenv
load_dotenv()

def check_environment():
    print("[INIT] Checking environment...")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key == "your_api_key_here":
        print("[WARN] ANTHROPIC_API_KEY not set. Using rule-based fallback.")
    else:
        print("[INIT] Anthropic API key: found ✓")
    try:
        import scapy; print("[INIT] Scapy: installed ✓")
    except ImportError:
        print("[ERROR] Scapy not installed."); sys.exit(1)
    from notifications.email_alerter import is_email_configured
    if is_email_configured():
        print("[INIT] Email alerts: configured ✓")
    else:
        print("[WARN] Email alerts not configured. Add SMTP settings to .env")
    print("[INIT] Environment OK.\n")

def feature_engineering_loop():
    from engine.feature_engineer import run_feature_engineering
    while True:
        try: run_feature_engineering(verbose=True)
        except Exception as e: print(f"[FE] {e}")
        time.sleep(30)

def baseline_loop():
    from engine.baseline_profiler import run_baseline_profiling
    time.sleep(60)
    while True:
        try: run_baseline_profiling(verbose=True)
        except Exception as e: print(f"[BASELINE] {e}")
        time.sleep(60)

def detection_loop():
    from engine.anomaly_detector import run_detection, retrain_model
    time.sleep(90)
    retrain_model()
    while True:
        try: run_detection(verbose=True)
        except Exception as e: print(f"[AI] {e}")
        time.sleep(30)

def explainer_loop():
    from explainer.llm_explainer import process_pending_alerts
    time.sleep(120)
    while True:
        try: process_pending_alerts(verbose=True)
        except Exception as e: print(f"[LLM] {e}")
        time.sleep(20)

def email_loop():
    from notifications.email_alerter import process_new_alerts_for_email
    time.sleep(150)
    while True:
        try:
            sent = process_new_alerts_for_email()
            if sent: print(f"[EMAIL] {sent} alert email(s) sent")
        except Exception as e: print(f"[EMAIL] {e}")
        time.sleep(30)

def dashboard_thread():
    from dashboard.app import run_dashboard
    port = int(os.getenv("DASHBOARD_PORT","5000"))
    run_dashboard(port=port)

def main():
    print()
    print("  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ")
    print(" ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗")
    print(" ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝")
    print(" ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗")
    print(" ╚██████╗   ██║   ██████╔╝███████╗██║  ██║")
    print("  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝")
    print("  SENTINEL — AI Network Threat Detector")
    print("  Full System: 6 Phases + Email + PDF + Heatmap")
    print()
    check_environment()

    threads = [
        threading.Thread(target=feature_engineering_loop, daemon=True, name="FeatureEng"),
        threading.Thread(target=baseline_loop,            daemon=True, name="Baseline"),
        threading.Thread(target=detection_loop,           daemon=True, name="Detector"),
        threading.Thread(target=explainer_loop,           daemon=True, name="Explainer"),
        threading.Thread(target=email_loop,               daemon=True, name="EmailAlerter"),
        threading.Thread(target=dashboard_thread,         daemon=True, name="Dashboard"),
    ]

    for t in threads:
        t.start()
        print(f"[INIT] {t.name} started ✓")

    print()
    print("[INIT] Dashboard → http://127.0.0.1:5000")
    print("[INIT] Capturing packets... (Ctrl+C to stop)\n")

    from capture.packet_capture import start_capture, INTERFACE
    start_capture(interface=INTERFACE or None)

if __name__ == "__main__":
    main()