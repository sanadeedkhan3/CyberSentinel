"""
capture/packet_capture.py
--------------------------
Phase 1: Network packet capture engine.

Uses Scapy to sniff packets on the local network interface.
For each packet it extracts metadata (never payload content) and writes
to the SQLite database via db/database.py.

Run with:  sudo python -m capture.packet_capture
Requires root/admin privileges for raw socket access.
"""

import os
import sys
import time
import socket
import ipaddress
from datetime import datetime
from dotenv import load_dotenv

# Add project root to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from db.database import initialize_database, insert_packet

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

INTERFACE = os.getenv("NETWORK_INTERFACE") or None  # None = auto-detect
PACKET_FILTER = "ip"                                 # Only capture IP packets

# Private IP ranges (RFC 1918) — used to classify direction
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Detect the machine's primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private/local range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def classify_direction(src_ip: str, dst_ip: str, local_ip: str) -> str:
    """
    Classify the packet direction relative to the local machine.
    - outbound: local machine sending to external
    - inbound:  external sending to local machine
    - internal: both src and dst are private IPs
    """
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)

    if src_ip == local_ip and not dst_private:
        return "outbound"
    elif dst_ip == local_ip and not src_private:
        return "inbound"
    elif src_private and dst_private:
        return "internal"
    else:
        return "unknown"


def extract_protocol(packet) -> str:
    """Extract the transport-layer protocol name from a Scapy packet."""
    # Import here so the module can be imported without scapy installed
    from scapy.all import TCP, UDP, ICMP
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"


# ── Packet handler ────────────────────────────────────────────────────────────

# Cache local IP so we don't call socket on every packet
_LOCAL_IP = None
_packet_counter = 0
_start_time = time.time()


def handle_packet(packet):
    """
    Called by Scapy for every captured packet.
    Extracts metadata and writes it to the database.
    """
    global _LOCAL_IP, _packet_counter

    # Lazy-load local IP
    if _LOCAL_IP is None:
        _LOCAL_IP = get_local_ip()

    try:
        from scapy.all import IP, TCP, UDP

        # Only process packets with an IP layer
        if IP not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        size_bytes = len(packet)
        timestamp = time.time()
        protocol = extract_protocol(packet)
        direction = classify_direction(src_ip, dst_ip, _LOCAL_IP)

        # Extract ports if available
        src_port = None
        dst_port = None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Write to database
        insert_packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size_bytes=size_bytes,
            direction=direction
        )

        _packet_counter += 1

        # Print a live summary every 100 packets
        if _packet_counter % 100 == 0:
            elapsed = time.time() - _start_time
            rate = _packet_counter / elapsed
            print(f"[CAPTURE] {_packet_counter} packets captured | "
                  f"{rate:.1f} pkt/s | "
                  f"Latest: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})")

    except Exception as e:
        # Never crash the sniffer on a bad packet — just log and continue
        print(f"[CAPTURE] Warning: could not parse packet: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def start_capture(interface: str = None, packet_limit: int = 0):
    """
    Start sniffing packets on the given interface.

    Args:
        interface:    Network interface (e.g. 'eth0', 'wlan0').
                      None = Scapy auto-detects.
        packet_limit: Stop after N packets (0 = run forever).
    """
    from scapy.all import sniff, conf

    global _start_time
    _start_time = time.time()

    local_ip = get_local_ip()
    iface_display = interface or conf.iface

    print("=" * 60)
    print("  CyberSentinel — Packet Capture Engine")
    print("=" * 60)
    print(f"  Interface : {iface_display}")
    print(f"  Local IP  : {local_ip}")
    print(f"  Filter    : {PACKET_FILTER}")
    print(f"  Limit     : {'∞' if packet_limit == 0 else packet_limit} packets")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("  Press Ctrl+C to stop.")
    print()

    # Initialize database tables
    initialize_database()

    try:
        sniff(
            iface=interface,
            filter=PACKET_FILTER,
            prn=handle_packet,
            store=False,          # Don't keep packets in memory
            count=packet_limit,   # 0 = infinite
        )
    except KeyboardInterrupt:
        elapsed = time.time() - _start_time
        print(f"\n[CAPTURE] Stopped after {_packet_counter} packets "
              f"in {elapsed:.1f} seconds.")
    except PermissionError:
        print("\n[ERROR] Permission denied.")
        print("        Packet capture requires root/administrator privileges.")
        print("        Run with: sudo python main.py")
        sys.exit(1)


if __name__ == "__main__":
    iface = INTERFACE or None
    start_capture(interface=iface)
