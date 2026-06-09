# ============================================================
# INTRUSION DETECTION SYSTEM (IDS) — BlueSentinel Security Suite
# Monitors network packets and flags suspicious activity
# Requires: pip install scapy
# Must run as root/admin for packet capture
# ============================================================

import json
import os
from datetime import datetime
from collections import defaultdict

# Scapy import with graceful fallback for environments without it
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[⚠️] Scapy not installed. Run: pip install scapy")


# ── Configuration ───────────────────────────────────────────

SUSPICIOUS_PORTS = {
    22:   "SSH Brute Force Attempt",
    23:   "Telnet (Unencrypted Protocol)",
    3389: "RDP Remote Desktop Attack",
    4444: "Metasploit Default Listener",
    5555: "Android ADB / Backdoor",
    6667: "IRC Botnet Communication",
    8080: "HTTP Proxy / Web Attack",
    1337: "Hacker Port (Elite)",
    9001: "Tor Network Traffic",
}

PORT_SCAN_THRESHOLD = 10    # Ports hit within TIME_WINDOW = port scan
TIME_WINDOW = 5             # Seconds to track connections per IP
ICMP_FLOOD_THRESHOLD = 20   # ICMP packets to flag as flood

# Track connections per IP for port scan detection
connection_tracker = defaultdict(list)
icmp_tracker = defaultdict(int)
alert_count = 0


# ── Logging ─────────────────────────────────────────────────

def log_alert(level, message):
    """Write IDS alert to shared log file."""
    global alert_count
    alert_count += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [IDS ENGINE] [{level}] {message}\n"
    os.makedirs("reports", exist_ok=True)
    with open("reports/alert_log.txt", "a") as f:
        f.write(log_entry)
    return log_entry


def print_alert(level, message):
    """Print color-coded alert to terminal."""
    icons = {
        "CRITICAL": "🔴",
        "WARNING":  "🟡",
        "INFO":     "🔵"
    }
    icon = icons.get(level, "⚪")
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{icon} {level}] {message}")
    log_alert(level, message)


# ── Detection Engines ────────────────────────────────────────

def detect_suspicious_port(src_ip, dst_port):
    """Check if destination port is in the suspicious ports list."""
    if dst_port in SUSPICIOUS_PORTS:
        reason = SUSPICIOUS_PORTS[dst_port]
        print_alert("CRITICAL", f"Suspicious port hit! {src_ip} → Port {dst_port} ({reason})")
        return True
    return False


def detect_port_scan(src_ip, dst_port):
    """
    Detect port scanning by tracking how many unique ports
    a single IP hits within the TIME_WINDOW.
    """
    now = datetime.now().timestamp()

    # Record this connection attempt
    connection_tracker[src_ip].append((now, dst_port))

    # Clean up old entries outside the time window
    connection_tracker[src_ip] = [
        (t, p) for t, p in connection_tracker[src_ip]
        if now - t <= TIME_WINDOW
    ]

    # Count unique ports hit
    unique_ports = set(p for _, p in connection_tracker[src_ip])

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        print_alert(
            "CRITICAL",
            f"PORT SCAN DETECTED! {src_ip} hit {len(unique_ports)} ports in {TIME_WINDOW}s"
        )
        connection_tracker[src_ip] = []  # Reset after alert
        return True
    return False


def detect_icmp_flood(src_ip):
    """Detect ICMP (ping) flood attacks."""
    icmp_tracker[src_ip] += 1
    if icmp_tracker[src_ip] >= ICMP_FLOOD_THRESHOLD:
        print_alert("CRITICAL", f"ICMP FLOOD DETECTED from {src_ip} ({icmp_tracker[src_ip]} packets)")
        icmp_tracker[src_ip] = 0  # Reset after alert
        return True
    return False


# ── Packet Processor ─────────────────────────────────────────

def process_packet(packet):
    """Main packet handler — called for every captured packet."""
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # TCP Packet Analysis
    if TCP in packet:
        dst_port = packet[TCP].dport
        detect_suspicious_port(src_ip, dst_port)
        detect_port_scan(src_ip, dst_port)

    # UDP Packet Analysis
    elif UDP in packet:
        dst_port = packet[UDP].dport
        if dst_port in SUSPICIOUS_PORTS:
            print_alert("WARNING", f"Suspicious UDP traffic: {src_ip} → Port {dst_port}")

    # ICMP (Ping) Flood Detection
    elif ICMP in packet:
        detect_icmp_flood(src_ip)


# ── IDS Runner ───────────────────────────────────────────────

def start_ids(interface=None, packet_count=0):
    """
    Start the IDS packet sniffer.
    interface: network interface (None = auto-detect)
    packet_count: 0 = capture forever
    """
    if not SCAPY_AVAILABLE:
        print("[❌] Cannot start IDS — Scapy not installed.")
        return

    print("\n" + "="*55)
    print("  🚨 BlueSentinel IDS Engine — ACTIVE")
    print("="*55)
    print(f"  Monitoring: {'All interfaces' if not interface else interface}")
    print(f"  Suspicious ports tracked: {len(SUSPICIOUS_PORTS)}")
    print(f"  Port scan threshold: {PORT_SCAN_THRESHOLD} ports / {TIME_WINDOW}s")
    print("  Press Ctrl+C to stop\n")

    log_alert("INFO", "IDS Engine started.")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            store=0,                 # Don't store packets in memory
            count=packet_count,
            filter="ip"              # Only capture IP packets
        )
    except KeyboardInterrupt:
        print(f"\n[*] IDS stopped. Total alerts generated: {alert_count}")
        log_alert("INFO", f"IDS Engine stopped. Total alerts: {alert_count}")
    except PermissionError:
        print("[❌] Permission denied. Run as root: sudo python ids_engine.py")


def simulate_detection():
    """
    Simulate IDS detections without real network traffic.
    Useful for testing and demonstration.
    """
    print("\n[🔵 SIMULATION MODE] Simulating attack scenarios...\n")

    test_cases = [
        ("192.168.1.100", 4444, "TCP"),
        ("10.0.0.55",     3389, "TCP"),
        ("172.16.0.1",    22,   "TCP"),
        ("192.168.1.200", 8080, "TCP"),
    ]

    for src_ip, port, proto in test_cases:
        detect_suspicious_port(src_ip, port)

    # Simulate port scan
    print("\n[*] Simulating port scan from 192.168.1.99...")
    for port in range(20, 35):
        detect_port_scan("192.168.1.99", port)

    print(f"\n[✅] Simulation complete. Check reports/alert_log.txt")


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs("reports", exist_ok=True)
    simulate_detection()
    # To run real IDS: start_ids()
