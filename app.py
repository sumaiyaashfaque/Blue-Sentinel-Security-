# ============================================================
# BLUESENTINEL DASHBOARD — Main Entry Point
# Unified Blue Team Security Suite
# Combines: File Monitor + IDS Engine + Firewall Checker
# ============================================================

import os
import sys
import json
import time
import threading
from datetime import datetime

# Add project root to path so imports work correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.file_monitor import create_baseline, check_integrity
from core.ids_engine import simulate_detection, start_ids, SCAPY_AVAILABLE
from core.firewall_checker import run_firewall_check


# ── Helpers ──────────────────────────────────────────────────

def load_settings():
    """Load configuration from settings.json."""
    settings_path = "config/settings.json"
    if os.path.exists(settings_path):
        with open(settings_path, "r") as f:
            return json.load(f)
    return {}


def clear_screen():
    """Clear terminal screen cross-platform."""
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    """Print the BlueSentinel ASCII banner."""
    banner = """
\033[94m
  ██████╗ ██╗     ██╗   ██╗███████╗
  ██╔══██╗██║     ██║   ██║██╔════╝
  ██████╔╝██║     ██║   ██║█████╗  
  ██╔══██╗██║     ██║   ██║██╔══╝  
  ██████╔╝███████╗╚██████╔╝███████╗
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
\033[0m
\033[96m  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     \033[0m
\033[96m  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     \033[0m
\033[96m  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     \033[0m
\033[96m  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     \033[0m
\033[96m  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ \033[0m
\033[96m  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝\033[0m

\033[93m           🛡️  Blue Team Security Suite v1.0.0  🛡️\033[0m
\033[90m         File Monitor | IDS Engine | Firewall Checker\033[0m
    """
    print(banner)


def print_separator():
    print("\033[90m" + "─" * 60 + "\033[0m")


def print_status_bar():
    """Show current time and system status."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alerts = count_alerts()
    print(f"\033[90m  🕐 {now}  |  📋 Total Alerts: {alerts}\033[0m")
    print_separator()


def count_alerts():
    """Count non-comment lines in the alert log."""
    log_path = "reports/alert_log.txt"
    if not os.path.exists(log_path):
        return 0
    with open(log_path, "r") as f:
        lines = [l for l in f.readlines() if l.strip() and not l.startswith("#")]
    return len(lines)


def show_recent_alerts(n=10):
    """Display the last N alerts from the log."""
    log_path = "reports/alert_log.txt"
    if not os.path.exists(log_path):
        print("  No alerts logged yet.")
        return

    with open(log_path, "r") as f:
        lines = [l.strip() for l in f.readlines()
                 if l.strip() and not l.startswith("#")]

    recent = lines[-n:] if len(lines) >= n else lines

    if not recent:
        print("  \033[92m[🟢] No alerts yet — system looks clean!\033[0m")
        return

    print(f"\n  \033[93mLast {len(recent)} Alerts:\033[0m\n")
    for line in recent:
        if "CRITICAL" in line:
            print(f"  \033[91m{line}\033[0m")
        elif "WARNING" in line or "HIGH" in line:
            print(f"  \033[93m{line}\033[0m")
        elif "SAFE" in line or "passed" in line:
            print(f"  \033[92m{line}\033[0m")
        else:
            print(f"  \033[90m{line}\033[0m")


# ── Menu Actions ─────────────────────────────────────────────

def menu_file_monitor():
    """File Monitor submenu."""
    clear_screen()
    print("\n\033[94m  🔥 FILE INTEGRITY MONITOR\033[0m")
    print_separator()
    print("  1. Create new baseline (first time setup)")
    print("  2. Run integrity check now")
    print("  3. Start real-time monitoring")
    print("  0. Back to main menu")
    print_separator()

    choice = input("  Select option: ").strip()
    settings = load_settings()
    watch_dir = settings.get("file_monitor", {}).get("watch_directory", ".")

    if choice == "1":
        print()
        create_baseline(watch_dir)
    elif choice == "2":
        print()
        alerts = check_integrity(watch_dir)
        print(f"\n  Total issues found: {len(alerts)}")
    elif choice == "3":
        interval = settings.get("file_monitor", {}).get("scan_interval_seconds", 10)
        from core.file_monitor import monitor_realtime
        monitor_realtime(watch_dir, interval)

    input("\n  Press Enter to continue...")


def menu_ids():
    """IDS Engine submenu."""
    clear_screen()
    print("\n\033[91m  🚨 INTRUSION DETECTION SYSTEM\033[0m")
    print_separator()
    print("  1. Run simulation (demo mode — no root needed)")
    print("  2. Start live IDS (requires root + Scapy)")
    print("  0. Back to main menu")
    print_separator()

    choice = input("  Select option: ").strip()

    if choice == "1":
        print()
        simulate_detection()
    elif choice == "2":
        if not SCAPY_AVAILABLE:
            print("\n  [❌] Scapy not installed. Run: pip install scapy")
        else:
            start_ids()

    input("\n  Press Enter to continue...")


def menu_firewall():
    """Firewall Checker submenu."""
    clear_screen()
    print("\n\033[93m  🧱 FIREWALL RULE CHECKER\033[0m")
    print_separator()
    print("  1. Run audit (simulation mode)")
    print("  2. Run audit (live iptables — Linux + root)")
    print("  3. View last audit report")
    print("  0. Back to main menu")
    print_separator()

    choice = input("  Select option: ").strip()

    if choice == "1":
        print()
        run_firewall_check(simulate=True)
    elif choice == "2":
        print()
        run_firewall_check(simulate=False)
    elif choice == "3":
        report_path = "reports/firewall_audit_report.txt"
        if os.path.exists(report_path):
            print()
            with open(report_path, "r") as f:
                print(f.read())
        else:
            print("\n  [!] No report found. Run an audit first.")

    input("\n  Press Enter to continue...")


def menu_alerts():
    """Alert log viewer."""
    clear_screen()
    print("\n\033[96m  📋 ALERT LOG VIEWER\033[0m")
    print_separator()
    show_recent_alerts(20)
    print()
    print_separator()
    print("  1. Clear all alerts")
    print("  0. Back")
    print_separator()

    choice = input("  Select option: ").strip()
    if choice == "1":
        with open("reports/alert_log.txt", "w") as f:
            f.write("# BlueSentinel Alert Log — Cleared\n")
        print("  [✅] Alert log cleared.")
        time.sleep(1)


def run_full_scan():
    """Run all three tools back to back."""
    clear_screen()
    print("\n\033[95m  🔄 RUNNING FULL SECURITY SCAN...\033[0m\n")
    print_separator()

    settings = load_settings()
    watch_dir = settings.get("file_monitor", {}).get("watch_directory", ".")

    # Step 1: File Integrity
    print("\n\033[94m[1/3] File Integrity Check\033[0m")
    alerts = check_integrity(watch_dir)
    print(f"      Issues: {len(alerts)}")

    # Step 2: IDS Simulation
    print("\n\033[91m[2/3] IDS Simulation\033[0m")
    simulate_detection()

    # Step 3: Firewall
    print("\n\033[93m[3/3] Firewall Audit\033[0m")
    findings, score = run_firewall_check(simulate=True)

    print("\n" + "="*55)
    print("  ✅ FULL SCAN COMPLETE")
    print(f"  File Issues : {len(alerts)}")
    print(f"  Firewall Risk Score: {score}/100")
    print(f"  Total Alerts Logged: {count_alerts()}")
    print("="*55)

    input("\n  Press Enter to continue...")


# ── Main Menu ────────────────────────────────────────────────

def main():
    """Main dashboard loop."""
    os.makedirs("reports", exist_ok=True)
    os.makedirs("config", exist_ok=True)

    while True:
        clear_screen()
        print_banner()
        print_status_bar()

        print("  \033[97mMAIN MENU\033[0m\n")
        print("  \033[94m[1]\033[0m  🔥  File Integrity Monitor")
        print("  \033[91m[2]\033[0m  🚨  Intrusion Detection System")
        print("  \033[93m[3]\033[0m  🧱  Firewall Rule Checker")
        print("  \033[96m[4]\033[0m  📋  View Alert Log")
        print("  \033[95m[5]\033[0m  🔄  Run Full Security Scan")
        print("  \033[90m[0]\033[0m  🚪  Exit\n")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == "1":
            menu_file_monitor()
        elif choice == "2":
            menu_ids()
        elif choice == "3":
            menu_firewall()
        elif choice == "4":
            menu_alerts()
        elif choice == "5":
            run_full_scan()
        elif choice == "0":
            print("\n  \033[92m[👋] BlueSentinel shutting down. Stay secure!\033[0m\n")
            sys.exit(0)
        else:
            print("\n  [!] Invalid option. Try again.")
            time.sleep(1)


# ── Entry Point ──────────────────────────────────────────────
if __name__ == "__main__":
    main()
