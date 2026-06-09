# ============================================================
# FILE INTEGRITY MONITOR — BlueSentinel Security Suite
# Detects unauthorized file changes using SHA-256 hashing
# ============================================================

import hashlib
import json
import os
import time
from datetime import datetime


BASELINE_FILE = "config/baseline.json"


def log_alert(message):
    """Write alert to the shared log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [FILE MONITOR] {message}\n"
    with open("reports/alert_log.txt", "a") as f:
        f.write(log_entry)
    return log_entry


def hash_file(filepath):
    """Generate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        return None


def create_baseline(directory):
    """
    Scan a directory and save SHA-256 hashes as the trusted baseline.
    Run this FIRST before monitoring starts.
    """
    print(f"\n[*] Creating baseline for: {directory}")
    baseline = {}
    file_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            file_hash = hash_file(path)
            if file_hash:
                baseline[path] = {
                    "hash": file_hash,
                    "size": os.path.getsize(path),
                    "last_modified": os.path.getmtime(path)
                }
                file_count += 1

    os.makedirs("config", exist_ok=True)
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"[✅] Baseline created — {file_count} files hashed and saved.")
    log_alert(f"Baseline created for '{directory}' — {file_count} files indexed.")
    return baseline


def check_integrity(directory):
    """
    Compare current file hashes against baseline.
    Returns list of alerts found.
    """
    alerts = []

    if not os.path.exists(BASELINE_FILE):
        msg = "No baseline found. Run create_baseline() first."
        print(f"[❌] {msg}")
        return alerts

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    current_files = {}
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            file_hash = hash_file(path)
            if file_hash:
                current_files[path] = file_hash

    # Check for modified or deleted files
    for path, data in baseline.items():
        if path not in current_files:
            alert = f"[🔴 CRITICAL] File DELETED: {path}"
            print(alert)
            alerts.append(log_alert(f"File DELETED: {path}"))
        elif current_files[path] != data["hash"]:
            alert = f"[🔴 CRITICAL] File MODIFIED: {path}"
            print(alert)
            alerts.append(log_alert(f"File MODIFIED: {path}"))

    # Check for new files added
    for path in current_files:
        if path not in baseline:
            alert = f"[🟡 WARNING] New file ADDED: {path}"
            print(alert)
            alerts.append(log_alert(f"New file ADDED: {path}"))

    if not alerts:
        print("[🟢 SAFE] All files intact. No changes detected.")
        log_alert("Integrity check passed — no changes detected.")

    return alerts


def monitor_realtime(directory, interval=10):
    """
    Continuously monitor a directory every N seconds.
    Press Ctrl+C to stop.
    """
    print(f"\n[🔍] Real-time monitoring started on: {directory}")
    print(f"[*] Checking every {interval} seconds... (Ctrl+C to stop)\n")

    try:
        while True:
            print(f"\n--- Scan @ {datetime.now().strftime('%H:%M:%S')} ---")
            check_integrity(directory)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    TEST_DIR = "."  # Monitor current directory
    create_baseline(TEST_DIR)
    print("\n[*] Modify a file then press Enter to run integrity check...")
    input()
    check_integrity(TEST_DIR)
