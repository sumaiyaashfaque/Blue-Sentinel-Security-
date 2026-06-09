# ============================================================
# FIREWALL RULE CHECKER — BlueSentinel Security Suite
# Audits firewall rules for misconfigurations and risks
# Works on Linux (iptables) and simulates on Windows
# ============================================================

import subprocess
import platform
import os
from datetime import datetime


# ── Risk Scoring ─────────────────────────────────────────────

RISK_RULES = [
    {
        "id": "FW-001",
        "pattern": "ACCEPT",
        "context": "0.0.0.0/0",
        "severity": "CRITICAL",
        "description": "Rule accepts ALL traffic from ANY source — too permissive",
        "recommendation": "Restrict to specific trusted IP ranges only"
    },
    {
        "id": "FW-002",
        "pattern": "INPUT",
        "context": "ACCEPT",
        "severity": "HIGH",
        "description": "Default INPUT policy set to ACCEPT — dangerous default",
        "recommendation": "Set default policy to DROP: iptables -P INPUT DROP"
    },
    {
        "id": "FW-003",
        "pattern": "23",
        "context": "ACCEPT",
        "severity": "CRITICAL",
        "description": "Telnet (port 23) is open — unencrypted protocol",
        "recommendation": "Block Telnet and use SSH (port 22) instead"
    },
    {
        "id": "FW-004",
        "pattern": "3389",
        "context": "ACCEPT",
        "severity": "HIGH",
        "description": "RDP (port 3389) exposed — common brute force target",
        "recommendation": "Restrict RDP to VPN or specific admin IPs only"
    },
    {
        "id": "FW-005",
        "pattern": "FORWARD",
        "context": "ACCEPT",
        "severity": "MEDIUM",
        "description": "IP forwarding enabled — check if this is intentional",
        "recommendation": "Disable if not acting as a router or VPN gateway"
    },
    {
        "id": "FW-006",
        "pattern": "21",
        "context": "ACCEPT",
        "severity": "HIGH",
        "description": "FTP (port 21) is open — transmits credentials in plaintext",
        "recommendation": "Use SFTP (port 22) instead and block port 21"
    },
]

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


# ── Logging ─────────────────────────────────────────────────

def log_alert(message):
    """Write firewall audit findings to shared log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [FIREWALL CHECKER] {message}\n"
    os.makedirs("reports", exist_ok=True)
    with open("reports/alert_log.txt", "a") as f:
        f.write(log_entry)


# ── Rule Fetcher ─────────────────────────────────────────────

def get_iptables_rules():
    """Fetch live iptables rules from the system (Linux only)."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n", "-v", "--line-numbers"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def get_simulated_rules():
    """
    Return simulated firewall rules for demo/testing.
    Intentionally contains vulnerabilities for detection.
    """
    return """
Chain INPUT (policy ACCEPT)
num  target  prot  opt  source       destination
1    ACCEPT  all   --   0.0.0.0/0   0.0.0.0/0    state RELATED,ESTABLISHED
2    ACCEPT  tcp   --   0.0.0.0/0   0.0.0.0/0    dport 22
3    ACCEPT  tcp   --   0.0.0.0/0   0.0.0.0/0    dport 23
4    ACCEPT  tcp   --   0.0.0.0/0   0.0.0.0/0    dport 3389
5    ACCEPT  tcp   --   0.0.0.0/0   0.0.0.0/0    dport 21

Chain FORWARD (policy ACCEPT)
num  target  prot  opt  source       destination
1    ACCEPT  all   --   0.0.0.0/0   0.0.0.0/0

Chain OUTPUT (policy ACCEPT)
num  target  prot  opt  source       destination
1    ACCEPT  all   --   0.0.0.0/0   0.0.0.0/0
"""


# ── Rule Analyzer ────────────────────────────────────────────

def analyze_rules(rules_text):
    """
    Scan firewall rules against known risk patterns.
    Returns list of findings with severity and recommendations.
    """
    findings = []

    for rule in RISK_RULES:
        if rule["pattern"] in rules_text and rule["context"] in rules_text:
            findings.append(rule)

    return findings


def calculate_risk_score(findings):
    """Calculate overall firewall risk score out of 100."""
    if not findings:
        return 0

    total = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    max_possible = len(RISK_RULES) * 10
    score = min(int((total / max_possible) * 100), 100)
    return score


def risk_label(score):
    """Convert numeric score to human-readable risk label."""
    if score >= 70:
        return "🔴 CRITICAL RISK"
    elif score >= 40:
        return "🟠 HIGH RISK"
    elif score >= 20:
        return "🟡 MEDIUM RISK"
    elif score > 0:
        return "🔵 LOW RISK"
    else:
        return "🟢 SECURE"


# ── Report Generator ─────────────────────────────────────────

def generate_report(findings, risk_score, rules_text):
    """Generate a professional firewall audit report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = "reports/firewall_audit_report.txt"

    os.makedirs("reports", exist_ok=True)

    with open(report_path, "w") as f:
        f.write("="*60 + "\n")
        f.write("  BLUESENTINEL — FIREWALL AUDIT REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"  Generated: {timestamp}\n")
        f.write(f"  Risk Score: {risk_score}/100  ({risk_label(risk_score)})\n")
        f.write(f"  Total Issues Found: {len(findings)}\n")
        f.write("="*60 + "\n\n")

        if findings:
            f.write("FINDINGS:\n\n")
            for i, finding in enumerate(findings, 1):
                f.write(f"[{finding['id']}] {finding['severity']} — {finding['description']}\n")
                f.write(f"  ➤ Recommendation: {finding['recommendation']}\n\n")
        else:
            f.write("No critical issues found. Firewall rules look secure.\n")

        f.write("\n--- RAW FIREWALL RULES ---\n")
        f.write(rules_text)

    return report_path


# ── Main Checker ─────────────────────────────────────────────

def run_firewall_check(simulate=False):
    """
    Run full firewall audit.
    simulate=True uses sample rules (for demo/testing)
    simulate=False uses real iptables (Linux + root required)
    """
    print("\n" + "="*55)
    print("  🧱 BlueSentinel Firewall Rule Checker")
    print("="*55)

    # Fetch rules
    if simulate or platform.system() != "Linux":
        print("  [*] Running in SIMULATION mode (demo rules)\n")
        rules_text = get_simulated_rules()
    else:
        print("  [*] Fetching live iptables rules...\n")
        rules_text = get_iptables_rules()
        if not rules_text:
            print("  [❌] Could not fetch rules. Try: sudo python firewall_checker.py")
            print("  [*] Switching to simulation mode...\n")
            rules_text = get_simulated_rules()

    # Analyze
    findings = analyze_rules(rules_text)
    risk_score = calculate_risk_score(findings)

    # Print results
    print(f"  Risk Score : {risk_score}/100")
    print(f"  Risk Level : {risk_label(risk_score)}")
    print(f"  Issues Found: {len(findings)}\n")

    if findings:
        print("  FINDINGS:")
        print("  " + "-"*50)
        for finding in findings:
            sev = finding['severity']
            icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
            print(f"\n  {icon} [{finding['id']}] {sev}")
            print(f"     Issue : {finding['description']}")
            print(f"     Fix   : {finding['recommendation']}")
            log_alert(f"[{finding['id']}] {sev} — {finding['description']}")
    else:
        print("  [🟢 SECURE] No misconfigurations detected.")
        log_alert("Firewall audit passed — no issues found.")

    # Generate report
    report_path = generate_report(findings, risk_score, rules_text)
    print(f"\n  [📄] Full report saved: {report_path}")

    return findings, risk_score


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    run_firewall_check(simulate=True)
