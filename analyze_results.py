# Vishrudh N | 727823TUCY054
# analyze_results.py — Parses IDS logs and prints analysis

import os
import glob
from datetime import datetime

ROLL_NUMBER = "727823TUCY054"
print(f"[ANALYZE] Roll Number: {ROLL_NUMBER} | Timestamp: {datetime.now()}")

log_dir = "logs"
log_files = glob.glob(f"{log_dir}/ids_run_*.txt")

if not log_files:
    print("[ANALYZE] No log files found. Run run_tool.py first.")
else:
    latest = max(log_files, key=os.path.getmtime)
    print(f"[ANALYZE] Reading log: {latest}\n")

    with open(latest) as f:
        content = f.read()

    alert_count = content.count("[ALERT]")
    port_scan   = content.count("PORT SCAN")
    brute_force = content.count("BRUTE FORCE")
    dos         = content.count("DoS ATTACK")

    print("="*55)
    print("  ANALYSIS RESULTS")
    print("="*55)
    print(f"  Total Alerts Detected : {alert_count}")
    print(f"  Port Scan Alerts      : {port_scan}")
    print(f"  Brute Force Alerts    : {brute_force}")
    print(f"  DoS Attack Alerts     : {dos}")
    print("="*55)

    report_path = f"logs/analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w") as f:
        f.write(f"Analysis Report — {datetime.now()}\n")
        f.write(f"Roll Number: {ROLL_NUMBER}\n")
        f.write("="*55 + "\n")
        f.write(f"Total Alerts    : {alert_count}\n")
        f.write(f"Port Scan       : {port_scan}\n")
        f.write(f"Brute Force     : {brute_force}\n")
        f.write(f"DoS Attack      : {dos}\n")

    print(f"\n[ANALYZE] Analysis report saved: {report_path}")

print(f"[ANALYZE] Done at: {datetime.now()}")
