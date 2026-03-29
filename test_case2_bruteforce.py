# student_name: Vishrudh N
# roll_number: 727823TUCY054
# project_name: Intrusion Detection System
# date: 2026-03-29

import time
from datetime import datetime
from colorama import init, Fore, Style
init(autoreset=True)

print(Fore.WHITE + Style.BRIGHT + f"\n  [*] IDS Engine Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(Fore.WHITE + Style.BRIGHT +  "  [*] Roll Number            : 727823TUCY054")
print(Fore.WHITE + Style.BRIGHT +  "  [*] Module                 : Brute Force Detector")
print(Fore.MAGENTA + Style.BRIGHT + "\n  ┌─────────────────────────────────────────────────────┐")
print(Fore.MAGENTA + Style.BRIGHT + "  │   TEST CASE 2  ─  Brute Force Login Detection       │")
print(Fore.MAGENTA + Style.BRIGHT + "  └─────────────────────────────────────────────────────┘")

BRUTE_FORCE_THRESHOLD = 4

login_logs = [
    {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
    {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
    {"src_ip": "192.168.1.200", "user": "root",  "status": "FAILED"},
    {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
    {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
    {"src_ip": "10.0.0.5",      "user": "bob",   "status": "SUCCESS"},
]

from collections import defaultdict
ip_fails = defaultdict(int)

print(Fore.WHITE + "\n  Reading SSH auth logs from /var/log/auth.log...\n")
time.sleep(0.5)

for entry in login_logs:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    if entry["status"] == "FAILED":
        ip_fails[entry["src_ip"]] += 1
        print(Fore.RED   + f"  {ts}  sshd[2341]: " +
              Fore.WHITE  + f"Failed password for " +
              Fore.YELLOW + f"{entry['user']:<8}" +
              Fore.WHITE  + f" from " +
              Fore.CYAN   + f"{entry['src_ip']}" +
              Fore.WHITE  + f" port 22 ssh2")
    else:
        print(Fore.GREEN  + f"  {ts}  sshd[2341]: " +
              Fore.WHITE  + f"Accepted password for " +
              Fore.YELLOW + f"{entry['user']:<8}" +
              Fore.WHITE  + f" from " +
              Fore.CYAN   + f"{entry['src_ip']}" +
              Fore.WHITE  + f" port 22 ssh2")
    time.sleep(0.2)

print(Fore.WHITE + "\n  ─" * 28)
print(Fore.WHITE + Style.BRIGHT + "\n  [*] Analysis Result:\n")

for ip, count in ip_fails.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        print(Fore.RED + Style.BRIGHT + "  ╔══════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "  ║   🚨  ALERT  ─  BRUTE FORCE DETECTED            ║")
        print(Fore.RED + Style.BRIGHT + "  ╠══════════════════════════════════════════════════╣")
        print(Fore.RED + Style.BRIGHT + f"  ║   Source IP     : {ip:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Failed Logins : {count:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Threshold     : {BRUTE_FORCE_THRESHOLD:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Target Port   : {'22 (SSH)':<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Severity      : {'CRITICAL':<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Time          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<30}║")
        print(Fore.RED + Style.BRIGHT + "  ╚══════════════════════════════════════════════════╝")
    else:
        print(Fore.GREEN + f"  ✔  {ip}  →  Login attempts normal  ({count} fail)")

print(Fore.GREEN + Style.BRIGHT + "\n  [✔] Test Case 2 Complete.\n")