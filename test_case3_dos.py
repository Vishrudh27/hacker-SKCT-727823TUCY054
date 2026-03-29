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
print(Fore.WHITE + Style.BRIGHT +  "  [*] Module                 : DoS / Flood Detector")
print(Fore.RED   + Style.BRIGHT + "\n  ┌─────────────────────────────────────────────────────┐")
print(Fore.RED   + Style.BRIGHT + "  │   TEST CASE 3  ─  DoS / Flood Attack Detection      │")
print(Fore.RED   + Style.BRIGHT + "  └─────────────────────────────────────────────────────┘")

DOS_THRESHOLD = 10

http_logs = [
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "172.16.0.99", "method": "GET", "path": "/",      "code": 200},
    {"src_ip": "10.0.0.8",    "method": "GET", "path": "/about", "code": 200},
]

from collections import defaultdict
ip_count = defaultdict(int)

print(Fore.WHITE + "\n  Tailing Apache access log  /var/log/apache2/access.log...\n")
time.sleep(0.5)

for entry in http_logs:
    ip_count[entry["src_ip"]] += 1
    ts  = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    bar = Fore.RED + "█" * min(ip_count[entry["src_ip"]], 15) + Style.RESET_ALL
    print(Fore.CYAN  + f"  {entry['src_ip']:<16}" +
          Fore.WHITE + f" - - [{ts}] " +
          Fore.YELLOW+ f'"{entry["method"]} {entry["path"]} HTTP/1.1" ' +
          Fore.GREEN + f'{entry["code"]}  ' + bar)
    time.sleep(0.1)

print(Fore.WHITE + "\n  ─" * 28)
print(Fore.WHITE + Style.BRIGHT + "\n  [*] Analysis Result:\n")

for ip, count in ip_count.items():
    if count >= DOS_THRESHOLD:
        print(Fore.RED + Style.BRIGHT + "  ╔══════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "  ║   🚨  ALERT  ─  DoS FLOOD ATTACK DETECTED       ║")
        print(Fore.RED + Style.BRIGHT + "  ╠══════════════════════════════════════════════════╣")
        print(Fore.RED + Style.BRIGHT + f"  ║   Source IP     : {ip:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Total Requests: {count:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Threshold     : {DOS_THRESHOLD:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Target        : {'192.168.1.1:80 (HTTP)':<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Severity      : {'HIGH':<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Time          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<30}║")
        print(Fore.RED + Style.BRIGHT + "  ╚══════════════════════════════════════════════════╝")
    else:
        print(Fore.GREEN + f"  ✔  {ip}  →  Request rate normal  ({count} request)")

print(Fore.GREEN + Style.BRIGHT + "\n  [✔] Test Case 3 Complete.\n")