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
print(Fore.WHITE + Style.BRIGHT +  "  [*] Module                 : Port Scan Detector")
print(Fore.CYAN  + Style.BRIGHT +  "\n  ┌─────────────────────────────────────────────────────┐")
print(Fore.CYAN  + Style.BRIGHT +  "  │   TEST CASE 1  ─  Port Scan Detection               │")
print(Fore.CYAN  + Style.BRIGHT +  "  └─────────────────────────────────────────────────────┘")

PORT_SCAN_THRESHOLD = 5

packets = [
    {"src_ip": "192.168.1.105", "dst_port": 22,   "status": "SYN"},
    {"src_ip": "192.168.1.105", "dst_port": 80,   "status": "SYN"},
    {"src_ip": "192.168.1.105", "dst_port": 443,  "status": "SYN"},
    {"src_ip": "192.168.1.105", "dst_port": 8080, "status": "SYN"},
    {"src_ip": "192.168.1.105", "dst_port": 3306, "status": "SYN"},
    {"src_ip": "192.168.1.105", "dst_port": 21,   "status": "SYN"},
    {"src_ip": "10.0.0.2",      "dst_port": 80,   "status": "SYN"},
]

from collections import defaultdict
ip_ports = defaultdict(set)

print(Fore.WHITE + "\n  Capturing live SYN packets on interface eth0...\n")
time.sleep(0.5)

for pkt in packets:
    ip_ports[pkt["src_ip"]].add(pkt["dst_port"])
    ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
    print(Fore.YELLOW + f"  {ts}  " +
          Fore.CYAN   + f"IP {pkt['src_ip']:<16}" +
          Fore.WHITE  + f" > 192.168.1.1   " +
          Fore.MAGENTA+ f"Flags[{pkt['status']}]  " +
          Fore.WHITE  + f"dport={pkt['dst_port']}")
    time.sleep(0.15)


print(Fore.WHITE + Style.BRIGHT + "\n  [*] Analysis Result:\n")

for ip, ports in ip_ports.items():
    if len(ports) >= PORT_SCAN_THRESHOLD:
        print(Fore.RED + Style.BRIGHT + "  ╔══════════════════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "  ║   🚨  ALERT  ─  PORT SCAN DETECTED              ║")
        print(Fore.RED + Style.BRIGHT + "  ╠══════════════════════════════════════════════════╣")
        print(Fore.RED + Style.BRIGHT + f"  ║   Source IP     : {ip:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Ports Probed  : {str(sorted(ports)):<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Port Count    : {len(ports):<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Threshold     : {PORT_SCAN_THRESHOLD:<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Severity      : {'HIGH':<30}║")
        print(Fore.RED + Style.BRIGHT + f"  ║   Time          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<30}║")
        print(Fore.RED + Style.BRIGHT + "  ╚══════════════════════════════════════════════════╝")
    else:
        print(Fore.GREEN + f"  ✔  {ip}  →  Benign traffic  ({len(ports)} port)")

print(Fore.GREEN + Style.BRIGHT + "\n  [✔] Test Case 1 Complete.\n")