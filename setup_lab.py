# student_name: Vishrudh N
# roll_number: 727823TUCY054
# project_name: Intrusion Detection System
# date: 2026-03-29

import time
from datetime import datetime
from colorama import init, Fore, Back, Style

init(autoreset=True)

ROLL_NUMBER = "727823TUCY054"

# ─── Thresholds ───────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 5
BRUTE_FORCE_THRESHOLD = 4
DOS_THRESHOLD         = 10

# ─── Simulated log data ───────────────────────────────────────────────────────
SIMULATED_LOGS = {
    "port_scan": [
        {"src_ip": "192.168.1.105", "dst_port": 22,   "status": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": 80,   "status": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": 443,  "status": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": 8080, "status": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": 3306, "status": "SYN"},
        {"src_ip": "192.168.1.105", "dst_port": 21,   "status": "SYN"},
        {"src_ip": "10.0.0.2",      "dst_port": 80,   "status": "SYN"},
    ],
    "brute_force": [
        {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
        {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
        {"src_ip": "192.168.1.200", "user": "root",  "status": "FAILED"},
        {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
        {"src_ip": "192.168.1.200", "user": "admin", "status": "FAILED"},
        {"src_ip": "10.0.0.5",      "user": "bob",   "status": "SUCCESS"},
    ],
    "dos": [
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "172.16.0.99", "request": "GET /"},
        {"src_ip": "10.0.0.8",    "request": "GET /about"},
    ],
}

alerts = []

# ─── Helpers ──────────────────────────────────────────────────────────────────
def banner():
    print()
    print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "  ║                                                      ║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "██╗██████╗ ███████╗" + Fore.WHITE + "   INTRUSION DETECTION   " + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "██║██╔══██╗██╔════╝" + Fore.WHITE + "        SYSTEM v1.0      " + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "██║██║  ██║███████╗" + Fore.YELLOW + "   Student : Vishrudh N  " + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "██║██║  ██║╚════██║" + Fore.YELLOW + "   Roll No : 727823TUCY054" + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "██║██████╔╝███████║" + Fore.WHITE + "                         " + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║   " + Fore.RED + Style.BRIGHT +
          "╚═╝╚═════╝ ╚══════╝" + Fore.WHITE + "                         " + Fore.CYAN + "║")
    print(Fore.CYAN + Style.BRIGHT + "  ║                                                      ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════╝")
    print()
    print(Fore.WHITE + Style.BRIGHT + f"  ► Roll Number : {Fore.YELLOW}727823TUCY054")
    print(Fore.WHITE + Style.BRIGHT + f"  ► Started At  : {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.WHITE + Style.BRIGHT +  "  ► Mode        : " + Fore.GREEN + "Simulation / Offline Analysis")
    print()

def section_header(num, title, color=Fore.CYAN):
    print()
    print(color + Style.BRIGHT + "  ┌─────────────────────────────────────────────────────┐")
    print(color + Style.BRIGHT + f"  │   TEST CASE {num}  ─  {title:<38}│")
    print(color + Style.BRIGHT + "  └─────────────────────────────────────────────────────┘")

def alert_box(msg, alert_type):
    print()
    print(Fore.RED + Style.BRIGHT + "  ╔══ 🚨 ALERT TRIGGERED " + "═" * 31 + "╗")
    print(Fore.RED + Style.BRIGHT + f"  ║  {alert_type:<54}║")
    print(Fore.RED + Style.BRIGHT + f"  ║  {msg:<54}║")
    print(Fore.RED + Style.BRIGHT + "  ╚" + "═" * 56 + "╝")
    print()

def ok_line(msg):
    print(Fore.GREEN + f"  ✔  {msg}")

# ─── Detection Functions ──────────────────────────────────────────────────────

def detect_port_scan(logs):
    section_header(1, "Port Scan Detection", Fore.BLUE)
    from collections import defaultdict
    ip_ports = defaultdict(set)

    print(Fore.WHITE + "\n  Monitoring incoming SYN packets...\n")
    for entry in logs:
        tag = Fore.YELLOW + "[PACKET]" + Style.RESET_ALL
        ip  = Fore.CYAN   + entry["src_ip"]    + Style.RESET_ALL
        prt = Fore.WHITE  + str(entry["dst_port"]) + Style.RESET_ALL
        st  = Fore.MAGENTA + entry["status"]    + Style.RESET_ALL
        print(f"  {tag}  {ip}  →  port {prt}   flag={st}")
        ip_ports[entry["src_ip"]].add(entry["dst_port"])
        time.sleep(0.12)

    print()
    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alert_box(f"  Source IP  : {ip}", "⚠  PORT SCAN DETECTED")
            print(Fore.RED + f"  ║  Ports Probed : {sorted(ports)}")
            print(Fore.RED + f"  ║  Count        : {len(ports)} ports  (threshold={PORT_SCAN_THRESHOLD})")
            alerts.append({"type": "Port Scan", "src_ip": ip,
                            "detail": str(sorted(ports)), "time": str(datetime.now())})
        else:
            ok_line(f"{ip}  →  Normal traffic  ({len(ports)} port)")


def detect_brute_force(logs):
    section_header(2, "Brute Force Login Detection", Fore.MAGENTA)
    from collections import defaultdict
    ip_fails = defaultdict(int)

    print(Fore.WHITE + "\n  Monitoring SSH / login attempts...\n")
    for entry in logs:
        tag = Fore.YELLOW + "[LOGIN] " + Style.RESET_ALL
        ip  = Fore.CYAN   + entry["src_ip"]  + Style.RESET_ALL
        usr = Fore.WHITE  + entry["user"]    + Style.RESET_ALL
        if entry["status"] == "FAILED":
            st = Fore.RED + "FAILED ✘" + Style.RESET_ALL
            ip_fails[entry["src_ip"]] += 1
        else:
            st = Fore.GREEN + "SUCCESS ✔" + Style.RESET_ALL
        print(f"  {tag}  {ip}   user={usr}   status={st}")
        time.sleep(0.12)

    print()
    for ip, count in ip_fails.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alert_box(f"  Source IP      : {ip}", "⚠  BRUTE FORCE DETECTED")
            print(Fore.RED + f"  ║  Failed Logins : {count}  (threshold={BRUTE_FORCE_THRESHOLD})")
            alerts.append({"type": "Brute Force", "src_ip": ip,
                            "detail": f"{count} failed logins", "time": str(datetime.now())})
        else:
            ok_line(f"{ip}  →  Login attempts within limit ({count})")


def detect_dos(logs):
    section_header(3, "DoS / Flood Attack Detection", Fore.RED)
    from collections import defaultdict
    ip_count = defaultdict(int)

    print(Fore.WHITE + "\n  Monitoring HTTP request flood...\n")
    for entry in logs:
        tag = Fore.YELLOW + "[HTTP]  " + Style.RESET_ALL
        ip  = Fore.CYAN   + entry["src_ip"]    + Style.RESET_ALL
        req = Fore.WHITE  + entry["request"]   + Style.RESET_ALL
        ip_count[entry["src_ip"]] += 1
        bar_len = min(ip_count[entry["src_ip"]], 20)
        bar = Fore.RED + "█" * bar_len + Style.RESET_ALL
        print(f"  {tag}  {ip}   {req}   [{bar}]")
        time.sleep(0.07)

    print()
    for ip, count in ip_count.items():
        if count >= DOS_THRESHOLD:
            alert_box(f"  Source IP   : {ip}", "⚠  DoS FLOOD DETECTED")
            print(Fore.RED + f"  ║  Requests  : {count}  (threshold={DOS_THRESHOLD})")
            alerts.append({"type": "DoS Attack", "src_ip": ip,
                            "detail": f"{count} requests", "time": str(datetime.now())})
        else:
            ok_line(f"{ip}  →  Request count normal ({count})")


def print_summary():
    print()
    print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "  ║              📋  IDS  SUMMARY  REPORT                   ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╠══════════════════════════════════════════════════════════╣")
    print(Fore.CYAN + Style.BRIGHT + f"  ║  Total Alerts Detected : " +
          Fore.RED + Style.BRIGHT + str(len(alerts)) +
          Fore.CYAN + Style.BRIGHT + "                                  ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╠═══╦══════════════╦══════════════════╦══════════════════╣")
    print(Fore.CYAN + Style.BRIGHT + "  ║ # ║  Attack Type ║   Source IP      ║  Detail          ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╠═══╬══════════════╬══════════════════╬══════════════════╣")

    for i, a in enumerate(alerts, 1):
        t  = a["type"][:12].ljust(12)
        ip = a["src_ip"][:16].ljust(16)
        d  = a["detail"][:16].ljust(16)
        print(Fore.CYAN + Style.BRIGHT +
              f"  ║ {Fore.RED}{i}{Fore.CYAN} ║ {Fore.YELLOW}{t}{Fore.CYAN} ║ {Fore.WHITE}{ip}{Fore.CYAN} ║ {Fore.WHITE}{d}{Fore.CYAN} ║")

    print(Fore.CYAN + Style.BRIGHT + "  ╠═══╩══════════════╩══════════════════╩══════════════════╣")
    print(Fore.CYAN + Style.BRIGHT + f"  ║  Completed At : " +
          Fore.YELLOW + datetime.now().strftime('%Y-%m-%d %H:%M:%S') +
          Fore.CYAN   + "                      ║")
    print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════════╝")
    print()
    print(Fore.GREEN + Style.BRIGHT + "  ✔  All test cases executed successfully.")
    print(Fore.WHITE + "  ─" * 30)
    print()


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    banner()
    detect_port_scan(SIMULATED_LOGS["port_scan"])
    detect_brute_force(SIMULATED_LOGS["brute_force"])
    detect_dos(SIMULATED_LOGS["dos"])
    print_summary()