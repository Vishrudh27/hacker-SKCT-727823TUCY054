# Vishrudh N | 727823TUCY054
# run_tool.py — Executes the IDS tool and saves logs

import subprocess
import os
from datetime import datetime

ROLL_NUMBER = "727823TUCY054"
print(f"[RUN] Roll Number: {ROLL_NUMBER} | Timestamp: {datetime.now()}")

os.makedirs("logs", exist_ok=True)
log_file = f"logs/ids_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

print(f"[RUN] Starting IDS tool... Output will be saved to {log_file}\n")

result = subprocess.run(
    ["python", "tool_main.py"],
    capture_output=True, text=True
)

output = result.stdout + result.stderr
print(output)

with open(log_file, "w") as f:
    f.write(f"IDS Run Log — {datetime.now()}\n")
    f.write(f"Roll Number: {ROLL_NUMBER}\n")
    f.write("="*55 + "\n")
    f.write(output)

print(f"\n[RUN] Log saved to: {log_file}")
print(f"[RUN] Finished at: {datetime.now()}")
