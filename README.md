# 🛡️ Intrusion Detection System (IDS)

**Student:** Vishrudh N  
**Roll Number:** 727823TUCY054  
**Project Folder:** `SKCT_727823TUCY054_IntrusionDetectionSystem`  
**Date:** 2026-03-29

---

## 📌 Project Description

A Python-based Intrusion Detection System (IDS) that simulates and detects three major network attack types:

| # | Attack Type | Detection Method |
|---|-------------|-----------------|
| 1 | Port Scan | Counts unique ports probed per source IP |
| 2 | Brute Force Login | Counts failed login attempts per source IP |
| 3 | DoS / Flood Attack | Counts HTTP requests per source IP in a time window |

---

## 🚀 How to Run

```bash
# Step 1 — Install dependencies
python setup_lab.py

# Step 2 — Run the IDS tool
python tool_main.py

# Step 3 — Run the full pipeline
python run_tool.py
python analyze_results.py
```

---

## 📁 File Structure

```
SKCT_727823TUCY054_IntrusionDetectionSystem/
├── tool_main.py              ← Main IDS tool (all 3 test cases)
├── setup_lab.py              ← Stage 1: Lab setup
├── run_tool.py               ← Stage 2: Run and log tool
├── analyze_results.py        ← Stage 3: Analyze logs
├── pipeline_727823TUCY054.yml← Pipeline definition
├── requirements.txt          ← Python dependencies
├── IDS_Demo.ipynb            ← Jupyter demo notebook
└── logs/                     ← Auto-generated run logs
```

---

## 🧪 Test Cases

### Test Case 1 — Port Scan Detection
- **Input:** IP `192.168.1.105` probes 6 ports (22, 80, 443, 8080, 3306, 21)
- **Expected Output:** ALERT triggered (threshold = 5 ports)

### Test Case 2 — Brute Force Login Detection
- **Input:** IP `192.168.1.200` makes 5 failed SSH login attempts
- **Expected Output:** ALERT triggered (threshold = 4 failures)

### Test Case 3 — DoS Attack Detection
- **Input:** IP `172.16.0.99` sends 11 HTTP requests rapidly
- **Expected Output:** ALERT triggered (threshold = 10 requests)

---

## 📊 Results Summary

All 3 attacks were successfully detected. Normal traffic was correctly classified as benign.

---

## 🔗 GitHub Repository

[hacker-skct-727823TUCY054](https://github.com/YOUR_USERNAME/hacker-skct-727823TUCY054)
