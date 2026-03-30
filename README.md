# 🛡️ RansomGuard — Ransomware Early Warning System

## ▶️ How to Run

### Windows
```
Double-click run.bat
```

### Linux / Mac
```bash
bash run.sh
```

### Manual (VS Code Terminal)
```bash
cd backend
pip install -r requirements.txt
python main.py
```

Then open → **http://localhost:8000**

---

## 📁 Project Structure

```
RansomGuard/
├── run.bat                  ← Windows one-click start
├── run.sh                   ← Linux/Mac one-click start
├── README.md
│
├── frontend/
│   └── dashboard.html       ← Full UI dashboard
│
└── backend/
    ├── main.py              ← FastAPI server (entry point)
    ├── requirements.txt
    │
    ├── api/
    │   ├── __init__.py
    │   └── routes.py        ← REST API endpoints
    │
    ├── modules/
    │   ├── __init__.py
    │   ├── file_monitor.py      ← Filesystem watcher
    │   ├── process_monitor.py   ← Process scanner
    │   ├── anomaly_detector.py  ← ML ensemble detection
    │   ├── entropy_analyzer.py  ← Shannon entropy analysis
    │   └── risk_scorer.py       ← Risk scoring + AlertManager
    │
    └── utils/
        ├── __init__.py
        └── logger.py
```

---

## 🔍 Detection Layers

| Layer | Method | Detects |
|-------|--------|---------|
| Rule Engine | Signature-based | Ransomware extensions, ransom notes, VSS deletion |
| Entropy Analysis | Shannon entropy | Encrypted files (>7.5 bits/byte) |
| Isolation Forest | ML anomaly | Behavioral deviations from baseline |
| Process Monitor | System scan | Suspicious processes, shadow copy attacks |

## 🚦 Risk Score (0–100)

| Score | Level | Action |
|-------|-------|--------|
| 90–100 | 🔴 CRITICAL | Auto-isolate + kill processes |
| 70–89  | 🟠 HIGH     | Alert SOC, suspend processes |
| 40–69  | 🟡 ELEVATED | Monitor + full logging |
| 10–39  | 🔵 LOW      | Log and watch |
| 0–9    | 🟢 NONE     | Normal |
