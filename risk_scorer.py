import uuid
import time
from datetime import datetime
from typing import Dict, List, Any
from collections import deque, Counter
from utils.logger import get_logger

logger = get_logger(__name__)


class RiskScorer:
    LEVELS = {
        (90, 100): ("CRITICAL",  "#ff2d5b", ["ISOLATE_HOST", "TERMINATE_PROCS", "NOTIFY_SOC"]),
        (70,  89): ("HIGH",      "#ff7c2b", ["ALERT_SOC",   "SUSPEND_PROCS",   "BACKUP_NOW"]),
        (40,  69): ("ELEVATED",  "#ffb800", ["MONITOR",     "LOG_FULL",        "ALERT_TEAM"]),
        (10,  39): ("LOW",       "#00c8ff", ["LOG", "WATCH"]),
        ( 0,   9): ("NONE",      "#00ff9d", ["LOG"]),
    }

    def __init__(self):
        self._history: deque = deque(maxlen=1000)
        self._baseline = 50.0

    async def calculate(self, file_rate, entropy_anomalies,
                        suspicious_procs, anomaly_score,
                        shadow_copy_deleted=False) -> Dict[str, Any]:
        parts = {
            "anomaly":  round(anomaly_score * 35, 2),
            "file_rate": round(min(25, (file_rate / max(self._baseline, 1)) * 5), 2),
            "entropy":  round(min(20, entropy_anomalies * 2), 2),
            "procs":    round(min(15, suspicious_procs * 3), 2),
            "vss":      5 if shadow_copy_deleted else 0,
        }
        total = round(min(100, max(0, sum(parts.values()))), 1)
        level, color, actions = self._get_level(total)

        result = {
            "score": total, "threat_level": level, "color": color,
            "recommended_actions": actions, "breakdown": parts,
            "threat_count": max(0, int(total / 20)),
            "malicious_pids": [],
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._history.append(result)
        if total < 20:
            self._baseline = self._baseline * 0.95 + file_rate * 0.05
        return result

    def _get_level(self, score):
        for (lo, hi), val in self.LEVELS.items():
            if lo <= score <= hi:
                return val
        return "UNKNOWN", "#ffffff", []

    def get_trend(self, n=30):
        return [e["score"] for e in list(self._history)[-n:]]


class AlertManager:
    COOLDOWN = {"CRITICAL": 30, "HIGH": 60, "MEDIUM": 300, "LOW": 600}

    def __init__(self):
        self._alerts: List[Dict] = []
        self._last: Dict[str, float] = {}
        self._suppressed = 0

    async def evaluate_and_generate(self, risk, file_events, proc_events) -> List[Dict]:
        level = risk.get("threat_level", "NONE")
        if level == "NONE":
            return []
        sev = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
               "ELEVATED": "MEDIUM", "LOW": "LOW"}.get(level, "LOW")
        now = time.time()
        if now - self._last.get(sev, 0) < self.COOLDOWN.get(sev, 300):
            self._suppressed += 1
            return []
        self._last[sev] = now
        alert = {
            "id": str(uuid.uuid4()), "severity": sev,
            "description": f"{level} threat — Risk: {risk['score']}/100. "
                           f"{', '.join(risk.get('recommended_actions', []))}",
            "source": "RiskScorer", "risk_score": risk["score"],
            "recommended_actions": risk.get("recommended_actions", []),
            "file_count": len(file_events), "proc_count": len(proc_events),
            "timestamp": datetime.utcnow().isoformat(), "status": "OPEN",
        }
        self._alerts.append(alert)
        logger.warning(f"ALERT [{sev}] score={risk['score']}")
        return [alert]

    def get_all(self, limit=100):
        return sorted(self._alerts[-limit:], key=lambda x: x["timestamp"], reverse=True)

    def acknowledge(self, alert_id):
        for a in self._alerts:
            if a["id"] == alert_id:
                a["status"] = "ACKNOWLEDGED"; return True
        return False

    def resolve(self, alert_id):
        for a in self._alerts:
            if a["id"] == alert_id:
                a["status"] = "RESOLVED"
                a["resolved_at"] = datetime.utcnow().isoformat()
                return True
        return False

    def summary(self):
        return {
            "total": len(self._alerts),
            "by_severity": dict(Counter(a["severity"] for a in self._alerts)),
            "by_status":   dict(Counter(a["status"]   for a in self._alerts)),
            "suppressed":  self._suppressed,
        }
