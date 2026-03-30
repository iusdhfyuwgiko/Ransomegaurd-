import numpy as np
from collections import deque
from datetime import datetime
from typing import Dict, List
from dataclasses import dataclass, field
from utils.logger import get_logger

logger = get_logger(__name__)

RANSOMWARE_EXTENSIONS = {
    ".locked", ".enc", ".crypt", ".wnry", ".wcry", ".locky",
    ".zepto", ".odin", ".cerber", ".vvv", ".micro", ".crypto",
    ".ecc", ".ezz", ".exx", ".xyz", ".missing", ".xtbl", ".vault",
}

SUSPICIOUS_PROCS = {
    "vssadmin", "wbadmin", "bcdedit", "wmic", "cipher",
    "powershell", "cmd", "wscript", "cscript", "mshta",
}

SUSPICIOUS_CMDS = [
    "delete shadows", "shadowcopy delete", "resize shadowstorage",
    "bootstatuspolicy", "recoveryenabled no", "-encodedcommand",
    "downloadstring", "bypass",
]


@dataclass
class DetectionResult:
    score: float
    method: str
    label: str
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0


class RuleEngine:
    def evaluate(self, file_rate, proc_events, entropy_data, file_events) -> DetectionResult:
        score = 0.0
        indicators = []

        if file_rate >= 1000:
            score = max(score, 0.95); indicators.append(f"CRITICAL file rate: {file_rate}/min")
        elif file_rate >= 500:
            score = max(score, 0.75); indicators.append(f"HIGH file rate: {file_rate}/min")
        elif file_rate >= 200:
            score = max(score, 0.40); indicators.append(f"Elevated file rate: {file_rate}/min")

        hits = sum(1 for e in file_events if e.get("is_ransomware_ext"))
        if hits:
            score = min(1.0, score + min(hits * 0.05, 0.5))
            indicators.append(f"Ransomware extensions: {hits} files")

        notes = [e for e in file_events if e.get("is_ransom_note")]
        if notes:
            score = min(1.0, score + 0.4)
            indicators.append(f"Ransom note: {notes[0].get('filename')}")

        if entropy_data.get("high_entropy_count", 0) >= 10:
            score = min(1.0, score + 0.3)
            indicators.append(f"High entropy files: {entropy_data['high_entropy_count']}")

        for proc in proc_events:
            name = proc.get("name", "").lower().replace(".exe", "")
            cmd  = " ".join(str(c) for c in proc.get("cmdline", [])).lower()
            if name in SUSPICIOUS_PROCS:
                score = min(1.0, score + 0.15)
                indicators.append(f"Suspicious proc: {proc.get('name')} PID:{proc.get('pid')}")
            for pat in SUSPICIOUS_CMDS:
                if pat in cmd:
                    score = min(1.0, score + 0.25)
                    indicators.append(f"Shadow copy attack: {proc.get('name')}")
                    break

        renames = [e for e in file_events if e.get("type") == "RENAMED" and e.get("extension_changed")]
        if len(renames) > 50:
            score = min(1.0, score + 0.4)
            indicators.append(f"Mass rename: {len(renames)} files")

        label = (
            "CONFIRMED RANSOMWARE" if score >= 0.9 else
            "HIGH PROBABILITY"     if score >= 0.7 else
            "SUSPICIOUS"           if score >= 0.4 else
            "ANOMALOUS"            if score >= 0.2 else "CLEAN"
        )
        return DetectionResult(score=round(score, 4), method="RuleEngine", label=label,
                               indicators=indicators, confidence=min(99, int(score * 100) + 5))


class IsolationForest:
    def __init__(self):
        self.mean = np.array([50.0, 4.5, 0.02, 0.01, 3.0])
        self.std  = np.array([30.0, 0.8, 0.05, 0.02, 2.0])

    def predict(self, file_events, proc_events, entropy_data) -> DetectionResult:
        n = len(file_events) or 1
        features = np.array([
            float(n),
            float(entropy_data.get("avg_entropy", 4.5)),
            sum(1 for e in file_events if e.get("type") == "RENAMED") / n,
            sum(1 for e in file_events if e.get("type") == "DELETED") / n,
            float(len(proc_events)),
        ])
        z = np.abs((features - self.mean) / (self.std + 1e-9))
        normalized = min(1.0, float(np.max(z)) / 5.0)
        names = ["file_rate", "entropy", "rename_ratio", "delete_ratio", "proc_count"]
        indicators = [f"Anomalous {n}: {v:.1f}σ" for n, v in zip(names, z) if v > 2]
        return DetectionResult(score=round(normalized, 4), method="IsolationForest",
                               label=f"Anomaly: {normalized:.3f}", indicators=indicators,
                               confidence=min(95, int(normalized * 100)))


class AnomalyDetector:
    WEIGHTS = {"rule": 0.50, "iso": 0.30, "entropy": 0.20}

    def __init__(self):
        self.rules    = RuleEngine()
        self.iso      = IsolationForest()
        self._history: deque = deque(maxlen=500)

    async def evaluate(self, file_events, proc_events, entropy_results) -> float:
        r = self.rules.evaluate(len(file_events), proc_events, entropy_results, file_events)
        i = self.iso.predict(file_events, proc_events, entropy_results)

        high  = entropy_results.get("high_entropy_count", 0)
        total = entropy_results.get("files_analyzed", 1)
        e_score = min(1.0, high / max(total, 1) * 3)

        fused = round(min(1.0, r.score * self.WEIGHTS["rule"] +
                          i.score * self.WEIGHTS["iso"] +
                          e_score  * self.WEIGHTS["entropy"]), 4)

        self._history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "fused": fused, "rule": r.score, "iso": i.score, "entropy": e_score,
            "indicators": r.indicators + i.indicators,
        })

        if fused > 0.8: logger.critical(f"HIGH CONFIDENCE RANSOMWARE — {fused:.3f}")
        elif fused > 0.5: logger.warning(f"Anomaly detected — {fused:.3f}")

        return fused

    def get_history(self, n=60):
        return list(self._history)[-n:]
