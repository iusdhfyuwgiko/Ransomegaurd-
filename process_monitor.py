import random
from datetime import datetime
from typing import Dict, List, Optional
from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — process monitor in demo mode")

SUSPICIOUS_PROC_NAMES = {
    "vssadmin", "wbadmin", "bcdedit", "wmic", "cipher",
    "powershell", "cmd", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin",
}

SUSPICIOUS_CMD_PATTERNS = [
    "delete shadows", "shadowcopy delete", "resize shadowstorage",
    "bootstatuspolicy", "recoveryenabled no", "-encodedcommand",
    "downloadstring", "invoke-webrequest", "bypass",
]

DEMO_PROCS = [
    {"name": "encryptor_v2.exe", "pid": 4821, "cpu_percent": 94.2,
     "risk": "CRITICAL", "cmdline": ["encryptor_v2.exe", "--all-drives", "--delete-shadows"]},
    {"name": "svchost_fake.exe", "pid": 3312, "cpu_percent": 67.1,
     "risk": "HIGH",     "cmdline": ["svchost_fake.exe", "-k", "netsvcs"]},
    {"name": "powershell.exe",   "pid": 2988, "cpu_percent": 45.0,
     "risk": "HIGH",     "cmdline": ["powershell.exe", "-enc", "JABzAD0ATgBlAHcA"]},
    {"name": "cmd.exe",          "pid": 1822, "cpu_percent": 22.3,
     "risk": "MEDIUM",   "cmdline": ["cmd.exe", "/c", "vssadmin delete shadows /all /quiet"]},
    {"name": "wscript.exe",      "pid": 941,  "cpu_percent": 12.1,
     "risk": "MEDIUM",   "cmdline": ["wscript.exe", "//B", "dropper.vbs"]},
]


class ProcessMonitor:
    def __init__(self):
        self._terminated: List[int] = []

    async def get_suspicious_processes(self) -> List[Dict]:
        if PSUTIL_AVAILABLE:
            return self._scan_real()
        return self._demo()

    def _scan_real(self) -> List[Dict]:
        found = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower().replace(".exe", "")
                    cmd  = " ".join(str(c) for c in (info.get("cmdline") or [])).lower()
                    risk = self._assess(name, cmd)
                    if risk:
                        found.append({**info, "risk": risk,
                                      "timestamp": datetime.utcnow().isoformat()})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error(f"Process scan error: {e}")
        return found

    def _demo(self) -> List[Dict]:
        return [
            {**p, "cpu_percent": round(p["cpu_percent"] + random.uniform(-3, 3), 1),
             "timestamp": datetime.utcnow().isoformat()}
            for p in DEMO_PROCS if p["pid"] not in self._terminated
        ]

    def _assess(self, name: str, cmd: str) -> Optional[str]:
        if name not in SUSPICIOUS_PROC_NAMES:
            return None
        for pat in SUSPICIOUS_CMD_PATTERNS:
            if pat in cmd:
                return "CRITICAL"
        return "MEDIUM"

    async def terminate_suspicious(self, pids: List[int]) -> Dict:
        results = {}
        for pid in pids:
            if PSUTIL_AVAILABLE:
                try:
                    psutil.Process(pid).terminate()
                    results[pid] = "TERMINATED"
                except Exception as e:
                    results[pid] = f"FAILED: {e}"
            else:
                self._terminated.append(pid)
                results[pid] = "TERMINATED (demo)"
        return {"terminated": results, "timestamp": datetime.utcnow().isoformat()}
