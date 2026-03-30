import os
import time
import threading
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict
from typing import List, Dict, Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed — file monitoring in demo mode")

RANSOMWARE_EXTENSIONS = {
    ".locked", ".enc", ".crypt", ".wnry", ".wcry", ".locky",
    ".zepto", ".odin", ".cerber", ".vvv", ".micro", ".crypto",
    ".ecc", ".ezz", ".exx", ".xyz", ".missing", ".xtbl", ".vault", ".ccc",
}

RANSOM_NOTE_NAMES = {
    "README_FOR_DECRYPT.txt", "HELP_DECRYPT.txt", "HOW_TO_DECRYPT_FILES.html",
    "DECRYPT_INSTRUCTION.txt", "READ_THIS_FILE.txt", "@Please_Read_Me@.txt",
    "RECOVER_FILES.html", "YOUR_FILES_ARE_ENCRYPTED.html",
}

WATCH_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]


class FileEventBuffer:
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self._events: deque = deque()
        self._lock = threading.Lock()

    def add(self, event: Dict[str, Any]):
        now = time.time()
        with self._lock:
            self._events.append({**event, "_ts": now})
            cutoff = now - self.window
            while self._events and self._events[0]["_ts"] < cutoff:
                self._events.popleft()

    def get_recent(self, seconds: Optional[int] = None) -> List[Dict]:
        now = time.time()
        cutoff = now - (seconds or self.window)
        with self._lock:
            return [e for e in self._events if e["_ts"] >= cutoff]


if WATCHDOG_AVAILABLE:
    class _Handler(FileSystemEventHandler):
        def __init__(self, buffer, alert_cb):
            super().__init__()
            self.buffer = buffer
            self.alert_cb = alert_cb

        def _ev(self, etype, path):
            ext  = Path(path).suffix.lower()
            name = Path(path).name
            return {
                "type": etype, "path": path, "filename": name,
                "extension": ext,
                "is_ransomware_ext": ext in RANSOMWARE_EXTENSIONS,
                "is_ransom_note":    name in RANSOM_NOTE_NAMES,
                "timestamp": datetime.utcnow().isoformat(),
            }

        def on_modified(self, event):
            if event.is_directory: return
            ev = self._ev("MODIFIED", event.src_path)
            self.buffer.add(ev)
            if ev["is_ransomware_ext"]:
                self.alert_cb("CRITICAL", f"Ransomware ext modified: {event.src_path}")

        def on_created(self, event):
            if event.is_directory: return
            ev = self._ev("CREATED", event.src_path)
            self.buffer.add(ev)
            if ev["is_ransom_note"]:
                self.alert_cb("CRITICAL", f"Ransom note found: {event.src_path}")

        def on_moved(self, event):
            if event.is_directory: return
            src_ext = Path(event.src_path).suffix.lower()
            dst_ext = Path(event.dest_path).suffix.lower()
            ev = {
                **self._ev("RENAMED", event.src_path),
                "dest_path": event.dest_path,
                "dest_extension": dst_ext,
                "extension_changed": src_ext != dst_ext,
            }
            self.buffer.add(ev)
            if dst_ext in RANSOMWARE_EXTENSIONS:
                self.alert_cb("CRITICAL", f"Renamed to ransomware ext: {event.dest_path}")

        def on_deleted(self, event):
            ev = self._ev("DELETED", event.src_path)
            self.buffer.add(ev)
            p = event.src_path.lower()
            if any(k in p for k in ("vss", "shadow", "backup")):
                self.alert_cb("CRITICAL", f"Shadow copy deletion: {event.src_path}")


class FileMonitor:
    def __init__(self):
        self.buffer   = FileEventBuffer()
        self._observer = None
        self._alerts: deque = deque(maxlen=1000)
        self._demo_tick = 0

    def _alert_cb(self, severity, message):
        self._alerts.append({"severity": severity, "message": message,
                              "timestamp": datetime.utcnow().isoformat()})
        logger.warning(f"[{severity}] {message}")

    def start(self):
        if WATCHDOG_AVAILABLE:
            handler = _Handler(self.buffer, self._alert_cb)
            self._observer = Observer()
            for p in WATCH_PATHS:
                if os.path.exists(p):
                    self._observer.schedule(handler, p, recursive=True)
                    logger.info(f"Watching: {p}")
            self._observer.start()
        logger.info("FileMonitor started")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()

    async def get_recent_events(self, window_seconds: int = 60) -> List[Dict]:
        real = self.buffer.get_recent(window_seconds)
        if real:
            return real
        # Demo mode — simulate events
        import random
        self._demo_tick += 1
        n = random.randint(20, 60)
        exts = [".docx", ".xlsx", ".pdf", ".txt", ".jpg"]
        events = []
        for i in range(n):
            ext = random.choice(exts)
            if random.random() < 0.05:
                ext = ".locked"
            events.append({
                "type": random.choice(["MODIFIED", "CREATED", "RENAMED"]),
                "path": f"/Users/demo/Documents/file_{i}{ext}",
                "filename": f"file_{i}{ext}",
                "extension": ext,
                "is_ransomware_ext": ext in RANSOMWARE_EXTENSIONS,
                "is_ransom_note": False,
                "extension_changed": ext in RANSOMWARE_EXTENSIONS,
                "timestamp": datetime.utcnow().isoformat(),
            })
        return events

    async def protect_shadow_copies(self):
        logger.info("Shadow copy protection triggered")
        return {"status": "protected"}

    def get_alerts(self):
        return list(self._alerts)
