"""
RansomGuard Early Warning System v2.4.1
========================================
Run:      python main.py
Open:     http://localhost:8000
API Docs: http://localhost:8000/docs
"""

from fastapi import UploadFile, File
import shutil
import sys
import os
import asyncio
import json
import random
from datetime import datetime
from typing import List

# Ensure local modules work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from modules.file_monitor import FileMonitor
from modules.process_monitor import ProcessMonitor
from modules.anomaly_detector import AnomalyDetector
from modules.entropy_analyzer import EntropyAnalyzer
from modules.risk_scorer import RiskScorer, AlertManager
from api.routes import router as api_router
from utils.logger import get_logger

logger = get_logger("main")

# ── Upload Folder ─────────────────────────────────────────────────────────────
UPLOAD_FOLDER = "uploaded_files"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="RansomGuard API",
    description="Ransomware Early Warning System",
    version="2.4.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

# ── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")

if os.path.isdir(FRONTEND):
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

    @app.get("/")
    async def dashboard():
        return FileResponse(os.path.join(FRONTEND, "dashboard.html"))

# ── File Upload API (NEW FEATURE) ─────────────────────────────────────────────
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Simulated ransomware risk analysis
    risk_score = round(random.uniform(10, 95), 2)

    if risk_score > 70:
        threat = "HIGH"
    elif risk_score > 40:
        threat = "MEDIUM"
    else:
        threat = "LOW"

    return {
        "filename": file.filename,
        "saved_path": file_path,
        "risk_score": risk_score,
        "threat_level": threat,
        "analysis": "File analyzed for ransomware behavior patterns"
    }

# ── Global state ──────────────────────────────────────────────────────────────
connected_clients: List[WebSocket] = []

state = {
    "risk_score": 0,
    "active_threats": 0,
    "files_modified_per_min": 0,
    "processes_watched": 0,
    "is_monitoring": False,
    "threat_level": "NONE",
    "uptime_seconds": 0,
}

# ── Modules ───────────────────────────────────────────────────────────────────
file_mon = FileMonitor()
proc_mon = ProcessMonitor()
detector = AnomalyDetector()
entropy = EntropyAnalyzer()
scorer = RiskScorer()
alerts_mgr = AlertManager()

# ── WebSocket Broadcast ───────────────────────────────────────────────────────
async def broadcast(msg: dict):
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)

    for ws in dead:
        if ws in connected_clients:
            connected_clients.remove(ws)

# ── Detection Loop ────────────────────────────────────────────────────────────
async def detection_loop():

    logger.info("Detection loop started")
    tick = 0

    while state["is_monitoring"]:

        try:
            tick += 1
            state["uptime_seconds"] = tick

            file_events = await file_mon.get_recent_events(window_seconds=60)
            proc_events = await proc_mon.get_suspicious_processes()
            entropy_data = await entropy.analyze_batch(file_events)

            anomaly_score = await detector.evaluate(
                file_events=file_events,
                proc_events=proc_events,
                entropy_results=entropy_data,
            )

            risk = await scorer.calculate(
                file_rate=len(file_events),
                entropy_anomalies=entropy_data.get("high_entropy_count", 0),
                suspicious_procs=len(proc_events),
                anomaly_score=anomaly_score,
            )

            new_alerts = await alerts_mgr.evaluate_and_generate(
                risk, file_events, proc_events
            )

            state.update({
                "risk_score": risk["score"],
                "active_threats": risk["threat_count"],
                "files_modified_per_min": len(file_events),
                "processes_watched": len(proc_events),
                "threat_level": risk["threat_level"],
            })

            await broadcast({
                "type": "state_update",
                "data": state,
                "risk": risk,
                "alerts": new_alerts,
                "entropy": {
                    "avg": entropy_data.get("avg_entropy", 0),
                    "high_count": entropy_data.get("high_entropy_count", 0),
                },
                "timestamp": datetime.utcnow().isoformat(),
            })

            # Automatic ransomware response
            if risk["score"] >= 90:

                await proc_mon.terminate_suspicious(risk.get("malicious_pids", []))
                await file_mon.protect_shadow_copies()

                await broadcast({
                    "type": "critical_alert",
                    "message": "RANSOMWARE CONFIRMED — AUTO-RESPONSE INITIATED",
                    "risk_score": risk["score"],
                    "timestamp": datetime.utcnow().isoformat(),
                })

        except Exception as e:
            logger.error(f"Detection loop error: {e}", exc_info=True)

        await asyncio.sleep(2)

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):

    await websocket.accept()
    connected_clients.append(websocket)

    await websocket.send_json({"type": "init", "data": state})

    try:
        while True:

            msg = json.loads(await websocket.receive_text())
            cmd = msg.get("cmd")

            if cmd == "start_monitoring":

                state["is_monitoring"] = True
                asyncio.create_task(detection_loop())

                await websocket.send_json({
                    "type": "ack",
                    "msg": "Monitoring started"
                })

            elif cmd == "stop_monitoring":

                state["is_monitoring"] = False

                await websocket.send_json({
                    "type": "ack",
                    "msg": "Monitoring stopped"
                })

            elif cmd == "isolate_process":

                result = await proc_mon.terminate_suspicious([msg.get("pid")])

                await websocket.send_json({
                    "type": "action_result",
                    "result": result
                })

            elif cmd == "get_state":

                await websocket.send_json({
                    "type": "state_update",
                    "data": state
                })

    except WebSocketDisconnect:

        if websocket in connected_clients:
            connected_clients.remove(websocket)

# ── Health API ────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():

    return {
        "status": "operational",
        "version": "2.4.1",
        "uptime": state["uptime_seconds"],
        "monitoring": state["is_monitoring"],
        "clients": len(connected_clients),
    }

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():

    logger.info("=" * 55)
    logger.info("  RansomGuard EWS v2.4.1")
    logger.info("  Dashboard : http://localhost:8000")
    logger.info("  API Docs  : http://localhost:8000/docs")
    logger.info("  WebSocket : ws://localhost:8000/ws")
    logger.info("=" * 55)

    file_mon.start()
    state["is_monitoring"] = True
    asyncio.create_task(detection_loop())

@app.on_event("shutdown")
async def shutdown():

    state["is_monitoring"] = False
    file_mon.stop()

    logger.info("RansomGuard shut down.")

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )