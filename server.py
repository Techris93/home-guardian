"""
Home Guardian — Web Server
FastAPI backend for the network monitoring dashboard.
"""

import asyncio
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from scanner import quick_scan
from monitor import DeviceMonitor


app = FastAPI(title="Home Guardian", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

monitor = DeviceMonitor()
monitor.load_state()


class TrustRequest(BaseModel):
    mac: str
    name: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/scan")
async def scan_network():
    """Scan the network and return discovered devices."""
    result = quick_scan()

    # Check each device against monitor
    alerts = []
    for device in result["devices"]:
        device_alerts = monitor.check_device(device)
        alerts.extend(device_alerts)

    result["alerts"] = alerts
    result["known_devices"] = list(monitor.known_devices.keys())
    monitor.save_state()
    return result


@app.post("/api/trust")
async def trust_device(req: TrustRequest):
    """Mark a device as trusted."""
    monitor.register_device(req.mac, {
        "name": req.name or "Unnamed Device",
        "mac": req.mac,
    })
    monitor.save_state()
    return {"status": "trusted", "mac": req.mac}


@app.get("/api/alerts")
async def get_alerts():
    """Get recent alerts."""
    return {
        "alerts": monitor.alerts[-50:],
        "total": len(monitor.alerts),
    }


@app.get("/api/status")
async def get_status():
    """Get monitor status."""
    return monitor.get_device_status()


@app.get("/api/health")
async def health():
    return {"status": "online", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    print("\n🏠 Home Guardian — Smart Network Monitor")
    print(f"   Dashboard:  http://localhost:5051")
    print(f"   API Docs:   http://localhost:5051/docs\n")
    uvicorn.run(app, host="0.0.0.0", port=5051)
