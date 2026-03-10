"""
Home Guardian — Web Server
FastAPI backend for the network monitoring dashboard.
"""

import asyncio
import os
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from scanner import quick_scan
from monitor import DeviceMonitor


# Security: load API key from environment — no hardcoded default
_API_KEY = os.getenv("HOME_GUARDIAN_API_KEY")
if not _API_KEY:
    raise RuntimeError(
        "HOME_GUARDIAN_API_KEY environment variable is not set. "
        "Set it before starting the server (e.g. export HOME_GUARDIAN_API_KEY=$(openssl rand -hex 16))."
    )

MAC_PATTERN = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')

app = FastAPI(title="Home Guardian", version="1.0.0")
# CORS: localhost only — never use "*" for the management API
_cors_origins = os.getenv("HOME_GUARDIAN_CORS_ORIGINS", "http://localhost:5051").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)

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
async def trust_device(
    req: TrustRequest,
    x_home_guardian_key: Optional[str] = Header(None)
):
    """Mark a device as trusted. Requires API key authentication."""
    # Auth check
    if not x_home_guardian_key or x_home_guardian_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Validate MAC address format (prevent injection / spoofed MACs)
    if not MAC_PATTERN.match(req.mac):
        raise HTTPException(status_code=422, detail="Invalid MAC address format")
    # Sanitise optional name field
    safe_name = (req.name or "Unnamed Device")[:64]
    monitor.register_device(req.mac, {
        "name": safe_name,
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
    # Bind to 127.0.0.1 only — never expose on all interfaces without a reverse proxy
    uvicorn.run(app, host="127.0.0.1", port=5051)
