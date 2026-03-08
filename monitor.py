"""
Home Guardian — Traffic Anomaly Monitor
Z-score based anomaly detection on network device behavior.
Reuses the pattern from OpenSentinel's anomaly_detector.py.
"""

import math
import json
import os
from typing import Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime


# ═══ Configuration ═══════════════════════════════════════════════════════════

Z_THRESHOLD = 2.5
MIN_SAMPLES = 5
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


class DeviceMonitor:
    """Tracks per-device metrics and flags anomalies."""

    def __init__(self, z_threshold: float = Z_THRESHOLD):
        self.z_threshold = z_threshold
        self.device_history: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.alerts: List[Dict] = []
        self.known_devices: Dict[str, Dict] = {}

    def register_device(self, mac: str, info: Dict):
        """Register a known/trusted device."""
        self.known_devices[mac] = {
            **info,
            "trusted": True,
            "registered_at": datetime.now().isoformat(),
        }

    def check_device(self, device: Dict) -> List[Dict]:
        """Check a device for anomalies and new device alerts."""
        mac = device.get("mac", "")
        alerts = []

        # Alert on new/unknown devices
        if mac not in self.known_devices:
            alert = {
                "type": "new_device",
                "severity": "warning",
                "device": device,
                "message": f"New device detected: {device.get('ip')} "
                           f"({device.get('vendor', 'Unknown')})",
                "timestamp": datetime.now().isoformat(),
            }
            alerts.append(alert)
            self.alerts.append(alert)

        return alerts

    def add_metric(self, mac: str, metric_name: str, value: float) -> Optional[Dict]:
        """Add a metric value and check for anomaly."""
        history = self.device_history[mac][metric_name]
        history.append(value)

        if len(history) < MIN_SAMPLES:
            return None

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance) if variance > 0 else 0.001
        z_score = (value - mean) / std_dev

        if abs(z_score) > self.z_threshold:
            alert = {
                "type": "anomaly",
                "severity": "high" if abs(z_score) > 4 else "medium",
                "device_mac": mac,
                "metric": metric_name,
                "value": value,
                "expected_mean": round(mean, 2),
                "z_score": round(z_score, 2),
                "message": f"Anomalous {metric_name}: {value} "
                           f"(expected ~{mean:.0f}, z={z_score:.1f})",
                "timestamp": datetime.now().isoformat(),
            }
            self.alerts.append(alert)
            return alert

        return None

    def get_device_status(self) -> Dict[str, Any]:
        """Get overview of all monitored devices."""
        return {
            "total_known": len(self.known_devices),
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-20:],
            "devices": {
                mac: {
                    "info": info,
                    "metrics": dict(self.device_history.get(mac, {})),
                }
                for mac, info in self.known_devices.items()
            },
        }

    def save_state(self):
        """Persist known devices and alerts."""
        os.makedirs(DATA_DIR, exist_ok=True)
        state = {
            "known_devices": self.known_devices,
            "alerts": self.alerts[-100:],  # keep last 100
            "saved_at": datetime.now().isoformat(),
        }
        with open(os.path.join(DATA_DIR, "monitor_state.json"), "w") as f:
            json.dump(state, f, indent=2)

    def load_state(self):
        """Load persisted state."""
        state_file = os.path.join(DATA_DIR, "monitor_state.json")
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                state = json.load(f)
                self.known_devices = state.get("known_devices", {})
                self.alerts = state.get("alerts", [])
