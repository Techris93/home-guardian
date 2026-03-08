<p align="center">
  <h1 align="center">🏠 Home Guardian</h1>
  <p align="center"><strong>Smart Home Network Monitor</strong></p>
  <p align="center">See every device on your WiFi. Get alerts for unknown devices.</p>
</p>

---

## Features

- **📡 Network Scanning** — Discovers all devices on your local network via ARP
- **🔍 Device Identification** — Recognizes Apple, Google, Amazon, Samsung, Raspberry Pi, etc.
- **⚠️ Unknown Device Alerts** — Flags new/unrecognized devices
- **✅ Trust Management** — Mark devices as trusted with custom names
- **📊 Anomaly Detection** — Z-score based traffic monitoring (OpenSentinel engine)

## Quick Start

```bash
pip install -r requirements.txt
python server.py
```

Open **http://localhost:5051** and click **Scan Network**.

## How It Works

1. ARP scan discovers devices on your local network
2. MAC addresses are compared against known vendor prefixes
3. New/unknown devices trigger alerts
4. You can mark devices as trusted
5. Anomaly detector monitors traffic patterns for suspicious activity

## Built With

- [FastAPI](https://fastapi.tiangolo.com/) — Backend
- [OpenSentinel](https://github.com/Techris93/OpenSentinel) — Anomaly detection engine

## License

MIT
