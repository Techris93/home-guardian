"""
Home Guardian — Network Scanner
Discovers devices on the local network using ARP ping.
"""

import subprocess
import re
import platform
import socket
import json
from typing import List, Dict, Any
from datetime import datetime

# ═══ Known device fingerprints ═══════════════════════════════════════════════

KNOWN_VENDORS = {
    "00:50:56": "VMware",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "f0:18:98": "Apple",
    "a4:83:e7": "Apple",
    "3c:22:fb": "Apple",
    "ac:bc:32": "Apple",
    "00:17:88": "Philips Hue",
    "b0:ce:18": "Google Nest",
    "f4:f5:d8": "Google",
    "30:fd:38": "Google",
    "68:54:fd": "Amazon Echo",
    "44:65:0d": "Amazon",
    "fc:65:de": "Samsung",
    "8c:79:f5": "Samsung",
    "78:02:f8": "Xiaomi",
    "50:ec:50": "TP-Link",
    "14:cc:20": "TP-Link",
}


def get_local_network() -> str:
    """Detect the local network CIDR."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 subnet
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def identify_vendor(mac: str) -> str:
    """Identify device vendor from MAC prefix."""
    prefix = mac[:8].lower()
    return KNOWN_VENDORS.get(prefix, "Unknown")


def scan_arp_table() -> List[Dict[str, Any]]:
    """Read current ARP table to find devices."""
    devices = []
    try:
        if platform.system() == "Darwin":
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
        elif platform.system() == "Linux":
            output = subprocess.run(["arp", "-n"], capture_output=True, text=True).stdout
        else:
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout

        # Parse ARP output: hostname (ip) at mac on interface
        for line in output.strip().split("\n"):
            # macOS format: hostname (10.0.1.1) at aa:bb:cc:dd:ee:ff on en0
            match = re.search(
                r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)',
                line
            )
            if not match:
                # Linux format: 10.0.1.1 ether aa:bb:cc:dd:ee:ff ...
                match = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([0-9a-fA-F:]+)',
                    line
                )

            if match:
                ip = match.group(1)
                mac = match.group(2).lower()

                if mac == "(incomplete)" or mac == "ff:ff:ff:ff:ff:ff":
                    continue

                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    hostname = ""

                vendor = identify_vendor(mac)

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "status": "active",
                })

    except Exception as e:
        print(f"[Scanner] Error: {e}")

    return devices


def quick_scan() -> Dict[str, Any]:
    """Run a quick network scan."""
    network = get_local_network()
    devices = scan_arp_table()

    return {
        "network": network,
        "devices": devices,
        "device_count": len(devices),
        "unknown_count": sum(1 for d in devices if d["vendor"] == "Unknown"),
        "scanned_at": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    print("🔍 Scanning local network...")
    result = quick_scan()
    print(f"\n📡 Network: {result['network']}")
    print(f"📱 Devices found: {result['device_count']}")
    print(f"❓ Unknown devices: {result['unknown_count']}\n")
    for d in result["devices"]:
        vendor_tag = f" ({d['vendor']})" if d['vendor'] != "Unknown" else " ⚠️ Unknown"
        print(f"  {d['ip']:16s} {d['mac']:20s}{vendor_tag}")
