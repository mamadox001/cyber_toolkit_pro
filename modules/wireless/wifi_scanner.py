# =============================================================================
# CyberToolkit Pro — WiFi Scanner (Wireless Security)
# =============================================================================
# Scans for nearby wireless networks and analyzes their security posture.
# Requires: netsh (Windows) or iwlist (Linux). Optional: scapy for advanced.
# =============================================================================

import os
import re
import subprocess
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "wifi_scanner",
    "category": "wireless",
    "description": "Scan nearby WiFi networks and analyze security (WPA/WEP/Open)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "scan",
         "description": "Action: 'scan' for nearby networks"},
        {"name": "interface", "required": False, "default": "",
         "description": "Network interface (auto-detect if empty)"},
    ],
    "tags": ["wireless", "wifi", "scanning", "security"],
}


def run(args):
    networks = []
    findings = []

    if os.name == "nt":
        networks = _scan_windows()
    else:
        networks = _scan_linux(args.get("interface", ""))

    # Analyze security
    open_networks = [n for n in networks if n.get("security", "").lower() in ("open", "none", "")]
    wep_networks = [n for n in networks if "wep" in n.get("security", "").lower()]
    wpa1_networks = [n for n in networks if n.get("security", "").lower() == "wpa"]
    hidden_networks = [n for n in networks if n.get("ssid", "") in ("", "<hidden>")]

    if open_networks:
        findings.append(Finding(
            title=f"Found {len(open_networks)} open (unencrypted) WiFi network(s)",
            severity=Severity.HIGH,
            description=f"Open networks: {', '.join(n.get('ssid', '?') for n in open_networks[:5])}",
            remediation="Enable WPA3/WPA2 encryption immediately"
        ))

    if wep_networks:
        findings.append(Finding(
            title=f"Found {len(wep_networks)} WEP-encrypted network(s)",
            severity=Severity.HIGH,
            description="WEP encryption is trivially breakable",
            remediation="Upgrade to WPA2/WPA3"
        ))

    if wpa1_networks:
        findings.append(Finding(
            title=f"Found {len(wpa1_networks)} WPA1-only network(s)",
            severity=Severity.MEDIUM,
            description="WPA1 (TKIP) has known vulnerabilities",
            remediation="Upgrade to WPA2-AES or WPA3"
        ))

    if hidden_networks:
        findings.append(Finding(
            title=f"Found {len(hidden_networks)} hidden SSID network(s)",
            severity=Severity.INFO,
            description="Hidden SSIDs do not provide real security"
        ))

    return ToolResult(
        tool_name="wifi_scanner",
        target="local",
        status="success",
        data={
            "networks": networks,
            "total": len(networks),
            "open": len(open_networks),
            "wep": len(wep_networks),
            "wpa2_wpa3": len(networks) - len(open_networks) - len(wep_networks) - len(wpa1_networks),
        },
        findings=findings,
    )


def _scan_windows():
    """Scan WiFi networks using netsh on Windows."""
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=15
        )

        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if current:
                    networks.append(current)
                ssid = line.split(":", 1)[1].strip() if ":" in line else ""
                current = {"ssid": ssid or "<hidden>"}
            elif "Network type" in line and ":" in line:
                current["type"] = line.split(":", 1)[1].strip()
            elif "Authentication" in line and ":" in line:
                current["security"] = line.split(":", 1)[1].strip()
            elif "Encryption" in line and ":" in line:
                current["encryption"] = line.split(":", 1)[1].strip()
            elif "BSSID" in line and ":" in line:
                # Extract MAC address (after first colon pair)
                bssid = ":".join(line.split(":")[1:]).strip()
                current["bssid"] = bssid
            elif "Signal" in line and ":" in line:
                signal = line.split(":", 1)[1].strip()
                current["signal"] = signal
            elif "Channel" in line and ":" in line:
                current["channel"] = line.split(":", 1)[1].strip()

        if current:
            networks.append(current)

    except Exception:
        pass

    return networks


def _scan_linux(interface=""):
    """Scan WiFi networks using iwlist or nmcli on Linux."""
    networks = []

    # Try nmcli first
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 5:
                networks.append({
                    "ssid": parts[0] or "<hidden>",
                    "bssid": parts[1],
                    "signal": parts[2] + "%",
                    "security": parts[3],
                    "channel": parts[4],
                })
        return networks
    except Exception:
        pass

    # Fallback to iwlist
    iface = interface or "wlan0"
    try:
        result = subprocess.run(
            ["sudo", "iwlist", iface, "scan"],
            capture_output=True, text=True, timeout=15
        )
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "Cell" in line and "Address" in line:
                if current:
                    networks.append(current)
                mac = line.split("Address:", 1)[1].strip() if "Address:" in line else ""
                current = {"bssid": mac}
            elif "ESSID:" in line:
                current["ssid"] = line.split('ESSID:"')[1].rstrip('"') if 'ESSID:"' in line else ""
            elif "Encryption key:" in line:
                current["encrypted"] = "on" in line.lower()
            elif "IE:" in line:
                current["security"] = line.split("IE:")[1].strip()

        if current:
            networks.append(current)
    except Exception:
        pass

    return networks
