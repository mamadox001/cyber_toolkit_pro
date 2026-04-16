# =============================================================================
# CyberToolkit Pro — ARP Spoof Detector (Network Security)
# =============================================================================
# Detects ARP spoofing attacks by analyzing the ARP table for duplicate
# MAC addresses mapped to different IPs.
# =============================================================================

import os
import re
import subprocess
from collections import defaultdict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "arp_detector",
    "category": "network",
    "description": "Detect ARP spoofing and man-in-the-middle attacks",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "detect",
         "description": "'detect' to analyze ARP table for anomalies"},
    ],
    "tags": ["network", "arp", "mitm", "detection"],
}


def run(args):
    arp_entries = _get_arp_table()
    findings = []
    alerts = []

    # Build MAC → IPs mapping
    mac_to_ips = defaultdict(list)
    ip_to_mac = {}

    for entry in arp_entries:
        mac = entry.get("mac", "").upper()
        ip = entry.get("ip", "")
        if mac and ip and mac != "FF-FF-FF-FF-FF-FF" and mac != "FF:FF:FF:FF:FF:FF":
            mac_to_ips[mac].append(ip)
            ip_to_mac[ip] = mac

    # Detection 1: Same MAC mapped to multiple IPs (ARP spoofing indicator)
    for mac, ips in mac_to_ips.items():
        unique_ips = list(set(ips))
        if len(unique_ips) > 1:
            alerts.append({
                "type": "duplicate_mac",
                "mac": mac,
                "ips": unique_ips,
            })
            findings.append(Finding(
                title=f"ARP SPOOFING SUSPECTED: MAC {mac} claims {len(unique_ips)} IPs",
                severity=Severity.CRITICAL,
                description=f"MAC address {mac} is associated with multiple IPs: {', '.join(unique_ips)}. This is a strong indicator of ARP spoofing/MitM.",
                remediation="1. Identify the real device\n2. Use static ARP entries\n3. Enable Dynamic ARP Inspection (DAI) on switches\n4. Use ARP monitoring tools"
            ))

    # Detection 2: Gateway MAC change
    gateway_ip = _get_gateway()
    if gateway_ip and gateway_ip in ip_to_mac:
        gateway_mac = ip_to_mac[gateway_ip]
        # Check if gateway IP appears with different MACs
        gateway_macs = [e.get("mac", "").upper() for e in arp_entries
                       if e.get("ip") == gateway_ip]
        if len(set(gateway_macs)) > 1:
            findings.append(Finding(
                title=f"Gateway MAC conflict detected ({gateway_ip})",
                severity=Severity.CRITICAL,
                description=f"Gateway {gateway_ip} has multiple MAC addresses: {', '.join(set(gateway_macs))}",
                remediation="Your gateway may be under ARP spoofing attack!"
            ))

    # Detection 3: Broadcast storm (many ARP entries)
    if len(arp_entries) > 200:
        findings.append(Finding(
            title=f"Unusually large ARP table ({len(arp_entries)} entries)",
            severity=Severity.MEDIUM,
            description="Could indicate ARP flooding attack",
        ))

    if not findings:
        findings.append(Finding(
            title="No ARP anomalies detected",
            severity=Severity.INFO,
            description=f"ARP table contains {len(arp_entries)} entries, all clean"
        ))

    return ToolResult(
        tool_name="arp_detector",
        target="local",
        status="success",
        data={
            "arp_entries": arp_entries[:50],
            "total_entries": len(arp_entries),
            "unique_macs": len(mac_to_ips),
            "unique_ips": len(ip_to_mac),
            "alerts": alerts,
            "gateway": gateway_ip,
        },
        findings=findings,
    )


def _get_arp_table():
    """Get ARP table entries from the system."""
    entries = []

    try:
        if os.name == "nt":
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                match = re.match(
                    r'\s*([\d.]+)\s+([\da-fA-F-]+)\s+(\w+)',
                    line
                )
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "mac": match.group(2),
                        "type": match.group(3),
                    })
        else:
            result = subprocess.run(
                ["arp", "-an"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                match = re.match(
                    r'\?\s*\(([\d.]+)\)\s+at\s+([\da-fA-F:]+)',
                    line
                )
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "mac": match.group(2),
                        "type": "dynamic",
                    })
    except Exception:
        pass

    return entries


def _get_gateway():
    """Get default gateway IP."""
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if re.match(r'\d+\.\d+\.\d+\.\d+', gw):
                        return gw
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'default via ([\d.]+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return ""
