# =============================================================================
# CyberToolkit Pro — Rogue AP Detector (Wireless Security)
# =============================================================================
# Detects potentially rogue access points by comparing observed BSSIDs
# against a known-good baseline or detecting evil twin attacks.
# =============================================================================

import os
import json
from datetime import datetime
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "rogue_ap_detector",
    "category": "wireless",
    "description": "Detect rogue access points and evil twin attacks",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "scan",
         "description": "'scan' to detect, 'baseline' to create known-good list"},
        {"name": "baseline_file", "required": False,
         "default": "config/ap_baseline.json",
         "description": "Path to known-good AP baseline file"},
    ],
    "tags": ["wireless", "rogue", "detection", "evil-twin"],
}


def run(args):
    action = args.get("target", "scan")
    baseline_file = args.get("baseline_file", "config/ap_baseline.json")

    # First, scan current networks
    from modules.wireless.wifi_scanner import run as wifi_scan
    scan_result = wifi_scan({"target": "scan"})
    current_networks = scan_result.data.get("networks", [])

    if action == "baseline":
        return _create_baseline(current_networks, baseline_file)

    return _detect_rogues(current_networks, baseline_file)


def _create_baseline(networks, baseline_file):
    """Save current networks as known-good baseline."""
    baseline = {
        "created_at": datetime.utcnow().isoformat(),
        "networks": {}
    }

    for net in networks:
        ssid = net.get("ssid", "")
        bssid = net.get("bssid", "").upper()
        if ssid and bssid:
            if ssid not in baseline["networks"]:
                baseline["networks"][ssid] = []
            baseline["networks"][ssid].append({
                "bssid": bssid,
                "security": net.get("security", ""),
                "channel": net.get("channel", ""),
            })

    os.makedirs(os.path.dirname(baseline_file) or ".", exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    return ToolResult(
        tool_name="rogue_ap_detector",
        target="baseline",
        status="success",
        data={
            "action": "baseline_created",
            "networks_saved": len(baseline["networks"]),
            "file": baseline_file,
        },
        findings=[Finding(
            title=f"Baseline saved with {len(baseline['networks'])} known SSIDs",
            severity=Severity.INFO
        )],
    )


def _detect_rogues(current_networks, baseline_file):
    """Compare current scan against baseline to detect rogues."""
    findings = []
    alerts = []

    # Load baseline
    baseline = {}
    if os.path.exists(baseline_file):
        try:
            with open(baseline_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                baseline = data.get("networks", {})
        except Exception:
            pass

    if not baseline:
        return ToolResult(
            tool_name="rogue_ap_detector",
            target="scan",
            status="warning",
            data={"error": "No baseline found. Run with target='baseline' first"},
            findings=[Finding(
                title="No AP baseline configured",
                severity=Severity.MEDIUM,
                remediation="Run: rogue_ap_detector with target='baseline'"
            )],
        )

    # Detect anomalies
    for net in current_networks:
        ssid = net.get("ssid", "")
        bssid = net.get("bssid", "").upper()
        security = net.get("security", "")

        if not ssid or ssid == "<hidden>":
            continue

        if ssid in baseline:
            known_bssids = [ap["bssid"].upper() for ap in baseline[ssid]]
            known_security = [ap.get("security", "") for ap in baseline[ssid]]

            # Check 1: Unknown BSSID for known SSID (possible evil twin)
            if bssid and bssid not in known_bssids:
                alerts.append({
                    "type": "evil_twin_suspected",
                    "ssid": ssid,
                    "bssid": bssid,
                    "known_bssids": known_bssids,
                })
                findings.append(Finding(
                    title=f"EVIL TWIN SUSPECTED: '{ssid}' from unknown BSSID {bssid}",
                    severity=Severity.CRITICAL,
                    description=f"SSID '{ssid}' seen from BSSID {bssid} which is NOT in baseline. Known: {', '.join(known_bssids)}",
                    remediation="Investigate immediately — do not connect to this network"
                ))

            # Check 2: Security downgrade
            if security and known_security and security not in known_security:
                alerts.append({
                    "type": "security_downgrade",
                    "ssid": ssid,
                    "current": security,
                    "expected": known_security[0],
                })
                findings.append(Finding(
                    title=f"Security downgrade on '{ssid}': {known_security[0]} → {security}",
                    severity=Severity.HIGH,
                    description="AP security level has changed — possible rogue AP",
                    remediation="Verify with network administrator"
                ))
        else:
            # New SSID not in baseline
            alerts.append({"type": "new_ssid", "ssid": ssid, "bssid": bssid})

    if not findings:
        findings.append(Finding(
            title="No rogue access points detected",
            severity=Severity.INFO,
            description=f"All {len(current_networks)} networks match baseline"
        ))

    return ToolResult(
        tool_name="rogue_ap_detector",
        target="scan",
        status="success",
        data={
            "networks_scanned": len(current_networks),
            "baseline_ssids": len(baseline),
            "alerts": alerts,
            "rogue_count": len([a for a in alerts if a["type"] in ("evil_twin_suspected", "security_downgrade")]),
        },
        findings=findings,
    )
