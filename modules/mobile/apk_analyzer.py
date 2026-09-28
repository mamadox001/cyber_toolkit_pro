# modules/mobile/apk_analyzer.py
# =============================================================================
# CyberToolkit Pro — Android APK Static Security Analyzer
# =============================================================================

import os
import zipfile
import re
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "apk_analyzer",
    "category": "mobile",
    "description": "Performs static security analysis of Android APK packages (manifest, permissions, flags)",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Path to .apk file or AndroidManifest.xml", "arg_type": "file", "required": True},
    ],
    "tags": ["mobile", "android", "apk", "manifest", "permissions", "reversing"],
}

DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
]

def run(args: Dict[str, Any]) -> ToolResult:
    target_path = args.get("target", "").strip()
    if not target_path:
        return ToolResult(tool_name="apk_analyzer", status="error", error="No target specified")
    if not os.path.exists(target_path):
        return ToolResult(tool_name="apk_analyzer", status="error", error=f"File not found: {target_path}")

    data = {"file": target_path, "is_apk": False, "permissions": [], "findings_count": 0}
    findings = []
    manifest_content = ""

    if target_path.lower().endswith(".apk"):
        data["is_apk"] = True
        try:
            with zipfile.ZipFile(target_path, "r") as z:
                # Read AndroidManifest.xml (raw or text)
                if "AndroidManifest.xml" in z.namelist():
                    raw = z.read("AndroidManifest.xml")
                    # Extract printable strings
                    manifest_content = "".join(chr(b) if 32 <= b < 127 or b in (10, 13) else " " for b in raw)
        except Exception as e:
            return ToolResult(tool_name="apk_analyzer", target=target_path, status="error", error=f"Failed to read APK zip: {e}")
    else:
        try:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                manifest_content = f.read()
        except Exception as e:
            return ToolResult(tool_name="apk_analyzer", target=target_path, status="error", error=f"Failed to read file: {e}")

    # Check for android:debuggable="true"
    if "debuggable" in manifest_content and "true" in manifest_content:
        findings.append(Finding(
            title="Application is Debuggable (android:debuggable='true')",
            severity=Severity.HIGH,
            description="The APK is compiled with debugging enabled, allowing arbitrary code execution and memory inspection via JDWP.",
            remediation="Ensure android:debuggable='false' in release builds.",
            target=target_path
        ))

    # Check for allowBackup="true"
    if "allowBackup" in manifest_content and "false" not in manifest_content:
        findings.append(Finding(
            title="Application Backup Allowed (android:allowBackup='true')",
            severity=Severity.MEDIUM,
            description="Application data can be backed up and extracted via adb backup.",
            remediation="Set android:allowBackup='false' in AndroidManifest.xml.",
            target=target_path
        ))

    # Check for cleartext traffic
    if "usesCleartextTraffic" in manifest_content and "true" in manifest_content:
        findings.append(Finding(
            title="Cleartext HTTP Traffic Permitted",
            severity=Severity.MEDIUM,
            description="The application allows unencrypted HTTP network communication.",
            remediation="Enforce HTTPS by setting android:usesCleartextTraffic='false'.",
            target=target_path
        ))

    # Check permissions
    for perm in DANGEROUS_PERMISSIONS:
        perm_short = perm.split(".")[-1]
        if perm in manifest_content or perm_short in manifest_content:
            data["permissions"].append(perm)
            findings.append(Finding(
                title=f"Dangerous Android Permission Requested: {perm_short}",
                severity=Severity.LOW,
                description=f"App requests sensitive permission {perm}.",
                remediation="Ensure this permission follows the principle of least privilege.",
                target=target_path
            ))

    data["findings_count"] = len(findings)

    return ToolResult(
        tool_name="apk_analyzer",
        target=target_path,
        status="success",
        data=data,
        findings=findings
    )
