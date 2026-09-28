# modules/mobile/ios_plist_parser.py
# =============================================================================
# CyberToolkit Pro — iOS Info.plist & App Bundle Security Parser
# =============================================================================

import os
import plistlib
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "ios_plist_parser",
    "category": "mobile",
    "description": "Analyzes iOS Info.plist files for App Transport Security (ATS) exceptions and privacy risks",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Path to Info.plist file", "arg_type": "file", "required": True},
    ],
    "tags": ["mobile", "ios", "plist", "ats", "privacy", "security"],
}

def run(args: Dict[str, Any]) -> ToolResult:
    target_path = args.get("target", "").strip()
    if not target_path:
        return ToolResult(tool_name="ios_plist_parser", status="error", error="No target file specified")
    if not os.path.isfile(target_path):
        return ToolResult(tool_name="ios_plist_parser", status="error", error=f"File not found: {target_path}")

    findings = []
    data = {"file": target_path}

    try:
        with open(target_path, "rb") as f:
            plist_data = plistlib.load(f)
    except Exception as e:
        return ToolResult(tool_name="ios_plist_parser", target=target_path, status="error", error=f"Failed to parse plist: {e}")

    data["bundle_id"] = plist_data.get("CFBundleIdentifier", "unknown")
    data["bundle_version"] = plist_data.get("CFBundleShortVersionString", "unknown")

    # 1. ATS (App Transport Security) checks
    ats = plist_data.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads", False) is True:
        findings.append(Finding(
            title="iOS App Transport Security (ATS) Disabled",
            severity=Severity.HIGH,
            description="NSAllowsArbitraryLoads is set to YES. The app allows insecure HTTP connections across all domains.",
            remediation="Set NSAllowsArbitraryLoads to NO and enforce TLS 1.2+ across all endpoints.",
            target=target_path
        ))

    if ats.get("NSAllowsArbitraryLoadsInWebContent", False) is True:
        findings.append(Finding(
            title="Insecure Web Content Loads Allowed in WebViews",
            severity=Severity.MEDIUM,
            description="NSAllowsArbitraryLoadsInWebContent is enabled, allowing mixed HTTP/HTTPS content in WebViews.",
            remediation="Enforce HTTPS in WebViews.",
            target=target_path
        ))

    # 2. Custom URL Schemes
    url_types = plist_data.get("CFBundleURLTypes", [])
    schemes = []
    for u in url_types:
        schemes.extend(u.get("CFBundleURLSchemes", []))
    data["url_schemes"] = schemes

    return ToolResult(
        tool_name="ios_plist_parser",
        target=target_path,
        status="success",
        data=data,
        findings=findings
    )
