# =============================================================================
# CyberToolkit Pro — Nmap Integration (Advanced)
# =============================================================================
# Wrapper around nmap with multiple scan profiles. Parses nmap XML output
# into structured ToolResult format.
#
# UPGRADED from original: Uses args dict instead of input(), supports
# profiles, and returns structured results.
# =============================================================================

import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "nmap_advanced",
    "category": "scanning",
    "description": "Nmap integration with multiple scan profiles and structured output",
    "author": "CyberToolkit Pro",
    "version": "2.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target IP or hostname"},
        {"name": "profile", "required": False, "default": "default",
         "description": "Scan profile: quick, default, full, stealth, vuln"},
    ],
    "tags": ["nmap", "scan", "network", "service"],
}

# Nmap scan profiles
PROFILES = {
    "quick":   "-T4 -F",
    "default": "-sC -sV -T4",
    "full":    "-sC -sV -O -T4 -p-",
    "stealth": "-sS -T2 -f",
    "vuln":    "-sV --script=vuln -T4",
    "udp":     "-sU -T4 --top-ports 100",
}


def _parse_nmap_xml(xml_path):
    """Parse nmap XML output into structured data."""
    hosts = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host_elem in root.findall("host"):
            host = {"address": "", "hostname": "", "ports": [], "os": ""}

            # Address
            addr = host_elem.find("address")
            if addr is not None:
                host["address"] = addr.get("addr", "")

            # Hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    host["hostname"] = hn.get("name", "")

            # Ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_data = {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", ""),
                        "state": "",
                        "service": "",
                        "version": "",
                    }
                    state = port_elem.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state", "")
                    service = port_elem.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "")
                        port_data["version"] = service.get("product", "") + " " + service.get("version", "")
                        port_data["version"] = port_data["version"].strip()

                    if port_data["state"] == "open":
                        host["ports"].append(port_data)

            # OS detection
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host["os"] = osmatch.get("name", "")

            hosts.append(host)
    except Exception as e:
        return [], str(e)

    return hosts, None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="nmap_advanced", status="error", error="No target specified")

    profile = args.get("profile", "default")
    nmap_flags = PROFILES.get(profile, PROFILES["default"])

    # Check if nmap is available
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ToolResult(
            tool_name="nmap_advanced",
            target=target,
            status="error",
            error="nmap is not installed or not in PATH",
        )

    # Run nmap with XML output
    xml_file = tempfile.mktemp(suffix=".xml")
    cmd = f"nmap {nmap_flags} -oX {xml_file} {target}"

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        stdout = proc.stdout
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="nmap_advanced", target=target,
            status="timeout", error="Nmap scan timed out after 300s",
        )

    # Parse results
    hosts, parse_error = _parse_nmap_xml(xml_file)

    # Cleanup temp file
    try:
        os.unlink(xml_file)
    except Exception:
        pass

    if parse_error:
        return ToolResult(
            tool_name="nmap_advanced", target=target,
            status="success",
            data={"raw_output": stdout, "parse_error": parse_error},
        )

    # Build structured output
    all_ports = []
    findings = []
    for host in hosts:
        for p in host["ports"]:
            all_ports.append(p)
            if p.get("version"):
                findings.append(Finding(
                    title=f"Service identified: {p['service']} {p['version']} on port {p['port']}",
                    severity=Severity.INFO,
                    evidence=f"Port {p['port']}/{p['protocol']}: {p['service']} {p['version']}",
                ))

    return ToolResult(
        tool_name="nmap_advanced",
        target=target,
        status="success",
        data={
            "profile": profile,
            "nmap_flags": nmap_flags,
            "hosts": hosts,
            "open_ports": all_ports,
            "open_count": len(all_ports),
        },
        findings=findings,
    )
