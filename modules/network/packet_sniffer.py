# =============================================================================
# CyberToolkit Pro — Packet Sniffer (Network Security)
# =============================================================================
# Captures and analyzes network packets for suspicious activity.
# Uses raw sockets on Linux or scapy when available.
# Falls back to tcpdump/tshark parsing when no capture is possible.
# =============================================================================

import os
import subprocess
import json
import re
from collections import Counter
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "packet_sniffer",
    "category": "network",
    "description": "Network packet capture and analysis for suspicious activity",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": False, "default": "capture",
         "description": "'capture' for live capture, or path to PCAP file"},
        {"name": "duration", "required": False, "default": "10",
         "description": "Capture duration in seconds"},
        {"name": "interface", "required": False, "default": "",
         "description": "Network interface to capture on"},
        {"name": "count", "required": False, "default": "100",
         "description": "Max packets to capture"},
    ],
    "tags": ["network", "sniffing", "packet", "analysis"],
}


def run(args):
    target = args.get("target", "capture")
    duration = int(args.get("duration", "10"))
    interface = args.get("interface", "")
    count = int(args.get("count", "100"))

    if target != "capture" and os.path.exists(target):
        return _analyze_pcap(target)

    return _live_capture(duration, interface, count)


def _live_capture(duration, interface, count):
    """Perform live packet capture using available tools."""
    packets = []
    method = "none"

    # Try tshark first (Wireshark CLI)
    try:
        cmd = ["tshark", "-c", str(count), "-a", f"duration:{duration}",
               "-T", "fields", "-e", "frame.number", "-e", "ip.src",
               "-e", "ip.dst", "-e", "ip.proto", "-e", "tcp.dstport",
               "-e", "udp.dstport", "-e", "frame.len", "-E", "separator=|"]
        if interface:
            cmd.extend(["-i", interface])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        for line in result.stdout.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 5:
                packets.append({
                    "num": parts[0],
                    "src": parts[1],
                    "dst": parts[2],
                    "proto": _proto_name(parts[3]),
                    "dst_port": parts[4] or parts[5] if len(parts) > 5 else "",
                    "length": parts[6] if len(parts) > 6 else "",
                })
        method = "tshark"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: tcpdump
    if not packets:
        try:
            cmd = ["tcpdump", "-c", str(count), "-nn", "-q"]
            if interface:
                cmd.extend(["-i", interface])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
            for line in result.stdout.splitlines():
                match = re.match(r'(\S+)\s+IP\s+(\S+)\s+>\s+(\S+):\s+(.+)', line)
                if match:
                    packets.append({
                        "time": match.group(1),
                        "src": match.group(2),
                        "dst": match.group(3),
                        "info": match.group(4)[:80],
                    })
            method = "tcpdump"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Fallback: netstat-based analysis (Windows/Linux)
    if not packets:
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["netstat", "-an"], capture_output=True, text=True, timeout=5
                )
            else:
                result = subprocess.run(
                    ["ss", "-tunapo"], capture_output=True, text=True, timeout=5
                )
            connections = []
            for line in result.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        "proto": parts[0],
                        "local": parts[1] if os.name != "nt" else parts[1],
                        "remote": parts[2] if os.name != "nt" else parts[2],
                        "state": parts[3] if len(parts) > 3 else "",
                    })
            packets = connections[:count]
            method = "netstat"
        except Exception:
            pass

    return _analyze_traffic(packets, method)


def _analyze_pcap(pcap_path):
    """Analyze a PCAP file."""
    packets = []
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
             "-e", "tcp.dstport", "-e", "frame.len", "-E", "separator=|"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 3:
                packets.append({
                    "src": parts[0], "dst": parts[1],
                    "proto": _proto_name(parts[2]),
                    "dst_port": parts[3] if len(parts) > 3 else "",
                    "length": parts[4] if len(parts) > 4 else "",
                })
    except Exception:
        pass

    return _analyze_traffic(packets, "pcap")


def _analyze_traffic(packets, method):
    """Analyze captured traffic for suspicious patterns."""
    findings = []

    if not packets:
        return ToolResult(
            tool_name="packet_sniffer",
            target="capture",
            status="warning",
            data={"error": f"No packets captured (method: {method}). Install tshark or tcpdump."},
            findings=[Finding(
                title="No capture tools available",
                severity=Severity.INFO,
                remediation="Install Wireshark (tshark) or tcpdump"
            )],
        )

    # Analysis
    src_ips = Counter(p.get("src", "") for p in packets if p.get("src"))
    dst_ips = Counter(p.get("dst", "") for p in packets if p.get("dst"))
    dst_ports = Counter(p.get("dst_port", "") for p in packets if p.get("dst_port"))

    # Detect port scanning (many different ports from one source)
    for src, count in src_ips.most_common(5):
        ports_from_src = set(p.get("dst_port", "") for p in packets
                            if p.get("src") == src and p.get("dst_port"))
        if len(ports_from_src) > 20:
            findings.append(Finding(
                title=f"Possible port scan from {src} ({len(ports_from_src)} unique ports)",
                severity=Severity.HIGH,
                description=f"Source {src} contacted {len(ports_from_src)} different ports",
                remediation="Investigate source IP and block if unauthorized"
            ))

    # Detect suspicious ports
    suspicious_ports = {"4444", "5555", "1234", "31337", "12345", "6667", "6666"}
    for port in dst_ports:
        if port in suspicious_ports:
            findings.append(Finding(
                title=f"Traffic on suspicious port {port}",
                severity=Severity.MEDIUM,
                description=f"Port {port} is commonly associated with backdoors/C2",
            ))

    return ToolResult(
        tool_name="packet_sniffer",
        target="capture",
        status="success",
        data={
            "method": method,
            "packet_count": len(packets),
            "top_sources": dict(src_ips.most_common(10)),
            "top_destinations": dict(dst_ips.most_common(10)),
            "top_ports": dict(dst_ports.most_common(15)),
            "sample_packets": packets[:20],
        },
        findings=findings,
    )


def _proto_name(proto_num):
    """Convert IP protocol number to name."""
    protos = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP"}
    return protos.get(str(proto_num), str(proto_num))
