# =============================================================================
# CyberToolkit Pro — Advanced Port Scanner
# =============================================================================
# Multi-threaded TCP port scanner with banner grabbing. Supports custom
# port ranges, configurable thread count, and service identification.
# =============================================================================

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "port_scanner",
    "category": "scanning",
    "description": "Multi-threaded TCP port scanner with banner grabbing",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target IP or hostname"},
        {"name": "ports", "required": False, "default": "1-1024", "description": "Port range (e.g. 1-1024 or 80,443,8080)"},
        {"name": "threads", "required": False, "default": "50", "description": "Number of threads"},
        {"name": "timeout", "required": False, "default": "2", "description": "Socket timeout in seconds"},
    ],
    "tags": ["port", "scan", "tcp", "banner"],
}

# Well-known port → service map for quick identification
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "Prometheus", 27017: "MongoDB",
}


def _parse_ports(port_str):
    """Parse port range string into list of port numbers."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _scan_port(target, port, timeout):
    """Scan a single port. Returns dict with port info or None if closed."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))

        if result == 0:
            # Port is open — try banner grab
            banner = ""
            service = COMMON_SERVICES.get(port, "Unknown")
            try:
                # Send probe for banner
                if port in (80, 443, 8080, 8443):
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                else:
                    sock.send(b"\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            sock.close()
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner[:200] if banner else "",
            }
        sock.close()
        return None
    except Exception:
        return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="port_scanner", status="error", error="No target specified")

    port_str = args.get("ports", "1-1024")
    threads = int(args.get("threads", 50))
    timeout = float(args.get("timeout", 2))

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return ToolResult(tool_name="port_scanner", target=target, status="error",
                          error=f"Cannot resolve hostname: {target}")

    ports = _parse_ports(port_str)
    open_ports = []

    # Multi-threaded scan
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    # Generate findings
    findings = []
    risky_ports = {23: "Telnet", 21: "FTP (cleartext)", 135: "MSRPC", 139: "NetBIOS", 445: "SMB"}
    for p in open_ports:
        if p["port"] in risky_ports:
            findings.append(Finding(
                title=f"Risky service on port {p['port']}: {risky_ports[p['port']]}",
                severity=Severity.MEDIUM,
                description=f"Port {p['port']} ({risky_ports[p['port']]}) is open and commonly targeted",
                remediation="Close this port if not needed, or restrict access via firewall",
            ))

    return ToolResult(
        tool_name="port_scanner",
        target=target,
        status="success",
        data={
            "target_ip": ip,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
        },
        findings=findings,
    )
