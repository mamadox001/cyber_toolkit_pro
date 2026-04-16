# =============================================================================
# CyberToolkit Pro — Service Detector
# =============================================================================
# Active service detection via protocol probes. Sends protocol-specific
# handshakes to identify the running service and version.
# =============================================================================

import socket
from core.models import ToolResult

TOOL_INFO = {
    "name": "service_detector",
    "category": "scanning",
    "description": "Service version detection via protocol-specific probes",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target IP or hostname"},
        {"name": "ports", "required": False, "default": "21,22,25,80,110,143,443,3306,5432,8080",
         "description": "Comma-separated list of ports to probe"},
        {"name": "timeout", "required": False, "default": "3", "description": "Socket timeout in seconds"},
    ],
    "tags": ["service", "detection", "version", "probe"],
}

# Protocol probes for specific ports
PROBES = {
    "http": b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "smtp": b"EHLO probe\r\n",
    "ftp":  b"",           # FTP sends banner on connect
    "ssh":  b"",           # SSH sends banner on connect
    "pop3": b"",           # POP3 sends banner on connect
    "imap": b"",           # IMAP sends banner on connect
    "mysql": b"",          # MySQL sends handshake on connect
}

PORT_PROBES = {
    21: "ftp", 22: "ssh", 25: "smtp", 80: "http", 110: "pop3",
    143: "imap", 443: "http", 587: "smtp", 3306: "mysql",
    5432: "ftp",  # Will try generic
    8080: "http", 8443: "http",
}


def _probe_port(target, port, timeout):
    """Probe a single port and attempt service identification."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Determine which probe to send
        probe_type = PORT_PROBES.get(port, "generic")
        probe_data = PROBES.get(probe_type, b"\r\n")

        # Some services send a banner immediately on connect
        banner = ""
        try:
            if probe_data:
                sock.send(probe_data)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        sock.close()

        # Service identification heuristics
        service = "unknown"
        version = ""

        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            service = "SSH"
            version = banner.split("\n")[0] if banner else ""
        elif "ftp" in banner_lower:
            service = "FTP"
            version = banner.split("\n")[0] if banner else ""
        elif "smtp" in banner_lower or "mail" in banner_lower:
            service = "SMTP"
            version = banner.split("\n")[0] if banner else ""
        elif "http" in banner_lower:
            service = "HTTP"
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    version = line.split(":", 1)[1].strip()
                    break
        elif "mysql" in banner_lower:
            service = "MySQL"
            version = banner[:50] if banner else ""
        elif "postgresql" in banner_lower:
            service = "PostgreSQL"
        elif "pop3" in banner_lower or "+ok" in banner_lower:
            service = "POP3"
        elif "imap" in banner_lower:
            service = "IMAP"
        elif banner:
            service = "identified"
            version = banner[:100]

        return {
            "port": port,
            "state": "open",
            "service": service,
            "version": version,
            "banner": banner[:200] if banner else "",
        }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="service_detector", status="error", error="No target specified")

    ports_str = args.get("ports", "21,22,25,80,110,143,443,3306,5432,8080")
    timeout = float(args.get("timeout", 3))

    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]

    services = []
    for port in ports:
        result = _probe_port(target, port, timeout)
        if result:
            services.append(result)

    return ToolResult(
        tool_name="service_detector",
        target=target,
        status="success",
        data={
            "services": services,
            "total_probed": len(ports),
            "services_found": len(services),
        },
    )
