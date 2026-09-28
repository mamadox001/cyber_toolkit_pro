# modules/network/traceroute_mapper.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "traceroute_mapper",
    "category": "network",
    "description": "Visual network path tracing with hop analysis",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['network', 'traceroute', 'path'],
}


def run(args):

    import subprocess, re, platform
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="traceroute_mapper", status="error", error="No target specified")
    data = {"target": target, "hops": [], "total_hops": 0}
    findings = []
    try:
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-w", "2000", "-h", "30", target]
        else:
            cmd = ["traceroute", "-n", "-w", "2", "-m", "30", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output_text = result.stdout
        hop_pattern = re.compile(r"^\s*(\d+)\s+(.+)$", re.MULTILINE)
        for match in hop_pattern.finditer(output_text):
            hop_num = int(match.group(1))
            hop_data = match.group(2).strip()
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", hop_data)
            ip = ip_match.group(1) if ip_match else "*"
            times = re.findall(r"(\d+\.?\d*)\s*ms", hop_data)
            avg_ms = round(sum(float(t) for t in times) / len(times), 1) if times else 0
            data["hops"].append({"hop": hop_num, "ip": ip, "latency_ms": avg_ms, "raw": hop_data[:80]})
        data["total_hops"] = len(data["hops"])
        data["raw_output"] = output_text[:2000]
        if data["hops"]:
            findings.append(Finding(title=f"Route traced: {data['total_hops']} hops to {target}", severity=Severity.INFO))
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name="traceroute_mapper", target=target, status="timeout", error="Traceroute timed out")
    except FileNotFoundError:
        return ToolResult(tool_name="traceroute_mapper", target=target, status="error", error="traceroute/tracert not found on system")
    except Exception as e:
        return ToolResult(tool_name="traceroute_mapper", target=target, status="error", error=str(e))
    return ToolResult(tool_name="traceroute_mapper", target=target, status="success", data=data, findings=findings)

