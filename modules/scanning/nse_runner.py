# =============================================================================
# CyberToolkit Pro — Nmap NSE Script Runner
# =============================================================================
# Execute Nmap Scripting Engine scripts against targets with structured
# output parsing. Supports script categories and custom arguments.
# =============================================================================

import subprocess
import re
import os
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "nse_runner",
    "category": "scanning",
    "description": "Nmap NSE script execution with vulnerability detection",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target host or IP"},
        {"name": "scripts", "required": False, "default": "vuln",
         "description": "NSE scripts/categories (e.g. vuln, auth, default, http-*)"},
        {"name": "ports", "required": False, "default": "80,443,22,21,25,3306,8080",
         "description": "Ports to scan"},
        {"name": "script_args", "required": False, "default": "",
         "description": "Script arguments (key=value pairs)"},
    ],
    "tags": ["scanning", "nmap", "nse", "vulnerability"],
}

# Popular NSE script categories and their risk levels
SCRIPT_SEVERITY = {
    "vuln": Severity.HIGH,
    "exploit": Severity.CRITICAL,
    "auth": Severity.HIGH,
    "brute": Severity.MEDIUM,
    "discovery": Severity.INFO,
    "default": Severity.INFO,
    "safe": Severity.INFO,
}

# Individual script severity mappings
VULN_SCRIPTS = {
    "ssl-heartbleed": Severity.CRITICAL,
    "smb-vuln-ms17-010": Severity.CRITICAL,
    "smb-vuln-ms08-067": Severity.CRITICAL,
    "http-shellshock": Severity.CRITICAL,
    "ssl-poodle": Severity.HIGH,
    "ssl-ccs-injection": Severity.HIGH,
    "http-sql-injection": Severity.HIGH,
    "http-xssed": Severity.HIGH,
    "ftp-anon": Severity.MEDIUM,
    "http-methods": Severity.MEDIUM,
    "ssh-auth-methods": Severity.INFO,
    "ssl-cert": Severity.INFO,
    "ssl-enum-ciphers": Severity.INFO,
    "http-headers": Severity.INFO,
    "http-title": Severity.INFO,
}


def run(args):
    target = args.get("target", "")
    scripts = args.get("scripts", "vuln")
    ports = args.get("ports", "80,443,22,21,25,3306,8080")
    script_args = args.get("script_args", "")

    # Build nmap command
    cmd = [
        "nmap", "-sV", "--script", scripts,
        "-p", ports, "--open",
        "-oN", "-",  # Normal output to stdout
        target
    ]

    if script_args:
        cmd.extend(["--script-args", script_args])

    # Execute nmap
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        output = result.stdout
        stderr = result.stderr
    except FileNotFoundError:
        return ToolResult(
            tool_name="nse_runner", target=target, status="error",
            error="Nmap is not installed. Install from https://nmap.org",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool_name="nse_runner", target=target, status="timeout",
            error="Nmap scan timed out after 120 seconds",
        )

    # Parse results
    script_results = _parse_nse_output(output)
    findings = _generate_findings(script_results, scripts)

    return ToolResult(
        tool_name="nse_runner",
        target=target,
        status="success",
        data={
            "target": target,
            "scripts": scripts,
            "ports_scanned": ports,
            "script_results": script_results,
            "total_scripts_run": len(script_results),
            "vulnerabilities_found": len([f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]),
        },
        findings=findings,
    )


def _parse_nse_output(output):
    """Parse NSE script output from nmap."""
    results = []
    current_port = ""
    current_script = ""
    current_output = []

    for line in output.splitlines():
        # Detect port line
        port_match = re.match(r'(\d+/\w+)\s+open\s+(\S+)', line)
        if port_match:
            current_port = port_match.group(1)
            continue

        # Detect script output start
        script_match = re.match(r'\|\s*(\S+):\s*(.*)', line)
        if script_match:
            # Save previous script
            if current_script:
                results.append({
                    "port": current_port,
                    "script": current_script,
                    "output": "\n".join(current_output),
                })

            current_script = script_match.group(1).rstrip(":")
            current_output = [script_match.group(2)] if script_match.group(2) else []
            continue

        # Script output continuation
        cont_match = re.match(r'\|\s*(.*)', line)
        if cont_match and current_script:
            current_output.append(cont_match.group(1))
            continue

        # End of script block
        if line.startswith("|_") and current_script:
            content = line[2:].strip()
            if content:
                current_output.append(content)
            results.append({
                "port": current_port,
                "script": current_script,
                "output": "\n".join(current_output),
            })
            current_script = ""
            current_output = []

    # Save last script
    if current_script:
        results.append({
            "port": current_port,
            "script": current_script,
            "output": "\n".join(current_output),
        })

    return results


def _generate_findings(script_results, category):
    """Generate findings from parsed NSE results."""
    findings = []
    default_sev = SCRIPT_SEVERITY.get(category, Severity.INFO)

    for result in script_results:
        script = result["script"]
        output = result["output"]
        port = result["port"]

        # Determine severity
        severity = VULN_SCRIPTS.get(script, default_sev)

        # Check for vulnerability indicators
        is_vuln = any(keyword in output.lower() for keyword in
                      ["vulnerable", "exploitable", "risk", "weak", "insecure",
                       "anonymous", "allowed", "state: vulnerable"])

        if is_vuln:
            severity = max(severity, Severity.HIGH, key=lambda s: ["info", "low", "medium", "high", "critical"].index(s.value))

        title = f"[{port}] {script}"
        if is_vuln:
            title = f"VULN: {title}"

        findings.append(Finding(
            title=title,
            severity=severity,
            description=output[:500],
            evidence=f"Port: {port}\nScript: {script}",
        ))

    return findings
