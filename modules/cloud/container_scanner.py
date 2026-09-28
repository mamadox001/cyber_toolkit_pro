# modules/cloud/container_scanner.py
# =============================================================================
# CyberToolkit Pro — Container Security & Misconfiguration Scanner
# =============================================================================

import os
import re
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "container_scanner",
    "category": "cloud",
    "description": "Audits Dockerfiles, docker-compose files, and container configs for security flaws",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Path to Dockerfile or directory containing container configs", "arg_type": "file", "required": True},
    ],
    "tags": ["cloud", "docker", "container", "devops", "security"],
}

RULES = [
    {
        "pattern": r"(?i)^\s*USER\s+root",
        "title": "Container runs explicitly as root",
        "severity": Severity.HIGH,
        "description": "Running containers as root weakens isolation and increases container breakout risk.",
        "remediation": "Create and switch to a non-privileged user using 'USER nonroot'."
    },
    {
        "pattern": r"(?i)^\s*FROM\s+[^:\r\n]+:latest",
        "title": "Use of ':latest' tag in base image",
        "severity": Severity.LOW,
        "description": "Using :latest image tags can lead to non-deterministic builds and untested vulnerabilities.",
        "remediation": "Pin base images to specific immutable tags or SHA256 digests."
    },
    {
        "pattern": r"(?i)^\s*ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN|APIKEY|API_KEY)\s*=",
        "title": "Hardcoded secret in container environment variables",
        "severity": Severity.HIGH,
        "description": "Environment variables containing credentials remain visible in image layers and inspection.",
        "remediation": "Use Docker secrets or inject credentials at runtime using secret managers."
    },
    {
        "pattern": r"(?i)(privileged:\s*true|--privileged)",
        "title": "Privileged container flag enabled",
        "severity": Severity.CRITICAL,
        "description": "Privileged containers share almost all host capabilities, allowing trivial host escape.",
        "remediation": "Remove privileged flag and only grant specifically required capabilities."
    },
    {
        "pattern": r'(?i)network_mode:\s*["\']?host',
        "title": "Host network namespace sharing",
        "severity": Severity.HIGH,
        "description": "Sharing host network bypasses network isolation between containers and host.",
        "remediation": "Use isolated bridge or overlay networks."
    },
    {
        "pattern": r'(?i)volumes:\s*(\r?\n)?\s*-\s*["\']?(/|/var/run/docker\.sock)',
        "title": "Host root or Docker socket mounted into container",
        "severity": Severity.CRITICAL,
        "description": "Mounting the Docker socket inside a container allows full root access to the host daemon.",
        "remediation": "Do not mount /var/run/docker.sock into containers."
    }
]

def run(args: Dict[str, Any]) -> ToolResult:
    target_path = args.get("target", "").strip()
    if not target_path:
        return ToolResult(tool_name="container_scanner", status="error", error="No target file or directory specified")

    files_to_check = []
    if os.path.isfile(target_path):
        files_to_check.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower() in ("dockerfile", "docker-compose.yml", "docker-compose.yaml") or f.lower().endswith((".dockerfile", ".docker")):
                    files_to_check.append(os.path.join(root, f))
    else:
        return ToolResult(tool_name="container_scanner", status="error", error=f"Target path '{target_path}' not found")

    data = {"files_scanned": len(files_to_check), "violations": []}
    findings = []

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            has_user = False
            for line_idx, line in enumerate(content.splitlines(), 1):
                if re.match(r"(?i)^\s*USER\s+", line) and not re.match(r"(?i)^\s*USER\s+root", line):
                    has_user = True

                for rule in RULES:
                    if re.search(rule["pattern"], line):
                        violation = {
                            "file": fpath,
                            "line": line_idx,
                            "rule": rule["title"],
                            "severity": rule["severity"].value
                        }
                        data["violations"].append(violation)
                        findings.append(Finding(
                            title=rule["title"],
                            severity=rule["severity"],
                            description=f"{rule['description']} (Found in {os.path.basename(fpath)}:L{line_idx})",
                            remediation=rule["remediation"],
                            target=f"{fpath}:{line_idx}"
                        ))
            
            # If Dockerfile has no USER instruction at all
            if "dockerfile" in os.path.basename(fpath).lower() and not has_user:
                findings.append(Finding(
                    title="Dockerfile lacks non-root USER declaration",
                    severity=Severity.MEDIUM,
                    description=f"{os.path.basename(fpath)} never declares a non-root USER, defaulting to root execution.",
                    remediation="Add 'USER nonroot' or another non-privileged user before ENTRYPOINT/CMD.",
                    target=fpath
                ))
        except Exception as e:
            data["violations"].append({"file": fpath, "error": str(e)})

    return ToolResult(
        tool_name="container_scanner",
        target=target_path,
        status="success",
        data=data,
        findings=findings
    )
