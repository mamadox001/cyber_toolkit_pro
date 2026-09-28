# modules/cloud/kubernetes_auditor.py
# =============================================================================
# CyberToolkit Pro — Kubernetes Manifest & RBAC Security Auditor
# =============================================================================

import os
import re
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "kubernetes_auditor",
    "category": "cloud",
    "description": "Audits Kubernetes manifests and RBAC configurations for security risks",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "YAML file or directory containing Kubernetes manifests", "arg_type": "file", "required": True},
    ],
    "tags": ["cloud", "k8s", "kubernetes", "rbac", "pods", "security"],
}

K8S_RULES = [
    {
        "pattern": r"(?i)privileged:\s*true",
        "title": "Privileged Pod Container Configured",
        "severity": Severity.CRITICAL,
        "description": "Containers with 'privileged: true' have direct access to host devices and kernel features.",
        "remediation": "Disable privileged mode and apply the Kubernetes Restricted Pod Security Standard."
    },
    {
        "pattern": r"(?i)hostPID:\s*true",
        "title": "Pod Shares Host Process ID Namespace",
        "severity": Severity.HIGH,
        "description": "hostPID allows the pod to see and interact with all processes running on the node.",
        "remediation": "Set hostPID: false."
    },
    {
        "pattern": r"(?i)hostNetwork:\s*true",
        "title": "Pod Uses Host Network Namespace",
        "severity": Severity.HIGH,
        "description": "hostNetwork allows the pod to listen on host interfaces and sniff host traffic.",
        "remediation": "Set hostNetwork: false."
    },
    {
        "pattern": r"(?i)allowPrivilegeEscalation:\s*true",
        "title": "Privilege Escalation Allowed",
        "severity": Severity.HIGH,
        "description": "allowPrivilegeEscalation allows child processes to gain more privileges than parent.",
        "remediation": "Set securityContext.allowPrivilegeEscalation: false."
    },
    {
        "pattern": r"(?i)readOnlyRootFilesystem:\s*false",
        "title": "Writable Root Filesystem",
        "severity": Severity.LOW,
        "description": "Root filesystem is writable, allowing attackers to download and execute persistence payloads.",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true."
    },
    {
        "pattern": r"(?i)runAsUser:\s*0",
        "title": "Pod Explicitly Runs As UID 0 (root)",
        "severity": Severity.HIGH,
        "description": "Container is configured to run explicitly as UID 0 (root).",
        "remediation": "Configure runAsNonRoot: true and provide a non-zero runAsUser."
    },
    {
        "pattern": r"(?i)automountServiceAccountToken:\s*true",
        "title": "Automounted Service Account Token",
        "severity": Severity.LOW,
        "description": "API service account tokens are automatically mounted inside pod filesystem.",
        "remediation": "Set automountServiceAccountToken: false unless the pod directly requires Kubernetes API access."
    }
]

def run(args: Dict[str, Any]) -> ToolResult:
    target_path = args.get("target", "").strip()
    if not target_path:
        return ToolResult(tool_name="kubernetes_auditor", status="error", error="No target specified")

    files_to_check = []
    if os.path.isfile(target_path):
        files_to_check.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.lower().endswith((".yaml", ".yml", ".json")):
                    files_to_check.append(os.path.join(root, f))
    else:
        return ToolResult(tool_name="kubernetes_auditor", status="error", error=f"Target path '{target_path}' not found")

    data = {"files_scanned": len(files_to_check), "issues_found": 0, "findings_summary": []}
    findings = []

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            for line_idx, line in enumerate(content.splitlines(), 1):
                for rule in K8S_RULES:
                    if re.search(rule["pattern"], line):
                        data["issues_found"] += 1
                        data["findings_summary"].append({
                            "file": fpath,
                            "line": line_idx,
                            "rule": rule["title"]
                        })
                        findings.append(Finding(
                            title=rule["title"],
                            severity=rule["severity"],
                            description=f"{rule['description']} in {os.path.basename(fpath)}:L{line_idx}",
                            remediation=rule["remediation"],
                            target=f"{fpath}:{line_idx}"
                        ))
        except Exception:
            pass

    return ToolResult(
        tool_name="kubernetes_auditor",
        target=target_path,
        status="success",
        data=data,
        findings=findings
    )
