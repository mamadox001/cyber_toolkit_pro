# modules/cloud/azure_blob_checker.py
# =============================================================================
# CyberToolkit Pro — Azure Blob Storage Container Checker
# =============================================================================

import urllib.request
import urllib.error
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "azure_blob_checker",
    "category": "cloud",
    "description": "Discovers publicly accessible Azure Blob Storage containers",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target storage account name or company keyword", "arg_type": "str", "required": True},
    ],
    "tags": ["cloud", "azure", "blob", "storage", "container"],
}

CONTAINERS = [
    "public", "data", "backup", "backups", "files", "uploads",
    "media", "images", "logs", "config", "documents", "test"
]

def run(args: Dict[str, Any]) -> ToolResult:
    raw_target = args.get("target", "").strip()
    if not raw_target:
        return ToolResult(tool_name="azure_blob_checker", status="error", error="No target specified")

    account = raw_target.lower().replace("-", "").replace("_", "").split(".")[0]
    data = {
        "storage_account": account,
        "containers_tested": len(CONTAINERS),
        "public_containers": [],
        "details": []
    }
    findings = []

    for container in CONTAINERS:
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=7) as resp:
                body = resp.read(5000).decode("utf-8", errors="ignore")
                is_listable = "EnumerationResults" in body
                data["public_containers"].append(container)
                data["details"].append({
                    "container": container,
                    "url": url,
                    "status": "PUBLIC_LISTABLE" if is_listable else "ACCESSIBLE",
                    "code": resp.status
                })
                findings.append(Finding(
                    title=f"Public Azure Blob Container: {container}",
                    severity=Severity.HIGH,
                    description=f"Azure Blob container '{container}' at {url} allows anonymous public access.",
                    remediation="Set container access level to 'Private (no anonymous access)' in Azure Portal.",
                    target=url
                ))
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                pass
            else:
                data["details"].append({"container": container, "url": url, "status": f"HTTP_{e.code}", "code": e.code})
        except Exception:
            pass

    return ToolResult(
        tool_name="azure_blob_checker",
        target=raw_target,
        status="success",
        data=data,
        findings=findings
    )
