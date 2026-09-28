# modules/cloud/s3_bucket_scanner.py
# =============================================================================
# CyberToolkit Pro — AWS S3 Bucket Scanner
# =============================================================================

import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "s3_bucket_scanner",
    "category": "cloud",
    "description": "Scans for open and misconfigured Amazon S3 buckets related to target",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Target company name or domain keyword", "arg_type": "str", "required": True},
        {"name": "permutations", "description": "Check common prefixes/suffixes (true/false)", "arg_type": "bool", "default": True},
    ],
    "tags": ["cloud", "aws", "s3", "storage", "leak"],
}

PATTERNS = [
    "{target}",
    "{target}-backup",
    "{target}-backups",
    "{target}-data",
    "{target}-public",
    "{target}-dev",
    "{target}-prod",
    "{target}-staging",
    "{target}-assets",
    "{target}-files",
    "{target}-logs",
    "{target}-media",
    "{target}-internal",
    "{target}-test",
]

def run(args: Dict[str, Any]) -> ToolResult:
    raw_target = args.get("target", "").strip()
    if not raw_target:
        return ToolResult(tool_name="s3_bucket_scanner", status="error", error="No target specified")
    
    # Strip URL prefixes and extensions if domain
    clean_target = raw_target.lower()
    for prefix in ["https://", "http://", "www."]:
        if clean_target.startswith(prefix):
            clean_target = clean_target[len(prefix):]
    clean_target = clean_target.split("/")[0].split(":")[0]
    keyword = clean_target.split(".")[0]

    buckets_to_test = [p.format(target=keyword) for p in PATTERNS]
    
    data = {
        "keyword": keyword,
        "buckets_tested": len(buckets_to_test),
        "open_buckets": [],
        "protected_buckets": [],
        "details": [],
    }
    findings = []

    for bucket in buckets_to_test:
        url = f"https://{bucket}.s3.amazonaws.com/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=7) as resp:
                status_code = resp.status
                body = resp.read(10000).decode("utf-8", errors="ignore")
                
                # Check if listable
                is_listable = "ListBucketResult" in body
                data["open_buckets"].append(bucket)
                data["details"].append({
                    "bucket": bucket,
                    "url": url,
                    "status": "PUBLIC_LISTABLE" if is_listable else "PUBLIC_ACCESSIBLE",
                    "code": status_code
                })
                
                findings.append(Finding(
                    title=f"Publicly Accessible S3 Bucket Found: {bucket}",
                    severity=Severity.CRITICAL if is_listable else Severity.HIGH,
                    description=f"Bucket {bucket} ({url}) returned HTTP {status_code}. Public listing: {is_listable}.",
                    remediation="Disable public access via S3 Block Public Access settings and apply restrictive bucket policies.",
                    target=url
                ))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Exists but forbidden
                data["protected_buckets"].append(bucket)
                data["details"].append({"bucket": bucket, "url": url, "status": "EXISTS_PROTECTED", "code": 403})
            elif e.code == 404:
                # Does not exist
                pass
            else:
                data["details"].append({"bucket": bucket, "url": url, "status": f"HTTP_{e.code}", "code": e.code})
        except Exception:
            pass

    return ToolResult(
        tool_name="s3_bucket_scanner",
        target=raw_target,
        status="success",
        data=data,
        findings=findings
    )
