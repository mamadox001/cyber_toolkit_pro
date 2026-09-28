# =============================================================================
# CyberToolkit Pro — Active Defense Canary Token Generator
# =============================================================================

from typing import Dict, Any
from core.models import ToolResult, Finding, Severity
from core.canary import get_canary_manager

TOOL_INFO = {
    "name": "canary_generator",
    "category": "detection",
    "description": "Generate deceptive honeytokens (AWS keys, Git tokens, Webhooks, DB creds) for intrusion tripwires",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "token_type", "description": "Type of canary: 'http_webhook', 'aws_keys', 'git_token', 'db_credential'", "arg_type": "str", "default": "http_webhook"},
        {"name": "memo", "description": "Placement memo/label for tracking (e.g. 'Finance laptop desktop')", "arg_type": "str", "default": "Deceptive Canary"},
        {"name": "base_url", "description": "Base dashboard URL for webhooks", "arg_type": "str", "default": "http://localhost:8000"},
        {"name": "action", "description": "'generate' or 'list'", "arg_type": "str", "default": "generate"},
    ],
    "tags": ["detection", "active_defense", "canary", "honeytoken", "tripwire", "deception"],
}


def run(args: Dict[str, Any]) -> ToolResult:
    action = args.get("action", "generate").lower()
    token_type = args.get("token_type", "http_webhook").lower()
    memo = args.get("memo", "Deceptive Canary")
    base_url = args.get("base_url", "http://localhost:8000")

    manager = get_canary_manager()

    if action == "list":
        canaries = manager.list_canaries()
        return ToolResult(
            tool_name="canary_generator",
            status="success",
            data={"total_canaries": len(canaries), "canaries": canaries}
        )

    # Generate
    created = manager.generate_token(token_type=token_type, memo=memo, base_url=base_url)

    findings = [
        Finding(
            title=f"Active Defense Canary Deployed ({token_type})",
            severity=Severity.INFO,
            description=f"Canary honeytoken generated for active defense monitoring.\nMemo: {memo}\nToken ID: {created['token_id']}",
            remediation="Plant this honeytoken in your target environment. If touched by an attacker, an instant alert will fire.",
            target=memo,
            evidence=created
        )
    ]

    return ToolResult(
        tool_name="canary_generator",
        status="success",
        data={
            "token_id": created["token_id"],
            "token_type": created["token_type"],
            "memo": created["memo"],
            "created_at": created["created_at"],
            "payload": created["payload"],
            "instructions": "Place this deceptive artifact in a sensitive directory or repository. Any access triggers an immediate alert."
        },
        findings=findings
    )
