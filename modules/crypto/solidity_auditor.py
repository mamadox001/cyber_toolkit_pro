# =============================================================================
# CyberToolkit Pro — Smart Contract Security Static Auditor (Solidity)
# =============================================================================
# Audits Solidity smart contracts for common high-severity vulnerabilities
# including reentrancy, tx.origin authentication, unchecked call returns,
# weak randomness, and access control flaws.
# =============================================================================

import os
import re
from typing import Dict, Any, List
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "solidity_auditor",
    "category": "crypto",
    "description": "Static security analyzer for Solidity (.sol) smart contracts (reentrancy, access control, low-level calls)",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "Path to Solidity (.sol) file or directory", "arg_type": "str", "required": True},
        {"name": "code", "description": "Direct Solidity code string to audit (optional)", "arg_type": "str", "default": ""},
    ],
    "tags": ["crypto", "web3", "smart_contract", "solidity", "audit", "static_analysis"],
}


def audit_solidity_code(content: str, source_path: str = "source.sol") -> List[Finding]:
    """Audit Solidity code lines against common security rules."""
    findings = []
    lines = content.splitlines()

    # Rule 1: tx.origin authorization
    for idx, line in enumerate(lines, 1):
        if re.search(r'\btx\.origin\b', line) and not re.search(r'//.*tx\.origin', line):
            findings.append(Finding(
                title="SWC-115: Authorization through tx.origin",
                severity=Severity.HIGH,
                description=f"Line {idx}: Using 'tx.origin' for authorization allows attackers to perform phishing attacks through intermediate contracts.",
                remediation="Use 'msg.sender' instead of 'tx.origin' for authentication and authorization checks.",
                target=f"{source_path}:{idx}",
                evidence={"line": idx, "code": line.strip()}
            ))

    # Rule 2: Deprecated selfdestruct / suicide
    for idx, line in enumerate(lines, 1):
        if re.search(r'\b(selfdestruct|suicide)\s*\(', line) and not line.strip().startswith("//"):
            findings.append(Finding(
                title="SWC-106: Unprotected Selfdestruct / Suicide",
                severity=Severity.CRITICAL,
                description=f"Line {idx}: 'selfdestruct' opcode detected. If access control is missing or bypassable, anyone can destroy the contract and wipe balances.",
                remediation="Verify strict multi-signature access controls or remove selfdestruct if not strictly required.",
                target=f"{source_path}:{idx}",
                evidence={"line": idx, "code": line.strip()}
            ))

    # Rule 3: Timestamp dependency
    for idx, line in enumerate(lines, 1):
        if re.search(r'\b(block\.timestamp|now)\b', line) and not line.strip().startswith("//"):
            if any(term in line for term in ["==", ">=", "<=", "%", "random"]):
                findings.append(Finding(
                    title="SWC-116: Block Timestamp Manipulation",
                    severity=Severity.MEDIUM,
                    description=f"Line {idx}: Critical condition or randomness relies on 'block.timestamp' or 'now', which can be manipulated by miners/validators.",
                    remediation="Do not use block.timestamp for critical entropy or strict time intervals under 15 seconds.",
                    target=f"{source_path}:{idx}",
                    evidence={"line": idx, "code": line.strip()}
                ))

    # Rule 4: Unchecked low-level call
    for idx, line in enumerate(lines, 1):
        if re.search(r'\.(call|delegatecall|send)(\s*\{.*?\})?\s*\(', line) and not line.strip().startswith("//"):
            # Check if assigned to bool or in require
            is_checked = (
                "require(" in line or
                "assert(" in line or
                re.search(r'\bbool\s+\w+\s*=', line) or
                re.search(r'\(\s*bool\s+\w+', line)
            )
            if not is_checked:
                findings.append(Finding(
                    title="SWC-104: Unchecked Return Value from Low-Level Call",
                    severity=Severity.HIGH,
                    description=f"Line {idx}: Low-level call return value is not captured or checked. If the execution fails, contract state will silently continue.",
                    remediation="Always check the return value: '(bool success, ) = target.call{value: val}(\"\"); require(success, \"Call failed\");'.",
                    target=f"{source_path}:{idx}",
                    evidence={"line": idx, "code": line.strip()}
                ))

    # Rule 5: State modification after external call (Potential Reentrancy)
    external_call_seen = False
    call_line = 0
    for idx, line in enumerate(lines, 1):
        if re.search(r'\.(call|transfer|send)(\s*\{.*?\})?\s*\(', line) and not line.strip().startswith("//"):
            external_call_seen = True
            call_line = idx
        elif external_call_seen:
            # Check if state is modified (e.g. balance[x] = 0 or counter += 1)
            if re.search(r'\b\w+\s*(\[.*?\])?\s*(\+=|-=|=|\+\+|--)', line) and not any(k in line for k in ["local", "temp", "let", "bool", "uint", "address"]):
                findings.append(Finding(
                    title="SWC-107: Potential Reentrancy (State Modification After Call)",
                    severity=Severity.CRITICAL,
                    description=f"Line {idx}: State variable modified after external call at line {call_line}. An attacker can re-enter before state update.",
                    remediation="Follow the Checks-Effects-Interactions pattern: update state variables before triggering external calls, or use ReentrancyGuard.",
                    target=f"{source_path}:{idx}",
                    evidence={"call_line": call_line, "state_update_line": idx, "code": line.strip()}
                ))
                external_call_seen = False
        if line.strip() == "}":
            external_call_seen = False

    # Rule 6: Integer Overflow (pre-0.8.0 without SafeMath)
    pragma_match = re.search(r'pragma\s+solidity\s+[\^><=]*\s*0\.([0-7])\.', content)
    if pragma_match and "SafeMath" not in content:
        findings.append(Finding(
            title="SWC-101: Integer Overflow and Underflow Risk",
            severity=Severity.HIGH,
            description="Solidity versions prior to 0.8.0 do not feature built-in overflow checks. SafeMath library was not detected.",
            remediation="Upgrade to Solidity 0.8.x or utilize OpenZeppelin SafeMath for all arithmetic operations.",
            target=source_path,
            evidence={"pragma": pragma_match.group(0)}
        ))

    return findings


def run(args: Dict[str, Any]) -> ToolResult:
    target = args.get("target", "")
    code = args.get("code", "")
    findings = []
    audited_files = []

    if code:
        findings.extend(audit_solidity_code(code, "inline.sol"))
        audited_files.append("inline.sol")
    elif target:
        if os.path.isfile(target):
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings.extend(audit_solidity_code(content, target))
                audited_files.append(target)
            except Exception as e:
                return ToolResult(tool_name="solidity_auditor", status="error", error=f"Failed to read file: {e}")
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith(".sol"):
                        full_p = os.path.join(root, file)
                        try:
                            with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            findings.extend(audit_solidity_code(content, full_p))
                            audited_files.append(full_p)
                        except Exception:
                            pass
        else:
            return ToolResult(tool_name="solidity_auditor", status="error", error=f"Target path not found: {target}")

    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    return ToolResult(
        tool_name="solidity_auditor",
        status="success",
        data={
            "files_audited": len(audited_files),
            "total_findings": len(findings),
            "critical_count": crit,
            "high_count": high,
            "medium_count": med,
            "audited_paths": audited_files,
        },
        findings=findings
    )
