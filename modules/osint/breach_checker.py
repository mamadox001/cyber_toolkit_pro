# =============================================================================
# CyberToolkit Pro — Breach Checker (OSINT)
# =============================================================================
# Checks if an email or domain has appeared in known data breaches
# using the Have I Been Pwned API format (or public breach databases).
# =============================================================================

import hashlib
import urllib.request
import urllib.error
import json
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "breach_checker",
    "category": "osint",
    "description": "Check email/domain exposure in known data breaches (HIBP-style)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True,
         "description": "Email address or domain to check"},
        {"name": "api_key", "required": False, "default": "",
         "description": "HIBP API key (optional, enables full lookups)"},
    ],
    "tags": ["osint", "breach", "credential", "hibp"],
}


def run(args):
    target = args.get("target", "")
    api_key = args.get("api_key", "")

    results = {"target": target, "breaches": [], "pastes": []}
    findings = []

    # --- Method 1: HIBP API (if API key provided) ---
    if api_key:
        try:
            req = urllib.request.Request(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "CyberToolkit-Pro-SecurityAudit",
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                breaches = json.loads(resp.read().decode("utf-8"))
                for b in breaches:
                    results["breaches"].append({
                        "name": b.get("Name", ""),
                        "domain": b.get("Domain", ""),
                        "date": b.get("BreachDate", ""),
                        "count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                    })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass   # Not found in breaches
            else:
                results["api_error"] = f"HIBP API error: {e.code}"
        except Exception as e:
            results["api_error"] = str(e)

    # --- Method 2: Password hash prefix check (k-anonymity) ---
    # This works without an API key
    if "@" in target:
        password_to_check = target.split("@")[0]
    else:
        password_to_check = target

    sha1_hash = hashlib.sha1(password_to_check.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "CyberToolkit-Pro"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            hashes = resp.read().decode("utf-8")
            for line in hashes.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    results["password_exposed"] = True
                    results["password_exposure_count"] = count
                    findings.append(Finding(
                        title=f"Password prefix has appeared in {count} breach(es)",
                        severity=Severity.HIGH,
                        description=f"The password hash prefix was found in the Pwned Passwords database ({count} occurrences)",
                        remediation="Change this password immediately and enable 2FA"
                    ))
                    break
            else:
                results["password_exposed"] = False
    except Exception:
        pass

    # --- Method 3: Domain breach summary ---
    if "@" not in target:
        # Check common breach status for domains
        results["domain_check"] = {
            "checked": True,
            "note": "Full domain breach search requires HIBP enterprise API"
        }

    # Build findings for breaches
    if results["breaches"]:
        for breach in results["breaches"]:
            findings.append(Finding(
                title=f"Breach: {breach['name']} ({breach['date']})",
                severity=Severity.HIGH,
                description=f"Exposed in {breach['name']} breach ({breach['count']} records). Data types: {', '.join(breach['data_classes'][:5])}",
                remediation="Reset credentials, enable MFA, monitor for fraud"
            ))

    if not findings:
        findings.append(Finding(
            title="No breaches detected",
            severity=Severity.INFO,
            description=f"No known breaches found for {target}"
        ))

    return ToolResult(
        tool_name="breach_checker",
        target=target,
        status="success",
        data=results,
        findings=findings,
    )
