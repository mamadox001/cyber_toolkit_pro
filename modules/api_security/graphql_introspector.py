# modules/api_security/graphql_introspector.py
# =============================================================================
# CyberToolkit Pro — GraphQL Introspection & Schema Auditor
# =============================================================================

import urllib.request
import urllib.error
import json
from typing import Any, Dict
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "graphql_introspector",
    "category": "api_security",
    "description": "Checks for enabled GraphQL introspection and maps types, queries, and sensitive mutations",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "target", "description": "GraphQL endpoint URL or domain", "arg_type": "str", "required": True},
    ],
    "tags": ["api", "graphql", "introspection", "schema", "owasp"],
}

INTROSPECTION_QUERY = {
    "query": """
    query {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
          }
        }
      }
    }
    """
}

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/v2/graphql"]

def run(args: Dict[str, Any]) -> ToolResult:
    raw_target = args.get("target", "").strip()
    if not raw_target:
        return ToolResult(tool_name="graphql_introspector", status="error", error="No target specified")

    if not raw_target.startswith(("http://", "https://")):
        raw_target = f"http://{raw_target}"

    targets_to_test = []
    if any(raw_target.endswith(p) for p in GRAPHQL_PATHS):
        targets_to_test.append(raw_target)
    else:
        base = raw_target.rstrip("/")
        targets_to_test = [f"{base}{p}" for p in GRAPHQL_PATHS]

    data = {"endpoints_tested": len(targets_to_test), "introspection_enabled": False, "types_count": 0, "types": []}
    findings = []

    payload = json.dumps(INTROSPECTION_QUERY).encode("utf-8")

    for url in targets_to_test:
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "CyberToolkitPro"}
        )
        try:
            with urllib.request.urlopen(req, timeout=7) as resp:
                if resp.status == 200:
                    resp_body = resp.read(200000).decode("utf-8", errors="ignore")
                    res_json = json.loads(resp_body)
                    if "data" in res_json and "__schema" in res_json.get("data", {}):
                        schema = res_json["data"]["__schema"]
                        types = schema.get("types", [])
                        custom_types = [t["name"] for t in types if not t["name"].startswith("__")]

                        data["introspection_enabled"] = True
                        data["active_endpoint"] = url
                        data["types_count"] = len(custom_types)
                        data["types"] = custom_types[:30]

                        findings.append(Finding(
                            title=f"GraphQL Introspection Enabled ({url})",
                            severity=Severity.MEDIUM,
                            description=f"Introspection is enabled on {url}, exposing complete API schema including {len(custom_types)} types.",
                            remediation="Disable GraphQL introspection in production environments.",
                            target=url
                        ))
                        break
        except Exception:
            pass

    return ToolResult(
        tool_name="graphql_introspector",
        target=raw_target,
        status="success",
        data=data,
        findings=findings
    )
