# modules/osint/github_dorker.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "github_dorker",
    "category": "osint",
    "description": "Generate GitHub search dork queries for exposed secrets and credentials",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to analyze"},
    ],
    "tags": ['osint', 'github', 'secrets', 'dork'],
}


def run(args):

    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="github_dorker", status="error", error="No target specified")
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    org_name = domain.split(".")[0]
    dork_templates = [
        (f'"{domain}" password', "Exposed passwords"),
        (f'"{domain}" api_key', "Exposed API keys"),
        (f'"{domain}" secret', "Exposed secrets"),
        (f'"{domain}" token', "Exposed tokens"),
        (f'"{domain}" AWS_ACCESS_KEY', "AWS credentials"),
        (f'"{domain}" PRIVATE KEY', "Private keys"),
        (f'"{domain}" filename:.env', "Environment files"),
        (f'"{domain}" filename:config', "Configuration files"),
        (f'"{domain}" filename:credentials', "Credential files"),
        (f'"{domain}" filename:.htpasswd', "Apache password files"),
        (f'org:{org_name} password', "Org-wide password search"),
        (f'org:{org_name} filename:.env', "Org-wide env files"),
        (f'"{domain}" jdbc:', "Database connection strings"),
        (f'"{domain}" mongodb+srv:', "MongoDB connection strings"),
        (f'"{domain}" SMTP_PASSWORD', "SMTP credentials"),
        (f'"{domain}" filename:id_rsa', "SSH private keys"),
        (f'"{domain}" filename:wp-config.php', "WordPress configs"),
        (f'"{domain}" extension:sql', "SQL dumps"),
        (f'"{domain}" filename:shadow', "Shadow password files"),
        (f'"{domain}" client_secret', "OAuth client secrets"),
    ]
    dorks = []
    for query, desc in dork_templates:
        url = f"https://github.com/search?q={query.replace(' ', '+')}&type=code"
        dorks.append({"query": query, "description": desc, "url": url})
    data = {"target": domain, "dorks": dorks, "total_dorks": len(dorks)}
    findings = [Finding(title=f"Generated {len(dorks)} GitHub dork queries", severity=Severity.INFO,
        description=f"Search GitHub for exposed secrets related to {domain}")]
    return ToolResult(tool_name="github_dorker", target=domain, status="success", data=data, findings=findings)

