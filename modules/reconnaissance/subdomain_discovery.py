# =============================================================================
# CyberToolkit Pro — Subdomain Discovery
# =============================================================================
# Wordlist-based subdomain brute force with DNS resolution. Supports
# multi-threaded resolution and custom wordlists.
# =============================================================================

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.models import ToolResult

TOOL_INFO = {
    "name": "subdomain_discovery",
    "category": "reconnaissance",
    "description": "Subdomain discovery via wordlist-based DNS brute force",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Base domain (e.g. example.com)"},
        {"name": "wordlist", "required": False, "default": "wordlists/subdomains.txt",
         "description": "Path to subdomain wordlist file"},
        {"name": "threads", "required": False, "default": "20",
         "description": "Number of threads for parallel resolution"},
    ],
    "tags": ["dns", "recon", "subdomain", "brute-force"],
}

# Built-in minimal wordlist if no file is available
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "api", "app", "beta",
    "blog", "cdn", "cloud", "cpanel", "dashboard", "db", "dev", "docs", "email",
    "git", "gitlab", "graphql", "help", "imap", "internal", "jenkins", "jira",
    "ldap", "login", "m", "manage", "media", "monitor", "mysql", "new", "news",
    "office", "old", "portal", "prod", "proxy", "redis", "remote", "repo",
    "s3", "sandbox", "search", "secure", "shop", "sip", "sso", "stage",
    "staging", "static", "status", "store", "support", "test", "testing",
    "tools", "upload", "vault", "vpn", "web", "wiki", "ws", "www2",
]


def _resolve(subdomain, domain):
    """Try to resolve a subdomain. Returns (subdomain, ip) or None."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except socket.gaierror:
        return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="subdomain_discovery", status="error", error="No target specified")

    wordlist_path = args.get("wordlist", "wordlists/subdomains.txt")
    threads = int(args.get("threads", 20))

    # Load wordlist
    subdomains = DEFAULT_SUBDOMAINS[:]
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        pass  # Use default list

    found = []

    # Multi-threaded DNS resolution
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_resolve, sub, target): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    # Sort by subdomain name
    found.sort(key=lambda x: x["subdomain"])

    return ToolResult(
        tool_name="subdomain_discovery",
        target=target,
        status="success",
        data={
            "subdomains": found,
            "total_tested": len(subdomains),
            "total_found": len(found),
        },
    )
