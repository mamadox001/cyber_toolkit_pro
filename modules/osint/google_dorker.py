# =============================================================================
# CyberToolkit Pro — Google Dorker (OSINT)
# =============================================================================
# Generates Google dork queries for finding sensitive files, exposed
# admin panels, and information leaks for a target domain.
# =============================================================================

from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "google_dorker",
    "category": "osint",
    "description": "Generate Google dork queries for OSINT and vulnerability discovery",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target domain"},
        {"name": "category", "required": False, "default": "all",
         "description": "Dork category: files, admin, errors, sensitive, all"},
    ],
    "tags": ["osint", "google", "dork", "reconnaissance"],
}

DORK_CATEGORIES = {
    "files": [
        ('Exposed PDF files', 'site:{target} filetype:pdf'),
        ('Exposed Word docs', 'site:{target} filetype:doc OR filetype:docx'),
        ('Exposed Excel files', 'site:{target} filetype:xls OR filetype:xlsx'),
        ('Backup files', 'site:{target} filetype:bak OR filetype:old OR filetype:backup'),
        ('SQL dump files', 'site:{target} filetype:sql'),
        ('Log files', 'site:{target} filetype:log'),
        ('Config files', 'site:{target} filetype:conf OR filetype:cfg OR filetype:ini'),
        ('Environment files', 'site:{target} filetype:env'),
        ('Private keys', 'site:{target} filetype:pem OR filetype:key'),
        ('CSV/DB files', 'site:{target} filetype:csv OR filetype:db OR filetype:sqlite'),
    ],
    "admin": [
        ('Admin panels', 'site:{target} inurl:admin'),
        ('Login pages', 'site:{target} inurl:login OR inurl:signin'),
        ('Dashboard pages', 'site:{target} inurl:dashboard'),
        ('Control panels', 'site:{target} inurl:cpanel OR inurl:webmail'),
        ('PHPMyAdmin', 'site:{target} inurl:phpmyadmin'),
        ('WordPress admin', 'site:{target} inurl:wp-admin OR inurl:wp-login'),
        ('API endpoints', 'site:{target} inurl:api OR inurl:swagger'),
        ('Git exposed', 'site:{target} inurl:.git'),
    ],
    "errors": [
        ('SQL errors', 'site:{target} "SQL syntax" OR "mysql_fetch" OR "ORA-"'),
        ('PHP errors', 'site:{target} "Warning:" "on line" filetype:php'),
        ('Stack traces', 'site:{target} "stack trace" OR "traceback"'),
        ('Server errors', 'site:{target} "Internal Server Error" OR "500"'),
        ('Debug mode', 'site:{target} "DEBUG" "True" OR "debug=1"'),
        ('Directory listing', 'site:{target} intitle:"Index of /"'),
    ],
    "sensitive": [
        ('Passwords in URL', 'site:{target} inurl:password OR inurl:passwd'),
        ('Email addresses', 'site:{target} "@{target}" filetype:txt OR filetype:csv'),
        ('Exposed credentials', 'site:{target} "password" filetype:txt OR filetype:log'),
        ('AWS keys', 'site:{target} "AKIA" OR "aws_secret"'),
        ('API keys', 'site:{target} "api_key" OR "apikey" OR "api-key"'),
        ('Robots.txt', 'site:{target} inurl:robots.txt'),
        ('Sitemap', 'site:{target} inurl:sitemap.xml'),
        ('Crossdomain policy', 'site:{target} inurl:crossdomain.xml'),
        ('Exposed .htaccess', 'site:{target} inurl:.htaccess'),
    ],
}


def run(args):
    target = args.get("target", "")
    category = args.get("category", "all").lower()

    dorks = []
    categories_used = []

    if category == "all":
        categories_used = list(DORK_CATEGORIES.keys())
    elif category in DORK_CATEGORIES:
        categories_used = [category]
    else:
        categories_used = list(DORK_CATEGORIES.keys())

    for cat in categories_used:
        for name, template in DORK_CATEGORIES[cat]:
            query = template.format(target=target)
            search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
            dorks.append({
                "category": cat,
                "name": name,
                "query": query,
                "search_url": search_url,
            })

    findings = [
        Finding(
            title=f"Generated {len(dorks)} Google dork queries for {target}",
            severity=Severity.INFO,
            description="Review each query manually in a browser for results",
        )
    ]

    return ToolResult(
        tool_name="google_dorker",
        target=target,
        status="success",
        data={
            "domain": target,
            "dorks": dorks,
            "total": len(dorks),
            "categories": categories_used,
        },
        findings=findings,
    )
