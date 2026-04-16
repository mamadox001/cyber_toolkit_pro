# =============================================================================
# CyberToolkit Pro — Social Recon (OSINT)
# =============================================================================
# Checks for the presence of a username or organization across popular
# social media and developer platforms.
# =============================================================================

import urllib.request
import urllib.error
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "social_recon",
    "category": "osint",
    "description": "Check username/org presence across social and dev platforms",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Username or organization name"},
    ],
    "tags": ["osint", "social", "reconnaissance", "username"],
}

# Platforms to check — (name, URL template, success indicator)
PLATFORMS = [
    ("GitHub", "https://github.com/{}", 200),
    ("GitLab", "https://gitlab.com/{}", 200),
    ("Twitter/X", "https://x.com/{}", 200),
    ("LinkedIn", "https://www.linkedin.com/in/{}", 200),
    ("Instagram", "https://www.instagram.com/{}/", 200),
    ("Reddit", "https://www.reddit.com/user/{}", 200),
    ("Medium", "https://medium.com/@{}", 200),
    ("YouTube", "https://www.youtube.com/@{}", 200),
    ("Pinterest", "https://www.pinterest.com/{}/", 200),
    ("TikTok", "https://www.tiktok.com/@{}", 200),
    ("Keybase", "https://keybase.io/{}", 200),
    ("HackerOne", "https://hackerone.com/{}", 200),
    ("Bugcrowd", "https://bugcrowd.com/{}", 200),
    ("Docker Hub", "https://hub.docker.com/u/{}", 200),
    ("NPM", "https://www.npmjs.com/~{}", 200),
    ("PyPI", "https://pypi.org/user/{}/", 200),
    ("Stack Overflow", "https://stackoverflow.com/users/?tab=accounts&SearchOn=displayname&Search={}", 200),
    ("Pastebin", "https://pastebin.com/u/{}", 200),
]


def run(args):
    target = args.get("target", "")



    found_profiles = []
    not_found = []
    errors = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    for platform_name, url_template, expected_code in PLATFORMS:
        url = url_template.format(target)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == expected_code:
                    found_profiles.append({
                        "platform": platform_name,
                        "url": url,
                        "status": "found",
                    })
                else:
                    not_found.append(platform_name)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                not_found.append(platform_name)
            elif e.code in (403, 429):
                errors.append({"platform": platform_name, "error": f"HTTP {e.code}"})
            else:
                not_found.append(platform_name)
        except Exception as e:
            errors.append({"platform": platform_name, "error": str(e)[:100]})

    # Build findings
    findings = []
    if found_profiles:
        findings.append(Finding(
            title=f"Found {len(found_profiles)} social profile(s) for '{target}'",
            severity=Severity.INFO,
            description="Public profiles discovered across platforms",
            evidence=", ".join(p["platform"] for p in found_profiles)
        ))

    return ToolResult(
        tool_name="social_recon",
        target=target,
        status="success",
        data={
            "username": target,
            "profiles_found": found_profiles,
            "not_found": not_found,
            "errors": errors,
            "total_checked": len(PLATFORMS),
            "total_found": len(found_profiles),
        },
        findings=findings,
    )
