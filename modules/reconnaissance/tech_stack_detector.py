# modules/reconnaissance/tech_stack_detector.py
# =============================================================================
# CyberToolkit Pro — Technology Stack Detector
# =============================================================================
# Fingerprints web technologies: CMS, WAF, CDN, frameworks, and server info.
# =============================================================================

import urllib.request
import urllib.error
import re
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "tech_stack_detector",
    "category": "reconnaissance",
    "description": "Detect WAF, CDN, CMS, and web framework technologies",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target URL or hostname"},
    ],
    "tags": ["recon", "fingerprint", "waf", "cms", "cdn"],
}

# WAF detection signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "awselb", "x-amz-cf-id"],
    "Akamai": ["x-akamai", "akamai"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva": ["incapsula", "x-iinfo", "visid_incap"],
    "Barracuda": ["barra_counter_session"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Fortinet": ["fortigate", "fortiwaF"],
    "Citrix NetScaler": ["ns_af", "citrix_ns_id"],
}

# CMS detection patterns
CMS_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"/xmlrpc\.php"],
    "Joomla": [r"/media/jui/", r"joomla", r"/administrator/"],
    "Drupal": [r"drupal", r"/sites/default/files/", r"Drupal"],
    "Magento": [r"magento", r"/skin/frontend/", r"mage/"],
    "Shopify": [r"shopify", r"cdn\.shopify\.com"],
    "Ghost": [r"ghost", r"ghost-api"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Express": [r"x-powered-by.*express"],
    "Next.js": [r"_next/", r"__NEXT_DATA__"],
    "React": [r"react", r"__REACT"],
    "Angular": [r"ng-version", r"angular"],
    "Vue.js": [r"vue", r"__vue__"],
}

# CDN detection
CDN_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Fastly": ["x-served-by", "x-cache", "fastly"],
    "Akamai": ["x-akamai-transformed"],
    "KeyCDN": ["x-edge-location"],
    "StackPath": ["x-sp-"],
    "Bunny CDN": ["bunnycdn"],
}


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="tech_stack_detector", status="error", error="No target specified")

    # Ensure URL format
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    findings = []
    data = {
        "target": target,
        "technologies": [],
        "waf_detected": [],
        "cdn_detected": [],
        "cms_detected": [],
        "server_info": {},
        "frameworks": [],
    }

    try:
        req = urllib.request.Request(target, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(100000).decode("utf-8", errors="replace")

            # Server info
            if "server" in headers:
                data["server_info"]["server"] = headers["server"]
                data["technologies"].append(f"Server: {headers['server']}")
            if "x-powered-by" in headers:
                data["server_info"]["x-powered-by"] = headers["x-powered-by"]
                data["technologies"].append(f"Powered by: {headers['x-powered-by']}")
                findings.append(Finding(
                    title=f"Technology exposed: {headers['x-powered-by']}",
                    severity=Severity.LOW,
                    description="X-Powered-By header reveals backend technology",
                    remediation="Remove X-Powered-By header from responses"
                ))

            # WAF detection
            all_header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in all_header_text:
                        data["waf_detected"].append(waf_name)
                        data["technologies"].append(f"WAF: {waf_name}")
                        break

            # CDN detection
            for cdn_name, sigs in CDN_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in all_header_text:
                        data["cdn_detected"].append(cdn_name)
                        data["technologies"].append(f"CDN: {cdn_name}")
                        break

            # CMS detection
            for cms_name, patterns in CMS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, all_header_text, re.IGNORECASE):
                        data["cms_detected"].append(cms_name)
                        data["technologies"].append(f"CMS/Framework: {cms_name}")
                        break

            # Remove duplicates
            data["technologies"] = list(set(data["technologies"]))
            data["waf_detected"] = list(set(data["waf_detected"]))
            data["cdn_detected"] = list(set(data["cdn_detected"]))
            data["cms_detected"] = list(set(data["cms_detected"]))

            if not data["waf_detected"]:
                findings.append(Finding(
                    title="No WAF detected",
                    severity=Severity.MEDIUM,
                    description="No Web Application Firewall was detected protecting this target",
                    remediation="Consider deploying a WAF (Cloudflare, AWS WAF, etc.)"
                ))

    except urllib.error.URLError as e:
        return ToolResult(tool_name="tech_stack_detector", target=target, status="error", error=str(e))
    except Exception as e:
        return ToolResult(tool_name="tech_stack_detector", target=target, status="error", error=str(e))

    return ToolResult(
        tool_name="tech_stack_detector", target=target,
        status="success", data=data, findings=findings
    )
