# CyberToolkit Pro v2.5

**Professional Cybersecurity Framework — Offensive & Defensive Security Toolkit**

A modular, extensible framework for penetration testing, security assessment, and blue team operations. Inspired by Metasploit, Burp Suite, and lightweight SIEM architectures.

> **76 tools** · **17 categories** · **Plugin architecture** · **SQLite database** · **Web dashboard** · **CI/CD ready**

---

## ⚡ Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run interactive shell
python main.py

# Run a specific tool
python main.py run scanning.port_scanner --target 10.10.10.10

# Run a pipeline
python main.py pipeline quick_scan --target example.com

# List all tools
python main.py list

# Start web dashboard
pip install fastapi uvicorn
python main.py dashboard

# Launch Hacker TUI
python main.py tui

# Run tests
python -m pytest tests/ -v
```

---

## 🏗️ Architecture

```
cyber_toolkit_pro/
├── main.py                    # CLI entry point (argparse)
├── core/                      # Framework engine
│   ├── cli.py                 # Interactive shell
│   ├── config.py              # YAML configuration
│   ├── executor.py            # Tool execution + scope/audit/DB integration
│   ├── async_executor.py      # Async execution engine (asyncio)
│   ├── loader.py              # Auto-discovery module loader
│   ├── logger.py              # Structured logging
│   ├── models.py              # Data models (ToolResult, Finding, etc.)
│   ├── output.py              # Console formatting + colors
│   ├── pipeline.py            # Workflow chaining engine
│   ├── registry.py            # Tool registry
│   ├── suggester.py           # AI reasoning engine
│   ├── scope.py               # Target scope enforcement
│   ├── vault.py               # Encrypted credential vault
│   ├── audit.py               # Immutable audit trail
│   ├── database.py            # SQLite persistent storage
│   ├── campaign.py            # Multi-target campaign engine
│   ├── differ.py              # Attack surface differential engine
│   ├── notifier.py            # Multi-channel alerts (Slack/Discord/Telegram/Email)
│   ├── scheduler.py           # Scan scheduling engine
│   ├── threat_intel.py        # Threat intel (VirusTotal, AbuseIPDB, Shodan)
│   ├── stix_exporter.py       # STIX 2.1 threat intelligence export
│   ├── plugin_manager.py      # Remote plugin install/update/list
│   └── tui.py                 # Textual terminal UI
├── modules/                   # Tool modules (auto-discovered)
│   ├── reconnaissance/        # DNS, WHOIS, subdomain, tech stack, CT logs, ASN
│   ├── scanning/              # Port scanner, nmap, service detection, NSE
│   ├── web/                   # Dir brute, SQLi, XSS, SSRF, CORS, CRLF, CSRF, cmd inj
│   ├── exploitation/          # Reverse shell, payloads, exploit runner
│   ├── passwords/             # Wordlist attack, hash cracker, cred checker
│   ├── detection/             # Anomaly detector, IP tracker, alert system
│   ├── log_analysis/          # Auth/web log parsers, SSH brute detection
│   ├── forensics/             # File analyzer, string extractor, YARA, timeline
│   ├── siem/                  # Log aggregation, search, alert generation
│   ├── osint/                 # Email harvest, social recon, breach, dorking, wayback
│   ├── network/               # Packet sniffer, ARP detector, DNS monitor, traceroute
│   ├── wireless/              # WiFi scanner, rogue AP detector
│   ├── cloud/                 # S3 buckets, Azure blob, metadata, container, k8s
│   ├── crypto/                # SSL/TLS audit, certificates, JWT analysis, weak crypto
│   ├── api_security/          # API fuzzing, BOLA/BFLA, rate limiting, GraphQL
│   ├── mobile/                # Android APK analysis, iOS Info.plist parser
│   └── reporting/             # JSON, HTML, executive, compliance, PDF reports
├── plugins/                   # Drop-in plugin system
├── config/                    # YAML configs + pipeline profiles + scope
├── wordlists/                 # Brute force wordlists
├── dashboard/                 # FastAPI web dashboard
├── tests/                     # pytest test suite
├── data/                      # SQLite database (auto-created)
├── logs/audit/                # Immutable audit trail (JSONL)
├── .github/workflows/ci.yml   # GitHub Actions CI
└── Dockerfile                 # Container support
```

---

## 🔴 Red Team Tools (17 modules)

| Category | Tool | Description |
|----------|------|-------------|
| Recon | `dns_lookup` | DNS A/MX/NS/TXT + SPF/DMARC analysis |
| Recon | `subdomain_discovery` | Multi-threaded subdomain brute force |
| Recon | `whois_lookup` | Socket-based WHOIS with referral |
| Recon | `http_fingerprint` | Security headers + tech detection |
| Scanning | `port_scanner` | 50-thread TCP scanner + banner grab |
| Scanning | `nmap_advanced` | 6 nmap profiles + XML parsing |
| Scanning | `service_detector` | Protocol-specific service probes |
| Scanning | `nse_runner` | Nmap NSE vulnerability script execution |
| Web | `dir_bruteforce` | Directory discovery + sensitive paths |
| Web | `http_fuzzer` | Parameter fuzzing with FUZZ marker |
| Web | `sqli_tester` | Safe SQLi detection (25+ error patterns) |
| Web | `xss_tester` | Reflected XSS detection (14 payloads) |
| Exploit | `reverse_shell` | Multi-session reverse shell handler |
| Exploit | `payload_generator` | 9 payload types across 6 languages |
| Exploit | `exploit_runner` | Modular exploit framework |
| Passwords | `wordlist_attack` | HTTP/FTP dictionary attack |
| Passwords | `hash_cracker` | MD5/SHA1/SHA256 auto-detect cracker |
| Passwords | `credential_checker` | Cross-service credential reuse |

## 🔵 Blue Team Tools (12 modules)

| Category | Tool | Description |
|----------|------|-------------|
| Detection | `anomaly_detector` | Threshold-based anomaly detection |
| Detection | `suspicious_ip_tracker` | IP watchlist + frequency tracking |
| Detection | `alert_system` | Rule-based security alerting |
| Log Analysis | `auth_log_parser` | auth.log SSH/brute-force parsing |
| Log Analysis | `web_log_parser` | Apache/Nginx attack detection |
| Log Analysis | `ssh_bruteforce_detector` | Attacker profiling |
| Forensics | `file_analyzer` | Multi-hash + entropy + magic bytes |
| Forensics | `string_extractor` | Binary strings + suspicious patterns |
| Forensics | `file_type_detector` | Extension mismatch detection |
| SIEM | `log_aggregator` | Multi-source log normalization |
| SIEM | `log_search` | Regex-based log search |
| SIEM | `alert_generator` | 6 detection rules + JSON export |

## 🌐 OSINT Tools (4 modules)

| Tool | Description |
|------|-------------|
| `email_harvester` | Scrape emails from web pages, DNS, common prefixes |
| `social_recon` | Check username across 18 social/dev platforms |
| `breach_checker` | HIBP API + k-anonymity password hash checking |
| `google_dorker` | Generate 35+ Google dork queries (files, admin, errors) |

## 📡 Network Security (3 modules)

| Tool | Description |
|------|-------------|
| `packet_sniffer` | Capture & analyze traffic (tshark/tcpdump/netstat) |
| `arp_detector` | ARP spoofing & MitM detection |
| `dns_monitor` | DNS tunneling, DGA, and poisoning detection |

## 📶 Wireless Security (2 modules)

| Tool | Description |
|------|-------------|
| `wifi_scanner` | Scan WiFi networks, analyze encryption (Windows/Linux) |
| `rogue_ap_detector` | Evil twin & rogue AP detection with baseline comparison |

## 📊 Reporting (4 modules)

| Tool | Description |
|------|-------------|
| `json_report` | Structured JSON with severity scoring |
| `html_report` | Dark-themed HTML with stat cards |
| `executive_report` | Non-technical executive summary (HTML) |
| `compliance_report` | PCI-DSS, HIPAA, SOC2, OWASP mapping |

---

## 🛡️ Security Features (v2.5)

### Target Scope Enforcement
```yaml
# config/scope.yaml
scope:
  enabled: true
  allowed_ips:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  allowed_domains:
    - "*.example.com"
  excluded_domains:
    - "*.gov"
```

### Encrypted Credential Vault
```python
from core.vault import get_vault
vault = get_vault()
vault.store("api_key", "sk-abc123", category="api")
vault.retrieve("api_key")  # → "sk-abc123"
```

### Immutable Audit Trail
Every tool execution is logged to `logs/audit/audit_YYYYMMDD.jsonl` with:
- Timestamp, operator, tool, target, arguments
- Result hash for integrity verification
- Sensitive argument redaction (passwords → `***REDACTED***`)

### SQLite Database
All scan results, findings, and targets are persisted in `data/cybertoolkit.db`:
```python
from core.database import get_db
db = get_db()
db.get_dashboard_stats()     # Aggregate statistics
db.get_scans(target="x")     # Scan history
db.get_target_history("x")   # Full target timeline
```

### Multi-Target Campaigns
```python
from core.campaign import Campaign
campaign = Campaign("Internal Audit", ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
campaign.run_tool_across_targets(port_scanner_module, max_concurrency=10)
summary = campaign.get_summary()
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=core --cov-report=term-missing

# Verify tool loading
python -c "from core.loader import load_all; from core.registry import get_registry; load_all(quiet=True); print(f'{get_registry().tool_count()} tools loaded')"
```

CI runs automatically on push via GitHub Actions (`.github/workflows/ci.yml`).

---

## 🔌 Creating Custom Plugins

Drop a `.py` file into `modules/` with `TOOL_INFO` and `run()`:

```python
# modules/my_category/my_tool.py
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "my_tool",
    "category": "my_category",
    "description": "My custom security tool",
    "author": "Your Name",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Target to scan"},
        {"name": "option", "required": False, "default": "default_val"},
    ],
    "tags": ["custom", "example"],
}

def run(args):
    target = args.get("target", "")
    return ToolResult(
        tool_name="my_tool",
        target=target,
        status="success",
        data={"result": "your data"},
        findings=[
            Finding(title="Something found", severity=Severity.MEDIUM)
        ],
    )
```

The tool will be auto-discovered on next launch — no registration needed.

---

## 🐳 Docker

```bash
# Build
docker build -t cybertoolkit .

# Interactive mode
docker run -it cybertoolkit

# Run a specific tool
docker run cybertoolkit run scanning.port_scanner --target 10.10.10.10

# Start dashboard
docker run -p 8443:8443 cybertoolkit dashboard
```

---

## ⚠️ Legal Notice

This framework is intended for **authorized security testing only**. Use exclusively in:
- Lab/testing environments you own
- CTF competitions
- Authorized penetration tests with written permission

Unauthorized use against systems you do not own is **illegal**. The authors assume no liability for misuse.

---

## 📝 License

MIT License — See LICENSE file for details.
