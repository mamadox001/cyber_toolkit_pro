# CyberToolkit Pro v2.0

> **Professional Cybersecurity Framework** — Offensive & Defensive Security Toolkit
>
> A modular, extensible framework for penetration testing, security assessment, and blue team operations. Inspired by Metasploit, Burp Suite, and lightweight SIEM architectures.

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
```

---

## 🏗️ Architecture

```
cyber_toolkit_pro/
├── main.py                 # CLI entry point (argparse)
├── core/                   # Framework engine
│   ├── cli.py              # Interactive shell
│   ├── config.py           # YAML configuration
│   ├── executor.py         # Tool execution + parallel
│   ├── loader.py           # Auto-discovery module loader
│   ├── logger.py           # Structured logging
│   ├── models.py           # Data models (ToolResult, Finding, etc.)
│   ├── output.py           # Console formatting + colors
│   ├── pipeline.py         # Workflow chaining engine
│   ├── registry.py         # Tool registry
│   └── suggester.py        # AI reasoning engine
├── modules/                # Tool modules (auto-discovered)
│   ├── reconnaissance/     # DNS, WHOIS, subdomain, HTTP fingerprint
│   ├── scanning/           # Port scanner, nmap, service detection
│   ├── web/                # Dir brute, fuzzer, SQLi, XSS testing
│   ├── exploitation/       # Reverse shell, payloads, exploit runner
│   ├── passwords/          # Wordlist attack, hash cracker, cred checker
│   ├── detection/          # Anomaly detector, IP tracker, alert system
│   ├── log_analysis/       # Auth/web log parsers, SSH brute detection
│   ├── forensics/          # File analyzer, string extractor, type detect
│   ├── siem/               # Log aggregation, search, alert generation
│   └── reporting/          # JSON + HTML report generation
├── plugins/                # Drop-in plugin system
├── config/                 # YAML configs + pipeline profiles
├── wordlists/              # Brute force wordlists
├── dashboard/              # FastAPI web dashboard
└── Dockerfile              # Container support
```

---

## 🔴 Red Team Tools (17 modules)

| Category | Tool | Description |
|----------|------|-------------|
| **Reconnaissance** | `dns_lookup` | DNS record enumeration (A/MX/NS/TXT/SOA) |
| | `subdomain_discovery` | Multi-threaded subdomain brute force |
| | `whois_lookup` | WHOIS registration lookup |
| | `http_fingerprint` | HTTP server/header/tech detection |
| **Scanning** | `port_scanner` | Threaded TCP scanner + banner grabbing |
| | `nmap_advanced` | Nmap wrapper with scan profiles |
| | `service_detector` | Protocol-based service identification |
| **Web** | `dir_bruteforce` | Web directory/file discovery |
| | `http_fuzzer` | Parameter fuzzing engine |
| | `sqli_tester` | Safe SQL injection detection |
| | `xss_tester` | Reflected XSS detection |
| **Exploitation** | `reverse_shell` | Multi-session listener (LAB ONLY) |
| | `payload_generator` | Multi-platform payload generation |
| | `exploit_runner` | Modular exploit framework |
| **Passwords** | `wordlist_attack` | Dictionary login testing |
| | `hash_cracker` | MD5/SHA1/SHA256 cracking |
| | `credential_checker` | Cross-service credential reuse testing |

## 🔵 Blue Team Tools (12 modules)

| Category | Tool | Description |
|----------|------|-------------|
| **Detection** | `anomaly_detector` | Threshold-based anomaly detection |
| | `suspicious_ip_tracker` | IP watchlist + frequency tracking |
| | `alert_system` | Rule-based security alerting |
| **Log Analysis** | `auth_log_parser` | Linux auth.log analysis |
| | `web_log_parser` | Apache/Nginx attack detection |
| | `ssh_bruteforce_detector` | SSH brute force profiling |
| **Forensics** | `file_analyzer` | Multi-hash + entropy + magic bytes |
| | `string_extractor` | Binary string extraction + analysis |
| | `file_type_detector` | Extension mismatch detection |
| **SIEM** | `log_aggregator` | Multi-source log normalization |
| | `log_search` | Regex-based log search |
| | `alert_generator` | Rule-based SIEM alerts |

---

## 🔧 Usage Examples

### Command Mode
```bash
# Port scan with custom range
python main.py run scanning.port_scanner --target 10.10.10.10 -a ports=1-65535 threads=100

# DNS enumeration
python main.py run reconnaissance.dns_lookup --target example.com

# Generate payloads
python main.py run exploitation.payload_generator --target 10.0.0.1 -a port=9001

# Analyze a suspicious file
python main.py run forensics.file_analyzer --target /path/to/suspicious.exe

# Parse auth logs for brute force
python main.py run log_analysis.ssh_bruteforce_detector --target /var/log/auth.log

# Save results as JSON
python main.py run scanning.port_scanner --target 10.10.10.10 -o results.json
```

### Pipeline Mode
```bash
# Quick scan pipeline (DNS → WHOIS → HTTP fingerprint → port scan → report)
python main.py pipeline quick_scan --target example.com

# Web audit pipeline (full web app security assessment)
python main.py pipeline web_audit --target http://example.com
```

### Interactive Shell
```bash
python main.py --interactive

# Inside the shell:
cybertk > list                              # List all tools
cybertk > categories                        # Show categories
cybertk > search sql                        # Search tools
cybertk > run scanning.port_scanner         # Run a tool
cybertk > scanning.port_scanner             # Shorthand
cybertk > pipeline quick_scan               # Run pipeline
cybertk > help                              # Show help
```

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
    # Your logic here
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

The tool will be **auto-discovered** on next launch — no registration needed.

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

Unauthorized use against systems you do not own is illegal. The authors assume no liability for misuse.

---

## 📝 License

MIT License — See LICENSE file for details.
