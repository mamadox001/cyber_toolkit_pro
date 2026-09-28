# =============================================================================
# CyberToolkit Pro — Target Scope Enforcement
# =============================================================================
# Restricts tool execution to authorized targets only. Prevents accidental
# testing of out-of-scope assets. Critical for professional pentesting.
#
# Usage: Define scope in config/scope.yaml
# =============================================================================

import os
import re
import ipaddress
from typing import List, Optional


class ScopeEnforcer:
    """Enforces target scope restrictions for all tool executions."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, scope_file: str = "config/scope.yaml"):
        if self._initialized:
            return
        self._initialized = True
        self.enabled = False
        self.allowed_ips = []        # List of ip_network objects
        self.allowed_domains = []     # List of domain patterns (regex)
        self.allowed_ports = []       # List of (start, end) tuples
        self.excluded_ips = []        # Explicitly blocked
        self.excluded_domains = []
        self._load_scope(scope_file)

    def _load_scope(self, scope_file: str):
        """Load scope configuration from YAML file."""
        if not os.path.exists(scope_file):
            return

        try:
            import yaml
            with open(scope_file, "r") as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            return

        scope = config.get("scope", {})
        self.enabled = scope.get("enabled", False)

        if not self.enabled:
            return

        # Parse allowed IPs and CIDR ranges
        for ip_str in scope.get("allowed_ips", []):
            try:
                self.allowed_ips.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

        # Parse allowed domains
        for domain in scope.get("allowed_domains", []):
            if domain.startswith("*."):
                base_domain = domain[2:]
                escaped_base = base_domain.replace(".", r"\.")
                pattern = rf"^(?:.*?\.)?{escaped_base}$"
            else:
                escaped_domain = domain.replace(".", r"\.").replace("*", r".*")
                pattern = f"^{escaped_domain}$"
            self.allowed_domains.append(re.compile(pattern, re.IGNORECASE))

        # Parse allowed ports
        for port_spec in scope.get("allowed_ports", []):
            if isinstance(port_spec, int):
                self.allowed_ports.append((port_spec, port_spec))
            elif isinstance(port_spec, str) and "-" in port_spec:
                start, end = port_spec.split("-", 1)
                self.allowed_ports.append((int(start), int(end)))

        # Parse exclusions
        for ip_str in scope.get("excluded_ips", []):
            try:
                self.excluded_ips.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

        for domain in scope.get("excluded_domains", []):
            if domain.startswith("*."):
                base_domain = domain[2:]
                escaped_base = base_domain.replace(".", r"\.")
                pattern = rf"^(?:.*?\.)?{escaped_base}$"
            else:
                escaped_domain = domain.replace(".", r"\.").replace("*", r".*")
                pattern = f"^{escaped_domain}$"
            self.excluded_domains.append(re.compile(pattern, re.IGNORECASE))

    def check_target(self, target: str) -> tuple:
        """
        Check if a target is within scope.
        Returns (allowed: bool, reason: str).
        """
        if not self.enabled:
            return True, "Scope enforcement disabled"

        if not target:
            return True, "No target specified"

        # Strip protocol prefixes
        clean_target = target
        for prefix in ["http://", "https://", "ftp://", "ssh://"]:
            if clean_target.startswith(prefix):
                clean_target = clean_target[len(prefix):]
        clean_target = clean_target.split("/")[0].split(":")[0]

        # Check exclusions first
        if self._is_excluded(clean_target):
            return False, f"Target '{clean_target}' is in the exclusion list"

        # Check if it's an IP
        try:
            ip = ipaddress.ip_address(clean_target)
            if self.allowed_ips:
                for network in self.allowed_ips:
                    if ip in network:
                        return True, f"IP {clean_target} is within allowed range {network}"
                return False, f"IP {clean_target} is not in any allowed IP range"
            return True, "No IP restrictions configured"
        except ValueError:
            pass

        # Check domain
        if self.allowed_domains:
            for pattern in self.allowed_domains:
                if pattern.match(clean_target):
                    return True, f"Domain '{clean_target}' matches allowed pattern"
            return False, f"Domain '{clean_target}' is not in allowed domains"

        return True, "No domain restrictions configured"

    def check_port(self, port: int) -> tuple:
        """Check if a port is within scope."""
        if not self.enabled or not self.allowed_ports:
            return True, "No port restrictions"

        for start, end in self.allowed_ports:
            if start <= port <= end:
                return True, f"Port {port} is within allowed range {start}-{end}"
        return False, f"Port {port} is not in any allowed port range"

    def _is_excluded(self, target: str) -> bool:
        """Check if target is explicitly excluded."""
        # Check IP exclusions
        try:
            ip = ipaddress.ip_address(target)
            for network in self.excluded_ips:
                if ip in network:
                    return True
        except ValueError:
            pass

        # Check domain exclusions
        for pattern in self.excluded_domains:
            if pattern.match(target):
                return True

        return False

    def enforce(self, target: str, port: Optional[int] = None) -> None:
        """
        Enforce scope — raises ScopeViolation if target is out of scope.
        Call this at the start of every tool's run() function.
        """
        allowed, reason = self.check_target(target)
        if not allowed:
            raise ScopeViolation(reason)

        if port is not None:
            allowed, reason = self.check_port(port)
            if not allowed:
                raise ScopeViolation(reason)


class ScopeViolation(Exception):
    """Raised when a target is outside the defined scope."""
    pass


# Module-level convenience
_enforcer = None


def get_scope() -> ScopeEnforcer:
    """Get the global scope enforcer instance."""
    global _enforcer
    if _enforcer is None:
        _enforcer = ScopeEnforcer()
    return _enforcer


def check_scope(target: str, port: int = None) -> tuple:
    """Quick scope check — returns (allowed, reason)."""
    enforcer = get_scope()
    allowed, reason = enforcer.check_target(target)
    if allowed and port is not None:
        allowed, reason = enforcer.check_port(port)
    return allowed, reason
