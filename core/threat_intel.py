# =============================================================================
# CyberToolkit Pro — Threat Intelligence Integration
# =============================================================================
# Query external threat intelligence feeds and reputation databases.
# Supports VirusTotal, AbuseIPDB, Shodan, and OTX AlienVault.
# =============================================================================

import json
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional
from datetime import datetime

from core.config import Config
from core.logger import get_logger

logger = get_logger("threat_intel")


class ThreatIntel:
    """Aggregated threat intelligence lookups across multiple providers."""

    def __init__(self):
        self._cfg = Config()
        self._cache = {}

    def _api_get(self, url: str, headers: Dict = None,
                  timeout: int = 15) -> Optional[Dict]:
        """Make an HTTP GET request and return JSON response."""
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.error(f"Threat intel API request failed: {e}")
            return None

    # -------------------------------------------------------------------------
    # VirusTotal
    # -------------------------------------------------------------------------
    def virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP reputation on VirusTotal."""
        api_key = self._cfg.get("threat_intel.virustotal_api_key", "")
        if not api_key:
            return {"error": "VirusTotal API key not configured"}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        return self._api_get(url, headers={"x-apikey": api_key})

    def virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Lookup domain reputation on VirusTotal."""
        api_key = self._cfg.get("threat_intel.virustotal_api_key", "")
        if not api_key:
            return {"error": "VirusTotal API key not configured"}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        return self._api_get(url, headers={"x-apikey": api_key})

    def virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Lookup file hash on VirusTotal."""
        api_key = self._cfg.get("threat_intel.virustotal_api_key", "")
        if not api_key:
            return {"error": "VirusTotal API key not configured"}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        return self._api_get(url, headers={"x-apikey": api_key})

    # -------------------------------------------------------------------------
    # AbuseIPDB
    # -------------------------------------------------------------------------
    def abuseipdb_check(self, ip: str, max_age_days: int = 90) -> Optional[Dict]:
        """Check IP reputation on AbuseIPDB."""
        api_key = self._cfg.get("threat_intel.abuseipdb_api_key", "")
        if not api_key:
            return {"error": "AbuseIPDB API key not configured"}
        url = (
            f"https://api.abuseipdb.com/api/v2/check?"
            f"ipAddress={ip}&maxAgeInDays={max_age_days}"
        )
        return self._api_get(url, headers={
            "Key": api_key, "Accept": "application/json"
        })

    # -------------------------------------------------------------------------
    # Shodan
    # -------------------------------------------------------------------------
    def shodan_host(self, ip: str) -> Optional[Dict]:
        """Lookup host information on Shodan."""
        api_key = self._cfg.get("threat_intel.shodan_api_key", "")
        if not api_key:
            return {"error": "Shodan API key not configured"}
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        return self._api_get(url)

    def shodan_search(self, query: str, page: int = 1) -> Optional[Dict]:
        """Search Shodan for hosts."""
        api_key = self._cfg.get("threat_intel.shodan_api_key", "")
        if not api_key:
            return {"error": "Shodan API key not configured"}
        encoded = urllib.parse.quote(query)
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={encoded}&page={page}"
        return self._api_get(url)

    # -------------------------------------------------------------------------
    # OTX AlienVault
    # -------------------------------------------------------------------------
    def otx_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP on OTX AlienVault."""
        api_key = self._cfg.get("threat_intel.otx_api_key", "")
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        return self._api_get(url, headers=headers)

    def otx_domain(self, domain: str) -> Optional[Dict]:
        """Lookup domain on OTX AlienVault."""
        api_key = self._cfg.get("threat_intel.otx_api_key", "")
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        return self._api_get(url, headers=headers)

    # -------------------------------------------------------------------------
    # GreyNoise
    # -------------------------------------------------------------------------
    def greynoise_ip(self, ip: str) -> Optional[Dict]:
        """Check IP on GreyNoise Community API."""
        api_key = self._cfg.get("threat_intel.greynoise_api_key", "")
        headers = {"Accept": "application/json"}
        if api_key:
            headers["key"] = api_key
        url = f"https://api.greynoise.io/v3/community/{ip}"
        return self._api_get(url, headers=headers)

    # -------------------------------------------------------------------------
    # Aggregated lookup
    # -------------------------------------------------------------------------
    def full_ip_lookup(self, ip: str) -> Dict:
        """Run IP through all configured threat intel providers."""
        results = {"ip": ip, "timestamp": datetime.utcnow().isoformat(), "providers": {}}

        vt = self.virustotal_ip(ip)
        if vt and "error" not in vt:
            results["providers"]["virustotal"] = vt

        abuse = self.abuseipdb_check(ip)
        if abuse and "error" not in abuse:
            results["providers"]["abuseipdb"] = abuse

        shodan = self.shodan_host(ip)
        if shodan and "error" not in shodan:
            results["providers"]["shodan"] = shodan

        otx = self.otx_ip(ip)
        if otx and "error" not in otx:
            results["providers"]["otx"] = otx

        gn = self.greynoise_ip(ip)
        if gn and "error" not in gn:
            results["providers"]["greynoise"] = gn

        return results

    def full_domain_lookup(self, domain: str) -> Dict:
        """Run domain through all configured threat intel providers."""
        results = {"domain": domain, "timestamp": datetime.utcnow().isoformat(), "providers": {}}

        vt = self.virustotal_domain(domain)
        if vt and "error" not in vt:
            results["providers"]["virustotal"] = vt

        otx = self.otx_domain(domain)
        if otx and "error" not in otx:
            results["providers"]["otx"] = otx

        return results


# Module-level singleton
_ti = None


def get_threat_intel() -> ThreatIntel:
    """Get the global threat intelligence instance."""
    global _ti
    if _ti is None:
        _ti = ThreatIntel()
    return _ti
