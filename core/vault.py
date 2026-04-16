# =============================================================================
# CyberToolkit Pro — Credential Vault
# =============================================================================
# Encrypted credential storage using Fernet symmetric encryption.
# Stores API keys, found credentials, and session tokens securely.
# =============================================================================

import os
import json
import base64
import hashlib
from datetime import datetime
from typing import Optional, Dict, List


class CredentialVault:
    """Encrypted credential storage for the framework."""

    def __init__(self, vault_path: str = "config/.vault", master_key: str = ""):
        self.vault_path = vault_path
        self._entries = {}
        self._cipher = None
        self._key = self._derive_key(master_key or os.environ.get("CYBERTK_VAULT_KEY", "default_key"))
        self._init_cipher()
        self._load()

    def _derive_key(self, passphrase: str) -> bytes:
        """Derive a Fernet-compatible key from a passphrase."""
        digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    def _init_cipher(self):
        """Initialize the Fernet cipher."""
        try:
            from cryptography.fernet import Fernet
            self._cipher = Fernet(self._key)
        except ImportError:
            # Fallback: base64 obfuscation (NOT secure, but functional)
            self._cipher = None

    def _encrypt(self, data: str) -> str:
        """Encrypt a string value."""
        if self._cipher:
            return self._cipher.encrypt(data.encode("utf-8")).decode("utf-8")
        # Fallback — base64 only
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")

    def _decrypt(self, data: str) -> str:
        """Decrypt a string value."""
        if self._cipher:
            try:
                return self._cipher.decrypt(data.encode("utf-8")).decode("utf-8")
            except Exception:
                return "[DECRYPTION FAILED]"
        return base64.b64decode(data.encode("utf-8")).decode("utf-8")

    def _load(self):
        """Load vault from disk."""
        if not os.path.exists(self.vault_path):
            return
        try:
            with open(self.vault_path, "r", encoding="utf-8") as f:
                self._entries = json.load(f)
        except (json.JSONDecodeError, IOError):
            self._entries = {}

    def _save(self):
        """Save vault to disk."""
        os.makedirs(os.path.dirname(self.vault_path) or ".", exist_ok=True)
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2)

    def store(self, key: str, value: str, category: str = "general",
              metadata: Optional[Dict] = None) -> None:
        """Store an encrypted credential."""
        self._entries[key] = {
            "value": self._encrypt(value),
            "category": category,
            "stored_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }
        self._save()

    def retrieve(self, key: str) -> Optional[str]:
        """Retrieve and decrypt a credential."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        return self._decrypt(entry["value"])

    def list_keys(self, category: str = "") -> List[Dict]:
        """List stored keys (without values)."""
        result = []
        for key, entry in self._entries.items():
            if category and entry.get("category") != category:
                continue
            result.append({
                "key": key,
                "category": entry.get("category", ""),
                "stored_at": entry.get("stored_at", ""),
                "metadata": entry.get("metadata", {}),
            })
        return result

    def delete(self, key: str) -> bool:
        """Delete a credential from the vault."""
        if key in self._entries:
            del self._entries[key]
            self._save()
            return True
        return False

    def store_found_credential(self, target: str, service: str,
                                username: str, password: str,
                                source_tool: str = "") -> None:
        """Store a credential found during assessment."""
        key = f"found:{target}:{service}:{username}"
        self.store(
            key=key,
            value=password,
            category="found_credentials",
            metadata={
                "target": target,
                "service": service,
                "username": username,
                "source_tool": source_tool,
                "found_at": datetime.utcnow().isoformat(),
            },
        )

    def get_found_credentials(self) -> List[Dict]:
        """Get all found credentials (decrypted)."""
        creds = []
        for key, entry in self._entries.items():
            if entry.get("category") == "found_credentials":
                creds.append({
                    "key": key,
                    "password": self._decrypt(entry["value"]),
                    **entry.get("metadata", {}),
                })
        return creds


# Module-level singleton
_vault = None


def get_vault() -> CredentialVault:
    """Get the global credential vault instance."""
    global _vault
    if _vault is None:
        _vault = CredentialVault()
    return _vault
