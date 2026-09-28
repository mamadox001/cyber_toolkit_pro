# =============================================================================
# CyberToolkit Pro — Credential Vault
# =============================================================================
# Encrypted credential storage using Fernet symmetric encryption and PBKDF2 HMAC.
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
        self.salt = None
        self._cipher = None
        self._passphrase = master_key or os.environ.get("CYBERTK_VAULT_KEY", "default_key")
        self._load()

    def _init_cipher(self, passphrase: str, salt: Optional[bytes] = None):
        """Initialize the Fernet cipher."""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes

            if salt is None:
                salt = os.urandom(16)
            self.salt = salt

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
            self._cipher = Fernet(key)
        except ImportError:
            self._cipher = None
            self.salt = None

    def _encrypt(self, data: str) -> str:
        """Encrypt a string value."""
        if self._cipher:
            return self._cipher.encrypt(data.encode("utf-8")).decode("utf-8")
        # Fallback — base64 encoding if cryptography is unavailable
        return base64.b64encode(data.encode("utf-8")).decode("utf-8")

    def _decrypt(self, data: str) -> str:
        """Decrypt a string value."""
        if self._cipher:
            try:
                return self._cipher.decrypt(data.encode("utf-8")).decode("utf-8")
            except Exception:
                pass
        try:
            return base64.b64decode(data.encode("utf-8")).decode("utf-8")
        except Exception:
            return "[DECRYPTION FAILED]"

    def _load(self):
        """Load vault from disk."""
        if not os.path.exists(self.vault_path):
            self._init_cipher(self._passphrase)
            return

        try:
            with open(self.vault_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            data = {}

        if isinstance(data, dict) and "salt" in data and "entries" in data:
            salt = base64.b64decode(data["salt"].encode("utf-8"))
            self._init_cipher(self._passphrase, salt)
            self._entries = data["entries"]
        else:
            # Legacy format - migrate it
            self._entries = data
            if self._entries:
                # Decrypt entries using the old legacy key derivation
                legacy_key = base64.urlsafe_b64encode(hashlib.sha256(self._passphrase.encode("utf-8")).digest())
                try:
                    from cryptography.fernet import Fernet
                    legacy_cipher = Fernet(legacy_key)

                    decrypted_entries = {}
                    for k, entry in self._entries.items():
                        try:
                            decrypted_val = legacy_cipher.decrypt(entry["value"].encode("utf-8")).decode("utf-8")
                            decrypted_entries[k] = {
                                "value": decrypted_val,
                                "category": entry.get("category", "general"),
                                "stored_at": entry.get("stored_at", ""),
                                "metadata": entry.get("metadata", {}),
                            }
                        except Exception:
                            decrypted_entries[k] = None
                except ImportError:
                    decrypted_entries = {}

                # Now generate new salt, derive key using PBKDF2, and encrypt everything again
                self._init_cipher(self._passphrase)
                if self._cipher:
                    for k, entry in decrypted_entries.items():
                        if entry is not None:
                            self._entries[k] = {
                                "value": self._cipher.encrypt(entry["value"].encode("utf-8")).decode("utf-8"),
                                "category": entry["category"],
                                "stored_at": entry["stored_at"],
                                "metadata": entry["metadata"],
                            }
                    self._save()
            else:
                self._init_cipher(self._passphrase)

    def _save(self):
        """Save vault to disk."""
        os.makedirs(os.path.dirname(self.vault_path) or ".", exist_ok=True)
        data = {
            "salt": base64.b64encode(self.salt).decode("utf-8") if self.salt else "",
            "entries": self._entries
        }
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

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
