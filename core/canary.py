# =============================================================================
# CyberToolkit Pro — Active Defense & Canary Token Engine
# =============================================================================
# Generates, tracks, and manages deceptive honeytokens (AWS keys, Git secrets,
# HTTP tripwires, DB credentials) to detect unauthorized intrusion attempts.
# =============================================================================

import os
import sqlite3
import secrets
import string
import datetime
from typing import Dict, Any, List, Optional
from core.notifier import get_notifier


class CanaryManager:
    """Manages creation, storage, and triggering of defensive canary tokens."""

    def __init__(self, db_path: str = "data/canaries.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canaries (
                    token_id TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    memo TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    triggered_count INTEGER DEFAULT 0,
                    last_triggered_at TEXT,
                    last_client_ip TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canary_hits (
                    hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT NOT NULL,
                    hit_timestamp TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    headers TEXT,
                    FOREIGN KEY(token_id) REFERENCES canaries(token_id)
                )
            """)
            conn.commit()

    def generate_token(self, token_type: str, memo: str = "", base_url: str = "http://localhost:8000") -> Dict[str, Any]:
        """
        Generate a new canary token of a given type.
        Supported types: 'http_webhook', 'aws_keys', 'git_token', 'db_credential'.
        """
        token_id = secrets.token_hex(12)
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {}

        if token_type == "aws_keys":
            # Realistic AWS Access Key ID format
            random_suffix = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
            access_key = f"AKIA{random_suffix}"
            secret_key = secrets.token_urlsafe(32)
            payload = {
                "aws_access_key_id": access_key,
                "aws_secret_access_key": secret_key,
                "region": "us-east-1",
                "notes": "Decoy AWS Credential — tripwire alert upon attempted authentication"
            }
        elif token_type == "git_token":
            # Realistic GitHub fine-grained or personal token format
            pat = f"ghp_{secrets.token_urlsafe(36)}"
            payload = {
                "github_pat": pat,
                "account": "admin-internal",
                "notes": "Decoy GitHub Token — alerts when accessed"
            }
        elif token_type == "db_credential":
            pw = secrets.token_urlsafe(16)
            payload = {
                "connection_string": f"postgresql://app_read_replica:{pw}@internal-db.corp.local:5432/finance_prod",
                "username": "app_read_replica",
                "password": pw,
                "notes": "Decoy Database Connection String"
            }
        else: # http_webhook / default
            token_type = "http_webhook"
            webhook_url = f"{base_url.rstrip('/')}/api/canary/ping/{token_id}"
            payload = {
                "webhook_url": webhook_url,
                "notes": "Decoy HTTP tripwire URL — fires notification upon HTTP GET/POST"
            }

        payload_str = str(payload)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO canaries (token_id, token_type, memo, payload, created_at, triggered_count)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (token_id, token_type, memo or f"Canary {token_type}", payload_str, created_at))
            conn.commit()

        return {
            "token_id": token_id,
            "token_type": token_type,
            "memo": memo,
            "created_at": created_at,
            "payload": payload
        }

    def trigger(self, token_id: str, client_ip: str = "Unknown", user_agent: str = "Unknown", headers: str = "") -> Optional[Dict[str, Any]]:
        """
        Trigger an alert for a tripped canary token.
        Notifies all configured alert channels (Discord, Slack, Telegram, Email).
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT token_id, token_type, memo, triggered_count FROM canaries WHERE token_id = ?", (token_id,))
            row = cursor.fetchone()
            if not row:
                return None

            tid, ttype, memo, count = row
            new_count = count + 1

            cursor.execute("""
                UPDATE canaries
                SET triggered_count = ?, last_triggered_at = ?, last_client_ip = ?
                WHERE token_id = ?
            """, (new_count, now, client_ip, token_id))

            cursor.execute("""
                INSERT INTO canary_hits (token_id, hit_timestamp, client_ip, user_agent, headers)
                VALUES (?, ?, ?, ?, ?)
            """, (token_id, now, client_ip, user_agent, headers))
            conn.commit()

        # Send alert via Notifier
        notifier = get_notifier()
        alert_title = f"[TRIPPED] Canary Honeytoken Activated: {memo or ttype}"
        alert_body = (
            f"Active Defense Tripwire Tripped!\n"
            f"Token ID: {token_id}\n"
            f"Type: {ttype}\n"
            f"Client IP: {client_ip}\n"
            f"User-Agent: {user_agent}\n"
            f"Total Triggers: {new_count}\n"
            f"Time: {now}"
        )
        notifier.notify(title=alert_title, message=alert_body, severity="critical")

        return {
            "token_id": token_id,
            "token_type": ttype,
            "memo": memo,
            "triggered_count": new_count,
            "last_triggered_at": now,
            "client_ip": client_ip,
        }

    def list_canaries(self) -> List[Dict[str, Any]]:
        """List all active canary tokens and their trigger status."""
        results = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM canaries ORDER BY created_at DESC")
            for row in cursor.fetchall():
                results.append(dict(row))
        return results

    def get_hits(self, token_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve historical hits/trips for canaries."""
        results = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if token_id:
                cursor.execute("SELECT * FROM canary_hits WHERE token_id = ? ORDER BY hit_id DESC", (token_id,))
            else:
                cursor.execute("SELECT * FROM canary_hits ORDER BY hit_id DESC LIMIT 100")
            for row in cursor.fetchall():
                results.append(dict(row))
        return results


_canary_manager = None

def get_canary_manager() -> CanaryManager:
    global _canary_manager
    if _canary_manager is None:
        _canary_manager = CanaryManager()
    return _canary_manager
