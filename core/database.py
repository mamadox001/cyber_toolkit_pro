# =============================================================================
# CyberToolkit Pro — SQLite Database Backend
# =============================================================================
# Persistent storage for scan results, findings, targets, and campaigns.
# Enables historical comparison, trend analysis, and reporting.
# =============================================================================

import os
import json
import sqlite3
import threading
from datetime import datetime
from typing import Optional, Dict, List


class Database:
    """SQLite-backed persistent storage for framework data."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: str = "data/cybertoolkit.db"):
        if self._initialized:
            return
        self._initialized = True
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """Create all database tables."""
        c = self.conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                campaign_id TEXT,
                tool_name TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                args TEXT,
                data TEXT,
                stdout TEXT,
                error TEXT,
                duration_ms REAL,
                findings_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                target_type TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                scan_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                notes TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                targets TEXT,
                status TEXT DEFAULT 'active',
                pipeline TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                total_scans INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0
            )
        """)

        # Indices for performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool_name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_campaign ON scans(campaign_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")

        self.conn.commit()

    # -------------------------------------------------------------------------
    # Scan operations
    # -------------------------------------------------------------------------
    def save_scan(self, scan_id: str, tool_name: str, target: str,
                  status: str, args: Dict, data: Dict,
                  findings: List[Dict], duration_ms: float,
                  campaign_id: str = "", stdout: str = "",
                  error: str = "") -> str:
        """Save a scan result to the database."""
        with self._lock:
            now = datetime.utcnow().isoformat() + "Z"
            c = self.conn.cursor()

            c.execute("""
                INSERT OR REPLACE INTO scans
                (scan_id, campaign_id, tool_name, target, status, args, data,
                 stdout, error, duration_ms, findings_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, campaign_id, tool_name, target, status,
                json.dumps(args, default=str),
                json.dumps(data, default=str),
                stdout, error, duration_ms, len(findings), now
            ))

            # Save findings
            for f in findings:
                title = f.title if hasattr(f, "title") else f.get("title", "")
                severity = f.severity.value if hasattr(f, "severity") and hasattr(f.severity, "value") else f.get("severity", "info")
                desc = f.description if hasattr(f, "description") else f.get("description", "")
                evidence = f.evidence if hasattr(f, "evidence") else f.get("evidence", "")
                remediation = f.remediation if hasattr(f, "remediation") else f.get("remediation", "")

                c.execute("""
                    INSERT INTO findings
                    (scan_id, title, severity, description, evidence, remediation, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, title, severity, desc, evidence, remediation, now))

            # Update target record
            c.execute("SELECT id FROM targets WHERE target = ?", (target,))
            if c.fetchone():
                c.execute("""
                    UPDATE targets SET last_seen = ?, scan_count = scan_count + 1,
                    total_findings = total_findings + ? WHERE target = ?
                """, (now, len(findings), target))
            else:
                c.execute("""
                    INSERT INTO targets (target, target_type, first_seen, last_seen,
                    scan_count, total_findings)
                    VALUES (?, ?, ?, ?, 1, ?)
                """, (target, _detect_target_type(target), now, now, len(findings)))

            self.conn.commit()
            return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a single scan result."""
        c = self.conn.cursor()
        c.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = c.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)

    def get_scans(self, target: str = "", tool: str = "",
                  campaign_id: str = "", limit: int = 50) -> List[Dict]:
        """Query scan history."""
        c = self.conn.cursor()
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        if tool:
            query += " AND tool_name LIKE ?"
            params.append(f"%{tool}%")
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        return [_row_to_dict(row) for row in c.fetchall()]

    def get_findings(self, scan_id: str = "", severity: str = "",
                     limit: int = 100) -> List[Dict]:
        """Query findings."""
        c = self.conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        return [_row_to_dict(row) for row in c.fetchall()]

    # -------------------------------------------------------------------------
    # Target operations
    # -------------------------------------------------------------------------
    def get_targets(self, limit: int = 100) -> List[Dict]:
        """Get all known targets."""
        c = self.conn.cursor()
        c.execute("SELECT * FROM targets ORDER BY last_seen DESC LIMIT ?", (limit,))
        return [_row_to_dict(row) for row in c.fetchall()]

    def get_target_history(self, target: str) -> Dict:
        """Get complete history for a target."""
        scans = self.get_scans(target=target, limit=1000)
        findings = []
        for scan in scans:
            findings.extend(self.get_findings(scan_id=scan["scan_id"]))
        return {"target": target, "scans": scans, "findings": findings}

    # -------------------------------------------------------------------------
    # Campaign operations
    # -------------------------------------------------------------------------
    def create_campaign(self, campaign_id: str, name: str,
                        targets: List[str], description: str = "",
                        pipeline: str = "") -> str:
        """Create a new campaign."""
        with self._lock:
            c = self.conn.cursor()
            now = datetime.utcnow().isoformat() + "Z"
            c.execute("""
                INSERT INTO campaigns
                (campaign_id, name, description, targets, pipeline, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (campaign_id, name, description, json.dumps(targets), pipeline, now))
            self.conn.commit()
            return campaign_id

    def get_campaign(self, campaign_id: str) -> Optional[Dict]:
        """Get campaign details."""
        c = self.conn.cursor()
        c.execute("SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,))
        row = c.fetchone()
        return _row_to_dict(row) if row else None

    def get_campaigns(self, limit: int = 50) -> List[Dict]:
        """List all campaigns."""
        c = self.conn.cursor()
        c.execute("SELECT * FROM campaigns ORDER BY created_at DESC LIMIT ?", (limit,))
        return [_row_to_dict(row) for row in c.fetchall()]

    def update_campaign_stats(self, campaign_id: str):
        """Recalculate campaign statistics."""
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT COUNT(*) FROM scans WHERE campaign_id = ?", (campaign_id,))
            total_scans = c.fetchone()[0]
            c.execute("""
                SELECT COUNT(*) FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE s.campaign_id = ?
            """, (campaign_id,))
            total_findings = c.fetchone()[0]
            c.execute("""
                UPDATE campaigns SET total_scans = ?, total_findings = ?
                WHERE campaign_id = ?
            """, (total_scans, total_findings, campaign_id))
            self.conn.commit()

    # -------------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------------
    def get_dashboard_stats(self) -> Dict:
        """Get statistics for the dashboard."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        total_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        total_findings = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM targets")
        total_targets = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM campaigns")
        total_campaigns = c.fetchone()[0]

        # Severity breakdown
        severity_counts = {}
        c.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        for row in c.fetchall():
            severity_counts[row[0]] = row[1]

        # Recent scans
        c.execute("SELECT tool_name, target, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10")
        recent = [_row_to_dict(row) for row in c.fetchall()]

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_targets": total_targets,
            "total_campaigns": total_campaigns,
            "severity_breakdown": severity_counts,
            "recent_scans": recent,
        }

    def close(self):
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        Database._instance = None
        global _db
        _db = None


def _row_to_dict(row) -> Dict:
    """Convert a sqlite3.Row to a plain dictionary."""
    if row is None:
        return {}
    return dict(row)


def _detect_target_type(target: str) -> str:
    """Detect if target is an IP, domain, URL, or file."""
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    if target.startswith(("http://", "https://")):
        return "url"
    if os.path.exists(target):
        return "file"
    return "domain"


# Module-level singleton
_db = None


def get_db() -> Database:
    """Get the global database instance."""
    global _db
    if _db is None or Database._instance is None:
        Database._instance = None
        _db = Database()
    return _db
