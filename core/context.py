"""
FuzzPhantom — ScanContext
Central dataclass that accumulates all discovered data during a scan run.
All modules read from and write to this shared context object.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Represents a single vulnerability or anomaly finding."""

    category: str          # e.g. "Parameter Fuzzing", "API Endpoint"
    url: str               # Affected URL
    parameter: str = ""    # Parameter name (if applicable)
    payload: str = ""      # Payload used (if applicable)
    status_code: int = 0   # HTTP response code
    original_status: int = 0
    response_length: int = 0
    original_length: int = 0
    error_keywords: list[str] = field(default_factory=list)
    severity: str = "INFO"  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detail: str = ""        # Human-readable description
    evidence: str = ""      # Snippet of response body evidence
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "status_code": self.status_code,
            "original_status": self.original_status,
            "response_length": self.response_length,
            "original_length": self.original_length,
            "error_keywords": self.error_keywords,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
            "extra": self.extra,
        }


@dataclass
class ScanContext:
    """
    Shared scan context passed between all FuzzPhantom modules.
    Thread-safe via internal RLock.
    """

    # ── Input ────────────────────────────────────────────────────────────────
    target_domain: str = ""
    domains: list[str] = field(default_factory=list)

    # ── Options ──────────────────────────────────────────────────────────────
    wordlist_path: str = ""
    payload_files: list[str] = field(default_factory=list)
    output_formats: list[str] = field(default_factory=list)
    output_dir: str = "reports"
    crawl_depth: int = 3
    rate_limit: int = 50            # requests per second
    threads: int = 20
    timeout: int = 10
    user_agent: str = (
        "Mozilla/5.0 (compatible; FuzzPhantom/1.0; +https://github.com/fuzzphantom)"
    )
    proxy: str | None = None        # e.g. "http://127.0.0.1:8080"
    dry_run: bool = False
    verbose: bool = False
    smart_wordlist: bool = False

    # ── Discovered data ──────────────────────────────────────────────────────
    subdomains: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    parameterized_urls: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    smart_wordlist_terms: list[str] = field(default_factory=list)

    # ── Findings ─────────────────────────────────────────────────────────────
    findings: list[Finding] = field(default_factory=list)

    # ── Internal ─────────────────────────────────────────────────────────────
    db_path: str = field(default="", init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self) -> None:
        import os
        from pathlib import Path
        os.makedirs(self.output_dir, exist_ok=True)
        sanitized_target = self.target_domain.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        if not sanitized_target:
            sanitized_target = "unknown"
        self.db_path = str(Path(self.output_dir) / f"scan_{sanitized_target}.db")
        self._init_db()

    def _init_db(self) -> None:
        import sqlite3
        with self._lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS subdomains (
                        subdomain TEXT UNIQUE
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS crawled_urls (
                        url TEXT UNIQUE
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS parameterized_urls (
                        url TEXT UNIQUE
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS api_endpoints (
                        url TEXT UNIQUE
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS js_files (
                        url TEXT UNIQUE
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        category TEXT,
                        url TEXT,
                        parameter TEXT,
                        payload TEXT,
                        status_code INTEGER,
                        original_status INTEGER,
                        response_length INTEGER,
                        original_length INTEGER,
                        severity TEXT,
                        detail TEXT,
                        evidence TEXT
                    )
                """)
                conn.commit()
                conn.close()
            except Exception:
                pass

    def add_subdomain(self, subdomain: str) -> None:
        with self._lock:
            if subdomain not in self.subdomains:
                self.subdomains.append(subdomain)
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.db_path)
                    conn.execute("INSERT OR IGNORE INTO subdomains (subdomain) VALUES (?)", (subdomain,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def add_url(self, url: str) -> None:
        with self._lock:
            if url not in self.crawled_urls:
                self.crawled_urls.append(url)
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.db_path)
                    conn.execute("INSERT OR IGNORE INTO crawled_urls (url) VALUES (?)", (url,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def add_parameterized_url(self, url: str) -> None:
        with self._lock:
            if url not in self.parameterized_urls:
                self.parameterized_urls.append(url)
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.db_path)
                    conn.execute("INSERT OR IGNORE INTO parameterized_urls (url) VALUES (?)", (url,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def add_api_endpoint(self, endpoint: str) -> None:
        with self._lock:
            if endpoint not in self.api_endpoints:
                self.api_endpoints.append(endpoint)
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.db_path)
                    conn.execute("INSERT OR IGNORE INTO api_endpoints (url) VALUES (?)", (endpoint,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def add_js_file(self, url: str) -> None:
        with self._lock:
            if url not in self.js_files:
                self.js_files.append(url)
                try:
                    import sqlite3
                    conn = sqlite3.connect(self.db_path)
                    conn.execute("INSERT OR IGNORE INTO js_files (url) VALUES (?)", (url,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
            try:
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                conn.execute("""
                    INSERT INTO findings (
                        category, url, parameter, payload, status_code,
                        original_status, response_length, original_length, severity, detail, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.category,
                    finding.url,
                    finding.parameter,
                    finding.payload,
                    finding.status_code,
                    finding.original_status,
                    finding.response_length,
                    finding.original_length,
                    finding.severity,
                    finding.detail,
                    finding.evidence
                ))
                conn.commit()
                conn.close()
            except Exception:
                pass

    def summary(self) -> dict[str, int]:
        return {
            "subdomains": len(self.subdomains),
            "crawled_urls": len(self.crawled_urls),
            "parameterized_urls": len(self.parameterized_urls),
            "api_endpoints": len(self.api_endpoints),
            "js_files": len(self.js_files),
            "findings": len(self.findings),
        }

