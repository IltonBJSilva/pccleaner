"""Histórico de varreduras e limpezas em SQLite (uma conexão por chamada + lock — thread-safe)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from pccleaner import config
from pccleaner.core.models import CleanReport, ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY, started_at REAL NOT NULL, finished_at REAL NOT NULL,
    duration REAL NOT NULL, files_scanned INTEGER DEFAULT 0, bytes_scanned INTEGER DEFAULT 0,
    findings INTEGER DEFAULT 0, recoverable_bytes INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
    cancelled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL, rule_id TEXT, name TEXT, path TEXT, category TEXT, app TEXT,
    safety TEXT, clean_mode TEXT, size_bytes INTEGER DEFAULT 0, file_count INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS cleans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, started_at REAL NOT NULL,
    finished_at REAL NOT NULL, duration REAL NOT NULL, freed_bytes INTEGER DEFAULT 0,
    files_removed INTEGER DEFAULT 0, errors INTEGER DEFAULT 0, cancelled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS clean_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clean_id INTEGER NOT NULL REFERENCES cleans(id) ON DELETE CASCADE,
    finding_id TEXT, path TEXT, freed INTEGER DEFAULT 0, files_removed INTEGER DEFAULT 0,
    files_skipped INTEGER DEFAULT 0, quarantined INTEGER DEFAULT 0, errors TEXT);
CREATE INDEX IF NOT EXISTS ix_clean_items_clean ON clean_items(clean_id);
"""


class HistoryDB:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else config.db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(str(self.path), timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

    def save_scan(self, result: ScanResult) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
            c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (result.scan_id, result.started_at, result.finished_at,
                       max(0.0, result.finished_at - result.started_at), result.files_scanned,
                       result.bytes_scanned, len(result.findings), result.recoverable_bytes,
                       len(result.errors), int(result.cancelled)))
            c.executemany(
                "INSERT INTO findings (scan_id, finding_id, rule_id, name, path, category, app, safety,"
                " clean_mode, size_bytes, file_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(result.scan_id, f.id, f.rule_id, f.name, f.path, f.category.value, f.app,
                  f.safety.value, f.clean_mode.value, f.size_bytes, f.file_count) for f in result.findings])

    def save_clean(self, report: CleanReport, scan_id: str | None = None) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO cleans (scan_id, started_at, finished_at, duration, freed_bytes, files_removed,"
                " errors, cancelled) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, report.started_at, report.finished_at, max(0.0, report.finished_at - report.started_at),
                 report.freed_bytes, report.files_removed, report.error_count, int(report.cancelled)))
            clean_id = int(cur.lastrowid)
            c.executemany(
                "INSERT INTO clean_items (clean_id, finding_id, path, freed, files_removed, files_skipped,"
                " quarantined, errors) VALUES (?,?,?,?,?,?,?,?)",
                [(clean_id, i.finding_id, i.path, i.freed_bytes, i.files_removed, i.files_skipped,
                  int(i.quarantined), "\n".join(i.errors)) for i in report.items])
        return clean_id

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT scan_id, started_at, duration, files_scanned, findings, recoverable_bytes,"
                             " cancelled FROM scans ORDER BY started_at DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r, cancelled=bool(r["cancelled"])) for r in rows]

    def last_scan(self) -> dict | None:
        s = self.list_scans(1)
        return s[0] if s else None

    def list_cleans(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id, scan_id, started_at, duration, freed_bytes, files_removed, errors,"
                             " cancelled FROM cleans ORDER BY started_at DESC, id DESC LIMIT ?",
                             (int(limit),)).fetchall()
        return [dict(r, cancelled=bool(r["cancelled"])) for r in rows]

    def clean_items(self, clean_id: int) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT finding_id, path, freed, files_removed, files_skipped, quarantined, errors"
                             " FROM clean_items WHERE clean_id = ? ORDER BY id", (int(clean_id),)).fetchall()
        return [dict(r, quarantined=bool(r["quarantined"]), errors=r["errors"] or "") for r in rows]

    def scan_findings(self, scan_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY size_bytes DESC",
                             (scan_id,)).fetchall()
        return [dict(r) for r in rows]
