"""Long-term scan history in SQLite.

The Redis ledger is the live source of truth and expires finished scans after
7 days. Every finished scan is archived here (no expiry) as one summary row plus
one row per finding. Evidence and response bodies are never stored.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vts_common.lifecycle import ScanStatus
from vts_common.service import log_event

TERMINAL_STATUSES = {
    ScanStatus.SUCCEEDED,
    ScanStatus.FAILED,
    ScanStatus.TIMED_OUT,
    ScanStatus.CANCELED,
}
SEVERITIES = ("critical", "high", "medium", "low", "info")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id          TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    mode             TEXT NOT NULL,
    exec_mode        TEXT,
    status           TEXT NOT NULL,
    outcome_code     TEXT,
    actor            TEXT,
    created_at       TEXT NOT NULL,
    completed_at     TEXT,
    duration_seconds INTEGER,
    revision         INTEGER,
    assets           INTEGER NOT NULL DEFAULT 0,
    findings         INTEGER NOT NULL DEFAULT 0,
    verified         INTEGER NOT NULL DEFAULT 0,
    execution        INTEGER NOT NULL DEFAULT 0,
    critical         INTEGER NOT NULL DEFAULT 0,
    high             INTEGER NOT NULL DEFAULT 0,
    medium           INTEGER NOT NULL DEFAULT 0,
    low              INTEGER NOT NULL DEFAULT 0,
    info             INTEGER NOT NULL DEFAULT 0,
    approvals_json   TEXT NOT NULL DEFAULT '{}',
    stages_json      TEXT NOT NULL DEFAULT '{}',
    archived_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_finding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scan_history(scan_id) ON DELETE CASCADE,
    template_id TEXT,
    name        TEXT,
    severity    TEXT NOT NULL,
    url         TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_completed ON scan_history(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_target ON scan_history(target);
CREATE INDEX IF NOT EXISTS idx_history_status ON scan_history(status);
CREATE INDEX IF NOT EXISTS idx_finding_scan ON scan_finding(scan_id);
"""

_SUMMARY_COLUMNS = (
    "scan_id, target, mode, exec_mode, status, outcome_code, actor, created_at, "
    "completed_at, duration_seconds, revision, assets, findings, verified, execution, "
    "critical, high, medium, low, info"
)


def history_record(snapshot, report: dict, actor: str | None) -> dict[str, Any]:
    """Flatten a scan snapshot + its aggregate report into one archivable record."""
    return {
        **report,
        "exec_mode": snapshot.exec_mode,
        "outcome_code": (snapshot.outcome or {}).get("code"),
        "actor": actor,
    }


def _summary_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    return {
        "scan_id": data["scan_id"],
        "target": data["target"],
        "mode": data["mode"],
        "exec_mode": data["exec_mode"],
        "status": data["status"],
        "outcome_code": data["outcome_code"],
        "actor": data["actor"],
        "created_at": data["created_at"],
        "completed_at": data["completed_at"],
        "duration_seconds": data["duration_seconds"],
        "revision": data["revision"],
        "summary": {
            "assets": data["assets"],
            "findings": data["findings"],
            "verified": data["verified"],
            "execution": data["execution"],
        },
        "findings_by_severity": {name: data[name] for name in SEVERITIES},
    }


class HistoryStore:
    """SQLite-backed archive. The file and schema are created on first use."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._ready = False

    def _connect(self) -> sqlite3.Connection:
        if not self._ready:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        if not self._ready:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(SCHEMA)
            self._ready = True
        return db

    # ---- synchronous API (used by tests and wrapped for the event loop)
    def save(self, record: dict[str, Any]) -> None:
        summary = record["summary"]
        severity = record["findings_by_severity"]
        db = self._connect()
        try:
            with db:
                db.execute("DELETE FROM scan_history WHERE scan_id = ?", (record["scan_id"],))
                db.execute(
                    f"INSERT INTO scan_history ({_SUMMARY_COLUMNS}, approvals_json, stages_json, archived_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        record["scan_id"], record["target"], record["mode"], record.get("exec_mode"),
                        record["status"], record.get("outcome_code"), record.get("actor"),
                        record["created_at"], record.get("completed_at"), record.get("duration_seconds"),
                        record.get("revision"),
                        summary["assets"], summary["findings"], summary["verified"], summary["execution"],
                        *(severity.get(name, 0) for name in SEVERITIES),
                        json.dumps(record.get("approvals", {})),
                        json.dumps(record.get("stages", {})),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                db.executemany(
                    "INSERT INTO scan_finding (scan_id, template_id, name, severity, url) VALUES (?,?,?,?,?)",
                    [
                        (record["scan_id"], f.get("template_id"), f.get("name"), f.get("severity", "info"), f.get("url"))
                        for f in record.get("findings", [])
                    ],
                )
        finally:
            db.close()

    def has(self, scan_id: str) -> bool:
        db = self._connect()
        try:
            return db.execute("SELECT 1 FROM scan_history WHERE scan_id = ?", (scan_id,)).fetchone() is not None
        finally:
            db.close()

    def list(
        self,
        status: str | None = None,
        target: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        where, params = [], []
        if status:
            where.append("status = ?")
            params.append(status)
        if target:
            where.append("LOWER(target) LIKE ? ESCAPE '\\'")
            escaped = target.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        db = self._connect()
        try:
            total = db.execute(f"SELECT COUNT(*) FROM scan_history {clause}", params).fetchone()[0]
            rows = db.execute(
                f"SELECT {_SUMMARY_COLUMNS} FROM scan_history {clause} "
                "ORDER BY COALESCE(completed_at, created_at) DESC, scan_id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return [_summary_row(row) for row in rows], total
        finally:
            db.close()

    def get(self, scan_id: str) -> dict[str, Any] | None:
        db = self._connect()
        try:
            row = db.execute(
                f"SELECT {_SUMMARY_COLUMNS}, approvals_json, stages_json, archived_at "
                "FROM scan_history WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            detail = _summary_row(row)
            detail["approvals"] = json.loads(row["approvals_json"])
            detail["stages"] = json.loads(row["stages_json"])
            detail["archived_at"] = row["archived_at"]
            order = " ".join(f"WHEN '{name}' THEN {i}" for i, name in enumerate(SEVERITIES))
            detail["findings"] = [
                dict(f)
                for f in db.execute(
                    "SELECT template_id, name, severity, url FROM scan_finding WHERE scan_id = ? "
                    f"ORDER BY CASE severity {order} ELSE 99 END, id",
                    (scan_id,),
                )
            ]
            return detail
        finally:
            db.close()

    # ---- async wrappers
    async def asave(self, record):
        await asyncio.to_thread(self.save, record)

    async def ahas(self, scan_id):
        return await asyncio.to_thread(self.has, scan_id)

    async def alist(self, **kwargs):
        return await asyncio.to_thread(lambda: self.list(**kwargs))

    async def aget(self, scan_id):
        return await asyncio.to_thread(self.get, scan_id)


async def archive_terminal_scans(ledger, store: HistoryStore) -> int:
    """Archive every finished scan that is not stored yet. Returns how many were added."""
    from .main import build_report  # local import: main imports this module

    added = 0
    cursor = None
    while True:
        page = await ledger.list_scans(None, cursor, 100)
        for snapshot in page.items:
            if snapshot.status not in TERMINAL_STATUSES or await store.ahas(snapshot.scan_id):
                continue
            findings, result_cursor = [], None
            while True:
                results = await ledger.list_results(snapshot.scan_id, "findings", result_cursor, 100)
                findings.extend(results.items)
                if results.next_cursor is None:
                    break
                result_cursor = results.next_cursor
            actor = await ledger.redis.hget(ledger.key(f"scan:{snapshot.scan_id}:meta"), "actor")
            await store.asave(history_record(snapshot, build_report(snapshot, findings), actor))
            added += 1
        if page.next_cursor is None:
            return added
        cursor = page.next_cursor


async def history_archiver(ledger, store: HistoryStore, interval_seconds: float = 5.0) -> None:
    while True:
        try:
            added = await archive_terminal_scans(ledger, store)
            if added:
                log_event("info", f"archived {added} finished scan(s) to history")
        except Exception as exc:  # keep archiving after a transient Redis/disk error
            log_event("error", f"history archiving failed: {type(exc).__name__}")
        await asyncio.sleep(interval_seconds)
