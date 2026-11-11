"""SQLite persistence: jobs/reports + append-only, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from .findings import utc_now

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    firmware_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    is_sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    report_json TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    firmware_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

PUBLIC_COLS = ("firmware_id", "job_id", "filename", "size", "sha256", "status", "stage", "progress",
               "error", "is_sample", "created_at", "started_at", "completed_at")


def _entry_hash(prev: str, ts: str, fid: str, action: str, details: str) -> str:
    return hashlib.sha256("|".join((prev, ts, fid, action, details)).encode()).hexdigest()


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=15)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # ---------------------------------------------------------------- jobs
    def create_job(self, firmware_id: str, filename: str, size: int, sha256: str, is_sample: bool = False) -> dict:
        job_id = str(uuid.uuid4())
        with self._conn() as c:
            c.execute(
                "INSERT INTO jobs (firmware_id, job_id, filename, size, sha256, status, stage, progress, is_sample, created_at)"
                " VALUES (?,?,?,?,?,'queued','queued',0,?,?)",
                (firmware_id, job_id, filename, size, sha256, int(is_sample), utc_now()),
            )
        return self.get_job(firmware_id)

    def update_job(self, firmware_id: str, **fields) -> None:
        allowed = {"status", "stage", "progress", "error", "started_at", "completed_at", "report_json"}
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE jobs SET {sets} WHERE firmware_id = ?", (*fields.values(), firmware_id))

    def get_job(self, firmware_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(f"SELECT {', '.join(PUBLIC_COLS)} FROM jobs WHERE firmware_id = ?", (firmware_id,)).fetchone()
        return self._public(row)

    def get_job_by_job_id(self, job_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(f"SELECT {', '.join(PUBLIC_COLS)} FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._public(row)

    def list_jobs(self, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(f"SELECT {', '.join(PUBLIC_COLS)} FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._public(r) for r in rows]

    def count_pending(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]

    def fail_interrupted(self) -> int:
        with self._conn() as c:
            cur = c.execute("UPDATE jobs SET status='failed', stage='failed', progress=100, error='Interrupted by server restart', "
                            "completed_at=? WHERE status IN ('queued','running')", (utc_now(),))
            return cur.rowcount

    def get_report(self, firmware_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT report_json FROM jobs WHERE firmware_id = ?", (firmware_id,)).fetchone()
        return json.loads(row["report_json"]) if row and row["report_json"] else None

    def save_report(self, firmware_id: str, report: dict) -> None:
        self.update_job(firmware_id, report_json=json.dumps(report, separators=(",", ":")))

    @staticmethod
    def _public(row) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        d["is_sample"] = bool(d["is_sample"])
        return d

    # ---------------------------------------------------------------- audit
    def audit(self, firmware_id: str, action: str, details: dict | None = None) -> dict:
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        ts = utc_now()
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            last = c.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["entry_hash"] if last else GENESIS
            h = _entry_hash(prev, ts, firmware_id, action, details_json)
            c.execute(
                "INSERT INTO audit_log (timestamp, firmware_id, action, details_json, prev_hash, entry_hash) VALUES (?,?,?,?,?,?)",
                (ts, firmware_id, action, details_json, prev, h),
            )
        return {"timestamp": ts, "action": action, "entry_hash": h}

    def audit_events(self, firmware_id: str | None = None, limit: int = 500) -> list[dict]:
        q, args = "SELECT * FROM audit_log", []
        if firmware_id:
            q += " WHERE firmware_id = ?"
            args.append(firmware_id)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
        return [{"id": r["id"], "timestamp": r["timestamp"], "firmware_id": r["firmware_id"], "action": r["action"],
                 "details": json.loads(r["details_json"]), "prev_hash": r["prev_hash"], "entry_hash": r["entry_hash"]}
                for r in rows]

    def verify_audit(self) -> dict:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        prev = GENESIS
        for r in rows:
            expected = _entry_hash(prev, r["timestamp"], r["firmware_id"], r["action"], r["details_json"])
            if r["prev_hash"] != prev or r["entry_hash"] != expected:
                return {"valid": False, "entries": len(rows), "broken_at": r["id"]}
            prev = r["entry_hash"]
        return {"valid": True, "entries": len(rows), "broken_at": None}
