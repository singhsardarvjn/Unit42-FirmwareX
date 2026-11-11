from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("FIRMWAREX_DATA_DIR", ROOT / "data")))
    max_upload_bytes: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_UPLOAD", 100 * 1024 * 1024))
    max_extracted_bytes: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_EXTRACTED", 300 * 1024 * 1024))
    max_files: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_FILES", 20000))
    max_scan_file_bytes: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_SCAN_FILE", 8 * 1024 * 1024))
    max_elfs: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_ELFS", 1000))
    job_timeout_seconds: int = field(default_factory=lambda: _int("FIRMWAREX_JOB_TIMEOUT", 600))
    workers: int = field(default_factory=lambda: _int("FIRMWAREX_WORKERS", 2))
    max_pending_jobs: int = field(default_factory=lambda: _int("FIRMWAREX_MAX_PENDING", 8))
    inline: bool = False  # run jobs synchronously (used by tests)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "firmwarex.sqlite3"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def key_path(self) -> Path:
        return self.data_dir / "fingerprint.key"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.upload_dir, self.work_dir):
            d.mkdir(parents=True, exist_ok=True)

    def load_fingerprint_key(self) -> bytes:
        """Per-installation secret used to fingerprint discovered secrets (HMAC)."""
        self.ensure_dirs()
        if self.key_path.exists():
            key = self.key_path.read_bytes()
            if len(key) >= 32:
                return key
        key = secrets.token_bytes(32)
        self.key_path.write_bytes(key)
        return key
