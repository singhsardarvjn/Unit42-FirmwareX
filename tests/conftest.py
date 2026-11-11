import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

KEY = b"unit-test-key-0123456789abcdef-xx"


@pytest.fixture()
def settings(tmp_path):
    s = Settings(data_dir=tmp_path / "data", inline=True)
    s.ensure_dirs()
    return s


@pytest.fixture()
def client(settings):
    return TestClient(create_app(settings))
