import os
from pathlib import Path

import pytest

# Base SQLite dédiée aux tests, définie AVANT l'import de l'application.
_TEST_DB = Path(__file__).parent / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"
os.environ["SEED_DEMO"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

SAMPLES = Path(__file__).parents[2] / "samples"


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def nuclei_sample() -> str:
    return (SAMPLES / "nuclei-sample.jsonl").read_text(encoding="utf-8")


@pytest.fixture()
def trivy_sample() -> str:
    return (SAMPLES / "trivy-sample.json").read_text(encoding="utf-8")


def pytest_sessionfinish(session, exitstatus):
    engine.dispose()
    _TEST_DB.unlink(missing_ok=True)
