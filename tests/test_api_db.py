"""API dengan PostgreSQL sungguhan: impor lewat HTTP, worker, lalu baca bukti dan alert seperti verifier dan triage.

Dilewati tanpa `ASTRIA_TEST_DATABASE_URL`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
import uuid
from pathlib import Path

import pytest
from astria_common.auth import (
    JwksSource,
    ServiceTokenVerifier,
    SigningKey,
    issue_service_token,
    load_or_create_signing_key,
)
from astria_common.db import Database
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import text

from astria_ingest.main import build_app
from astria_ingest.settings import Settings

DB_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
FIXTURES = Path(__file__).parent / "fixtures" / "samples"

pytestmark = [
    pytest.mark.skipif(not DB_URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi"),
]


async def _drop(schema: str) -> None:
    db = Database(SecretStr(DB_URL or ""))
    await db.start()
    await db.wait_ready(10)
    async with db.engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    await db.stop()


@pytest.fixture
def setup(tmp_path: Path):
    key: SigningKey = load_or_create_signing_key(tmp_path / "identity.pem")
    verifier = ServiceTokenVerifier(JwksSource("http://identity.invalid", fetch=lambda: {"keys": [key.public_jwk()]}))
    root = tmp_path / "import"
    shutil.copytree(FIXTURES, root)
    schema = f"t_{uuid.uuid4().hex[:8]}"
    settings = Settings(
        env="test",
        database_url=SecretStr(DB_URL or ""),
        db_schema=schema,
        import_root=root,
        evidence_store=tmp_path / "gudang",
    )
    with TestClient(build_app(settings, token_verifier=verifier)) as client:
        deadline = time.monotonic() + 15
        while client.get("/ready").status_code != 200 and time.monotonic() < deadline:
            time.sleep(0.2)
        yield client, key
    asyncio.run(_drop(schema))


def _auth(key: SigningKey, subject: str) -> dict[str, str]:
    token, _ = issue_service_token(key, subject=subject, audience="svc:ingest")
    return {"Authorization": f"Bearer {token}"}


def _wait_done(client: TestClient, key: SigningKey, job_id: str) -> dict:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        job = client.get(f"/svc/v1/imports/{job_id}", headers=_auth(key, "svc:api")).json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.1)
    raise AssertionError("job tidak selesai")


def test_import_then_read_like_verifier_and_triage(setup) -> None:
    client, key = setup
    body = {"adapter": "hayabusa", "path_ref": "chains/svc-backup.jsonl"}
    first = client.post("/svc/v1/imports", json=body, headers=_auth(key, "svc:seed"))
    assert first.status_code == 202
    job_id = first.json()["job_id"]
    assert _wait_done(client, key, job_id)["status"] == "completed"

    again = client.post("/svc/v1/imports", json=body, headers=_auth(key, "svc:api"))
    assert again.status_code == 200
    assert again.json()["job_id"] == job_id

    batch = client.post(
        "/svc/v1/evidence:batch",
        json={"ids": ["EV-hb01-000024", "EV-hb01-000001", "EV-hb99-000001"]},
        headers=_auth(key, "svc:verifier"),
    ).json()
    assert [i["evidence_id"] for i in batch["items"]] == ["EV-hb01-000001", "EV-hb01-000024"]
    assert batch["not_found"] == ["EV-hb99-000001"]
    assert "Sintetis-Bukan-Rahasia1" not in str(batch)
    assert all(len(i["record_sha256"]) == 64 for i in batch["items"])

    page1 = client.get(f"/svc/v1/jobs/{job_id}/alerts?limit=20", headers=_auth(key, "svc:triage")).json()
    assert [a["record_no"] for a in page1["items"]] == list(range(1, 21))
    assert page1["next_cursor"] == "20"
    page2 = client.get(
        f"/svc/v1/jobs/{job_id}/alerts?limit=20&cursor={page1['next_cursor']}", headers=_auth(key, "svc:triage")
    ).json()
    assert [a["record_no"] for a in page2["items"]] == list(range(21, 32))
    assert page2["next_cursor"] is None
    ranged = client.get(f"/svc/v1/jobs/{job_id}/alerts?from=24&to=26", headers=_auth(key, "svc:triage")).json()
    assert [a["evidence_ids"] for a in ranged["items"]] == [["EV-hb01-000024"], ["EV-hb01-000025"], ["EV-hb01-000026"]]
    assert any("S0039" in a["techniques"] for a in ranged["items"])


@pytest.mark.parametrize(
    ("ref", "status", "code"),
    [
        ("../rahasia.txt", 422, "PATH_TIDAK_VALID"),
        ("tidak-ada.jsonl", 422, "PATH_TIDAK_ADA"),
        ("chains", 422, "PATH_BUKAN_BERKAS"),
    ],
)
def test_import_rejections(setup, ref: str, status: int, code: str) -> None:
    client, key = setup
    resp = client.post("/svc/v1/imports", json={"adapter": "hayabusa", "path_ref": ref}, headers=_auth(key, "svc:api"))
    assert resp.status_code == status
    assert resp.json()["error"]["code"] == code


def test_unknown_job_is_404(setup) -> None:
    client, key = setup
    resp = client.get("/svc/v1/imports/ING-20261110-00000000", headers=_auth(key, "svc:api"))
    assert resp.status_code == 404


def test_import_rejects_unexpected_sha256(setup) -> None:
    client, key = setup
    body = {"adapter": "hayabusa", "path_ref": "chains/svc-backup.jsonl", "expected_sha256": "0" * 64}
    resp = client.post("/svc/v1/imports", json=body, headers=_auth(key, "svc:api"))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "SHA256_TIDAK_COCOK"
