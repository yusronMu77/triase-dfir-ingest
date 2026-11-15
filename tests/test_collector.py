"""Real HTTP handlers, PostgreSQL transactions, HMAC, consent and encrypted custody.

Set ASTRIA_TEST_DATABASE_URL to a disposable PostgreSQL database. Synthetic age-shaped
bytes here exercise custody only and deliberately do not prove successful decryption.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from astria_common.auth import JwksSource, ServiceTokenVerifier, issue_service_token, load_or_create_signing_key
from astria_common.db import Database
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select, text, update

from astria_ingest import collector_store as tables
from astria_ingest.collector import AGE_MAGIC
from astria_ingest.main import build_app
from astria_ingest.settings import Settings

DB_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
KEY = hashlib.sha256(b"synthetic-collector-test-only").digest()
KEY_ID = "test-collector"
BASE = "/svc/v1/collector"
JOB_ID = "SJ-test-1"
ARCHIVE = AGE_MAGIC + b"synthetic-custody-test-not-real-age-encryption" * 4
SCOPE = {
    "backup": "none",
    "download": "non-system",
    "remove_trusted": "yes",
    "intrusion_logs": "no",
    "hash_files": "no",
    "browser_history": "no",
    "magisk_modules": "no",
}


def signed(method: str, path: str, body: bytes = b"", *, key_id: str = KEY_ID, key: bytes = KEY, ts: int | None = None):
    stamp = str(ts if ts is not None else int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, stamp, key_id, digest]).encode()
    return {
        "X-Astria-Key-Id": key_id,
        "X-Astria-Timestamp": stamp,
        "X-Astria-Signature": hmac.new(key, canonical, hashlib.sha256).hexdigest(),
    }


def provision_body():
    expiration = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    serial_hash = hashlib.sha256(b"SYNTHETIC_SERIAL").hexdigest()
    return {
        "collector_key_id": KEY_ID,
        "job": {
            "job_id": JOB_ID,
            "consent_id": "CS-test-1",
            "scope_flags": SCOPE,
            "device": {"label": "Synthetic phone", "serial_tail": "RIAL", "serial_sha256": serial_hash},
            "expires_at": expiration,
            "trace_id": "1" * 32,
            "owner_ref": "synthetic-owner",
            "purpose": "Synthetic test only",
            "limitations": "No real device or evidence",
        },
        "consent": {
            "owner_ref": "synthetic-owner",
            "purpose": "Synthetic test only",
            "basis": "explicit_owner_consent",
            "given_at": datetime.now(UTC).isoformat(),
            "record_ref": "synthetic-consent-record",
            "record_sha256": hashlib.sha256(b"test consent").hexdigest(),
            "scope_flags": SCOPE,
            "device_serial_sha256": serial_hash,
            "expires_at": expiration,
            "explicit": True,
        },
    }


@pytest.fixture
def setup(tmp_path: Path):
    if not DB_URL:
        pytest.skip("ASTRIA_TEST_DATABASE_URL required for PostgreSQL ingress tests")
    key_file = tmp_path / "hmac-key"
    key_file.write_text(KEY.hex(), encoding="ascii")
    key_file.chmod(0o600)
    signing = load_or_create_signing_key(tmp_path / "identity.pem")
    verifier = ServiceTokenVerifier(JwksSource("http://unused.invalid", fetch=lambda: {"keys": [signing.public_jwk()]}))
    schema = "collector_" + uuid.uuid4().hex[:10]
    settings = Settings(
        env="test",
        database_url=SecretStr(DB_URL),
        db_schema=schema,
        collector_enabled=True,
        collector_keys={KEY_ID: key_file, "other-collector": key_file},
        collector_age_recipient="age1" + "q" * 58,
        collector_archive_root=tmp_path / "archives",
        device_scan_users=["test-authorizer"],
    )
    options = {"loop_factory": asyncio.SelectorEventLoop} if os.name == "nt" else {}
    with TestClient(build_app(settings, token_verifier=verifier), backend_options=options) as client:
        deadline = time.monotonic() + 15
        while client.get("/ready").status_code != 200:
            assert time.monotonic() < deadline, "database readiness failed"
            time.sleep(0.05)

        def manager_auth(*, user="test-authorizer", roles=None, subject="svc:api"):
            token, _ = issue_service_token(
                signing,
                subject=subject,
                audience="svc:ingest",
                act={"sub": user, "roles": roles if roles is not None else ["dfir"]},
            )
            return {"Authorization": "Bearer " + token}

        yield client, settings, manager_auth

    async def cleanup():
        db = Database(SecretStr(DB_URL))
        await db.start()
        await db.wait_ready(10)
        async with db.engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await db.stop()

    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(cleanup())


def prepare(setup):
    client, _, auth = setup
    response = client.post("/svc/v1/device-scans", json=provision_body(), headers=auth())
    assert response.status_code == 201, response.text
    return client


def upload(client, data=ARCHIVE, *, key_id=KEY_ID, digest=None, length=None):
    path = f"{BASE}/acquisitions/{JOB_ID}"
    headers = signed("PUT", path, data, key_id=key_id)
    headers.update(
        {
            "X-Archive-Sha256": digest or hashlib.sha256(data).hexdigest(),
            "Content-Length": str(len(data) if length is None else length),
        }
    )
    if digest:
        stamp = headers["X-Astria-Timestamp"]
        canonical = "\n".join(["PUT", path, stamp, key_id, digest]).encode()
        headers["X-Astria-Signature"] = hmac.new(KEY, canonical, hashlib.sha256).hexdigest()
    return client.put(path, content=data, headers=headers)


def progress(client, stage):
    path = f"{BASE}/jobs/{JOB_ID}/progress"
    data = json.dumps({"stage": stage}).encode()
    return client.post(path, content=data, headers=signed("POST", path, data))


def test_complete_custody_workflow_and_idempotent_retry(setup):
    client = prepare(setup)
    config = client.get(f"{BASE}/config", headers=signed("GET", f"{BASE}/config")).json()
    assert config["age_recipient_sha256"] == hashlib.sha256(config["age_recipient"].encode()).hexdigest()
    job = client.get(f"{BASE}/jobs/next", headers=signed("GET", f"{BASE}/jobs/next"))
    assert job.status_code == 200 and job.json()["job_id"] == JOB_ID
    assert progress(client, "selesai").status_code == 409
    for stage in ("perangkat_terdeteksi", "mengambil", "mengemas", "mengunggah"):
        assert progress(client, stage).status_code == 204
    receipt = upload(client)
    assert receipt.status_code == 201, receipt.text
    assert receipt.json()["status"] == "received"
    assert receipt.json()["metadata_status"] == "pending_verification"
    assert upload(client).json() == receipt.json()
    root = setup[1].collector_archive_root
    assert len(list(root.glob("*.zip.age"))) == 1
    assert next(root.glob("*.zip.age")).read_bytes() == ARCHIVE
    assert not list(root.glob("*.tmp"))
    assert progress(client, "selesai").status_code == 204
    assert client.get(f"{BASE}/jobs/next", headers=signed("GET", f"{BASE}/jobs/next")).status_code == 204


@pytest.mark.parametrize(
    "kwargs", [{"ts": 0}, {"ts": int(time.time()) + 3600}, {"key": b"wrong"}, {"key_id": "unknown"}]
)
def test_invalid_hmac_or_clock_skew(setup, kwargs):
    client = setup[0]
    path = f"{BASE}/config"
    response = client.get(path, headers=signed("GET", path, **kwargs))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SIGNATURE_INVALID"


@pytest.mark.parametrize("kwargs", [{"user": "other-user"}, {"roles": ["analis"]}, {"subject": "svc:gateway"}])
def test_management_authorization_requires_user_grant_and_role(setup, kwargs):
    client, _, auth = setup
    assert client.post("/svc/v1/device-scans", json=provision_body(), headers=auth(**kwargs)).status_code == 403


def test_consent_is_explicit_bound_and_unique(setup):
    client, _, auth = setup
    body = provision_body()
    body["consent"]["explicit"] = False
    assert client.post("/svc/v1/device-scans", json=body, headers=auth()).status_code in (400, 422)
    body = provision_body()
    body["consent"]["device_serial_sha256"] = "0" * 64
    assert client.post("/svc/v1/device-scans", json=body, headers=auth()).status_code in (400, 422)
    prepare(setup)
    assert client.post("/svc/v1/device-scans", json=provision_body(), headers=auth()).status_code == 409


def test_revocation_blocks_all_collector_job_operations(setup):
    client = prepare(setup)
    assert client.post(f"/svc/v1/device-scans/{JOB_ID}/revoke", headers=setup[2]()).status_code == 204
    assert progress(client, "mengambil").status_code == 403
    assert upload(client).status_code == 403
    assert client.get(f"{BASE}/jobs/next", headers=signed("GET", f"{BASE}/jobs/next")).status_code == 204


def test_job_bound_to_specific_collector_key(setup):
    client = prepare(setup)
    assert upload(client, key_id="other-collector").status_code == 404
    assert (
        client.get(
            f"{BASE}/jobs/next", headers=signed("GET", f"{BASE}/jobs/next", key_id="other-collector")
        ).status_code
        == 204
    )


@pytest.mark.parametrize(
    "data,digest,length,status",
    [
        (ARCHIVE, "0" * 64, None, 422),
        (ARCHIVE, None, len(ARCHIVE) + 1, 422),
        (ARCHIVE, None, len(ARCHIVE) - 1, 422),
        (b"plain evidence" * 20, None, None, 422),
        (ARCHIVE, None, 30 * 1024**3, 413),
    ],
)
def test_invalid_archive_never_committed(setup, data, digest, length, status):
    client = prepare(setup)
    assert upload(client, data, digest=digest, length=length).status_code == status
    assert not list(setup[1].collector_archive_root.glob("*.zip.age"))
    assert not list(setup[1].collector_archive_root.glob("*.tmp"))


def test_different_archive_cannot_replace_received_evidence(setup):
    client = prepare(setup)
    assert upload(client).status_code == 201
    assert upload(client, ARCHIVE + b"different").status_code == 409
    assert next(setup[1].collector_archive_root.glob("*.zip.age")).read_bytes() == ARCHIVE


def test_progress_rejects_backward_stages(setup):
    client = prepare(setup)
    assert progress(client, "mengemas").status_code == 204
    assert progress(client, "mengambil").status_code == 409


def test_signed_query_is_bound(setup):
    client = setup[0]
    path = f"{BASE}/config"
    assert client.get(path + "?tamper=1", headers=signed("GET", path)).status_code == 401
    assert client.get(path + "?x=1", headers=signed("GET", path + "?x=1")).status_code == 200


def test_default_disabled():
    with TestClient(build_app(Settings(env="test"))) as client:
        assert client.get(f"{BASE}/config").status_code == 404


def test_expiration_and_recovery_after_ack(setup):
    client = prepare(setup)
    first = upload(client)
    assert first.status_code == 201

    async def expire():
        settings = setup[1]
        db = Database(settings.database_url, schema=settings.db_schema)
        await db.start()
        await db.wait_ready(10)
        async with db.engine.begin() as conn:
            await conn.execute(update(tables.job).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
            assert (await conn.execute(select(tables.acquisition.c.job_id))).scalar_one() == JOB_ID
        await db.stop()

    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(expire())
    assert progress(client, "mengambil").status_code == 410
    assert upload(client).json() == first.json()
    assert upload(client, ARCHIVE + b"x").status_code == 409
