"""API tanpa basis data: token, daftar pemanggil, validasi masukan, dan bentuk item untuk verifier."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from astria_common.auth import (
    JwksSource,
    ServiceTokenVerifier,
    SigningKey,
    issue_service_token,
    load_or_create_signing_key,
)
from fastapi.testclient import TestClient

from astria_ingest.api import evidence_item
from astria_ingest.main import build_app
from astria_ingest.settings import Settings

JOB = "ING-20261110-ABCD1234"
IMPORT_BODY = {"adapter": "hayabusa", "path_ref": "chains/svc-backup.jsonl"}
ENDPOINTS = [
    ("post", "/svc/v1/imports", IMPORT_BODY, "import"),
    ("get", f"/svc/v1/imports/{JOB}", None, "import"),
    ("post", "/svc/v1/evidence:batch", {"ids": ["EV-hb01-000001"]}, "read"),
    ("get", f"/svc/v1/jobs/{JOB}/alerts", None, "read"),
]


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> SigningKey:
    return load_or_create_signing_key(tmp_path_factory.mktemp("kunci") / "identity.pem")


@pytest.fixture
def client(key: SigningKey, tmp_path: Path):
    verifier = ServiceTokenVerifier(JwksSource("http://identity.invalid", fetch=lambda: {"keys": [key.public_jwk()]}))
    settings = Settings(env="test", import_root=tmp_path, evidence_store=tmp_path / "gudang")
    with TestClient(build_app(settings, token_verifier=verifier)) as c:
        yield c


def _auth(key: SigningKey, subject: str, audience: str = "svc:ingest") -> dict[str, str]:
    token, _ = issue_service_token(key, subject=subject, audience=audience)
    return {"Authorization": f"Bearer {token}"}


def _call(client: TestClient, method: str, path: str, body: Any, headers: dict[str, str] | None = None):
    return client.request(method.upper(), path, json=body, headers=headers or {})


@pytest.mark.parametrize(("method", "path", "body", "_kind"), ENDPOINTS)
def test_token_required(client: TestClient, method: str, path: str, body: Any, _kind: str) -> None:
    resp = _call(client, method, path, body)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "TOKEN_WAJIB"


@pytest.mark.parametrize(("method", "path", "body", "_kind"), ENDPOINTS)
def test_wrong_audience(client: TestClient, key: SigningKey, method: str, path: str, body: Any, _kind: str) -> None:
    resp = _call(client, method, path, body, _auth(key, "svc:api", audience="svc:triage"))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "AUDIENS_SALAH"


@pytest.mark.parametrize(("method", "path", "body", "kind"), ENDPOINTS)
@pytest.mark.parametrize("subject", ["svc:notifier", "svc:triage", "svc:seed", "svc:verifier", "svc:dfir"])
def test_caller_allowlist(
    client: TestClient, key: SigningKey, method: str, path: str, body: Any, kind: str, subject: str
) -> None:
    allowed = {
        "import": {"svc:api", "svc:seed", "svc:devtools"},
        "read": {"svc:triage", "svc:verifier", "svc:api", "svc:dfir"},
    }
    resp = _call(client, method, path, body, _auth(key, subject))
    if subject in allowed[kind]:
        assert resp.status_code == 503  # lolos auth; tanpa basis data di uji ini
        assert resp.json()["error"]["code"] == "INGEST_TIDAK_SIAP"
    else:
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "PEMANGGIL_DITOLAK"


@pytest.mark.parametrize(
    "body",
    [
        {"adapter": "wazuh", "path_ref": "a.jsonl"},
        {"adapter": "hayabusa", "path_ref": ""},
        {"adapter": "hayabusa", "path_ref": "a" * 1025},
        {"adapter": "hayabusa", "path_ref": "a.jsonl", "lain": 1},
        {"adapter": "hayabusa"},
        {"adapter": "hayabusa", "path_ref": 5},
    ],
)
def test_import_body_validation(client: TestClient, key: SigningKey, body: dict[str, Any]) -> None:
    resp = client.post("/svc/v1/imports", json=body, headers=_auth(key, "svc:api"))
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDASI_GAGAL"


@pytest.mark.parametrize(
    "ids",
    [[], ["EV-hb01-000001"] * 501, ["ev-hb01-000001"], ["EV-hb01-000000"], ["EV-hb01-1"], [1]],
)
def test_evidence_batch_validation(client: TestClient, key: SigningKey, ids: list[Any]) -> None:
    resp = client.post("/svc/v1/evidence:batch", json={"ids": ids}, headers=_auth(key, "svc:verifier"))
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] in ("VALIDASI_GAGAL", "ID_TIDAK_VALID")


@pytest.mark.parametrize(
    "path",
    [
        "/svc/v1/imports/ING-1",
        "/svc/v1/imports/..%2F..%2Fetc",
        "/svc/v1/jobs/ING-20261110-abcd1234/alerts",
        f"/svc/v1/jobs/{JOB}/alerts?limit=501",
        f"/svc/v1/jobs/{JOB}/alerts?from=0",
        f"/svc/v1/jobs/{JOB}/alerts?cursor=-1",
    ],
)
def test_path_and_query_validation(client: TestClient, key: SigningKey, path: str) -> None:
    subject = "svc:api"
    assert client.get(path, headers=_auth(key, subject)).status_code in (400, 404)


# ---- bentuk item untuk verifier ----

_EVENT_DARI_KIND = re.compile(r"\.(\d{3,5})$")


def _verifier_parse_items(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Salinan logika `astria_verifier.evidence.parse_items` (verifier@main 2026-11-10) untuk uji kontrak konsumen."""
    out: dict[str, dict[str, Any]] = {}
    for item in payload.get("items", []):
        teks = [str(item[k]) for k in ("host", "account", "excerpt") if item.get(k)]
        if m := _EVENT_DARI_KIND.search(str(item.get("kind", ""))):
            teks.append(f"EventID={m.group(1)}")
        out[item["evidence_id"]] = {
            "sha256": item["record_sha256"],
            "fields": {str(k): str(v) for k, v in (item.get("fields") or {}).items()},
            "teks": tuple(teks),
        }
    return out


def test_evidence_item_matches_verifier_contract() -> None:
    row = SimpleNamespace(
        evidence_id="EV-hb01-000024",
        source_id="hb01",
        record_no=24,
        record_sha256="a" * 64,
        occurred_at=datetime(2026, 11, 10, 2, 24, 40, 118000, tzinfo=UTC),
        host="WS-ADM-04",
        account="svc-backup",
        kind="windows.security.4688",
        event_id=4688,
        rule_title="Proc Exec",
        details={"Cmdline": "net user adm-support Sintetis-Bukan-Rahasia1 /add", "PID": 4312, "User": "svc-backup"},
        extra={"ParentProcessName": "C:\\Windows\\System32\\cmd.exe"},
        injection_suspect=False,
    )
    payload = {"items": [evidence_item(row).model_dump()], "not_found": []}
    parsed = _verifier_parse_items(payload)["EV-hb01-000024"]
    assert parsed["sha256"] == "a" * 64
    assert "EventID=4688" in parsed["teks"]
    assert parsed["fields"]["User"] == "svc-backup"
    assert parsed["fields"]["PID"] == "4312"
    assert payload["items"][0]["occurred_at"] == "2026-11-10T02:24:40.118000Z"
    assert "Sintetis-Bukan-Rahasia1" not in str(payload)
    assert "raw" not in payload["items"][0]
