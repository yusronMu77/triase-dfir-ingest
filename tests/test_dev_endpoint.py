import pytest
from astria_common.envguard import EnvironmentGuardError
from fastapi.testclient import TestClient

from astria_ingest.main import build_app
from astria_ingest.settings import Settings

PATH = "/internal/v1/dev/sample-event"


def test_dev_endpoint_absent_by_default() -> None:
    with TestClient(build_app(Settings(env="test"))) as client:
        assert client.post(PATH, json={}).status_code == 404


def test_dev_endpoint_requires_service_token_when_enabled() -> None:
    with TestClient(build_app(Settings(env="dev", dev_endpoints=True))) as client:
        resp = client.post(PATH, json={})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "TOKEN_WAJIB"


@pytest.mark.parametrize("env", ["demo", "prod", "test"])
def test_dev_endpoint_refused_outside_dev(env: str) -> None:
    with pytest.raises(EnvironmentGuardError):
        build_app(Settings(env=env, dev_endpoints=True))
