"""Rakit aplikasi ingest.

Komponen standar (basis data, bus, relay outbox), tabel ingest (`store.metadata`), dan `ImportWorker` yang menjalankan
lintasan 2 impor di latar. Khusus dev: endpoint yang menerbitkan `evidence.ingested` contoh lewat outbox.
"""

from astria_common.app import create_app
from astria_common.auth import ServiceTokenVerifier
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_ingest import api, dev, store
from astria_ingest.jobs import ImportWorker
from astria_ingest.settings import Settings


def build_app(settings: Settings | None = None, *, token_verifier: ServiceTokenVerifier | None = None) -> FastAPI:
    settings = settings or Settings()
    runtime = standard_runtime(settings, metadata=[store.metadata])
    if runtime.db is not None:
        runtime.add(ImportWorker(runtime.db, settings))
    routers = [api.router]
    if settings.dev_endpoints:
        routers.append(dev.router)
    return create_app(settings, components=runtime.components, routers=routers, token_verifier=token_verifier)
