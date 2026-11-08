"""Rakit aplikasi ingest.

Tahap 0: komponen standar dan, khusus dev, endpoint yang menerbitkan `evidence.ingested` contoh lewat
outbox. Adapter Hayabusa, penyimpanan bukti, dan API baca bukti dibangun di Tahap 1.
"""

from astria_common.app import create_app
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_ingest import api, dev
from astria_ingest.settings import Settings


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    runtime = standard_runtime(settings)
    routers = [api.router]
    if settings.dev_endpoints:
        routers.append(dev.router)
    return create_app(settings, components=runtime.components, routers=routers)
