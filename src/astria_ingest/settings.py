"""Konfigurasi ingest dari env `ASTRIA_*`."""

from astria_common.settings import AstriaSettings


class Settings(AstriaSettings):
    service_name: str = "ingest"

    dev_endpoints: bool = False
    """Aktifkan `POST /internal/v1/dev/sample-event`. Pagar ASTRIA_ENV menolak nilai True di luar dev."""
