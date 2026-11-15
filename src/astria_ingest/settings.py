"""Konfigurasi ingest dari env `ASTRIA_*`."""

from pathlib import Path

from astria_common.settings import AstriaSettings
from pydantic import Field

from astria_ingest.limits import MIB, Limits


class Settings(AstriaSettings):
    service_name: str = "ingest"

    dev_endpoints: bool = False
    """Aktifkan `POST /internal/v1/dev/sample-event`. Pagar ASTRIA_ENV menolak nilai True di luar dev."""

    import_root: Path = Path("/data/import")
    """Folder impor (mount read-only). `path_ref` dari pemanggil selalu relatif terhadap folder ini (K15)."""

    evidence_store: Path = Path("/var/lib/astria/ingest/evidence")
    """Gudang bukti content-addressed milik ingest (read-write, K21). Induknya `/var/lib/astria/ingest` sudah ada di
    image (milik uid 10001), jadi cukup satu volume di sana; rootfs kontainer read-only."""

    max_file_bytes: int = Field(1024 * MIB, ge=1)
    max_line_bytes: int = Field(1 * MIB, ge=1)
    max_lines: int = Field(999_999, ge=1, le=999_999)
    max_depth: int = Field(32, ge=1)

    batch_size: int = Field(500, ge=1, le=5000)
    """Baris fisik per batch: satu transaksi dan satu event `evidence.ingested` per batch (K8)."""

    reject_ratio: float = Field(0.5, ge=0.0, le=1.0)
    """Berkas ditolak bila proporsi baris rusak melebihi nilai ini (K9)."""

    import_callers: list[str] = ["svc:api", "svc:seed", "svc:devtools"]
    """Boleh memulai impor dan membaca status job (K18). `svc:devtools` sementara sampai `svc:seed` ada (K20)."""

    read_callers: list[str] = ["svc:triage", "svc:verifier", "svc:api", "svc:dfir"]
    """Boleh membaca bukti dan alert (K18)."""

    collector_enabled: bool = False
    collector_keys: dict[str, Path] = Field(default_factory=dict)
    """Key ID -> mounted secret file containing a 32-byte or longer hex HMAC key. Never inline keys."""
    collector_age_recipient: str | None = None
    collector_archive_root: Path = Path("/var/lib/astria/ingest/acquisitions")
    collector_max_archive_bytes: int = Field(20 * 1024 * MIB, ge=128)
    collector_upload_timeout_s: int = Field(3600, ge=1, le=86400)
    device_scan_users: list[str] = Field(default_factory=list)
    """Explicitly authorized identity user IDs; admin/dfir role alone is insufficient."""

    @property
    def limits(self) -> Limits:
        return Limits(
            max_file_bytes=self.max_file_bytes,
            max_line_bytes=self.max_line_bytes,
            max_lines=self.max_lines,
            max_depth=self.max_depth,
        )
