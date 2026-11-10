"""Impor berkas dua lintasan (K8).

Lintasan 1 (`start_import`, sinkron di permintaan): penjaga path, salin streaming ke gudang + SHA-256, cek idempotensi,
pindai semua baris (parse + normalisasi) tanpa menyimpan, putuskan terima/tolak, lalu buat `raw_source` + `ingest_job`.

Lintasan 2 (`run_job`, latar): baca **salinan gudang** per `batch_size` baris fisik. Satu transaksi per batch: bukti,
alert, karantina, progres job, dan satu `evidence.ingested` di outbox. Job yang terhenti dilanjutkan dari batch terakhir
yang ter-commit (`last_record_no`); ID bukti dan ID event deterministik, jadi tidak ada data atau event ganda.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from astria_common.component import Check
from astria_common.db import Database
from astria_common.log import get_logger
from astria_common.outbox import enqueue
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from astria_ingest import events
from astria_ingest.adapters.hayabusa import (
    BARIS_TERLALU_PANJANG,
    FileFormatError,
    Line,
    LineError,
    iter_lines,
    parse_line,
)
from astria_ingest.hashing import batch_sha256, record_sha256, stream_sha256
from astria_ingest.ids import HAYABUSA_PREFIX, alert_id, evidence_id, source_code
from astria_ingest.limits import Limits
from astria_ingest.normalize import NormalizedAlert, normalize
from astria_ingest.paths import resolve_import_path
from astria_ingest.settings import Settings
from astria_ingest.store import (
    JOB_COMPLETED,
    JOB_COMPLETED_WITH_ERRORS,
    JOB_FAILED,
    JOB_PENDING,
    JOB_QUEUED,
    JOB_RUNNING,
    alert,
    alert_evidence,
    evidence,
    ingest_job,
    raw_source,
    rejected_record,
    source_seq,
)
from astria_ingest.store_files import StoredFile, copy_into_store, ensure_store, remove_from_store

log = get_logger(__name__)

FORMAT_TIDAK_VALID = "FORMAT_TIDAK_VALID"
GUDANG_TIDAK_KONSISTEN = "GUDANG_TIDAK_KONSISTEN"
JOB_GAGAL = "JOB_GAGAL"
ADAPTER_TIDAK_DIKENAL = "ADAPTER_TIDAK_DIKENAL"
MAX_ERROR_SAMPLES = 20
ADAPTERS = {"hayabusa": HAYABUSA_PREFIX}


class ImportRejected(Exception):
    """Impor ditolak di lintasan 1. `stats` tidak memuat isi baris."""

    def __init__(self, code: str, message: str, stats: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.stats = stats or {}


@dataclass
class ScanResult:
    total_lines: int = 0
    valid: int = 0
    blank: int = 0
    rejected: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)

    def add_error(self, record_no: int, code: str) -> None:
        self.rejected += 1
        if len(self.samples) < MAX_ERROR_SAMPLES:
            self.samples.append({"record_no": record_no, "code": code})

    def stats(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "valid": self.valid,
            "blank": self.blank,
            "rejected": self.rejected,
            "error_samples": self.samples,
        }


@dataclass(frozen=True)
class ImportOutcome:
    job_id: str
    source_id: str
    file_sha256: str
    status: str
    created: bool
    stats: dict[str, Any]


def _evaluate(line: Line, limits: Limits) -> NormalizedAlert | str | None:
    """Alert hasil normalisasi, kode galat, atau None untuk baris kosong."""
    if line.kind == "blank":
        return None
    if line.kind == "too_long":
        return BARIS_TERLALU_PANJANG
    try:
        return normalize(parse_line(line.raw, limits))
    except LineError as exc:
        return exc.code


def scan_file(path: Path, limits: Limits) -> ScanResult:
    """Pindai seluruh salinan gudang tanpa menyimpan apa pun. Melempar `FileFormatError` untuk galat seluruh berkas."""
    result = ScanResult()
    with path.open("rb") as fp:
        for line in iter_lines(fp, limits):
            result.total_lines = line.record_no
            outcome = _evaluate(line, limits)
            if outcome is None:
                result.blank += 1
            elif isinstance(outcome, str):
                result.add_error(line.record_no, outcome)
            else:
                result.valid += 1
    return result


def rejection_reason(scan: ScanResult, reject_ratio: float) -> str | None:
    checked = scan.valid + scan.rejected
    if scan.valid == 0:
        return "tidak ada baris yang sah"
    if checked and scan.rejected / checked > reject_ratio:
        return "proporsi baris rusak melebihi ambang"
    return None


def new_job_id() -> str:
    return f"ING-{datetime.now(UTC):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"


async def _existing(conn: AsyncConnection, file_sha256: str) -> ImportOutcome | None:
    row = (
        await conn.execute(
            select(ingest_job.c.job_id, ingest_job.c.status, ingest_job.c.stats, raw_source.c.source_id)
            .join(raw_source, raw_source.c.source_id == ingest_job.c.source_id)
            .where(raw_source.c.file_sha256 == file_sha256)
        )
    ).first()
    if row is None:
        return None
    return ImportOutcome(row.job_id, row.source_id, file_sha256, row.status, False, dict(row.stats))


async def start_import(
    engine: AsyncEngine, settings: Settings, *, adapter: str, path_ref: object, requested_by: str
) -> ImportOutcome:
    """Lintasan 1. Melempar `PathRejected`, `StoreError`, atau `ImportRejected`; tidak menulis apa pun bila ditolak."""
    prefix = ADAPTERS.get(adapter)
    if prefix is None:
        raise ImportRejected(ADAPTER_TIDAK_DIKENAL, "adapter tidak dikenal")
    limits = settings.limits
    resolved = await asyncio.to_thread(resolve_import_path, settings.import_root, path_ref)
    store_dir = await asyncio.to_thread(ensure_store, settings.evidence_store)
    stored: StoredFile = await asyncio.to_thread(
        copy_into_store, resolved.path, store_dir, max_file_bytes=limits.max_file_bytes
    )

    async with engine.connect() as conn:
        found = await _existing(conn, stored.sha256)
    if found is not None:
        return found

    try:
        scan = await asyncio.to_thread(scan_file, stored.path, limits)
    except FileFormatError as exc:
        await asyncio.to_thread(remove_from_store, stored)
        raise ImportRejected(exc.code, str(exc)) from None
    reason = rejection_reason(scan, settings.reject_ratio)
    if reason is not None:
        await asyncio.to_thread(remove_from_store, stored)
        raise ImportRejected(FORMAT_TIDAK_VALID, reason, scan.stats())

    job_id = new_job_id()
    try:
        async with engine.begin() as conn:
            seq = int(await conn.scalar(source_seq.next_value()))
            source_id = source_code(prefix, seq)
            await conn.execute(
                raw_source.insert().values(
                    source_id=source_id,
                    seq=seq,
                    kind=f"{adapter}_jsonl",
                    file_sha256=stored.sha256,
                    size_bytes=stored.size,
                    path_ref=resolved.ref,
                    storage_ref=stored.sha256,
                )
            )
            await conn.execute(
                ingest_job.insert().values(
                    job_id=job_id,
                    source_id=source_id,
                    status=JOB_QUEUED,
                    requested_by=requested_by,
                    stats=scan.stats(),
                )
            )
    except IntegrityError:
        # Impor bersamaan berkas yang sama: unik file_sha256 memilih satu pemenang. Nomor sequence boleh bolong.
        async with engine.connect() as conn:
            found = await _existing(conn, stored.sha256)
        if found is None:
            raise
        return found
    log.info("impor_diterima", job_id=job_id, source_id=source_id, valid=scan.valid, rejected=scan.rejected)
    return ImportOutcome(job_id, source_id, stored.sha256, JOB_QUEUED, True, scan.stats())


def _chunks(path: Path, limits: Limits, batch_size: int, after: int) -> Iterator[tuple[int, list[Line]]]:
    """(batch_no, baris) per `batch_size` baris fisik, melewati baris <= `after` (sudah ter-commit)."""
    current: list[Line] = []
    current_no = -1
    with path.open("rb") as fp:
        for line in iter_lines(fp, limits):
            if line.record_no <= after:
                continue
            batch_no = (line.record_no - 1) // batch_size
            if current and batch_no != current_no:
                yield current_no, current
                current = []
            current_no = batch_no
            current.append(line)
    if current:
        yield current_no, current


async def _write_batch(
    conn: AsyncConnection,
    *,
    job_id: str,
    source_id: str,
    file_sha256: str,
    batch_no: int,
    lines: list[Line],
    limits: Limits,
) -> None:
    hashes: list[str] = []
    for line in lines:
        outcome = _evaluate(line, limits)
        if outcome is None:
            continue
        if isinstance(outcome, str):
            raw = line.raw if line.kind == "data" else None
            await conn.execute(
                rejected_record.insert().values(source_id=source_id, record_no=line.record_no, code=outcome, raw=raw)
            )
            continue
        a = outcome
        eid = evidence_id(source_id, line.record_no)
        aid = alert_id(source_id, line.record_no)
        digest = record_sha256(line.raw)
        hashes.append(digest)
        await conn.execute(
            evidence.insert().values(
                evidence_id=eid,
                source_id=source_id,
                record_no=line.record_no,
                record_sha256=digest,
                raw=line.raw,
                occurred_at=a.occurred_at,
                host=a.host,
                account=a.account,
                kind=a.kind,
                event_id=a.event_id,
                record_id=a.record_id,
                src_ip=a.src_ip,
                details=a.details,
                extra=a.extra,
            )
        )
        await conn.execute(
            alert.insert().values(
                alert_id=aid,
                source_id=source_id,
                record_no=line.record_no,
                rule_id=a.rule_id,
                rule_title=a.rule_title,
                rule_file=a.rule_file,
                level=a.level,
                severity=a.severity,
                tactics=list(a.tactics),
                techniques=list(a.mitre_tags),
                other_tags=list(a.other_tags),
                occurred_at=a.occurred_at,
                host=a.host,
                account=a.account,
                src_ip=a.src_ip,
                kind=a.kind,
            )
        )
        await conn.execute(alert_evidence.insert().values(alert_id=aid, evidence_id=eid))

    last = lines[-1].record_no
    if hashes:
        await enqueue(
            conn,
            events.evidence_ingested(
                job_id=job_id,
                source_id=source_id,
                batch_no=batch_no,
                first=lines[0].record_no,
                last=last,
                count=len(hashes),
                file_sha256=file_sha256,
                batch_sha256=batch_sha256(hashes),
            ),
        )
    await conn.execute(update(ingest_job).where(ingest_job.c.job_id == job_id).values(last_record_no=last))


async def run_job(engine: AsyncEngine, settings: Settings, job_id: str) -> str:
    """Lintasan 2 untuk satu job. Mengembalikan status akhir. Aman dipanggil ulang (lanjut dari batch terakhir)."""
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                select(ingest_job, raw_source.c.file_sha256, raw_source.c.storage_ref)
                .join(raw_source, raw_source.c.source_id == ingest_job.c.source_id)
                .where(ingest_job.c.job_id == job_id)
                .with_for_update(of=ingest_job, skip_locked=True)
            )
        ).first()
        if row is None or row.status not in JOB_PENDING:
            return row.status if row is not None else JOB_FAILED
        await conn.execute(
            update(ingest_job)
            .where(ingest_job.c.job_id == job_id)
            .values(status=JOB_RUNNING, started_at=row.started_at or datetime.now(UTC))
        )

    source_id, file_sha256, requested_by = row.source_id, row.file_sha256, row.requested_by
    path = settings.evidence_store / row.storage_ref
    limits = settings.limits
    try:
        digest, _size = await asyncio.to_thread(_hash_file, path)
        if digest != file_sha256:
            raise ImportRejected(GUDANG_TIDAK_KONSISTEN, "salinan gudang tidak cocok dengan hash")
        chunks = _chunks(path, limits, settings.batch_size, row.last_record_no)
        while (item := await asyncio.to_thread(next, chunks, None)) is not None:
            batch_no, lines = item
            async with engine.begin() as conn:
                await _write_batch(
                    conn,
                    job_id=job_id,
                    source_id=source_id,
                    file_sha256=file_sha256,
                    batch_no=batch_no,
                    lines=lines,
                    limits=limits,
                )
    except Exception as exc:
        code = exc.code if isinstance(exc, ImportRejected) else JOB_GAGAL
        log.error("impor_gagal", job_id=job_id, error=type(exc).__name__, code=code)
        await _finish(engine, job_id, JOB_FAILED, code, requested_by, source_id, file_sha256)
        return JOB_FAILED

    rejected = int(row.stats.get("rejected", 0))
    status = JOB_COMPLETED_WITH_ERRORS if rejected else JOB_COMPLETED
    await _finish(engine, job_id, status, None, requested_by, source_id, file_sha256)
    log.info("impor_selesai", job_id=job_id, source_id=source_id, status=status)
    return status


def _hash_file(path: Path) -> tuple[str, int]:
    with path.open("rb") as fp:
        return stream_sha256(fp)


async def _finish(
    engine: AsyncEngine,
    job_id: str,
    status: str,
    error_code: str | None,
    actor: str,
    source_id: str,
    file_sha256: str,
) -> None:
    async with engine.begin() as conn:
        stats = await conn.scalar(select(ingest_job.c.stats).where(ingest_job.c.job_id == job_id))
        await conn.execute(
            update(ingest_job)
            .where(ingest_job.c.job_id == job_id)
            .values(status=status, error_code=error_code, finished_at=datetime.now(UTC))
        )
        action = "ingest.file.failed" if status == JOB_FAILED else "ingest.file.imported"
        payload = {
            "source_id": source_id,
            "file_sha256": file_sha256,
            "status": status,
            "error_code": error_code,
            "valid": (stats or {}).get("valid"),
            "rejected": (stats or {}).get("rejected"),
        }
        await enqueue(conn, events.import_audit(job_id=job_id, actor=actor, action=action, payload=payload))


class ImportWorker:
    """Komponen latar: menjalankan job `queued`/`running` satu per satu, termasuk yang tertinggal saat restart."""

    name = "import_worker"
    required = False

    def __init__(self, db: Database, settings: Settings) -> None:
        self._db = db
        self._settings = settings
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._last_error: str | None = None

    def wake(self) -> None:
        self._wake.set()

    async def start(self) -> None:
        self._wake.set()
        self._task = asyncio.create_task(self._run(), name="import-worker")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        if self._last_error:
            return Check("degraded", f"putaran terakhir gagal ({self._last_error})")
        return Check("ok")

    async def run_pending(self) -> int:
        """Jalankan semua job tertunda. Dipakai worker dan tes."""
        async with self._db.engine.connect() as conn:
            job_ids = (
                await conn.scalars(
                    select(ingest_job.c.job_id)
                    .where(ingest_job.c.status.in_(JOB_PENDING))
                    .order_by(ingest_job.c.created_at)
                )
            ).all()
        for job_id in job_ids:
            await run_job(self._db.engine, self._settings, job_id)
        return len(job_ids)

    async def _run(self) -> None:
        await self._db.wait_ready()
        while True:
            await self._wake.wait()
            self._wake.clear()
            try:
                await self.run_pending()
                self._last_error = None
            except Exception as exc:  # noqa: BLE001 - dicoba lagi saat dibangunkan berikutnya
                self._last_error = type(exc).__name__
                log.warning("import_worker_gagal", error=self._last_error)
