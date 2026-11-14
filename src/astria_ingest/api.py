"""API layanan ingest (`/svc/v1`, K3). Semua endpoint wajib token layanan untuk audiens `svc:ingest`.

Pemanggil dibatasi per endpoint lewat setting (K18): impor untuk `import_callers`, baca untuk `read_callers`.
Teks yang keluar selalu lewat `render` (sanitasi + redaksi saat output, K12). `raw` tidak pernah dikirim.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Any, Literal

from astria_common.auth import ServicePrincipal, require_service
from astria_common.db import Database
from astria_common.errors import AstriaError
from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from astria_ingest.ids import parse_evidence_id
from astria_ingest.jobs import ImportRejected, start_import
from astria_ingest.paths import PathRejected
from astria_ingest.render import clean, render_excerpt, render_fields
from astria_ingest.settings import Settings
from astria_ingest.store import alert, evidence, ingest_job, raw_source
from astria_ingest.store_files import BERKAS_TERLALU_BESAR, StoreError

router = APIRouter(prefix="/svc/v1", tags=["ingest"])

AUDIENCE = "svc:ingest"
MAX_BATCH_IDS = 500
MAX_PAGE = 500
JOB_ID_PATTERN = r"^ING-[0-9]{8}-[0-9A-F]{8}$"

_service = require_service(AUDIENCE)


def _allowed_caller(kind: Literal["import", "read"]) -> Callable[..., Awaitable[ServicePrincipal]]:
    async def dependency(
        request: Request, principal: Annotated[ServicePrincipal, Depends(_service)]
    ) -> ServicePrincipal:
        settings: Settings = request.app.state.settings
        allowed = settings.import_callers if kind == "import" else settings.read_callers
        if principal.subject not in allowed:
            raise AstriaError("PEMANGGIL_DITOLAK", "layanan ini tidak boleh memanggil endpoint ini", 403)
        return principal

    return dependency


ImportCaller = Annotated[ServicePrincipal, Depends(_allowed_caller("import"))]
ReadCaller = Annotated[ServicePrincipal, Depends(_allowed_caller("read"))]
JobId = Annotated[str, Path(pattern=JOB_ID_PATTERN)]


def _engine(request: Request) -> AsyncEngine:
    db: Database | None = request.app.state.components.get("postgres")
    if db is None or not db.is_ready:
        raise AstriaError("INGEST_TIDAK_SIAP", "basis data ingest belum siap", 503)
    return db.engine


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


# ---- impor ----


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adapter: Literal["hayabusa"]
    path_ref: str = Field(min_length=1, max_length=1024)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """SHA-256 yang diharapkan pemanggil. Bila diisi dan berbeda dari isi berkas, impor ditolak sebelum job dibuat."""


class ImportResponse(BaseModel):
    job_id: str
    source_id: str
    file_sha256: str
    status: str
    created: bool
    stats: dict[str, Any]


@router.post("/imports", response_model=ImportResponse, status_code=202)
async def create_import(
    body: ImportRequest, request: Request, response: Response, caller: ImportCaller
) -> ImportResponse:
    engine = _engine(request)
    settings: Settings = request.app.state.settings
    try:
        outcome = await start_import(
            engine,
            settings,
            adapter=body.adapter,
            path_ref=body.path_ref,
            requested_by=caller.subject,
            expected_sha256=body.expected_sha256,
        )
    except PathRejected as exc:
        raise AstriaError(exc.code, str(exc), 422) from None
    except StoreError as exc:
        raise AstriaError(exc.code, str(exc), 413 if exc.code == BERKAS_TERLALU_BESAR else 422) from None
    except ImportRejected as exc:
        raise AstriaError(exc.code, str(exc), 422) from None
    if outcome.created:
        worker = request.app.state.components.get("import_worker")
        if worker is not None:
            worker.wake()
    else:
        response.status_code = 200
    return ImportResponse(**outcome.__dict__)


class JobResponse(BaseModel):
    job_id: str
    source_id: str
    file_sha256: str
    status: str
    stats: dict[str, Any]
    last_record_no: int
    error_code: str | None
    created_at: str | None
    started_at: str | None
    finished_at: str | None


@router.get("/imports/{job_id}", response_model=JobResponse)
async def get_import(job_id: JobId, request: Request, _caller: ImportCaller) -> JobResponse:
    async with _engine(request).connect() as conn:
        row = (
            await conn.execute(
                select(ingest_job, raw_source.c.file_sha256)
                .join(raw_source, raw_source.c.source_id == ingest_job.c.source_id)
                .where(ingest_job.c.job_id == job_id)
            )
        ).first()
    if row is None:
        raise AstriaError("JOB_TIDAK_ADA", "job tidak ditemukan", 404)
    return JobResponse(
        job_id=row.job_id,
        source_id=row.source_id,
        file_sha256=row.file_sha256,
        status=row.status,
        stats=dict(row.stats),
        last_record_no=row.last_record_no,
        error_code=row.error_code,
        created_at=_iso(row.created_at),
        started_at=_iso(row.started_at),
        finished_at=_iso(row.finished_at),
    )


# ---- baca bukti (verifier, triage, api) ----


class EvidenceBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(min_length=1, max_length=MAX_BATCH_IDS)


class EvidenceItem(BaseModel):
    evidence_id: str
    source_id: str
    record_no: int
    record_sha256: str
    occurred_at: str
    host: str
    account: str | None
    kind: str
    fields: dict[str, str]
    excerpt: str
    sanitized: bool = True
    injection_suspect: bool


class EvidenceBatchResponse(BaseModel):
    items: list[EvidenceItem]
    not_found: list[str]


def evidence_item(row: Any) -> EvidenceItem:
    """Satu baris `evidence` (+ `rule_title` dari `alert`) -> item API tersanitasi. Tanpa `raw`."""
    return EvidenceItem(
        evidence_id=row.evidence_id,
        source_id=row.source_id,
        record_no=row.record_no,
        record_sha256=row.record_sha256,
        occurred_at=_iso(row.occurred_at) or "",
        host=clean(row.host, 256),
        account=clean(row.account, 256) if row.account is not None else None,
        kind=row.kind,
        fields=render_fields(row.details or {}, row.extra or {}),
        excerpt=render_excerpt(row.event_id, row.rule_title, row.details or {}),
        injection_suspect=row.injection_suspect,
    )


_EVIDENCE_COLUMNS = (
    evidence.c.evidence_id,
    evidence.c.source_id,
    evidence.c.record_no,
    evidence.c.record_sha256,
    evidence.c.occurred_at,
    evidence.c.host,
    evidence.c.account,
    evidence.c.kind,
    evidence.c.event_id,
    evidence.c.details,
    evidence.c.extra,
    evidence.c.injection_suspect,
    alert.c.rule_title,
)


@router.post("/evidence:batch", response_model=EvidenceBatchResponse)
async def evidence_batch(body: EvidenceBatchRequest, request: Request, _caller: ReadCaller) -> EvidenceBatchResponse:
    ids = sorted(set(body.ids))
    if any(parse_evidence_id(i) is None for i in ids):
        raise AstriaError("ID_TIDAK_VALID", "format ID bukti harus EV-<kode>-<nnnnnn>", 400)
    async with _engine(request).connect() as conn:
        rows = (
            await conn.execute(
                select(*_EVIDENCE_COLUMNS)
                .join(alert, (alert.c.source_id == evidence.c.source_id) & (alert.c.record_no == evidence.c.record_no))
                .where(evidence.c.evidence_id.in_(ids))
                .order_by(evidence.c.evidence_id)
            )
        ).all()
    items = [evidence_item(r) for r in rows]
    found = {i.evidence_id for i in items}
    return EvidenceBatchResponse(items=items, not_found=[i for i in ids if i not in found])


# ---- alert per job (triage) ----


class AlertItem(BaseModel):
    alert_id: str
    evidence_ids: list[str]
    record_no: int
    occurred_at: str
    host: str
    account: str | None
    src_ip: str | None
    rule_id: str | None
    rule_title: str
    level: str
    severity: str
    tactics: list[str]
    techniques: list[str]
    other_tags: list[str]
    kind: str


class AlertPage(BaseModel):
    job_id: str
    source_id: str
    items: list[AlertItem]
    next_cursor: str | None


def _texts(values: Any) -> list[str]:
    return [clean(v, 128) for v in (values or [])]


@router.get("/jobs/{job_id}/alerts", response_model=AlertPage)
async def job_alerts(
    job_id: JobId,
    request: Request,
    _caller: ReadCaller,
    from_: Annotated[int, Query(alias="from", ge=1)] = 1,
    to: Annotated[int | None, Query(ge=1)] = None,
    cursor: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = MAX_PAGE,
) -> AlertPage:
    async with _engine(request).connect() as conn:
        source_id = await conn.scalar(select(ingest_job.c.source_id).where(ingest_job.c.job_id == job_id))
        if source_id is None:
            raise AstriaError("JOB_TIDAK_ADA", "job tidak ditemukan", 404)
        start = max(from_, (cursor or 0) + 1)
        query = (
            select(alert, evidence.c.evidence_id)
            .join(evidence, (evidence.c.source_id == alert.c.source_id) & (evidence.c.record_no == alert.c.record_no))
            .where(alert.c.source_id == source_id, alert.c.record_no >= start)
            .order_by(alert.c.record_no)
            .limit(limit + 1)
        )
        if to is not None:
            query = query.where(alert.c.record_no <= to)
        rows = (await conn.execute(query)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    items = [
        AlertItem(
            alert_id=r.alert_id,
            evidence_ids=[r.evidence_id],
            record_no=r.record_no,
            occurred_at=_iso(r.occurred_at) or "",
            host=clean(r.host, 256),
            account=clean(r.account, 256) if r.account is not None else None,
            src_ip=clean(r.src_ip, 64) if r.src_ip is not None else None,
            rule_id=clean(r.rule_id, 64) if r.rule_id is not None else None,
            rule_title=clean(r.rule_title, 512),
            level=clean(r.level, 32),
            severity=r.severity,
            tactics=_texts(r.tactics),
            techniques=_texts(r.techniques),
            other_tags=_texts(r.other_tags),
            kind=r.kind,
        )
        for r in rows
    ]
    next_cursor = str(rows[-1].record_no) if more and rows else None
    return AlertPage(job_id=job_id, source_id=source_id, items=items, next_cursor=next_cursor)
