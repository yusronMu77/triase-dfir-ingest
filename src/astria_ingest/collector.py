"""Consent-gated Collector ingress. A receipt proves encrypted custody, never acquisition completeness."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from astria_common.auth import ServicePrincipal, require_service
from astria_common.errors import AstriaError
from astria_common.outbox import enqueue
from fastapi import APIRouter, Depends, Request, Response
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from astria_ingest import collector_store as tables
from astria_ingest.collector_models import CollectorConfig, Job, Progress, Provision, Receipt
from astria_ingest.events import import_audit
from astria_ingest.settings import Settings

router = APIRouter(prefix="/svc/v1", tags=["collector"])
HEX = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
STAGES = {"queued": 0, "perangkat_terdeteksi": 1, "mengambil": 2, "mengemas": 3, "mengunggah": 4}
AGE_MAGIC = b"age-encryption.org/v1\n"
Manager = Annotated[ServicePrincipal, Depends(require_service("svc:ingest", {"svc:api"}))]


def fail(code: str, status: int) -> AstriaError:
    return AstriaError(code, "permintaan Collector ditolak; lihat kode galat", status)


def enabled(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    if not settings.collector_enabled:
        raise fail("COLLECTOR_DISABLED", 404)
    return settings


def engine(request: Request) -> AsyncEngine:
    db = request.app.state.components.get("postgres")
    if db is None or not db.is_ready:
        raise fail("INGEST_TIDAK_SIAP", 503)
    return db.engine


def validate_settings(settings: Settings) -> None:
    """Fail at startup; key bytes are read only while authenticating to allow rotation."""
    if not settings.collector_enabled:
        return
    if not settings.database_url or not settings.database_url.get_secret_value().startswith("postgresql"):
        raise ValueError("Collector ingress requires PostgreSQL")
    if not settings.collector_age_recipient or not re.fullmatch(
        r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", settings.collector_age_recipient
    ):
        raise ValueError("Collector requires an age X25519 recipient")
    if not settings.collector_keys:
        raise ValueError("Collector requires mounted HMAC key files")
    for key_id in settings.collector_keys:
        if not IDENTIFIER.fullmatch(key_id):
            raise ValueError("invalid Collector key ID")
        read_key(settings, key_id)


def read_key(settings: Settings, key_id: str) -> bytes:
    try:
        path = settings.collector_keys[key_id]
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError
        raw = path.read_bytes()
        if len(raw) > 1024:
            raise ValueError
        key = bytes.fromhex(raw.decode("ascii").strip())
        if len(key) < 32:
            raise ValueError
        return key
    except KeyError, OSError, ValueError, UnicodeError:
        raise fail("SIGNATURE_INVALID", 401) from None


def authenticate(request: Request, body_hash: str) -> str:
    settings = enabled(request)
    names = ["x-astria-key-id", "x-astria-timestamp", "x-astria-signature"]
    if any(len(request.headers.getlist(name)) != 1 for name in names):
        raise fail("SIGNATURE_INVALID", 401)
    key_id, timestamp, signature = (request.headers[name] for name in names)
    if not IDENTIFIER.fullmatch(key_id) or not re.fullmatch(r"[0-9]{1,12}", timestamp):
        raise fail("SIGNATURE_INVALID", 401)
    if abs(time.time() - int(timestamp)) > 300 or not HEX.fullmatch(signature):
        raise fail("SIGNATURE_INVALID", 401)
    # Raw URL bytes preserve query ordering and percent escaping; a proxy must not rewrite the signed path.
    path = request.scope.get("raw_path", request.url.path.encode()).decode("ascii")
    query = request.scope.get("query_string", b"").decode("ascii")
    canonical = "\n".join([request.method.upper(), path + ("?" + query if query else ""), timestamp, key_id, body_hash])
    expected = hmac.new(read_key(settings, key_id), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise fail("SIGNATURE_INVALID", 401)
    return key_id


async def bounded_body(request: Request, limit: int = 16384) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise fail("BODY_TOO_LARGE", 413)
        body.extend(chunk)
    return bytes(body)


def manager(settings: Settings, caller: ServicePrincipal) -> str:
    act = caller.act or {}
    actor = act.get("sub")
    if actor not in settings.device_scan_users or not set(act.get("roles", [])).intersection({"admin", "dfir"}):
        raise fail("DEVICE_SCAN_FORBIDDEN", 403)
    if not isinstance(actor, str):
        raise fail("DEVICE_SCAN_FORBIDDEN", 403)
    return actor


async def authorized_job(conn: AsyncConnection, job_id: str, key_id: str, *, lock: bool = False) -> Any:
    if not IDENTIFIER.fullmatch(job_id):
        raise fail("JOB_NOT_FOUND", 404)
    statement = (
        select(tables.job, tables.consent.c.revoked)
        .select_from(tables.job)
        .join(tables.consent, tables.consent.c.consent_id == tables.job.c.consent_id)
        .where(tables.job.c.job_id == job_id, tables.job.c.key_id == key_id)
    )
    if lock:
        statement = statement.with_for_update(of=tables.job)
    row = (await conn.execute(statement)).first()
    if row is None:
        raise fail("JOB_NOT_FOUND", 404)
    if row.revoked:
        raise fail("CONSENT_REVOKED", 403)
    if row.expires_at <= datetime.now(UTC):
        raise fail("JOB_EXPIRED", 410)
    return row


@router.post("/device-scans", response_model=Job, status_code=201)
async def provision(body: Provision, request: Request, caller: Manager) -> Job:
    settings = enabled(request)
    actor = manager(settings, caller)
    if body.collector_key_id not in settings.collector_keys or body.job.expires_at <= datetime.now(UTC):
        raise fail("JOB_INVALID", 422)
    try:
        async with engine(request).begin() as conn:
            await conn.execute(
                tables.consent.insert().values(
                    consent_id=body.job.consent_id,
                    document=body.consent.model_dump(mode="json"),
                    recorded_by=actor,
                    revoked=False,
                )
            )
            await conn.execute(
                tables.job.insert().values(
                    job_id=body.job.job_id,
                    consent_id=body.job.consent_id,
                    key_id=body.collector_key_id,
                    document=body.job.model_dump(mode="json"),
                    stage="queued",
                    expires_at=body.job.expires_at,
                )
            )
            await enqueue(
                conn,
                import_audit(
                    job_id=body.job.job_id,
                    actor=actor,
                    action="device_scan.authorized",
                    payload={
                        "consent_id": body.job.consent_id,
                        "consent_record_sha256": body.consent.record_sha256,
                        "scope_flags": body.job.scope_flags.model_dump(),
                        "expanded_scope_reason": body.expanded_scope_reason,
                    },
                ),
            )
    except IntegrityError:
        raise fail("JOB_OR_CONSENT_EXISTS", 409) from None
    return body.job


@router.post("/device-scans/{job_id}/revoke", status_code=204)
async def revoke(job_id: str, request: Request, caller: Manager) -> Response:
    actor = manager(enabled(request), caller)
    async with engine(request).begin() as conn:
        row = (await conn.execute(select(tables.job).where(tables.job.c.job_id == job_id).with_for_update())).first()
        if row is None:
            raise fail("JOB_NOT_FOUND", 404)
        was_revoked = (
            await conn.execute(select(tables.consent.c.revoked).where(tables.consent.c.consent_id == row.consent_id))
        ).scalar_one()
        if not was_revoked:
            await conn.execute(
                update(tables.consent).where(tables.consent.c.consent_id == row.consent_id).values(revoked=True)
            )
            await enqueue(
                conn,
                import_audit(
                    job_id=job_id, actor=actor, action="device_scan.revoked", payload={"consent_id": row.consent_id}
                ),
            )
    return Response(status_code=204)


@router.get("/collector/config", response_model=CollectorConfig)
async def configuration(request: Request) -> CollectorConfig:
    authenticate(request, hashlib.sha256(b"").hexdigest())
    recipient = enabled(request).collector_age_recipient
    assert recipient is not None
    return CollectorConfig(age_recipient=recipient, age_recipient_sha256=hashlib.sha256(recipient.encode()).hexdigest())


@router.get("/collector/jobs/next", response_model=Job, responses={204: {"description": "No authorized job"}})
async def next_job(request: Request) -> Job | Response:
    key_id = authenticate(request, hashlib.sha256(b"").hexdigest())
    async with engine(request).connect() as conn:
        row = (
            await conn.execute(
                select(tables.job.c.document)
                .select_from(tables.job)
                .join(tables.consent, tables.consent.c.consent_id == tables.job.c.consent_id)
                .where(
                    tables.job.c.key_id == key_id,
                    tables.consent.c.revoked.is_(False),
                    tables.job.c.expires_at > datetime.now(UTC),
                    tables.job.c.stage == "queued",
                )
                .order_by(tables.job.c.expires_at, tables.job.c.job_id)
                .limit(1)
            )
        ).first()
    return Job.model_validate(row.document) if row else Response(status_code=204)


@router.post("/collector/jobs/{job_id}/progress", status_code=204)
async def progress(job_id: str, request: Request) -> Response:
    raw = await bounded_body(request, 4096)
    key_id = authenticate(request, hashlib.sha256(raw).hexdigest())
    try:
        body = Progress.model_validate_json(raw)
    except ValidationError:
        raise fail("PROGRESS_INVALID", 422) from None
    async with engine(request).begin() as conn:
        row = await authorized_job(conn, job_id, key_id, lock=True)
        if body.stage == "selesai":
            receipt = (
                await conn.execute(select(tables.acquisition.c.job_id).where(tables.acquisition.c.job_id == job_id))
            ).first()
            if not receipt:
                raise fail("ARCHIVE_NOT_RECEIVED", 409)
        elif row.stage in {"received", "selesai"}:
            raise fail("PROGRESS_CONFLICT", 409)
        elif body.stage != "gagal" and STAGES.get(body.stage, -1) < STAGES.get(row.stage, 0):
            raise fail("PROGRESS_CONFLICT", 409)
        await conn.execute(
            update(tables.job).where(tables.job.c.job_id == job_id).values(stage=body.stage, code=body.code)
        )
    return Response(status_code=204)


def archive_root(settings: Settings) -> Path:
    root = settings.collector_archive_root.absolute()
    for part in [root, *root.parents]:
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise fail("ARCHIVE_PATH_UNSAFE", 503)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def receipt_for(row: Any) -> Receipt:
    return Receipt(
        acquisition_id=row.acquisition_id,
        job_id=row.job_id,
        archive_sha256=row.archive_sha256,
        archive_size=row.archive_size,
    )


@router.put("/collector/acquisitions/{job_id}", response_model=Receipt, status_code=201)
async def upload(job_id: str, request: Request) -> Receipt:
    settings = enabled(request)
    digest = request.headers.get("x-archive-sha256", "")
    length_text = request.headers.get("content-length", "")
    if not HEX.fullmatch(digest) or len(request.headers.getlist("x-archive-sha256")) != 1:
        raise fail("ARCHIVE_HASH_REQUIRED", 400)
    if not re.fullmatch(r"[0-9]{1,12}", length_text) or len(request.headers.getlist("content-length")) != 1:
        raise fail("CONTENT_LENGTH_REQUIRED", 411)
    length = int(length_text)
    if not len(AGE_MAGIC) < length <= settings.collector_max_archive_bytes:
        raise fail("ARCHIVE_SIZE_INVALID", 413)
    key_id = authenticate(request, digest)
    async with engine(request).connect() as conn:
        # Exact committed retries may recover custody acknowledgment after expiration, but never after revocation.
        prior = (
            await conn.execute(
                select(tables.acquisition, tables.job.c.key_id, tables.consent.c.revoked)
                .select_from(tables.acquisition)
                .join(tables.job, tables.job.c.job_id == tables.acquisition.c.job_id)
                .join(tables.consent, tables.consent.c.consent_id == tables.job.c.consent_id)
                .where(tables.acquisition.c.job_id == job_id)
            )
        ).first()
        if prior is not None:
            if prior.key_id != key_id or prior.revoked:
                raise fail("JOB_NOT_FOUND", 404)
            if prior.archive_sha256 != digest or prior.archive_size != length:
                raise fail("ARCHIVE_CONFLICT", 409)
            return receipt_for(prior)
        await authorized_job(conn, job_id, key_id)
    root = archive_root(settings)
    temporary = root / ("upload-" + uuid.uuid4().hex + ".tmp")
    hasher = hashlib.sha256()
    total = 0
    prefix = bytearray()
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, 0o600)
            async with asyncio.timeout(settings.collector_upload_timeout_s):
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > length:
                        raise fail("ARCHIVE_LENGTH_MISMATCH", 422)
                    if len(prefix) < len(AGE_MAGIC):
                        prefix.extend(chunk[: len(AGE_MAGIC) - len(prefix)])
                    hasher.update(chunk)
                    handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        if total != length or not hmac.compare_digest(hasher.hexdigest(), digest):
            raise fail("ARCHIVE_HASH_MISMATCH", 422)
        if prefix != AGE_MAGIC:
            raise fail("ARCHIVE_NOT_ENCRYPTED", 422)
        async with engine(request).begin() as conn:
            await authorized_job(conn, job_id, key_id, lock=True)
            existing = (
                await conn.execute(select(tables.acquisition).where(tables.acquisition.c.job_id == job_id))
            ).first()
            if existing:
                if existing.archive_sha256 != digest or existing.archive_size != length:
                    raise fail("ARCHIVE_CONFLICT", 409)
                return receipt_for(existing)
            acquisition_id = "AQ-" + uuid.uuid4().hex
            destination = root / (acquisition_id + ".zip.age")
            # Publish without overwriting any existing artifact. An interrupted DB commit may leave an
            # encrypted orphan; it is retained for operator reconciliation, never silently deleted.
            os.link(temporary, destination)
            if os.name != "nt":
                directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            await conn.execute(
                tables.acquisition.insert().values(
                    job_id=job_id,
                    acquisition_id=acquisition_id,
                    archive_sha256=digest,
                    archive_size=length,
                    storage_name=destination.name,
                    received_at=datetime.now(UTC),
                )
            )
            await conn.execute(update(tables.job).where(tables.job.c.job_id == job_id).values(stage="received"))
            await enqueue(
                conn,
                import_audit(
                    job_id=job_id,
                    actor="collector:" + key_id,
                    action="collector.archive_received",
                    payload={
                        "acquisition_id": acquisition_id,
                        "archive_sha256": digest,
                        "archive_size": length,
                        "metadata_status": "pending_verification",
                    },
                ),
            )
            return Receipt(acquisition_id=acquisition_id, job_id=job_id, archive_sha256=digest, archive_size=length)
    except TimeoutError:
        raise fail("UPLOAD_TIMEOUT", 408) from None
    finally:
        temporary.unlink(missing_ok=True)
