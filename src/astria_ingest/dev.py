"""Endpoint khusus dev (Tahap 0): terbitkan satu `evidence.ingested` contoh lewat outbox.

Membuktikan jalur penuh: transaksi ingest menulis event dan catatan audit asinkron ke outbox, relay
menerbitkan ke JetStream, triage dan audit mengonsumsinya secara idempoten. Hanya terpasang bila
`ASTRIA_DEV_ENDPOINTS=true`, dan pagar ASTRIA_ENV menolak start dengan nilai itu di luar dev.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from astria_common.auth import ServicePrincipal, require_service
from astria_common.db import Database
from astria_common.errors import AstriaError
from astria_common.events import new_event
from astria_common.outbox import enqueue, outbox
from astria_contracts import example
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

router = APIRouter(prefix="/internal/v1/dev", tags=["dev"])


class SampleRequest(BaseModel):
    event_id: str | None = Field(None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    """Isi untuk menguji dedupe: id yang sama menghasilkan event yang sama."""


class SampleResponse(BaseModel):
    event_id: str
    audit_event_id: str
    job_id: str


@router.post("/sample-event", response_model=SampleResponse, status_code=202)
async def sample_event(
    body: SampleRequest,
    request: Request,
    principal: ServicePrincipal = Depends(require_service("svc:ingest")),  # noqa: B008
) -> SampleResponse:
    db: Database = request.app.state.components["postgres"]
    if not db.is_ready:
        raise AstriaError("INGEST_TIDAK_SIAP", "basis data ingest belum siap", 503)

    event_id = body.event_id or str(uuid.uuid4())
    job_id = f"ING-{datetime.now(UTC):%Y%m%d}-{uuid.uuid5(uuid.NAMESPACE_URL, event_id).hex[:4].upper()}"
    data = example("evidence.ingested")["data"]
    event = new_event(
        "evidence.ingested", data, correlation={"job_id": job_id, "source_id": data["source_id"]}, event_id=event_id
    )
    audit = new_event(
        "audit.record",
        {
            "idempotency_key": f"ingest-sample-{event_id}",
            "occurred_at": event.occurred_at.isoformat(),
            "actor": principal.subject,
            "actor_type": "service",
            "action": "ingest.sample.emitted",
            "target_type": "job",
            "target_id": job_id,
            "via": "system",
            "payload": {"event_id": event_id, "count": data["count"]},
        },
        correlation={"job_id": job_id},
        event_id=f"audit-{event_id}",
    )
    async with db.engine.begin() as conn:
        exists = await conn.scalar(select(outbox.c.id).where(outbox.c.id == event_id))
        if not exists:
            await enqueue(conn, event)
            await enqueue(conn, audit)
    return SampleResponse(event_id=event.id, audit_event_id=audit.id, job_id=job_id)
