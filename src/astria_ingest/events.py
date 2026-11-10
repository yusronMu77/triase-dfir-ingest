"""Event yang diterbitkan ingest: `evidence.ingested` per batch dan `audit.record` per job.

ID event deterministik (uuid5) agar penulisan ulang batch yang sama tidak menghasilkan event baru (K7).
`file_sha256` dan `batch_sha256` butuh `astria-contracts` v0.2.0 (contracts#5) lewat `common` yang memakainya.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from astria_common.events import new_event
from astria_contracts import Envelope

_NAMESPACE = uuid.UUID("0b0c6a52-5a3e-4c8e-9f0e-8d1f2a7c4b61")


def event_id_for(kind: str, *parts: object) -> str:
    return str(uuid.uuid5(_NAMESPACE, ":".join([kind, *map(str, parts)])))


def alerts_ref(job_id: str, first: int, last: int) -> str:
    return f"/svc/v1/jobs/{job_id}/alerts?from={first}&to={last}"


def evidence_ingested(
    *,
    job_id: str,
    source_id: str,
    batch_no: int,
    first: int,
    last: int,
    count: int,
    file_sha256: str,
    batch_sha256: str,
) -> Envelope:
    data: dict[str, Any] = {
        "source_id": source_id,
        "count": count,
        "record_range": {"from": first, "to": last},
        "batch_ref": alerts_ref(job_id, first, last),
        "alert_ids_count": count,
        "file_sha256": file_sha256,
        "batch_sha256": batch_sha256,
    }
    return new_event(
        "evidence.ingested",
        data,
        correlation={"job_id": job_id, "source_id": source_id},
        event_id=event_id_for("evidence.ingested", source_id, batch_no),
    )


def import_audit(*, job_id: str, actor: str, action: str, payload: dict[str, Any]) -> Envelope:
    return new_event(
        "audit.record",
        {
            "idempotency_key": f"ingest-{action}-{job_id}",
            "occurred_at": datetime.now(UTC).isoformat(),
            "actor": actor,
            "actor_type": "service",
            "action": action,
            "target_type": "job",
            "target_id": job_id,
            "via": "api",
            "payload": payload,
        },
        correlation={"job_id": job_id, "source_id": payload.get("source_id")},
        event_id=event_id_for("audit.record", action, job_id),
    )
