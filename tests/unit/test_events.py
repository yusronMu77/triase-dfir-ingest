from __future__ import annotations

import pytest
from astria_contracts.events.evidence_ingested import EvidenceIngested

from astria_ingest import events
from astria_ingest.hashing import sha256_hex

HAS_HASH_FIELDS = "file_sha256" in EvidenceIngested.model_fields
needs_contracts_v020 = pytest.mark.xfail(
    not HAS_HASH_FIELDS,
    reason="butuh astria-contracts v0.2.0 (contracts#5) lewat rilis common baru",
    strict=True,
)


@needs_contracts_v020
def test_evidence_ingested_event_is_valid_and_deterministic() -> None:
    kwargs = dict(
        job_id="ING-20261110-ABCD1234",
        source_id="hb01",
        batch_no=0,
        first=1,
        last=31,
        count=31,
        file_sha256=sha256_hex(b"berkas"),
        batch_sha256=sha256_hex(b"batch"),
    )
    a = events.evidence_ingested(**kwargs)
    b = events.evidence_ingested(**kwargs)
    assert a.id == b.id
    assert a.data["record_range"] == {"from": 1, "to": 31}
    assert a.data["batch_ref"] == "/svc/v1/jobs/ING-20261110-ABCD1234/alerts?from=1&to=31"
    assert a.data["file_sha256"] == sha256_hex(b"berkas")
    assert events.evidence_ingested(**(kwargs | {"batch_no": 1})).id != a.id


def test_audit_event() -> None:
    env = events.import_audit(
        job_id="ING-20261110-ABCD1234",
        actor="svc:api",
        action="ingest.file.imported",
        payload={"source_id": "hb01", "file_sha256": sha256_hex(b"x")},
    )
    assert env.type == "audit.record"
    assert env.id == events.event_id_for("audit.record", "ingest.file.imported", "ING-20261110-ABCD1234")
    assert env.data["target_id"] == "ING-20261110-ABCD1234"
