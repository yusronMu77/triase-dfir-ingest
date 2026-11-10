"""Uji integrasi impor dengan PostgreSQL sungguhan (`ASTRIA_TEST_DATABASE_URL`, tersedia di kontainer py devenv).

Dilewati bila env kosong (CI tanpa DB). Event `evidence.ingested` memuat field hash, jadi uji ini juga menunggu
`astria-contracts` v0.2.0 (contracts#5) lewat rilis `common` baru.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from pathlib import Path

import orjson
import pytest
from astria_common import outbox
from astria_common.db import Database
from astria_common.events import decode
from astria_contracts.events.evidence_ingested import EvidenceIngested
from pydantic import SecretStr
from sqlalchemy import func, select, text, update

from astria_ingest import store
from astria_ingest.hashing import batch_sha256, record_sha256
from astria_ingest.jobs import FORMAT_TIDAK_VALID, ImportRejected, _chunks, _write_batch, run_job, start_import
from astria_ingest.settings import Settings
from astria_ingest.store_files import ensure_store

DB_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")
FIXTURES = Path(__file__).parent / "fixtures" / "samples"
SVC_BACKUP_SHA = "de76a576a6556fdf2077e2ac11cd920cb7505e24e7850a050880983da5d38666"
LINE = (
    '{{ "Timestamp":"2026-11-10 02:14:07.000 +00:00","RuleTitle":"T","Level":"low","Computer":"H{n}",'
    '"Channel":"Sec","EventID":4625,"RecordID":{n} }}'
)

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not DB_URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi"),
    pytest.mark.xfail(
        "file_sha256" not in EvidenceIngested.model_fields,
        reason="butuh astria-contracts v0.2.0 (contracts#5) lewat rilis common baru",
        strict=True,
    ),
]


@pytest.fixture
async def db():
    schema = f"t_{uuid.uuid4().hex[:8]}"
    database = Database(SecretStr(DB_URL or ""), schema=schema, metadata=[outbox.metadata, store.metadata])
    await database.start()
    await database.wait_ready(10)
    yield database
    async with database.engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await database.stop()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    root = tmp_path / "import"
    shutil.copytree(FIXTURES, root)
    ensure_store(tmp_path / "gudang")
    return Settings(env="test", import_root=root, evidence_store=tmp_path / "gudang", batch_size=500)


def _synthetic(root: Path, name: str, lines: int, extra: bytes = b"") -> str:
    (root / name).write_bytes("\n".join(LINE.format(n=n) for n in range(1, lines + 1)).encode() + b"\n" + extra)
    return name


async def _count(db: Database, table) -> int:
    async with db.engine.connect() as conn:
        return int(await conn.scalar(select(func.count()).select_from(table)))


async def _events(db: Database, event_type: str) -> list:
    async with db.engine.connect() as conn:
        rows = (
            await conn.execute(
                select(outbox.outbox.c.envelope)
                .where(outbox.outbox.c.event_type == event_type)
                .order_by(outbox.outbox.c.created_at, outbox.outbox.c.id)
            )
        ).all()
    return [decode(orjson.dumps(r.envelope))[0] for r in rows]


async def _import(db: Database, settings: Settings, ref: str):
    return await start_import(db.engine, settings, adapter="hayabusa", path_ref=ref, requested_by="svc:seed")


async def test_import_sample_end_to_end(db: Database, settings: Settings) -> None:
    out = await _import(db, settings, "chains/svc-backup.jsonl")
    assert (out.source_id, out.file_sha256, out.created) == ("hb01", SVC_BACKUP_SHA, True)
    assert await run_job(db.engine, settings, out.job_id) == store.JOB_COMPLETED

    assert await _count(db, store.evidence) == 31
    assert await _count(db, store.alert) == await _count(db, store.alert_evidence) == 31
    async with db.engine.connect() as conn:
        ids = (await conn.scalars(select(store.evidence.c.evidence_id).order_by(store.evidence.c.record_no))).all()
        raws = (await conn.scalars(select(store.evidence.c.raw).order_by(store.evidence.c.record_no))).all()
        hashes = (await conn.scalars(select(store.evidence.c.record_sha256).order_by(store.evidence.c.record_no))).all()
    assert ids[0] == "EV-hb01-000001" and ids[-1] == "EV-hb01-000031"
    assert hashes == [record_sha256(bytes(r)) for r in raws]
    assert any(b"Sintetis-Bukan-Rahasia1" in bytes(r) for r in raws)  # data asli utuh (K21)

    (ev,) = await _events(db, "evidence.ingested")
    assert ev.data["record_range"] == {"from": 1, "to": 31}
    assert ev.data["file_sha256"] == SVC_BACKUP_SHA
    assert ev.data["batch_sha256"] == batch_sha256(hashes)
    (audit,) = await _events(db, "audit.record")
    assert audit.data["action"] == "ingest.file.imported"


async def test_reimport_is_idempotent(db: Database, settings: Settings) -> None:
    first = await _import(db, settings, "chains/svc-backup.jsonl")
    await run_job(db.engine, settings, first.job_id)
    shutil.copy(settings.import_root / "chains" / "svc-backup.jsonl", settings.import_root / "salinan.jsonl")
    again = await _import(db, settings, "salinan.jsonl")
    assert (again.job_id, again.source_id, again.created) == (first.job_id, "hb01", False)
    assert await run_job(db.engine, settings, first.job_id) == store.JOB_COMPLETED
    assert await _count(db, store.evidence) == 31
    assert len(await _events(db, "evidence.ingested")) == 1


async def test_batches_and_second_source(db: Database, settings: Settings) -> None:
    await run_job(db.engine, settings, (await _import(db, settings, "benign/J2.jsonl")).job_id)
    out = await _import(db, settings, _synthetic(settings.import_root, "besar.jsonl", 1200))
    assert out.source_id == "hb02"
    await run_job(db.engine, settings, out.job_id)
    ranges = [e.data["record_range"] for e in await _events(db, "evidence.ingested") if e.data["source_id"] == "hb02"]
    assert ranges == [{"from": 1, "to": 500}, {"from": 501, "to": 1000}, {"from": 1001, "to": 1200}]


async def test_concurrent_different_files_get_different_codes(db: Database, settings: Settings) -> None:
    a = _synthetic(settings.import_root, "a.jsonl", 3)
    b = _synthetic(settings.import_root, "b.jsonl", 4)
    got = await asyncio.gather(_import(db, settings, a), _import(db, settings, b))
    assert sorted(o.source_id for o in got) == ["hb01", "hb02"]


async def test_concurrent_same_file_single_winner(db: Database, settings: Settings) -> None:
    got = await asyncio.gather(*[_import(db, settings, "benign/J2.jsonl") for _ in range(3)])
    assert len({o.job_id for o in got}) == 1
    assert await _count(db, store.raw_source) == 1


async def test_resume_after_crash_has_no_duplicates(db: Database, settings: Settings) -> None:
    out = await _import(db, settings, _synthetic(settings.import_root, "besar.jsonl", 1200))
    path = settings.evidence_store / out.file_sha256
    batch_no, lines = next(_chunks(path, settings.limits, 500, 0))
    async with db.engine.begin() as conn:  # batch pertama ter-commit, lalu proses "mati"
        await _write_batch(
            conn,
            job_id=out.job_id,
            source_id=out.source_id,
            file_sha256=out.file_sha256,
            batch_no=batch_no,
            lines=lines,
            limits=settings.limits,
        )
        await conn.execute(
            update(store.ingest_job).where(store.ingest_job.c.job_id == out.job_id).values(status=store.JOB_RUNNING)
        )
    assert await run_job(db.engine, settings, out.job_id) == store.JOB_COMPLETED
    assert await _count(db, store.evidence) == 1200
    assert len(await _events(db, "evidence.ingested")) == 3


async def test_rejected_file_leaves_nothing(db: Database, settings: Settings) -> None:
    (settings.import_root / "rusak.jsonl").write_bytes(b"{x}\n{y}\n")
    with pytest.raises(ImportRejected) as exc:
        await _import(db, settings, "rusak.jsonl")
    assert exc.value.code == FORMAT_TIDAK_VALID
    assert await _count(db, store.raw_source) == 0
    assert [p.name for p in settings.evidence_store.iterdir()] == []


async def test_bad_lines_are_quarantined(db: Database, settings: Settings) -> None:
    ref = _synthetic(settings.import_root, "campur.jsonl", 3, extra=b"{rusak}\n")
    out = await _import(db, settings, ref)
    assert await run_job(db.engine, settings, out.job_id) == store.JOB_COMPLETED_WITH_ERRORS
    async with db.engine.connect() as conn:
        row = (await conn.execute(select(store.rejected_record))).one()
    assert (row.record_no, row.code, bytes(row.raw)) == (4, "JSON_RUSAK", b"{rusak}")
    assert await _count(db, store.evidence) == 3
