"""Tabel ingest (SQLAlchemy Core, PostgreSQL). Dibuat dengan `create_all` saat start (K14), skema `ingest`.

Mengikuti note app-ingest 4.1-4.2, dengan selisih yang disengaja:
- `evidence.raw` (bytea) menyimpan bytes asli baris (K21); `fields`/`excerpt` tidak disimpan, tetapi dirender
  saat output (K12).
- `record_sha256` disimpan sebagai hex teks 64 karakter (sama dengan bentuk di API dan event), bukan bytea 32.
- `rejected_record` menampung baris rusak (K9); `source_id` dari sequence `ingest_source_seq` (K7).
- Tidak ada jalur UPDATE untuk `evidence.raw` di kode; hanya INSERT.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Sequence,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()
JSONType = JSON().with_variant(JSONB(), "postgresql")

source_seq = Sequence("ingest_source_seq", start=1, minvalue=1, metadata=metadata)

JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_COMPLETED = "completed"
JOB_COMPLETED_WITH_ERRORS = "completed_with_errors"
JOB_FAILED = "failed"
JOB_STATUSES = (JOB_QUEUED, JOB_RUNNING, JOB_COMPLETED, JOB_COMPLETED_WITH_ERRORS, JOB_FAILED)
JOB_PENDING = (JOB_QUEUED, JOB_RUNNING)
JOB_DONE = (JOB_COMPLETED, JOB_COMPLETED_WITH_ERRORS)

_HEX64 = "~ '^[0-9a-f]{64}$'"

raw_source = Table(
    "raw_source",
    metadata,
    Column("source_id", Text, primary_key=True),
    Column("seq", BigInteger, nullable=False, unique=True),
    Column("kind", Text, nullable=False),
    Column("file_sha256", Text, nullable=False, unique=True),
    Column("size_bytes", BigInteger, nullable=False),
    Column("path_ref", Text, nullable=False),
    Column("storage_ref", Text, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("hold", Boolean, nullable=False, server_default="false"),
    CheckConstraint(f"file_sha256 {_HEX64}", name="raw_source_file_sha256_hex"),
)

ingest_job = Table(
    "ingest_job",
    metadata,
    Column("job_id", Text, primary_key=True),
    Column("kind", Text, nullable=False, server_default="file_import"),
    Column("source_id", Text, ForeignKey("raw_source.source_id"), nullable=False, unique=True),
    Column("status", Text, nullable=False),
    Column("requested_by", Text, nullable=False),
    Column("stats", JSONType, nullable=False),
    Column("last_record_no", Integer, nullable=False, server_default="0"),
    Column("error_code", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    CheckConstraint(f"status IN ({', '.join(repr(s) for s in JOB_STATUSES)})", name="ingest_job_status"),
)
Index("ingest_job_status_created", ingest_job.c.status, ingest_job.c.created_at)

evidence = Table(
    "evidence",
    metadata,
    Column("evidence_id", Text, primary_key=True),
    Column("source_id", Text, ForeignKey("raw_source.source_id"), nullable=False),
    Column("record_no", Integer, nullable=False),
    Column("record_sha256", Text, nullable=False),
    Column("raw", LargeBinary, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("host", Text, nullable=False),
    Column("account", Text, nullable=True),
    Column("kind", Text, nullable=False),
    Column("event_id", Integer, nullable=False),
    Column("record_id", BigInteger, nullable=True),
    Column("src_ip", Text, nullable=True),
    Column("details", JSONType, nullable=False),
    Column("extra", JSONType, nullable=False),
    Column("injection_suspect", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint("source_id", "record_no", name="evidence_source_record"),
    CheckConstraint("record_no >= 1", name="evidence_record_no_positive"),
    CheckConstraint(f"record_sha256 {_HEX64}", name="evidence_record_sha256_hex"),
)
Index("evidence_host_time", evidence.c.host, evidence.c.occurred_at)
Index("evidence_account_time", evidence.c.account, evidence.c.occurred_at)

alert = Table(
    "alert",
    metadata,
    Column("alert_id", Text, primary_key=True),
    Column("source_id", Text, ForeignKey("raw_source.source_id"), nullable=False),
    Column("record_no", Integer, nullable=False),
    Column("rule_id", Text, nullable=True),
    Column("rule_title", Text, nullable=False),
    Column("rule_file", Text, nullable=True),
    Column("level", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("tactics", JSONType, nullable=False),
    Column("techniques", JSONType, nullable=False),
    Column("other_tags", JSONType, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("host", Text, nullable=False),
    Column("account", Text, nullable=True),
    Column("src_ip", Text, nullable=True),
    Column("kind", Text, nullable=False),
    UniqueConstraint("source_id", "record_no", name="alert_source_record"),
)
Index("alert_rule_host", alert.c.rule_id, alert.c.host)

alert_evidence = Table(
    "alert_evidence",
    metadata,
    Column("alert_id", Text, ForeignKey("alert.alert_id"), primary_key=True),
    Column("evidence_id", Text, ForeignKey("evidence.evidence_id"), primary_key=True),
)

rejected_record = Table(
    "rejected_record",
    metadata,
    Column("source_id", Text, ForeignKey("raw_source.source_id"), primary_key=True),
    Column("record_no", Integer, primary_key=True),
    Column("code", Text, nullable=False),
    # Bytes asli baris; NULL untuk baris yang terlalu panjang (tidak dimuat). Tidak pernah keluar lewat API/log.
    Column("raw", LargeBinary, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
