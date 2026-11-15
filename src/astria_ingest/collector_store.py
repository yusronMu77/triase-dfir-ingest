"""Durable consent, job and encrypted custody records; no evidence decryption or analysis."""

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    MetaData,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()
Json = JSON().with_variant(JSONB(), "postgresql")

consent = Table(
    "collector_consent",
    metadata,
    Column("consent_id", Text, primary_key=True),
    Column("document", Json, nullable=False),
    Column("recorded_by", Text, nullable=False),
    Column("revoked", Boolean, nullable=False, default=False),
)
job = Table(
    "collector_job",
    metadata,
    Column("job_id", Text, primary_key=True),
    Column("consent_id", Text, ForeignKey("collector_consent.consent_id"), nullable=False, unique=True),
    Column("key_id", Text, nullable=False),
    Column("document", Json, nullable=False),
    Column("stage", Text, nullable=False),
    Column("code", Text),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)
acquisition = Table(
    "collector_acquisition",
    metadata,
    Column("job_id", Text, ForeignKey("collector_job.job_id"), primary_key=True),
    Column("acquisition_id", Text, nullable=False, unique=True),
    Column("archive_sha256", Text, nullable=False),
    Column("archive_size", BigInteger, nullable=False),
    Column("storage_name", Text, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
)
