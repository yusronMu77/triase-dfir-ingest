"""Collector v1 wire models, validated independently of Collector's deployment package."""

from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f]+$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Scope(Model):
    # Deliberately no defaults: consent must enumerate every acquisition option.
    backup: Literal["none", "all"]
    download: Literal["none", "non-system", "all"]
    remove_trusted: Literal["yes", "no"]
    intrusion_logs: Literal["yes", "no"]
    hash_files: Literal["yes", "no"]
    browser_history: Literal["yes", "no"]
    magisk_modules: Literal["yes", "no"]


class Device(Model):
    label: Text
    serial_tail: Annotated[str, Field(min_length=1, max_length=4, pattern=r"^[A-Za-z0-9_-]+$")]
    serial_sha256: Hash


class Job(Model):
    job_id: Identifier
    consent_id: Identifier
    device: Device
    scope_flags: Scope
    expires_at: AwareDatetime
    trace_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    owner_ref: Text
    purpose: Text
    limitations: Text

    @field_validator("trace_id")
    @classmethod
    def nonzero_trace(cls, value: str) -> str:
        if value == "0" * 32:
            raise ValueError("trace_id must not be zero")
        return value


class Consent(Model):
    owner_ref: Text
    purpose: Text
    basis: Literal["explicit_owner_consent"]
    given_at: AwareDatetime
    record_ref: Text
    record_sha256: Hash
    scope_flags: Scope
    device_serial_sha256: Hash
    expires_at: AwareDatetime
    explicit: Literal[True]


class Provision(Model):
    job: Job
    consent: Consent
    collector_key_id: Identifier
    expanded_scope_reason: Text | None = None

    @model_validator(mode="after")
    def consent_matches(self) -> Self:
        if (
            self.job.owner_ref != self.consent.owner_ref
            or self.job.purpose != self.consent.purpose
            or self.job.scope_flags != self.consent.scope_flags
            or self.job.device.serial_sha256 != self.consent.device_serial_sha256
            or self.job.expires_at > self.consent.expires_at
            or self.consent.given_at > datetime.now(UTC)
            or self.consent.given_at >= self.job.expires_at
        ):
            raise ValueError("consent does not authorize this job")
        minimal = Scope(
            backup="none",
            download="non-system",
            remove_trusted="yes",
            intrusion_logs="no",
            hash_files="no",
            browser_history="no",
            magisk_modules="no",
        )
        if self.job.scope_flags != minimal and self.expanded_scope_reason is None:
            raise ValueError("a written reason is required for non-default scope")
        return self


class Progress(Model):
    stage: Literal["perangkat_terdeteksi", "mengambil", "mengemas", "mengunggah", "gagal", "selesai"]
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")] | None = None


class CollectorConfig(Model):
    age_recipient: str
    age_recipient_sha256: Hash
    androidqf_version: Literal["1.8.3"] = "1.8.3"


class Receipt(Model):
    acquisition_id: Identifier
    job_id: Identifier
    status: Literal["received"] = "received"
    archive_sha256: Hash
    archive_size: int = Field(ge=1)
    metadata_status: Literal["pending_verification"] = "pending_verification"
