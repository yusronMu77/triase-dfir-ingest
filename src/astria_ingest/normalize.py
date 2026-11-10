"""Normalisasi satu baris Hayabusa (sudah lolos `parse_line`) menjadi field terstruktur.

Nilai disimpan **apa adanya** (K12): tidak ada sanitasi atau redaksi di sini; itu dikerjakan `render` saat output.
Tag (`MitreTactics`, `MitreTags`, `OtherTags`) tidak divalidasi (K16): `S0039` dan T1070.001 tetap ada.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from astria_ingest.adapters.hayabusa import LineError

TIMESTAMP_TIDAK_SAH = "TIMESTAMP_TIDAK_SAH"

# `2026-11-10 02:14:07.000 +00:00` (-U), zona lokal `+07:00` (tanpa -U), ISO `2026-11-10T02:14:07.000Z` (-O).
_TIMESTAMP = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[ T](?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,9}))?"
    r" ?(?P<tz>Z|[+-]\d{2}:?\d{2})"
)

SEVERITY = {
    "info": "informational",
    "informational": "informational",
    "low": "low",
    "med": "medium",
    "medium": "medium",
    "high": "high",
    "crit": "critical",
    "critical": "critical",
    "emer": "critical",
    "emergency": "critical",
}
SEVERITY_UNKNOWN = "unknown"

# Singkatan kanal Hayabusa (rules/config/channel_abbreviations.txt) yang dipakai di `kind`.
CHANNEL_SLUG = {
    "Sec": "security",
    "Sys": "system",
    "App": "application",
    "Sysmon": "sysmon",
    "PwSh": "powershell",
    "PwShClassic": "powershell-classic",
    "Defender": "defender",
}

# Urutan kunci `Details` untuk akun yang paling relevan (note format bagian 3).
ACCOUNT_KEYS = ("TgtUser", "TargetUserName", "User", "SubjectUserName", "SrcSID")
SRC_IP_KEYS = ("SrcIP", "IpAddress")


@dataclass(frozen=True, slots=True)
class NormalizedAlert:
    occurred_at: datetime
    host: str
    account: str | None
    kind: str
    channel: str
    event_id: int
    record_id: int | None
    rule_title: str
    rule_id: str | None
    rule_file: str | None
    level: str
    severity: str
    src_ip: str | None
    evtx_file: str | None
    tactics: tuple[str, ...] = ()
    mitre_tags: tuple[str, ...] = ()
    other_tags: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


def parse_timestamp(value: str) -> datetime:
    """Waktu Hayabusa -> datetime UTC. Tanpa zona waktu ditolak (ambigu). Pecahan detik dipotong ke mikrodetik."""
    m = _TIMESTAMP.fullmatch(value.strip())
    if m is None:
        raise LineError(TIMESTAMP_TIDAK_SAH)
    frac = (m["frac"] or "0")[:6].ljust(6, "0")
    tz = m["tz"]
    try:
        local = datetime.fromisoformat(f"{m['date']}T{m['time']}.{frac}")
        if tz == "Z":
            offset = UTC
        else:
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            hours, minutes = int(digits[:2]), int(digits[2:])
            if hours > 23 or minutes > 59:
                raise ValueError
            offset = timezone(sign * timedelta(hours=hours, minutes=minutes))
    except ValueError:
        raise LineError(TIMESTAMP_TIDAK_SAH) from None
    return local.replace(tzinfo=offset).astimezone(UTC)


def severity_of(level: str) -> str:
    return SEVERITY.get(level.strip().lower(), SEVERITY_UNKNOWN)


def channel_slug(channel: str) -> str:
    known = CHANNEL_SLUG.get(channel)
    if known:
        return known
    slug = re.sub(r"[^a-z0-9]+", "-", channel.lower()).strip("-")
    return slug or "unknown"


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _first(details: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _text(details.get(key))
        if value is not None and value != "-":
            return value
    return None


def normalize(record: dict[str, Any]) -> NormalizedAlert:
    """Objek dari `parse_line` -> `NormalizedAlert`. Melempar `LineError` bila waktunya tidak sah."""
    details = record.get("Details") if isinstance(record.get("Details"), dict) else {}
    extra = record.get("ExtraFieldInfo") if isinstance(record.get("ExtraFieldInfo"), dict) else {}
    record_id = record.get("RecordID")
    if isinstance(record_id, bool) or not isinstance(record_id, int):
        record_id = None
    channel = record["Channel"]
    event_id = record["EventID"]
    return NormalizedAlert(
        occurred_at=parse_timestamp(record["Timestamp"]),
        host=record["Computer"],
        account=_first(details, ACCOUNT_KEYS),
        kind=f"windows.{channel_slug(channel)}.{event_id}",
        channel=channel,
        event_id=event_id,
        record_id=record_id,
        rule_title=record["RuleTitle"],
        rule_id=_text(record.get("RuleID")),
        rule_file=_text(record.get("RuleFile")),
        level=record["Level"],
        severity=severity_of(record["Level"]),
        src_ip=_first(details, SRC_IP_KEYS),
        evtx_file=_text(record.get("EvtxFile")),
        tactics=_str_tuple(record.get("MitreTactics")),
        mitre_tags=_str_tuple(record.get("MitreTags")),
        other_tags=_str_tuple(record.get("OtherTags")),
        details=details,
        extra=extra,
    )
