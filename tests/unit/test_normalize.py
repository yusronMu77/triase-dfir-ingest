from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from astria_ingest.adapters.hayabusa import LineError
from astria_ingest.normalize import TIMESTAMP_TIDAK_SAH, channel_slug, normalize, parse_timestamp, severity_of

UTC_0214 = datetime(2026, 11, 10, 2, 14, 7, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-10 02:14:07.000 +00:00",
        "2026-11-10 09:14:07.000 +07:00",
        "2026-11-09 21:14:07.000 -05:00",
        "2026-11-10T02:14:07.000Z",
        "2026-11-10T02:14:07Z",
        "2026-11-10 02:14:07 +0000",
        "2026-11-10T02:14:07.000000000Z",
    ],
)
def test_timestamp_formats_to_utc(value: str) -> None:
    got = parse_timestamp(value)
    assert got == UTC_0214
    assert got.tzinfo is UTC


def test_timestamp_fraction_truncated_to_microseconds() -> None:
    assert parse_timestamp("2026-11-10T02:14:07.1234567Z").microsecond == 123456


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-10 02:14:07.000",  # tanpa zona: ambigu
        "2026-13-10 02:14:07.000 +00:00",
        "2026-11-10 25:14:07.000 +00:00",
        "2026-11-10 02:14:07.000 +24:00",
        "10/11/2026 02:14:07",
        "",
        "2026-11-10 02:14:07.000 +00:00 x",
    ],
)
def test_timestamp_invalid(value: str) -> None:
    with pytest.raises(LineError) as exc:
        parse_timestamp(value)
    assert exc.value.code == TIMESTAMP_TIDAK_SAH


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("info", "informational"),
        ("low", "low"),
        ("med", "medium"),
        ("high", "high"),
        ("crit", "critical"),
        ("emer", "critical"),
        ("Critical", "critical"),
        ("medium", "medium"),
        ("aneh", "unknown"),
    ],
)
def test_severity(level: str, severity: str) -> None:
    assert severity_of(level) == severity


def test_channel_slug() -> None:
    assert channel_slug("Sec") == "security"
    assert channel_slug("Microsoft-Windows-Sysmon/Operational") == "microsoft-windows-sysmon-operational"
    assert channel_slug("!!!") == "unknown"


def _record(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "Timestamp": "2026-11-10 02:14:07.000 +00:00",
        "RuleTitle": "Logon Failure (Wrong Password)",
        "Level": "low",
        "Computer": "WS-ADM-04",
        "Channel": "Sec",
        "EventID": 4625,
        "RecordID": 4217,
        "Details": {"Type": "3 - NETWORK", "TgtUser": "svc-backup", "SrcIP": "10.20.8.31", "Proc": "-"},
        "ExtraFieldInfo": {"SubStatus": "WRONG PW"},
        "RuleFile": "Sec_4625_Low_LogonFail_WrongPW.yml",
        "RuleID": "e87bd730-df45-4ae9-85de-6c75369c5d29",
        "EvtxFile": "WS-ADM-04/Security.evtx",
    }
    base.update(over)
    return base


def test_normalize_basic() -> None:
    a = normalize(_record())
    assert a.occurred_at == UTC_0214
    assert a.kind == "windows.security.4625"
    assert (a.host, a.account, a.src_ip, a.record_id) == ("WS-ADM-04", "svc-backup", "10.20.8.31", 4217)
    assert (a.level, a.severity) == ("low", "low")
    assert a.tactics == a.mitre_tags == a.other_tags == ()


def test_normalize_correlation_line() -> None:
    a = normalize(
        _record(
            Level="med",
            RecordID=None,
            Details={"Count": 20, "TargetUserName": "svc-backup", "IpAddress": "10.20.8.31"},
            ExtraFieldInfo={},
            MitreTactics=["CredAccess"],
            MitreTags=["T1110.003"],
        )
    )
    assert a.record_id is None
    assert (a.account, a.src_ip, a.severity) == ("svc-backup", "10.20.8.31", "medium")
    assert a.mitre_tags == ("T1110.003",)


def test_tags_kept_as_is() -> None:
    a = normalize(_record(MitreTags=["T1007", "S0039", "T1070.001"], OtherTags=["attack.1136.001"]))
    assert a.mitre_tags == ("T1007", "S0039", "T1070.001")
    assert a.other_tags == ("attack.1136.001",)


@pytest.mark.parametrize(
    ("details", "account"),
    [
        ({"User": "svc-backup", "Cmdline": "whoami"}, "svc-backup"),
        ({"SubjectUserName": "svc-backup"}, "svc-backup"),
        ({"SrcSID": "S-1-5-21-1-2-3-1104", "TgtGrp": "Administrators"}, "S-1-5-21-1-2-3-1104"),
        ({"TgtUser": "-", "User": "budi"}, "budi"),
        ({"Proc": "x"}, None),
    ],
)
def test_account_selection(details: dict[str, Any], account: str | None) -> None:
    assert normalize(_record(Details=details)).account == account


def test_weird_types_do_not_crash() -> None:
    a = normalize(_record(Details=["x"], ExtraFieldInfo="y", RecordID=True, MitreTags="T1", RuleID=5))
    assert (a.details, a.extra, a.record_id, a.mitre_tags, a.rule_id) == ({}, {}, None, (), None)
