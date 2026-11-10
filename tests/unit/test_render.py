from __future__ import annotations

from typing import Any

import pytest

from astria_ingest.normalize import normalize
from astria_ingest.render import (
    MASK,
    MAX_EXCERPT_CHARS,
    TRUNCATED,
    clean,
    redact,
    render_excerpt,
    render_fields,
    strip_controls,
)

SECRET = "Sintetis-Bukan-Rahasia1"  # noqa: S105 - sandi palsu dari data sintetis samples


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"net user adm-support {SECRET} /add", f"net user adm-support {MASK} /add"),
        ("net user adm-support S3cr3t! /add", f"net user adm-support {MASK} /add"),
        (f"NET.EXE USER adm {SECRET}", f"NET.EXE USER adm {MASK}"),
        (f"net1 user adm {SECRET} /add", f"net1 user adm {MASK} /add"),
        (f"mysql -u root -p {SECRET} db", f"mysql -u root -p {MASK} db"),
        (f"runas /p:{SECRET} cmd", f"runas /p:{MASK} cmd"),
        (f"password={SECRET}", f"password={MASK}"),
        (f"Password : {SECRET}", f"Password : {MASK}"),
    ],
)
def test_redact_positive(text: str, expected: str) -> None:
    assert redact(text) == expected
    assert SECRET not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "net user adm-support /add",
        "net user adm-support /delete",
        "net user /domain",
        "net user",
        "Get-ChildItem -path C:\\Temp -parameter x",
        "Reset your password before Monday",
        "password",
        "C:\\Windows\\System32\\net.exe",
    ],
)
def test_redact_benign(text: str) -> None:
    assert redact(text) == text


@pytest.mark.parametrize(
    "text",
    [f"net user adm {SECRET} /add", f"x -p {SECRET}", f"/p:{SECRET}", f"password={SECRET}", f"net user a {MASK}"],
)
def test_redact_idempotent(text: str) -> None:
    once = redact(text)
    assert redact(once) == once


def test_zero_width_cannot_hide_secret() -> None:
    text = f"pass\u200bword={SECRET} net\u2060 user adm {SECRET}"
    out = clean(text)
    assert SECRET not in out
    assert "\u200b" not in out and "\u2060" not in out


def test_strip_controls() -> None:
    assert strip_controls("a\tb\nc\r\x00d\x1b[31me\u202ef\ufeffg") == "a b c d[31mefg"


def test_clean_types_and_truncate() -> None:
    assert clean(None) == ""
    assert clean(True) == "true"
    assert clean(4625) == "4625"
    long = clean("x" * 10_000, 100)
    assert len(long) == 100
    assert long.endswith(TRUNCATED)


def _alert(**details: Any) -> Any:
    return normalize(
        {
            "Timestamp": "2026-11-10 02:24:40.118 +00:00",
            "RuleTitle": "New User Created Via Net.EXE",
            "Level": "med",
            "Computer": "WS-ADM-04",
            "Channel": "Sec",
            "EventID": 4688,
            "RecordID": 4262,
            "Details": details,
            "ExtraFieldInfo": {"ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "Nested": {"A": [1, "dua"]}},
        }
    )


def test_render_fields_flatten_and_redact() -> None:
    fields = render_fields(_alert(Cmdline=f"net user adm-support {SECRET} /add", PID=4312, User="svc-backup"))
    assert fields["Cmdline"] == f"net user adm-support {MASK} /add"
    assert fields["PID"] == "4312"
    assert fields["Nested.A"] == "1, dua"
    assert all(isinstance(v, str) for v in fields.values())
    assert SECRET not in "".join(fields.values())


def test_render_excerpt() -> None:
    excerpt = render_excerpt(_alert(Cmdline=f"net user adm-support {SECRET} /add\n\u202eevil", User="svc-backup"))
    assert excerpt.startswith("EventID=4688 New User Created Via Net.EXE")
    assert "User=svc-backup" in excerpt
    assert SECRET not in excerpt
    assert "\n" not in excerpt and "\u202e" not in excerpt
    assert len(render_excerpt(_alert(Cmdline="y" * 5000))) <= MAX_EXCERPT_CHARS
