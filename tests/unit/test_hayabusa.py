from __future__ import annotations

import io
import json
from collections.abc import Callable
from typing import Any

import pytest

from astria_ingest.adapters.hayabusa import (
    BUKAN_OBJEK,
    ENCODING_TIDAK_DIDUKUNG,
    FIELD_WAJIB,
    JSON_RUSAK,
    KEY_GANDA,
    NILAI_TIDAK_SAH,
    TEKS_TIDAK_SAH,
    TERLALU_BANYAK_BARIS,
    TERLALU_DALAM,
    UTF8_RUSAK,
    FileFormatError,
    Line,
    LineError,
    iter_lines,
    parse_line,
)
from astria_ingest.limits import Limits

LIMITS = Limits()
VALID = (
    b'{ "Timestamp":"2026-11-10 02:14:07.000 +00:00","RuleTitle":"PW Guessing","Level":"med",'
    b'"Computer":"WS-ADM-04","Channel":"Sec","EventID":4625,"MitreTags":["T1110.003","S0039"],'
    b'"Details":{"Count":20},"ExtraFieldInfo":{} }'
)


def _lines(data: bytes, limits: Limits = LIMITS) -> list[Line]:
    return list(iter_lines(io.BytesIO(data), limits))


def _error(raw: bytes, limits: Limits = LIMITS) -> str:
    with pytest.raises(LineError) as exc:
        parse_line(raw, limits)
    return exc.value.code


def test_lf_crlf_and_last_line_without_newline() -> None:
    got = _lines(b"a\nb\r\nc")
    assert [(x.record_no, x.kind, x.raw) for x in got] == [(1, "data", b"a"), (2, "data", b"b"), (3, "data", b"c")]


def test_blank_lines_are_counted_but_marked() -> None:
    got = _lines(b"a\n\n   \r\n\tb\n")
    assert [(x.record_no, x.kind) for x in got] == [(1, "data"), (2, "blank"), (3, "blank"), (4, "data")]


def test_empty_file() -> None:
    assert _lines(b"") == []


def test_utf8_bom_removed_from_first_line_only() -> None:
    got = _lines(b"\xef\xbb\xbfa\n\xef\xbb\xbfb\n")
    assert got[0].raw == b"a"
    assert got[1].raw == b"\xef\xbb\xbfb"


@pytest.mark.parametrize("bom", [b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00"])
def test_utf16_and_utf32_rejected(bom: bytes) -> None:
    with pytest.raises(FileFormatError) as exc:
        _lines(bom + "{}\n".encode("utf-16-le"))
    assert exc.value.code == ENCODING_TIDAK_DIDUKUNG


def test_too_long_line_is_skipped_without_loading() -> None:
    limits = Limits(max_line_bytes=10)
    got = _lines(b"short\n" + b"x" * 50 + b"\nnext\n" + b"y" * 11, limits)
    assert [(x.record_no, x.kind, x.raw) for x in got] == [
        (1, "data", b"short"),
        (2, "too_long", b""),
        (3, "data", b"next"),
        (4, "too_long", b""),
    ]


def test_line_exactly_at_limit_is_accepted() -> None:
    limits = Limits(max_line_bytes=10)
    assert _lines(b"x" * 10 + b"\r\n", limits)[0].kind == "data"
    assert _lines(b"x" * 11 + b"\n", limits)[0].kind == "too_long"


def test_too_many_lines() -> None:
    with pytest.raises(FileFormatError) as exc:
        _lines(b"a\n" * 4, Limits(max_lines=3))
    assert exc.value.code == TERLALU_BANYAK_BARIS


def test_parse_valid_keeps_tags_as_is() -> None:
    obj = parse_line(VALID, LIMITS)
    assert obj["EventID"] == 4625
    assert obj["MitreTags"] == ["T1110.003", "S0039"]
    assert "RecordID" not in obj


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"\xff\xfe{}", UTF8_RUSAK),
        (b'{"a":"\xc3"}', UTF8_RUSAK),
        (b"{not json}", JSON_RUSAK),
        (b'{"a":1', JSON_RUSAK),
        (b'{"a":1} {"b":2}', JSON_RUSAK),
        (b'{"a":' + b"9" * 5000 + b"}", JSON_RUSAK),
        (b'{"a":1,"a":2}', KEY_GANDA),
        (b'{"a":{"b":1,"b":1}}', KEY_GANDA),
        (b'{"a":NaN}', NILAI_TIDAK_SAH),
        (b'{"a":-Infinity}', NILAI_TIDAK_SAH),
        (b'{"a":"\\ud800"}', TEKS_TIDAK_SAH),
        (b'{"\\udfff":1}', TEKS_TIDAK_SAH),
        (b"[1,2]", BUKAN_OBJEK),
        (b"42", BUKAN_OBJEK),
        (b'"teks"', BUKAN_OBJEK),
        (b"null", BUKAN_OBJEK),
    ],
)
def test_parse_errors(raw: bytes, code: str) -> None:
    assert _error(raw) == code


def test_depth_limit() -> None:
    limits = Limits(max_depth=3)
    obj = json.loads(VALID)
    obj["Details"] = {"a": [1]}  # objek(1) -> Details(2) -> list(3)
    assert parse_line(json.dumps(obj).encode(), limits)
    obj["Details"] = {"a": [[1]]}
    assert _error(json.dumps(obj).encode(), limits) == TERLALU_DALAM


def test_very_deep_nesting_does_not_crash() -> None:
    raw = b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    assert _error(raw) in (TERLALU_DALAM, JSON_RUSAK)


def _pop(key: str) -> Callable[[dict[str, Any]], None]:
    return lambda o: o.pop(key)


def _set(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda o: o.update({key: value})


@pytest.mark.parametrize(
    "mutate",
    [
        _pop("Timestamp"),
        _pop("EventID"),
        _set("EventID", "4625"),
        _set("EventID", True),
        _set("EventID", 46.25),
        _set("Computer", ""),
        _set("Level", None),
        _set("RuleTitle", ["x"]),
    ],
)
def test_required_fields(mutate: Callable[[dict[str, Any]], None]) -> None:
    obj = json.loads(VALID)
    mutate(obj)
    assert _error(json.dumps(obj).encode()) == FIELD_WAJIB
