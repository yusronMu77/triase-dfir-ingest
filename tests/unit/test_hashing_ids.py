from __future__ import annotations

import hashlib
import io

import pytest

from astria_ingest.hashing import batch_sha256, record_sha256, sha256_hex, stream_sha256
from astria_ingest.ids import evidence_id, parse_evidence_id, source_code
from astria_ingest.limits import Limits


def test_stream_hash_equals_one_shot() -> None:
    data = b"a" * (3 * 1024 * 1024 + 17)
    digest, size = stream_sha256(io.BytesIO(data), chunk_bytes=1024 * 1024)
    assert digest == hashlib.sha256(data).hexdigest()
    assert size == len(data)


def test_record_hash_is_raw_bytes() -> None:
    assert record_sha256(b'{ "a":1 }') == sha256_hex(b'{ "a":1 }')
    assert record_sha256(b'{ "a":1 }') != record_sha256(b'{"a":1}')


def test_batch_hash_is_deterministic_and_order_sensitive() -> None:
    a, b = sha256_hex(b"1"), sha256_hex(b"2")
    assert batch_sha256([a, b]) == sha256_hex(f"{a}\n{b}".encode())
    assert batch_sha256([a, b]) == batch_sha256(iter([a, b]))
    assert batch_sha256([a, b]) != batch_sha256([b, a])


@pytest.mark.parametrize("bad", [[], ["ABC"], [sha256_hex(b"1").upper()], ["0" * 63]])
def test_batch_hash_rejects_bad_input(bad: list[str]) -> None:
    with pytest.raises(ValueError):
        batch_sha256(bad)


@pytest.mark.parametrize(
    ("seq", "code"), [(1, "hb01"), (9, "hb09"), (42, "hb42"), (100, "hb100"), (999_999, "hb999999")]
)
def test_source_code(seq: int, code: str) -> None:
    assert source_code("hb", seq) == code


@pytest.mark.parametrize(
    ("prefix", "seq"), [("hb", 0), ("hb", -1), ("hb", 1_000_000), ("hb", True), ("HB", 1), ("h", 1), ("h1", 1)]
)
def test_source_code_rejects(prefix: str, seq: int) -> None:
    with pytest.raises(ValueError):
        source_code(prefix, seq)


def test_evidence_id_roundtrip() -> None:
    eid = evidence_id("hb01", 1)
    assert eid == "EV-hb01-000001"
    assert parse_evidence_id(eid) == ("hb01", 1)
    assert parse_evidence_id(evidence_id("hb100", 999_999)) == ("hb100", 999_999)


@pytest.mark.parametrize(
    ("source", "record_no"), [("hb01", 0), ("hb01", 1_000_000), ("hb1", 1), ("HB01", 1), ("hb01", True)]
)
def test_evidence_id_rejects(source: str, record_no: int) -> None:
    with pytest.raises(ValueError):
        evidence_id(source, record_no)


@pytest.mark.parametrize(
    "value",
    [
        "EV-hb01-000000",
        "EV-hb01-1",
        "EV-hb01-0000001",
        "ev-hb01-000001",
        "EV-hb1-000001",
        "EV-hb01-000001 ",
        "EV-hb01-00000a",
        "",
    ],
)
def test_parse_evidence_id_rejects(value: str) -> None:
    assert parse_evidence_id(value) is None


def test_limits_validation() -> None:
    assert Limits().max_lines == 999_999
    with pytest.raises(ValueError):
        Limits(max_lines=1_000_000)
    with pytest.raises(ValueError):
        Limits(max_depth=0)
