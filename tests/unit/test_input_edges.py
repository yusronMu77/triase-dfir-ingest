"""Nilai yang lolos JSON tetapi akan gagal di Python atau PostgreSQL: ditolak per baris sejak lintasan 1."""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from astria_ingest.adapters.hayabusa import (
    BOM_UTF8,
    FIELD_WAJIB,
    MAX_EVENT_ID,
    NILAI_TIDAK_SAH,
    TEKS_TIDAK_SAH,
    LineError,
    iter_lines,
    parse_line,
)
from astria_ingest.limits import Limits
from astria_ingest.normalize import TIMESTAMP_TIDAK_SAH, normalize, parse_timestamp
from astria_ingest.paths import resolve_import_path
from astria_ingest.store_files import BERKAS_BERUBAH, StoreError, copy_into_store, ensure_store

LIMITS = Limits()


def _line(**over: str) -> bytes:
    fields = {
        "Timestamp": '"2026-11-10 02:14:07.000 +00:00"',
        "RuleTitle": '"T"',
        "Level": '"low"',
        "Computer": '"H"',
        "Channel": '"Sec"',
        "EventID": "4625",
    } | over
    return ("{" + ",".join(f'"{k}":{v}' for k, v in fields.items()) + "}").encode()


def _error(raw: bytes) -> str:
    with pytest.raises(LineError) as exc:
        normalize(parse_line(raw, LIMITS))
    return exc.value.code


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"Computer": '"A\\u0000B"'}, TEKS_TIDAK_SAH),
        ({"Details": '{"x":"a\\u0000"}'}, TEKS_TIDAK_SAH),
        ({"Details": '{"a\\u0000":1}'}, TEKS_TIDAK_SAH),
        ({"Details": '{"n":1e999}'}, NILAI_TIDAK_SAH),
        ({"Details": '{"n":-1e999}'}, NILAI_TIDAK_SAH),
        ({"EventID": str(MAX_EVENT_ID + 1)}, FIELD_WAJIB),
        ({"EventID": "99999999999"}, FIELD_WAJIB),
        ({"EventID": "-1"}, FIELD_WAJIB),
        ({"Timestamp": '"0001-01-01 00:00:00.000 +01:00"'}, TIMESTAMP_TIDAK_SAH),
        ({"Timestamp": '"9999-12-31 23:59:59.000 -01:00"'}, TIMESTAMP_TIDAK_SAH),
    ],
)
def test_values_that_would_break_storage_are_rejected_per_line(over: dict[str, str], code: str) -> None:
    assert _error(_line(**over)) == code


def test_edge_values_that_fit_are_accepted() -> None:
    a = normalize(parse_line(_line(EventID=str(MAX_EVENT_ID), Details='{"n":1.5e300}'), LIMITS))
    assert a.event_id == MAX_EVENT_ID
    assert a.details["n"] == 1.5e300
    assert parse_timestamp("0001-01-01 00:00:00.000 -01:00").year == 1


@pytest.mark.parametrize("record_id", ["-1", str(2**63), str(2**70)])
def test_record_id_out_of_bigint_range_becomes_none(record_id: str) -> None:
    assert normalize(parse_line(_line(RecordID=record_id), LIMITS)).record_id is None


def test_bom_does_not_shrink_first_line_budget() -> None:
    limits = Limits(max_line_bytes=256)
    body = _line()
    filler = b" " * (limits.max_line_bytes - len(body))
    line = body[:-1] + filler + b"}"  # tepat max_line_bytes
    assert len(line) == limits.max_line_bytes
    lines = list(iter_lines(io.BytesIO(BOM_UTF8 + line + b"\r\n" + line + b"\n"), limits))
    assert [ln.kind for ln in lines] == ["data", "data"]
    assert lines[0].raw == line


def test_first_line_without_bom_keeps_normal_budget() -> None:
    limits = Limits(max_line_bytes=256)
    long = b"x" * (limits.max_line_bytes + 1)
    lines = list(iter_lines(io.BytesIO(long + b"\n" + _line() + b"\n"), limits))
    assert [ln.kind for ln in lines] == ["too_long", "data"]


def test_identity_from_path_guard_matches_opened_file(tmp_path: Path) -> None:
    root = tmp_path / "import"
    root.mkdir()
    (root / "a.jsonl").write_bytes(_line() + b"\n")
    resolved = resolve_import_path(root, "a.jsonl")
    st = os.stat(root / "a.jsonl")
    assert resolved.identity == (st.st_dev, st.st_ino)
    stored = copy_into_store(
        resolved.path, ensure_store(tmp_path / "gudang"), max_file_bytes=1024, expect_identity=resolved.identity
    )
    assert stored.created


def test_swapped_file_after_check_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "import"
    root.mkdir()
    target = root / "a.jsonl"
    target.write_bytes(_line() + b"\n")
    resolved = resolve_import_path(root, "a.jsonl")
    if not resolved.identity[1]:
        pytest.skip("sistem berkas tanpa nomor inode")
    os.replace(target, tmp_path / "lama.jsonl")  # dipindah, bukan dihapus: inode lama tidak bisa dipakai ulang
    (tmp_path / "luar.jsonl").write_bytes(b"rahasia\n")
    os.replace(tmp_path / "luar.jsonl", target)  # berkas lain di nama yang sama (mirip pertukaran komponen path)
    store = ensure_store(tmp_path / "gudang")
    with pytest.raises(StoreError) as exc:
        copy_into_store(resolved.path, store, max_file_bytes=1024, expect_identity=resolved.identity)
    assert exc.value.code == BERKAS_BERUBAH
    assert [p.name for p in store.iterdir()] == []
