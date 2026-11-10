"""Lintasan 1 tanpa DB: pemindaian, keputusan tolak, dan pemecahan batch."""

from __future__ import annotations

from pathlib import Path

import pytest

from astria_ingest.adapters.hayabusa import BARIS_TERLALU_PANJANG, JSON_RUSAK, FileFormatError
from astria_ingest.jobs import MAX_ERROR_SAMPLES, _chunks, rejection_reason, scan_file
from astria_ingest.limits import Limits
from astria_ingest.normalize import TIMESTAMP_TIDAK_SAH

FIXTURES = Path(__file__).parent.parent / "fixtures" / "samples"
LINE = (
    b'{ "Timestamp":"2026-11-10 02:14:07.000 +00:00","RuleTitle":"T","Level":"low","Computer":"H",'
    b'"Channel":"Sec","EventID":4625 }'
)


def _write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "f.jsonl"
    p.write_bytes(data)
    return p


def test_scan_sample() -> None:
    scan = scan_file(FIXTURES / "chains" / "svc-backup.jsonl", Limits())
    assert (scan.total_lines, scan.valid, scan.blank, scan.rejected) == (31, 31, 0, 0)
    assert rejection_reason(scan, 0.5) is None


def test_scan_counts_errors_without_content(tmp_path: Path) -> None:
    bad_time = LINE.replace(b"+00:00", b"")
    data = LINE + b"\n\n{rusak}\n" + bad_time + b"\n" + b"x" * (len(LINE) + 10) + b"\n" + LINE + b"\n"
    scan = scan_file(_write(tmp_path, data), Limits(max_line_bytes=len(LINE)))
    assert (scan.total_lines, scan.valid, scan.blank, scan.rejected) == (6, 2, 1, 3)
    assert scan.samples == [
        {"record_no": 3, "code": JSON_RUSAK},
        {"record_no": 4, "code": TIMESTAMP_TIDAK_SAH},
        {"record_no": 5, "code": BARIS_TERLALU_PANJANG},
    ]
    assert "rusak" not in str(scan.stats())


def test_error_samples_are_capped(tmp_path: Path) -> None:
    scan = scan_file(_write(tmp_path, LINE + b"\n" + b"{x}\n" * 50), Limits())
    assert scan.rejected == 50
    assert len(scan.samples) == MAX_ERROR_SAMPLES


@pytest.mark.parametrize(
    ("valid", "rejected", "ratio", "rejected_file"),
    [
        (0, 0, 0.5, True),
        (0, 3, 0.5, True),
        (1, 1, 0.5, False),
        (1, 2, 0.5, True),
        (10, 0, 0.0, False),
        (9, 1, 0.0, True),
    ],
)
def test_rejection_reason(valid: int, rejected: int, ratio: float, rejected_file: bool) -> None:
    from astria_ingest.jobs import ScanResult

    scan = ScanResult(total_lines=valid + rejected, valid=valid, rejected=rejected)
    assert (rejection_reason(scan, ratio) is not None) is rejected_file


def test_scan_utf16_is_file_error(tmp_path: Path) -> None:
    with pytest.raises(FileFormatError):
        scan_file(_write(tmp_path, b"\xff\xfe" + "{}\n".encode("utf-16-le")), Limits())


def test_chunks_by_physical_line_and_resume(tmp_path: Path) -> None:
    path = _write(tmp_path, b"\n".join([LINE] * 12) + b"\n")
    got = [(no, [line.record_no for line in lines]) for no, lines in _chunks(path, Limits(), 5, 0)]
    assert got == [(0, [1, 2, 3, 4, 5]), (1, [6, 7, 8, 9, 10]), (2, [11, 12])]
    resumed = [(no, [line.record_no for line in lines]) for no, lines in _chunks(path, Limits(), 5, 5)]
    assert resumed == [(1, [6, 7, 8, 9, 10]), (2, [11, 12])]
