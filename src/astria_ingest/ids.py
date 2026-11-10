"""ID deterministik: kode sumber (`hb01`) dan ID bukti (`EV-hb01-000001`). Lihat K4, K7, K19."""

from __future__ import annotations

import re

SOURCE_PREFIX = re.compile(r"[a-z]{2}")
SOURCE_CODE = re.compile(r"[a-z]{2}[0-9]{2,6}")
EVIDENCE_ID = re.compile(r"EV-(?P<source>[a-z]{2}[0-9]{2,6})-(?P<record>[0-9]{6})")

MAX_SOURCE_SEQ = 999_999
MAX_RECORD_NO = 999_999

HAYABUSA_PREFIX = "hb"


def source_code(prefix: str, seq: int) -> str:
    """Kode sumber dari prefix adapter dan nomor sequence: `hb` + 1 -> `hb01`, `hb` + 100 -> `hb100`."""
    if not SOURCE_PREFIX.fullmatch(prefix):
        raise ValueError("prefix adapter harus dua huruf kecil")
    if isinstance(seq, bool) or not 1 <= seq <= MAX_SOURCE_SEQ:
        raise ValueError("nomor sumber di luar rentang")
    return f"{prefix}{seq:02d}"


def evidence_id(source: str, record_no: int) -> str:
    """ID bukti dari kode sumber dan nomor baris fisik (1-based)."""
    if not SOURCE_CODE.fullmatch(source):
        raise ValueError("kode sumber tidak valid")
    if isinstance(record_no, bool) or not 1 <= record_no <= MAX_RECORD_NO:
        raise ValueError("record_no di luar rentang")
    return f"EV-{source}-{record_no:06d}"


def parse_evidence_id(value: str) -> tuple[str, int] | None:
    """(kode sumber, record_no) atau None bila formatnya salah. Nomor 000000 ditolak."""
    m = EVIDENCE_ID.fullmatch(value)
    if m is None:
        return None
    record_no = int(m["record"])
    if record_no < 1:
        return None
    return m["source"], record_no
