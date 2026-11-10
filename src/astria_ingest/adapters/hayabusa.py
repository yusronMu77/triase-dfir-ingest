"""Pembaca Hayabusa JSONL (dfir-timeline, v4.x). Input tidak tepercaya: dibaca streaming, per baris, dengan batas.

`iter_lines` memecah berkas menjadi baris fisik bernomor (1-based, baris kosong tetap dihitung, K4) tanpa memuat baris
yang terlalu panjang. `parse_line` mengubah bytes satu baris menjadi objek JSON yang sudah diperiksa. Galat per baris
memakai kode stabil (K9); galat yang membuat seluruh berkas tidak bisa dibaca melempar `FileFormatError`.

Bentuk yang wajib diterima (note 2026-11-07-hayabusa-v4-format-jsonl): key tag bisa hilang, baris korelasi
tanpa `RecordID`, `ExtraFieldInfo` bisa `{}`, `MitreTags` bisa berisi ID non-teknik (`S0039`). Nilai tag tidak
divalidasi di sini.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO, Literal

from astria_ingest.limits import Limits

BOM_UTF8 = b"\xef\xbb\xbf"
_BOM_UTF16 = (b"\xff\xfe", b"\xfe\xff")
_DRAIN_BYTES = 64 * 1024

# Galat seluruh berkas
ENCODING_TIDAK_DIDUKUNG = "ENCODING_TIDAK_DIDUKUNG"
TERLALU_BANYAK_BARIS = "TERLALU_BANYAK_BARIS"

# Galat per baris
BARIS_TERLALU_PANJANG = "BARIS_TERLALU_PANJANG"
UTF8_RUSAK = "UTF8_RUSAK"
JSON_RUSAK = "JSON_RUSAK"
KEY_GANDA = "KEY_GANDA"
NILAI_TIDAK_SAH = "NILAI_TIDAK_SAH"
TERLALU_DALAM = "TERLALU_DALAM"
TEKS_TIDAK_SAH = "TEKS_TIDAK_SAH"
BUKAN_OBJEK = "BUKAN_OBJEK"
FIELD_WAJIB = "FIELD_WAJIB"

REQUIRED_TEXT = ("Timestamp", "RuleTitle", "Level", "Computer", "Channel")
"""Field teks wajib (profil apa pun). `EventID` wajib berupa bilangan bulat."""

MAX_EVENT_ID = 65_535
"""EventID Windows 16 bit. Di luar rentang ditolak per baris (bukan gagal saat INSERT ke kolom int)."""


class FileFormatError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LineError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class Line:
    record_no: int
    kind: Literal["data", "blank", "too_long"]
    raw: bytes = b""
    """Bytes baris tanpa akhiran baris (dan tanpa BOM di baris 1). Kosong untuk `too_long`: isinya tidak dimuat."""


def iter_lines(fp: BinaryIO, limits: Limits) -> Iterator[Line]:
    """Pecah berkas menjadi baris bernomor.

    Melempar `FileFormatError` untuk UTF-16/32 atau jumlah baris yang melewati batas.
    """
    line_limit = limits.max_line_bytes + 2  # muat juga "\r\n"
    # Baris 1 boleh diawali BOM UTF-8 yang dibuang sebelum diukur, jadi jatah bacanya ditambah panjang BOM.
    read_limit = line_limit + len(BOM_UTF8)
    record_no = 0
    while chunk := fp.readline(read_limit):
        record_no += 1
        if record_no > limits.max_lines:
            raise FileFormatError(TERLALU_BANYAK_BARIS, "jumlah baris melebihi batas")
        truncated = not chunk.endswith(b"\n") and len(chunk) >= read_limit
        if record_no == 1:
            if chunk.startswith(_BOM_UTF16):
                raise FileFormatError(ENCODING_TIDAK_DIDUKUNG, "berkas harus UTF-8 (UTF-16/32 tidak didukung)")
            if chunk.startswith(BOM_UTF8):
                chunk = chunk[len(BOM_UTF8) :]
            elif not truncated and not chunk.endswith(b"\n") and len(chunk) >= line_limit:
                truncated = True  # tanpa BOM, jatah baris 1 sama dengan baris lain
            read_limit = line_limit

        if truncated:
            _drain_line(fp)
            yield Line(record_no, "too_long")
            continue

        raw = chunk[:-1] if chunk.endswith(b"\n") else chunk
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > limits.max_line_bytes:
            yield Line(record_no, "too_long")
        elif not raw.strip():
            yield Line(record_no, "blank")
        else:
            yield Line(record_no, "data", raw)


def _drain_line(fp: BinaryIO) -> None:
    """Buang sisa baris yang terlalu panjang tanpa menyimpannya."""
    while rest := fp.readline(_DRAIN_BYTES):
        if rest.endswith(b"\n"):
            return


class _DuplicateKey(Exception):
    pass


class _BadConstant(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey
        out[key] = value
    return out


def _reject_constant(_name: str) -> Any:
    raise _BadConstant


def _finite_float(text: str) -> float:
    """Angka yang meluap (mis. `1e999`) menjadi inf, dan JSONB tidak bisa menyimpannya."""
    value = float(text)
    if not math.isfinite(value):
        raise _BadConstant
    return value


def _check_tree(value: Any, max_depth: int) -> None:
    """Kedalaman dan teks (surrogate tunggal tidak bisa di-encode UTF-8) diperiksa iteratif, tanpa rekursi."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            if depth > max_depth:
                raise LineError(TERLALU_DALAM)
            for key, child in node.items():
                _check_text(key)
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            if depth > max_depth:
                raise LineError(TERLALU_DALAM)
            stack.extend((child, depth + 1) for child in node)
        elif isinstance(node, str):
            _check_text(node)


def _check_text(text: str) -> None:
    """Surrogate tunggal tidak bisa di-encode UTF-8; NUL ditolak PostgreSQL di kolom teks dan JSONB."""
    if "\x00" in text:
        raise LineError(TEKS_TIDAK_SAH)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise LineError(TEKS_TIDAK_SAH) from None


def parse_line(raw: bytes, limits: Limits) -> dict[str, Any]:
    """Bytes satu baris -> objek Hayabusa yang lolos pemeriksaan dasar. Melempar `LineError`."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise LineError(UTF8_RUSAK) from None
    try:
        value = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant, parse_float=_finite_float
        )
    except _DuplicateKey:
        raise LineError(KEY_GANDA) from None
    except _BadConstant:
        raise LineError(NILAI_TIDAK_SAH) from None
    except RecursionError:
        raise LineError(TERLALU_DALAM) from None
    except ValueError:  # JSONDecodeError, dan angka dengan digit melebihi batas konversi int
        raise LineError(JSON_RUSAK) from None

    if not isinstance(value, dict):
        raise LineError(BUKAN_OBJEK)
    _check_tree(value, limits.max_depth)

    for field in REQUIRED_TEXT:
        item = value.get(field)
        if not isinstance(item, str) or not item.strip():
            raise LineError(FIELD_WAJIB)
    event_id = value.get("EventID")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or not 0 <= event_id <= MAX_EVENT_ID:
        raise LineError(FIELD_WAJIB)
    return value
