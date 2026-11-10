"""Hash bukti (K5). Semua hash SHA-256, hex huruf kecil 64 karakter.

- Berkas: bytes mentah seluruh berkas, apa adanya (termasuk BOM dan akhiran baris).
  Sama dengan `sha256` di manifest samples.
- Rekaman: bytes satu baris tanpa akhiran `\\n`/`\\r\\n` dan tanpa BOM UTF-8 di baris pertama.
- Batch: `record_sha256` hex yang diurutkan `record_no`, digabung satu LF, lalu di-hash (field `batch_sha256` event).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import BinaryIO

CHUNK_BYTES = 1024 * 1024
SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_sha256(raw: bytes) -> str:
    """Hash satu rekaman. `raw` sudah tanpa akhiran baris dan BOM (lihat `adapters.hayabusa.iter_lines`)."""
    return sha256_hex(raw)


def stream_sha256(fp: BinaryIO, *, chunk_bytes: int = CHUNK_BYTES) -> tuple[str, int]:
    """Hash berkas secara streaming dari posisi sekarang sampai akhir. Mengembalikan (hex, jumlah byte)."""
    h = hashlib.sha256()
    total = 0
    while chunk := fp.read(chunk_bytes):
        h.update(chunk)
        total += len(chunk)
    return h.hexdigest(), total


def batch_sha256(record_hashes: Iterable[str]) -> str:
    """Hash batch dari hash rekaman yang **sudah** diurutkan `record_no`. Tiap elemen wajib hex 64 huruf kecil."""
    items = list(record_hashes)
    if not items:
        raise ValueError("batch kosong")
    for item in items:
        if not SHA256_HEX.fullmatch(item):
            raise ValueError("record_sha256 tidak valid")
    return sha256_hex("\n".join(items).encode("ascii"))
