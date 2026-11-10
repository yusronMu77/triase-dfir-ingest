"""Gudang bukti content-addressed (K21a). Berkas disalin streaming ke `<store>/<sha256>` dan tidak pernah ditimpa.

Penyalinan menulis ke berkas sementara di folder gudang, lalu `os.link` ke nama hash: atomik dan gagal bila
nama itu sudah ada, jadi isi lama tidak tertimpa. Sesudah disalin, ingest hanya membaca salinan ini (bukan
berkas asli), sehingga berkas asli yang diganti di tengah proses tidak memengaruhi hasil (TOCTOU).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from astria_ingest.hashing import CHUNK_BYTES, SHA256_HEX

BERKAS_TERLALU_BESAR = "BERKAS_TERLALU_BESAR"
BERKAS_TIDAK_TERBACA = "BERKAS_TIDAK_TERBACA"
GUDANG_TIDAK_KONSISTEN = "GUDANG_TIDAK_KONSISTEN"

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


class StoreError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class StoredFile:
    sha256: str
    size: int
    path: Path
    created: bool
    """True bila salinan baru dibuat oleh panggilan ini; False bila isi yang sama sudah ada di gudang."""


def ensure_store(store_dir: Path) -> Path:
    store_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return store_dir


def stored_path(store_dir: Path, sha256: str) -> Path:
    if not SHA256_HEX.fullmatch(sha256):
        raise ValueError("sha256 tidak valid")
    return store_dir / sha256


def copy_into_store(src: Path, store_dir: Path, *, max_file_bytes: int) -> StoredFile:
    """Salin `src` ke gudang sambil menghitung SHA-256. Batas ukuran dicek sebelum dan selama membaca."""
    try:
        fd = os.open(src, _OPEN_FLAGS)
    except OSError:
        raise StoreError(BERKAS_TIDAK_TERBACA, "berkas tidak dapat dibuka") from None
    with os.fdopen(fd, "rb") as fp:
        st = os.fstat(fp.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise StoreError(BERKAS_TIDAK_TERBACA, "bukan berkas biasa")
        if st.st_size > max_file_bytes:
            raise StoreError(BERKAS_TERLALU_BESAR, "berkas melebihi batas ukuran")

        tmp_fd, tmp_name = tempfile.mkstemp(dir=store_dir, prefix=".tmp-")
        tmp = Path(tmp_name)
        try:
            h = hashlib.sha256()
            total = 0
            with os.fdopen(tmp_fd, "wb") as out:
                while chunk := fp.read(CHUNK_BYTES):
                    total += len(chunk)
                    if total > max_file_bytes:
                        raise StoreError(BERKAS_TERLALU_BESAR, "berkas melebihi batas ukuran")
                    h.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            digest = h.hexdigest()
            dest = stored_path(store_dir, digest)
            try:
                os.link(tmp, dest)
                created = True
            except FileExistsError:
                existing = os.lstat(dest)
                if not stat.S_ISREG(existing.st_mode) or existing.st_size != total:
                    raise StoreError(GUDANG_TIDAK_KONSISTEN, "isi gudang tidak cocok dengan hash") from None
                created = False
            # Lepas nama sementara dulu: di Windows atribut read-only berlaku untuk semua hard link berkas yang sama.
            tmp.unlink()
            if created:
                os.chmod(dest, 0o444)
            return StoredFile(sha256=digest, size=total, path=dest, created=created)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()


def remove_from_store(stored: StoredFile) -> None:
    """Hapus salinan yang baru dibuat (impor ditolak di lintasan 1). Salinan lama milik impor lain tidak disentuh."""
    if not stored.created:
        return
    with contextlib.suppress(FileNotFoundError):
        os.chmod(stored.path, 0o600)
        stored.path.unlink()
