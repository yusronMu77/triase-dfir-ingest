"""Penjaga path impor. `path_ref` dari pemanggil tidak tepercaya; hanya berkas biasa di dalam `import_root` yang lolos.

Aturan `path_ref`: relatif bergaya POSIX (`chains/a.jsonl`), tanpa `..`/`.`/segmen kosong, tanpa `\\`, `:`, NUL, atau
karakter kontrol. Setiap komponen diperiksa dengan `lstat` dari root ke bawah: symlink dan junction ditolak di level
mana pun, komponen antara harus folder, komponen akhir harus berkas biasa. Terakhir `realpath` dipastikan tetap di root.
"""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

MAX_REF_CHARS = 1024
MAX_PART_BYTES = 255

PATH_TIDAK_VALID = "PATH_TIDAK_VALID"
PATH_TIDAK_ADA = "PATH_TIDAK_ADA"
PATH_SYMLINK = "PATH_SYMLINK"
PATH_BUKAN_BERKAS = "PATH_BUKAN_BERKAS"
PATH_DI_LUAR_ROOT = "PATH_DI_LUAR_ROOT"


class PathRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ResolvedPath:
    path: Path
    """Path absolut berkas di dalam root."""
    ref: str
    """`path_ref` yang sudah diperiksa (bentuk kanonik yang dicatat di DB)."""


def _check_ref(ref: object) -> tuple[str, ...]:
    if not isinstance(ref, str) or not ref:
        raise PathRejected(PATH_TIDAK_VALID, "path_ref wajib berupa teks tidak kosong")
    if len(ref) > MAX_REF_CHARS:
        raise PathRejected(PATH_TIDAK_VALID, "path_ref terlalu panjang")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in ref):
        raise PathRejected(PATH_TIDAK_VALID, "path_ref memuat karakter kontrol")
    if "\\" in ref or ":" in ref:
        raise PathRejected(PATH_TIDAK_VALID, "path_ref harus relatif bergaya POSIX")
    if ref.startswith("/"):
        raise PathRejected(PATH_TIDAK_VALID, "path_ref tidak boleh absolut")
    parts = tuple(ref.split("/"))
    for part in parts:
        if part in ("", ".", ".."):
            raise PathRejected(PATH_TIDAK_VALID, "path_ref memuat segmen kosong, '.' atau '..'")
        if len(part.encode("utf-8", "surrogatepass")) > MAX_PART_BYTES:
            raise PathRejected(PATH_TIDAK_VALID, "nama komponen path terlalu panjang")
    return parts


def _is_link(path: Path, st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or os.path.isjunction(path)


def resolve_import_path(root: Path, ref: object) -> ResolvedPath:
    """Periksa `ref` terhadap `root`. Melempar `PathRejected` dengan kode galat yang stabil."""
    parts = _check_ref(ref)
    root_real = Path(os.path.realpath(root))
    if not root_real.is_dir():
        raise PathRejected(PATH_TIDAK_ADA, "folder impor tidak ada")

    current = root_real
    for index, part in enumerate(parts):
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            raise PathRejected(PATH_TIDAK_ADA, "berkas tidak ditemukan") from None
        except OSError:
            raise PathRejected(PATH_TIDAK_VALID, "path tidak dapat diperiksa") from None
        if _is_link(current, st):
            raise PathRejected(PATH_SYMLINK, "symlink atau junction tidak diizinkan")
        last = index == len(parts) - 1
        if not last and not stat.S_ISDIR(st.st_mode):
            raise PathRejected(PATH_TIDAK_ADA, "komponen path bukan folder")
        if last and not stat.S_ISREG(st.st_mode):
            raise PathRejected(PATH_BUKAN_BERKAS, "path bukan berkas biasa")

    final_real = os.path.realpath(current)
    if os.path.commonpath([final_real, root_real]) != str(root_real):
        raise PathRejected(PATH_DI_LUAR_ROOT, "path keluar dari folder impor")
    return ResolvedPath(path=current, ref="/".join(parts))
