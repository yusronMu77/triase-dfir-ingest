"""Batas input tidak tepercaya (K10). Nilai default; layanan mengisinya dari `Settings`."""

from __future__ import annotations

from dataclasses import dataclass

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Limits:
    max_file_bytes: int = 1024 * MIB
    """Ukuran berkas maksimum. Dicek dari `fstat` sebelum membaca dan dihitung ulang saat menyalin."""

    max_line_bytes: int = 1 * MIB
    """Panjang satu baris (tanpa akhiran baris). Baris lebih panjang ditolak tanpa dimuat utuh."""

    max_lines: int = 999_999
    """Jumlah baris fisik maksimum. Sama dengan kapasitas nomor 6 digit di ID bukti `EV-<kode>-<nnnnnn>`."""

    max_depth: int = 32
    """Kedalaman objek/array JSON maksimum dalam satu baris."""

    def __post_init__(self) -> None:
        for name in ("max_file_bytes", "max_line_bytes", "max_lines", "max_depth"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} harus >= 1")
        if self.max_lines > 999_999:
            raise ValueError("max_lines melebihi kapasitas ID bukti (999999)")
