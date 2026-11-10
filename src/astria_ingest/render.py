"""Render output (K12): sanitasi dan redaksi dikerjakan **saat data keluar** lewat API, bukan saat disimpan.

Urutan per nilai teks: buang karakter kontrol/format (`Cc`, `Cf`, termasuk zero-width) -> redaksi kredensial -> potong.
Berbeda dari urutan note app-ingest 5.5 (potong dulu): karakter tak terlihat dibuang sebelum redaksi agar tidak bisa
memecah pola (`pass\\u200bword=`), dan pemotongan terakhir tidak membuat redaksi terlewat.

Pola redaksi titik awal dari note 5.5, dengan satu perbaikan: `net user <nama> /add` tidak dianggap kata sandi.
Pagar prompt untuk model bahasa adalah tugas `narrative` saat menyusun prompt; heuristik injeksi belum ada (K12).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from astria_ingest.normalize import NormalizedAlert

MASK = "********"
TRUNCATED = "…[dipotong]"
MAX_FIELD_CHARS = 8192
MAX_EXCERPT_CHARS = 2000
MAX_FIELDS = 200
_WHITESPACE_CONTROLS = {"\t": " ", "\n": " ", "\r": " "}

_NOT_MASKED = r"(?!\*{8}(?:\s|$))"
REDACT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # net user <nama> <sandi>; token yang diawali "/" adalah opsi (/add, /domain), bukan sandi.
    (re.compile(rf"(\bnet1?(?:\.exe)?\s+user\s+(?!/)\S+\s+)(?!/){_NOT_MASKED}(\S+)", re.IGNORECASE), r"\1" + MASK),
    (re.compile(rf"(\s-p\s+){_NOT_MASKED}(\S+)"), r"\1" + MASK),
    (re.compile(rf"(\s/p:){_NOT_MASKED}(\S+)", re.IGNORECASE), r"\1" + MASK),
    (re.compile(rf"(password\s*[=:]\s*){_NOT_MASKED}(\S+)", re.IGNORECASE), r"\1" + MASK),
)


def strip_controls(text: str) -> str:
    out = []
    for ch in text:
        if ch in _WHITESPACE_CONTROLS:
            out.append(_WHITESPACE_CONTROLS[ch])
        elif unicodedata.category(ch) not in ("Cc", "Cf"):
            out.append(ch)
    return "".join(out)


def redact(text: str) -> str:
    for pattern, repl in REDACT_RULES:
        text = pattern.sub(repl, text)
    return text


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - len(TRUNCATED))] + TRUNCATED


def clean(value: Any, max_chars: int = MAX_FIELD_CHARS) -> str:
    """Satu nilai apa pun -> teks aman untuk output."""
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, str):
        text = value
    elif isinstance(value, int | float):
        text = str(value)
    else:
        text = repr(value)
    return truncate(redact(strip_controls(text)), max_chars)


def flatten(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Objek bersarang -> {"a.b": nilai}; list dijadikan teks dipisah koma. Kedalaman sudah dibatasi parser."""
    out: dict[str, Any] = {}
    for key, item in value.items():
        name = f"{prefix}{key}"
        if isinstance(item, Mapping):
            out.update(flatten(item, f"{name}."))
        elif isinstance(item, list):
            out[name] = ", ".join(clean(x) if not isinstance(x, Mapping | list) else repr(x) for x in item)
        else:
            out[name] = item
    return out


def render_fields(alert: NormalizedAlert) -> dict[str, str]:
    """`Details` lalu `ExtraFieldInfo` diratakan ke string tersanitasi. `Details` menang bila nama sama."""
    merged = flatten(alert.extra) | flatten(alert.details)
    fields: dict[str, str] = {}
    for key in list(merged)[:MAX_FIELDS]:
        fields[clean(key, 128)] = clean(merged[key])
    return fields


def render_excerpt(alert: NormalizedAlert) -> str:
    """Kutipan ringkas untuk manusia dan verifier: aturan, EventID, lalu isi `Details` (tersanitasi)."""
    parts = [f"EventID={alert.event_id}", alert.rule_title]
    parts.extend(f"{key}={value}" for key, value in flatten(alert.details).items())
    return clean(" ".join(str(p) for p in parts), MAX_EXCERPT_CHARS)
