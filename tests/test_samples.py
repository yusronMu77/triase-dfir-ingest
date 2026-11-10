"""Tes golden: tiga berkas samples (bentuk keluaran Hayabusa v4.3.1 asli) terbaca utuh.

Hash berkas wajib sama dengan manifest samples.
"""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path

import pytest

from astria_ingest.adapters.hayabusa import iter_lines, parse_line
from astria_ingest.hashing import record_sha256
from astria_ingest.ids import evidence_id
from astria_ingest.limits import Limits
from astria_ingest.normalize import normalize
from astria_ingest.render import render_excerpt, render_fields
from astria_ingest.store_files import copy_into_store, ensure_store

FIXTURES = Path(__file__).parent / "fixtures" / "samples"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
FILES = {item["path"]: item for item in MANIFEST["berkas"]}


@pytest.mark.parametrize("rel", sorted(FILES))
def test_sample_file_hash_matches_manifest_and_parses(rel: str, tmp_path: Path) -> None:
    expected = FILES[rel]
    stored = copy_into_store(FIXTURES / rel, ensure_store(tmp_path / "gudang"), max_file_bytes=Limits().max_file_bytes)
    assert stored.sha256 == expected["sha256"]
    assert stored.size == expected["bytes"]

    with stored.path.open("rb") as fp:
        lines = list(iter_lines(fp, Limits()))
    data = [line for line in lines if line.kind == "data"]
    assert len(lines) == len(data) == expected["baris"]
    assert [line.record_no for line in data] == list(range(1, expected["baris"] + 1))

    records = [parse_line(line.raw, Limits()) for line in data]
    assert all(isinstance(r["EventID"], int) for r in records)
    hashes = [record_sha256(line.raw) for line in data]
    assert len(set(hashes)) == len(hashes)


def test_svc_backup_shapes() -> None:
    with (FIXTURES / "chains" / "svc-backup.jsonl").open("rb") as fp:
        records = [parse_line(line.raw, Limits()) for line in iter_lines(fp, Limits())]
    assert any("RecordID" not in r for r in records)  # baris korelasi
    assert any("S0039" in r.get("MitreTags", []) for r in records)
    assert any("T1070.001" in r.get("MitreTags", []) for r in records)
    assert evidence_id("hb01", len(records)) == "EV-hb01-000031"


@pytest.mark.parametrize("rel", sorted(FILES))
def test_samples_normalize_and_render_without_secret(rel: str) -> None:
    with (FIXTURES / rel).open("rb") as fp:
        lines = list(iter_lines(fp, Limits()))
    alerts = [normalize(parse_line(line.raw, Limits())) for line in lines]
    assert all(a.occurred_at.tzinfo is UTC for a in alerts)
    assert all(a.kind.startswith("windows.security.") for a in alerts)
    assert all(a.severity != "unknown" for a in alerts)
    rendered = "\n".join(render_excerpt(a) + json.dumps(render_fields(a)) for a in alerts)
    assert "Sintetis-Bukan-Rahasia1" not in rendered
    # Data asli tetap utuh untuk hash dan gudang (K12, K21).
    if rel == "chains/svc-backup.jsonl":
        assert any(b"Sintetis-Bukan-Rahasia1" in line.raw for line in lines)
        assert any(a.account == "svc-backup" for a in alerts)
