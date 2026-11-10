from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from astria_ingest.store_files import (
    BERKAS_TERLALU_BESAR,
    BERKAS_TIDAK_TERBACA,
    StoreError,
    copy_into_store,
    ensure_store,
    remove_from_store,
)


@pytest.fixture
def store(tmp_path: Path) -> Path:
    return ensure_store(tmp_path / "gudang")


def _leftovers(store: Path) -> list[str]:
    return [p.name for p in store.iterdir() if p.name.startswith(".tmp-")]


def test_copy_hash_matches_and_is_content_addressed(tmp_path: Path, store: Path) -> None:
    data = b'{ "a":1 }\n' * 1000
    src = tmp_path / "a.jsonl"
    src.write_bytes(data)
    got = copy_into_store(src, store, max_file_bytes=10_000_000)
    assert got.sha256 == hashlib.sha256(data).hexdigest()
    assert got.size == len(data)
    assert got.created is True
    assert got.path == store / got.sha256
    assert got.path.read_bytes() == data
    assert _leftovers(store) == []


def test_same_content_is_not_overwritten(tmp_path: Path, store: Path) -> None:
    src = tmp_path / "a.jsonl"
    src.write_bytes(b"isi\n")
    first = copy_into_store(src, store, max_file_bytes=100)
    mtime = os.stat(first.path).st_mtime_ns
    second = copy_into_store(src, store, max_file_bytes=100)
    assert second.created is False
    assert second.path == first.path
    assert os.stat(first.path).st_mtime_ns == mtime
    assert _leftovers(store) == []


def test_too_large_before_reading(tmp_path: Path, store: Path) -> None:
    src = tmp_path / "besar.jsonl"
    src.write_bytes(b"x" * 101)
    with pytest.raises(StoreError) as exc:
        copy_into_store(src, store, max_file_bytes=100)
    assert exc.value.code == BERKAS_TERLALU_BESAR
    assert list(store.iterdir()) == []


def test_missing_source(tmp_path: Path, store: Path) -> None:
    with pytest.raises(StoreError) as exc:
        copy_into_store(tmp_path / "tidak-ada", store, max_file_bytes=100)
    assert exc.value.code == BERKAS_TIDAK_TERBACA


def test_directory_source(tmp_path: Path, store: Path) -> None:
    folder = tmp_path / "folder"
    folder.mkdir()
    with pytest.raises(StoreError) as exc:
        copy_into_store(folder, store, max_file_bytes=100)
    assert exc.value.code == BERKAS_TIDAK_TERBACA


def test_symlink_source_not_followed(tmp_path: Path, store: Path) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW tidak ada di platform ini (dijaga paths.py)")
    target = tmp_path / "asli.jsonl"
    target.write_bytes(b"{}\n")
    link = tmp_path / "link.jsonl"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink tidak didukung")
    with pytest.raises(StoreError) as exc:
        copy_into_store(link, store, max_file_bytes=100)
    assert exc.value.code == BERKAS_TIDAK_TERBACA


def test_remove_only_when_created(tmp_path: Path, store: Path) -> None:
    src = tmp_path / "a.jsonl"
    src.write_bytes(b"isi\n")
    first = copy_into_store(src, store, max_file_bytes=100)
    second = copy_into_store(src, store, max_file_bytes=100)
    remove_from_store(second)
    assert first.path.exists()
    remove_from_store(first)
    assert not first.path.exists()
