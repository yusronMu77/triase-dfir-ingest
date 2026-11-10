from __future__ import annotations

import os
from pathlib import Path

import pytest

from astria_ingest.paths import (
    PATH_BUKAN_BERKAS,
    PATH_SYMLINK,
    PATH_TIDAK_ADA,
    PATH_TIDAK_VALID,
    PathRejected,
    resolve_import_path,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "import"
    (r / "chains").mkdir(parents=True)
    (r / "chains" / "a.jsonl").write_bytes(b"{}\n")
    (tmp_path / "rahasia.txt").write_bytes(b"jangan dibaca")
    return r


def _code(root: Path, ref: object) -> str:
    with pytest.raises(PathRejected) as exc:
        resolve_import_path(root, ref)
    return exc.value.code


def test_valid_path(root: Path) -> None:
    got = resolve_import_path(root, "chains/a.jsonl")
    assert got.ref == "chains/a.jsonl"
    assert got.path.read_bytes() == b"{}\n"


@pytest.mark.parametrize(
    "ref",
    [
        "",
        None,
        123,
        "../rahasia.txt",
        "chains/../../rahasia.txt",
        "chains/../chains/a.jsonl",
        "./chains/a.jsonl",
        "chains//a.jsonl",
        "chains/a.jsonl/",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:rahasia.txt",
        r"\\host\share\a.jsonl",
        r"chains\a.jsonl",
        "chains/a.jsonl\x00.txt",
        "chains/a\nb.jsonl",
        "chains/a\u202e.jsonl",
        "chains/a.jsonl:stream",
        "a" * 1025,
        "x" * 256,
    ],
)
def test_rejects_invalid_ref(root: Path, ref: object) -> None:
    assert _code(root, ref) == PATH_TIDAK_VALID


def test_missing_file(root: Path) -> None:
    assert _code(root, "chains/tidak-ada.jsonl") == PATH_TIDAK_ADA


def test_missing_root(tmp_path: Path) -> None:
    assert _code(tmp_path / "tidak-ada", "a.jsonl") == PATH_TIDAK_ADA


def test_directory_is_not_a_file(root: Path) -> None:
    assert _code(root, "chains") == PATH_BUKAN_BERKAS


def test_file_used_as_directory(root: Path) -> None:
    assert _code(root, "chains/a.jsonl/b.jsonl") == PATH_TIDAK_ADA


def _symlink(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError, NotImplementedError:
        pytest.skip("symlink tidak didukung di lingkungan ini")


def test_symlink_file_rejected(root: Path, tmp_path: Path) -> None:
    _symlink(tmp_path / "rahasia.txt", root / "link.jsonl")
    assert _code(root, "link.jsonl") == PATH_SYMLINK


def test_symlink_file_inside_root_rejected(root: Path) -> None:
    _symlink(root / "chains" / "a.jsonl", root / "alias.jsonl")
    assert _code(root, "alias.jsonl") == PATH_SYMLINK


def test_symlink_directory_rejected(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "luar"
    outside.mkdir()
    (outside / "x.jsonl").write_bytes(b"{}\n")
    _symlink(outside, root / "luar", directory=True)
    assert _code(root, "luar/x.jsonl") == PATH_SYMLINK


def test_root_itself_may_be_symlink(tmp_path: Path, root: Path) -> None:
    link_root = tmp_path / "root-link"
    _symlink(root, link_root, directory=True)
    assert resolve_import_path(link_root, "chains/a.jsonl").ref == "chains/a.jsonl"
