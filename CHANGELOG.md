# Changelog

## [Unreleased]

### Changed

- `read_callers` bawaan menambah `svc:dfir`: dfir membaca bukti kartu lewat `POST /svc/v1/evidence:batch` untuk linimasa dan rantai penguasaan (dfir#2).

### Added

- Golden dataset samples#4: 15 berkas (R1-R7, J1-J6, D1/H1), hash manifest dan normalisasi log Security/System.
- `POST /svc/v1/imports` menerima `expected_sha256` opsional (hex kecil 64): bila berbeda dari SHA-256 isi berkas, impor ditolak 422 `SHA256_TIDAK_COCOK` sebelum job dibuat dan salinan baru di gudang dibuang (api#12; kontrak `contracts/openapi/ingest-internal.yaml`).
- Impor Hayabusa JSONL (ingest#2): `POST /svc/v1/imports` dan `GET /svc/v1/imports/{job_id}`, penjaga path (tanpa `..` dan symlink, identitas berkas dicocokkan setelah dibuka), gudang bukti content-addressed dengan SHA-256, impor ulang berkas yang sama idempoten.
- Parser dan normalisasi Hayabusa: batas ukuran, baris, dan kedalaman; tolak key ganda, NaN/Infinity, NUL, surrogate tunggal, EventID dan waktu di luar rentang; karantina baris rusak di `rejected_record`.
- Job dua lintasan: pindai lalu tulis per 500 baris dalam satu transaksi, satu `evidence.ingested` (dengan `file_sha256` dan `batch_sha256`) per batch lewat outbox, audit `ingest.file.imported`/`ingest.file.failed`; lanjut setelah restart, advisory lock per job, coba ulang galat sementara.
- API baca: `POST /svc/v1/evidence:batch` (bentuk `{items, not_found}` untuk verifier) dan `GET /svc/v1/jobs/{job_id}/alerts` berhalaman; teks tersanitasi dan disensor saat output, tanpa `raw`.
- Daftar pemanggil per endpoint dari setting (`import_callers`, `read_callers`).

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Endpoint dev `POST /internal/v1/dev/sample-event` (hanya bila `ASTRIA_DEV_ENDPOINTS=true` dan `ASTRIA_ENV=dev`): satu `evidence.ingested` dan satu `audit.record` lewat outbox.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
