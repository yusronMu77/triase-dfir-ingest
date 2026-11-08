# Changelog

## [Unreleased]

### Added

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Endpoint dev `POST /internal/v1/dev/sample-event` (hanya bila `ASTRIA_DEV_ENDPOINTS=true` dan `ASTRIA_ENV=dev`): satu `evidence.ingested` dan satu `audit.record` lewat outbox.
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
