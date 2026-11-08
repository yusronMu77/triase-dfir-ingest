"""Jalankan layanan: `astria-ingest` atau `python -m astria_ingest`."""

from astria_common.app import run

from astria_ingest.main import build_app
from astria_ingest.settings import Settings


def main() -> None:
    settings = Settings()
    run(build_app(settings), settings)


if __name__ == "__main__":
    main()
