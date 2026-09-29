"""Docspector desktop launcher — single-binary local demo runtime.

Inspect. Verify. Trust.

This is the PyInstaller entry point. It turns the FastAPI backend plus the
built React frontend into a double-click local application:

1. Creates a per-user writable data directory (database, file storage,
   generated JWT secret) outside the read-only bundle.
2. Creates the SQLite schema and idempotently seeds the synthetic demo
   users and case.
3. Serves the API and the built SPA from one local origin and opens the
   default browser.

Environment overrides (all optional): DOCSPECTOR_PORT, DOCSPECTOR_NO_BROWSER,
plus every normal backend setting (DATABASE_URL, DEMO_MODE, ...).

All bundled data is synthetic and fictional; the runtime binds to
127.0.0.1 only, matching the PRD's local/air-gapped deployment target.
"""

from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import webbrowser
from pathlib import Path

APP_DIR_NAME = "Docspector"
DEFAULT_PORT = 8000


def resource_root() -> Path:
    """Directory holding bundled read-only resources (frontend build)."""
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        return Path(bundle_dir)
    return Path(__file__).resolve().parent


def data_root() -> Path:
    """Per-user writable directory for database, storage, and secrets."""
    override = os.environ.get("DOCSPECTOR_DATA_DIR", "").strip()
    if override:
        root = Path(override)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(
            Path.home() / "AppData" / "Local"
        )
        root = Path(base) / APP_DIR_NAME
    else:
        xdg = os.environ.get("XDG_DATA_HOME") or str(
            Path.home() / ".local" / "share"
        )
        root = Path(xdg) / APP_DIR_NAME.lower()
    root.mkdir(parents=True, exist_ok=True)
    return root


def load_or_create_jwt_secret(root: Path) -> str:
    """Persist a per-installation random JWT signing secret."""
    secret_file = root / "jwt_secret.key"
    if secret_file.is_file():
        existing = secret_file.read_text(encoding="utf-8").strip()
        if len(existing) >= 32:
            return existing
    fresh = secrets.token_urlsafe(48)
    secret_file.write_text(fresh, encoding="utf-8")
    return fresh


def pick_port(preferred: int) -> int:
    """Bind-test the preferred port; fall back to an OS-assigned free one."""
    for candidate in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", candidate))
                return probe.getsockname()[1]
        except OSError:
            continue
    return preferred


def configure_environment() -> Path:
    """Set runtime configuration before any app module is imported."""
    root = data_root()
    storage_dir = root / "storage" / "private"
    storage_dir.mkdir(parents=True, exist_ok=True)

    db_path = (root / "docspector.db").as_posix()
    os.environ.setdefault("APP_ENV", "demo")
    os.environ.setdefault("DEMO_MODE", "true")
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{db_path}")
    os.environ.setdefault("STORAGE_DIR", str(storage_dir))
    os.environ.setdefault("JWT_SECRET_KEY", load_or_create_jwt_secret(root))

    ui_candidates = (
        resource_root() / "frontend_dist",  # PyInstaller bundle
        resource_root().parent / "frontend" / "dist",  # source checkout
    )
    for ui_dir in ui_candidates:
        if (ui_dir / "index.html").is_file():
            os.environ.setdefault("DOCSPECTOR_UI_DIR", str(ui_dir))
            break

    return root


def initialize_database() -> None:
    """Create the schema and seed synthetic demo data (idempotent)."""
    import app.db.models  # noqa: F401  (register all mapped tables)
    from app.db.base import Base
    from app.db.session import SessionLocal, engine
    from scripts.seed_demo import seed_demo_data

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_demo_data(db)
        db.commit()
    finally:
        db.close()


def main() -> None:
    root = configure_environment()

    initialize_database()

    from app.main import app  # imported only after environment is final

    port = pick_port(int(os.environ.get("DOCSPECTOR_PORT", str(DEFAULT_PORT))))
    url = f"http://127.0.0.1:{port}"

    print()
    print("=" * 62)
    print("  Docspector — Inspect. Verify. Trust.")
    print("=" * 62)
    print(f"  Application : {url}")
    print(f"  API docs    : {url}/docs")
    print(f"  Data folder : {root}")
    print("  Demo logins : docspector.io / docspector.so /")
    print("                docspector.legal / docspector.auditor")
    print("  Stop        : press Ctrl+C or close this window")
    print("=" * 62)
    print()

    if os.environ.get("DOCSPECTOR_NO_BROWSER", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    ):
        threading.Timer(1.2, webbrowser.open, args=(url,)).start()

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
