"""Optional built-frontend serving for packaged (desktop) builds.

Inspect. Verify. Trust.

When the environment variable ``DOCSPECTOR_UI_DIR`` points at a Vite build
output directory (``frontend/dist``), the API process also serves the
single-page application from the same origin. API routes keep priority;
unknown non-API paths fall back to ``index.html`` so client-side routing
(React Router ``BrowserRouter``) survives refreshes and deep links.

In normal development this module is inert and the backend behaves exactly
as before (JSON root endpoint, separate Vite dev server on :5173).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.errors import AppError, ERROR_RESOURCE_NOT_FOUND

# Paths that must keep their normal API/framework behaviour and never be
# swallowed by the SPA fallback.
_RESERVED_PREFIXES: tuple[str, ...] = (
    "api/",
    "api",
    "docs",
    "redoc",
    "openapi.json",
    "health",
)


def mount_frontend(app: FastAPI, ui_dir: str) -> bool:
    """Serve a built SPA from ``ui_dir``. Returns True if mounted."""
    dist_dir = Path(ui_dir).resolve()
    index_file = dist_dir / "index.html"
    if not index_file.is_file():
        return False

    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=str(assets_dir)),
            name="ui-assets",
        )

    @app.get("/", include_in_schema=False)
    def ui_index() -> FileResponse:
        return FileResponse(index_file)

    @app.get("/{spa_path:path}", include_in_schema=False)
    def ui_spa_fallback(spa_path: str) -> FileResponse:
        normalized = spa_path.lstrip("/")
        if normalized in _RESERVED_PREFIXES or any(
            normalized.startswith(prefix) for prefix in ("api/", "docs/", "redoc/")
        ):
            raise AppError(
                message="The requested resource was not found.",
                code=ERROR_RESOURCE_NOT_FOUND,
                status_code=status.HTTP_404_NOT_FOUND,
            )

        candidate = (dist_dir / normalized).resolve()
        # Serve real build files (favicon, manifest, ...) but never allow
        # path traversal outside the build directory.
        if candidate.is_file() and candidate.is_relative_to(dist_dir):
            return FileResponse(candidate)
        return FileResponse(index_file)

    return True
