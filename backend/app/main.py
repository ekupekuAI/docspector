import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.cases import router as cases_router
from app.api.custody import router as custody_router
from app.api.demo import router as demo_router
from app.api.documents import router as documents_router
from app.api.reports import router as reports_router
from app.api.transfers import router as transfers_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.request_id import RequestIdMiddleware
from app.core.request_limits import RequestBodyLimitMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.ui import mount_frontend

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="Inspect. Verify. Trust.",
    version=settings.app_version,
)

# Middleware Stack (Innermost to Outermost during registration; outermost handles incoming requests first)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=settings.max_json_body_size_bytes,
)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Universal API error contract handlers
register_exception_handlers(app)

app.include_router(auth_router)
app.include_router(cases_router)
app.include_router(documents_router)
app.include_router(transfers_router)
app.include_router(alerts_router)
app.include_router(custody_router)
app.include_router(reports_router)
app.include_router(demo_router)




@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }


# Packaged (desktop) builds set DOCSPECTOR_UI_DIR to a built frontend
# directory; the SPA is then served from the same origin as the API.
# In normal development this is unset and the JSON root endpoint remains.
_ui_dir = os.environ.get("DOCSPECTOR_UI_DIR", "").strip()
_ui_mounted = bool(_ui_dir) and mount_frontend(app, _ui_dir)

if not _ui_mounted:

    @app.get("/")
    def root() -> dict[str, str]:
        return {
            "product": settings.app_name,
            "tagline": "Inspect. Verify. Trust.",
            "status": settings.app_env,
        }
