"""Docspector HTTP Security Headers Middleware (Milestone 20).

Inspect. Verify. Trust.

Applies standard defensive HTTP security headers to all responses:
- X-Content-Type-Options: nosniff (Prevents MIME sniffing attacks)
- X-Frame-Options: DENY (Prevents clickjacking and framing)
- Referrer-Policy: no-referrer (Prevents leaking referrer information)
- Content-Security-Policy: default-src 'self' (Restricts origin resource loading)
"""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware to attach defensive HTTP security headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response
