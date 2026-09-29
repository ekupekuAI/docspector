"""Docspector Request-ID Tracking Middleware (Milestone 14).

Inspect. Verify. Trust.

Propagates and tracks X-Request-ID across the HTTP lifecycle:
1. Reuses incoming safe, non-empty X-Request-ID header if provided.
2. Generates a new UUID4 string if missing or blank.
3. Sets request.state.request_id for downstream logging and error handlers.
4. Adds X-Request-ID to every HTTP response.
"""

from __future__ import annotations

import re
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

SAFE_REQUEST_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-\.]{1,128}$")


def sanitize_request_id(incoming_id: str | None) -> str:
    """Sanitize and validate incoming request ID or generate a new UUID4."""
    if incoming_id:
        stripped = incoming_id.strip()
        if stripped and SAFE_REQUEST_ID_REGEX.match(stripped):
            return stripped
    return str(uuid.uuid4())


class RequestIdMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware to assign and propagate X-Request-ID."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        req_id = sanitize_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = req_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response
