"""Docspector Request Body Size Limit Middleware (Milestone 20).

Inspect. Verify. Trust.

Guards non-multipart (e.g. JSON API) requests against oversized payloads and
unbounded memory allocation attacks.
Multipart form-data uploads remain governed by their dedicated streaming 25 MiB validator.
"""

from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.errors import ERROR_FILE_TOO_LARGE, build_error_payload, get_request_id_from_request


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware to enforce request body size limits on non-multipart requests."""

    def __init__(self, app, max_body_size: int = 1 * 1024 * 1024):
        super().__init__(app)
        self.max_body_size = max_body_size

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_type = request.headers.get("content-type", "").lower()
        # Multipart form data uploads have their own dedicated streaming 25 MiB validator
        if not content_type.startswith("multipart/form-data"):
            content_length_header = request.headers.get("content-length")
            if content_length_header:
                try:
                    content_length = int(content_length_header)
                    if content_length > self.max_body_size:
                        req_id = get_request_id_from_request(request)
                        payload = build_error_payload(
                            code=ERROR_FILE_TOO_LARGE,
                            message=f"Request body exceeds maximum allowed size of {self.max_body_size} bytes.",
                            details={
                                "max_bytes": self.max_body_size,
                                "received_bytes": content_length,
                            },
                            request_id=req_id,
                        )
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content=payload,
                            headers={"X-Request-ID": req_id},
                        )
                except ValueError:
                    pass

        return await call_next(request)
