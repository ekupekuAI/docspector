"""Docspector Standard API Error Contract & Exception Handling (Milestone 14).

Inspect. Verify. Trust.

Enforces:
1. Universal API error contract:
   {
     "error": {
       "code": "ERROR_CODE",
       "message": "Human-readable message",
       "details": {},
       "request_id": "request-id"
     }
   }
2. Stable machine-readable error codes.
3. Safe HTTP 500 fallback without leaking internals or stack traces.
4. X-Request-ID response header propagation.
"""

from __future__ import annotations

import logging
from typing import Any
import uuid

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("docspector.api")

# Canonical Machine-Readable Error Codes
ERROR_AUTH_REQUIRED = "AUTH_REQUIRED"
ERROR_INVALID_TOKEN = "INVALID_TOKEN"
ERROR_FORBIDDEN = "FORBIDDEN"
ERROR_RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
ERROR_CASE_ACCESS_DENIED = "CASE_ACCESS_DENIED"
ERROR_DOCUMENT_ACCESS_DENIED = "DOCUMENT_ACCESS_DENIED"
ERROR_VERSION_ACCESS_DENIED = "VERSION_ACCESS_DENIED"
ERROR_INVALID_STATE = "INVALID_STATE"
ERROR_CONFLICT = "CONFLICT"
ERROR_FILE_TOO_LARGE = "FILE_TOO_LARGE"
ERROR_UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
ERROR_VALIDATION_ERROR = "VALIDATION_ERROR"
ERROR_INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
ERROR_DEMO_MODE_REQUIRED = "DEMO_MODE_REQUIRED"
ERROR_DEMO_PERMISSION_REQUIRED = "DEMO_PERMISSION_REQUIRED"
ERROR_METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
ERROR_RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
ERROR_INTERNAL_ERROR = "INTERNAL_ERROR"


class AppError(Exception):
    """Base application exception with explicit error code, message, and details."""

    def __init__(
        self,
        message: str,
        code: str = ERROR_INTERNAL_ERROR,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def get_request_id_from_request(request: Request) -> str:
    """Extract or generate a safe request ID from request state or headers."""
    state_id = getattr(request.state, "request_id", None)
    if state_id:
        return state_id
    header_id = request.headers.get("X-Request-ID")
    if header_id and header_id.strip() and len(header_id) <= 128:
        return header_id.strip()
    return str(uuid.uuid4())


def build_error_payload(
    code: str,
    message: str,
    details: dict[str, Any] | None,
    request_id: str,
) -> dict[str, Any]:
    """Construct standard API error response payload according to PRD contract."""
    clean_details = details if details is not None else {}
    return {
        "error": {
            "code": code,
            "message": message,
            "details": clean_details,
            "request_id": request_id,
        },
        "detail": message,  # Backward-compatible detail field
    }


def map_http_status_to_error_code(status_code: int, detail: str) -> str:
    """Map standard HTTP status codes and detail text to canonical error codes."""
    lower_detail = detail.lower()

    if status_code == 401:
        if "token" in lower_detail:
            return ERROR_INVALID_TOKEN
        return ERROR_AUTH_REQUIRED

    if status_code == 403:
        if "demo mode" in lower_detail:
            return ERROR_DEMO_MODE_REQUIRED
        if "demo" in lower_detail:
            return ERROR_DEMO_PERMISSION_REQUIRED
        return ERROR_FORBIDDEN

    if status_code == 404:
        if "case" in lower_detail:
            return ERROR_CASE_ACCESS_DENIED
        if "version" in lower_detail:
            return ERROR_VERSION_ACCESS_DENIED
        if "document" in lower_detail:
            return ERROR_DOCUMENT_ACCESS_DENIED
        return ERROR_RESOURCE_NOT_FOUND

    if status_code == 405:
        return ERROR_METHOD_NOT_ALLOWED

    if status_code == 409:
        if "state" in lower_detail or "restricted" in lower_detail or "status" in lower_detail:
            return ERROR_INVALID_STATE
        return ERROR_CONFLICT

    if status_code == 413:
        return ERROR_FILE_TOO_LARGE

    if status_code == 415:
        return ERROR_UNSUPPORTED_FILE_TYPE

    if status_code == 422:
        return ERROR_VALIDATION_ERROR

    if status_code == 429:
        return ERROR_RATE_LIMIT_EXCEEDED

    return ERROR_INTERNAL_ERROR if status_code >= 500 else ERROR_VALIDATION_ERROR


def register_exception_handlers(app: FastAPI) -> None:
    """Register universal exception handlers conforming to the API error contract."""

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        req_id = get_request_id_from_request(request)
        payload = build_error_payload(
            code=exc.code,
            message=exc.message,
            details=exc.details,
            request_id=req_id,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=payload,
            headers={"X-Request-ID": req_id},
        )

    @app.exception_handler(StarletteHTTPException)
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException | HTTPException
    ) -> JSONResponse:
        req_id = get_request_id_from_request(request)
        
        # Handle dict details if supplied
        if isinstance(exc.detail, dict):
            code = exc.detail.get("code") or map_http_status_to_error_code(exc.status_code, "")
            message = exc.detail.get("message") or str(exc.detail)
            details = exc.detail.get("details", {})
        else:
            message = str(exc.detail)
            code = map_http_status_to_error_code(exc.status_code, message)
            details = {}

        payload = build_error_payload(
            code=code,
            message=message,
            details=details,
            request_id=req_id,
        )
        
        headers = dict(exc.headers or {})
        headers["X-Request-ID"] = req_id

        return JSONResponse(
            status_code=exc.status_code,
            content=payload,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        req_id = get_request_id_from_request(request)
        
        # Sanitize validation errors to safe structures
        errors_list = []
        for err in exc.errors():
            loc = [str(x) for x in err.get("loc", [])]
            errors_list.append({
                "loc": loc,
                "msg": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            })

        payload = build_error_payload(
            code=ERROR_VALIDATION_ERROR,
            message="Request validation failed.",
            details={"validation_errors": errors_list},
            request_id=req_id,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=payload,
            headers={"X-Request-ID": req_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = get_request_id_from_request(request)
        logger.error(f"Unhandled exception [request_id={req_id}]: {exc}", exc_info=True)

        payload = build_error_payload(
            code=ERROR_INTERNAL_ERROR,
            message="An internal server error occurred.",
            details={},
            request_id=req_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=payload,
            headers={"X-Request-ID": req_id},
        )
