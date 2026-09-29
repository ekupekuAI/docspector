# Docspector Universal API Error Contract

**Standard Version:** 1.0 (Milestone 14 / Milestone 20)
**Security Invariant:** Zero internal stack trace, file path, SQL, or database exception disclosure.

---

## 1. Canonical Error Envelope Schema

All non-2xx API responses returned by the FastAPI backend conform to the single standardized JSON schema:

```json
{
  "error": {
    "code": "ERROR_CODE_STRING",
    "message": "Sanitized, human-readable error description.",
    "details": {},
    "request_id": "c2c41631-a0dd-4a4b-8bc0-e9b64c84cc01"
  }
}
```

### Envelope Fields:
- **`code`** (string): Stable machine-readable error code (e.g. `DEMO_MODE_REQUIRED`, `INVALID_STATE`, `UNAUTHORIZED_ACCESS`).
- **`message`** (string): Safe, user-facing explanation suitable for display in UI alert components.
- **`details`** (object): Optional dictionary containing sanitized contextual parameters (e.g. validation error fields). Never contains internal traceback or environment secrets.
- **`request_id`** (string): Unique UUID generated per incoming HTTP request via `RequestIdMiddleware` for correlation across access logs and incident audits.

---

## 2. Standard HTTP Status Code Mappings

| HTTP Status | Primary Error Code | Trigger Condition | Client Treatment |
|---|---|---|---|
| **400 Bad Request** | `INVALID_INPUT` / `VALIDATION_ERROR` | Malformed parameters or invalid multipart structure | Present field-level correction guidance |
| **401 Unauthorized** | `AUTHENTICATION_REQUIRED` / `INVALID_TOKEN` | Missing, malformed, or expired JWT bearer token | Prompt user to sign in again |
| **403 Forbidden** | `INSUFFICIENT_PERMISSIONS` / `DEMO_MODE_REQUIRED` | Role unauthorized or demo action invoked outside DEMO_MODE | Display authorization notice; do not retry |
| **404 Not Found** | `RESOURCE_NOT_FOUND` / `CASE_ACCESS_DENIED` | Nonexistent record or unauthorized access (IDOR non-disclosure) | Display not found notification |
| **409 Conflict** | `INVALID_STATE` / `CONCURRENCY_CONFLICT` | Concurrent state transition collision or restricted transfer attempt | Refresh record from authoritative backend |
| **413 Payload Too Large**| `REQUEST_ENTITY_TOO_LARGE` | Upload exceeds 25 MiB or JSON body exceeds 1 MiB | Advise user of size limits |
| **415 Unsupported Type** | `UNSUPPORTED_MEDIA_TYPE` | Upload MIME magic bytes do not match allowed formats (PDF, PNG, TXT) | Request supported format |
| **422 Unprocessable** | `UNPROCESSABLE_ENTITY` | Pydantic schema validation failure | Display parameter guidance |
| **429 Too Many Requests**| `RATE_LIMIT_EXCEEDED` | Exceeded 5 failed login attempts per minute | Display `Retry-After` cooldown timer |
| **500 Internal Error** | `INTERNAL_SERVER_ERROR` | Unexpected runtime condition | Display generic failure notice with `request_id` |
