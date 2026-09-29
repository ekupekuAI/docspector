"""Milestone 20: API Abuse, HTTP Security Headers & Rate Limiting Hardening Tests.

Inspect. Verify. Trust.

Verifies:
1. HTTP Security Headers (nosniff, DENY, no-referrer, CSP) across 2xx and error responses.
2. CORS validation and origin access control.
3. Request body limits (non-multipart JSON vs streaming 25 MiB multipart file upload).
4. Process-local in-memory login rate limiting and abuse mitigation.
5. Request-ID validation, CRLF/control-char sanitization, and UUID generation.
6. Error envelope format stability and absence of internal stack trace leakage.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import time
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.core.errors import (
    ERROR_AUTH_REQUIRED,
    ERROR_FILE_TOO_LARGE,
    ERROR_FORBIDDEN,
    ERROR_INTERNAL_ERROR,
    ERROR_METHOD_NOT_ALLOWED,
    ERROR_RATE_LIMIT_EXCEEDED,
    ERROR_RESOURCE_NOT_FOUND,
    ERROR_VALIDATION_ERROR,
)
from app.core.rate_limit import InMemoryRateLimiter, login_rate_limiter
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, User
from app.db.session import get_db
from app.main import app
from scripts.seed_demo import seed_demo_data

settings = get_settings()


@pytest.fixture
def test_env(monkeypatch):
    """Set up an isolated test environment with temporary storage and in-memory DB."""
    with tempfile.TemporaryDirectory() as temp_storage:
        temp_storage_path = Path(temp_storage)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))
        monkeypatch.setattr(settings, "demo_mode", False)

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False,
        )

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        session = TestingSessionLocal()
        seed_demo_data(session)
        session.commit()

        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        test_client = TestClient(app)

        yield {
            "client": test_client,
            "db": session,
            "so_user": so_user,
            "legal_user": legal_user,
        }

        app.dependency_overrides.clear()
        session.close()


@pytest.fixture
def client(test_env):
    return test_env["client"]


@pytest.fixture
def admin_token_headers(test_env):
    token = create_access_token(test_env["so_user"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_token_headers(test_env):
    token = create_access_token(test_env["legal_user"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def clean_rate_limiter():
    """Reset rate limiter state between tests."""
    login_rate_limiter.clear()
    yield
    login_rate_limiter.clear()


# ==============================================================================
# PHASE 3 & 8 — HTTP SECURITY HEADERS & METHOD / ROUTE ABUSE
# ==============================================================================

def test_httpsec_01_content_type_options_nosniff(client: TestClient):
    """HTTPSEC-01: Verify X-Content-Type-Options: nosniff is present."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_httpsec_02_frame_options_deny(client: TestClient):
    """HTTPSEC-02: Verify X-Frame-Options: DENY is present."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_httpsec_03_referrer_policy_no_referrer(client: TestClient):
    """HTTPSEC-03: Verify Referrer-Policy: no-referrer is present."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_httpsec_04_headers_present_on_success(client: TestClient):
    """HTTPSEC-04: Verify security headers and CSP remain present on 200 OK responses."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("Content-Security-Policy") == "default-src 'self'"


def test_httpsec_05_headers_present_on_api_errors(client: TestClient):
    """HTTPSEC-05: Verify security headers remain present on API error responses (401, 404, 422)."""
    # 401 Unauthorized
    r401 = client.get("/api/v1/cases")
    assert r401.status_code == 401
    assert r401.headers.get("X-Content-Type-Options") == "nosniff"
    assert r401.headers.get("X-Frame-Options") == "DENY"

    # 404 Not Found
    r404 = client.get("/api/v1/nonexistent_route_probe")
    assert r404.status_code == 404
    assert r404.headers.get("X-Content-Type-Options") == "nosniff"
    assert r404.headers.get("X-Frame-Options") == "DENY"

    # 422 Validation Error
    r422 = client.post("/api/v1/auth/login", json={"invalid_field": 123})
    assert r422.status_code == 422
    assert r422.headers.get("X-Content-Type-Options") == "nosniff"
    assert r422.headers.get("X-Frame-Options") == "DENY"


def test_httpsec_06_unsupported_http_method_returns_405(client: TestClient):
    """HTTPSEC-06: Unsupported HTTP method returns 405 Method Not Allowed with standard error envelope."""
    # POST to /health where only GET is supported
    response = client.post("/health")
    assert response.status_code == 405
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == ERROR_METHOD_NOT_ALLOWED
    assert "request_id" in data["error"]
    assert response.headers.get("X-Request-ID") == data["error"]["request_id"]


def test_httpsec_07_unknown_route_returns_controlled_404(client: TestClient):
    """HTTPSEC-07: Probing unknown routes returns controlled 404 response without system leakage."""
    response = client.get("/api/v1/secret_internal_admin_path_probe")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == ERROR_RESOURCE_NOT_FOUND


def test_httpsec_08_no_internal_stack_trace_leakage(client: TestClient):
    """HTTPSEC-08: Ensure error responses do not leak tracebacks, internal paths, or SQL statements."""
    response = client.get("/api/v1/cases/../../../etc/passwd")
    assert response.status_code in (401, 404, 422)
    body = response.text.lower()
    assert "traceback" not in body
    assert "sqlite" not in body
    assert "d:\\docspector" not in body
    assert "c:\\" not in body


# ==============================================================================
# PHASE 4 — CORS CONFIGURATION
# ==============================================================================

def test_cors_01_allowed_configured_origin_succeeds(client: TestClient):
    """CORS-01: Configured origin receives CORS authorization headers."""
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_cors_02_untrusted_origin_rejected(client: TestClient):
    """CORS-02: Untrusted external origin is not granted CORS access."""
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://malicious-attacker-site.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    # Untrusted origins must NOT receive Access-Control-Allow-Origin matching the attacker
    assert response.headers.get("Access-Control-Allow-Origin") != "http://malicious-attacker-site.com"


def test_cors_03_wildcard_origin_not_used_with_credentials_in_default():
    """CORS-03: Default configuration does not use wildcard origins with credentials enabled."""
    s = Settings()
    assert "*" not in s.cors_allowed_origins
    assert "http://localhost:5173" in s.cors_allowed_origins


def test_cors_04_production_configuration_rejects_unsafe_wildcard_cors():
    """CORS-04: Production environment strictly forbids wildcard CORS origins when credentials are enabled."""
    with pytest.raises(ValueError, match="Wildcard CORS origin"):
        Settings(
            app_env="production",
            jwt_secret_key="a" * 64,
            demo_mode=False,
            cors_allowed_origins=["*"],
            cors_allow_credentials=True,
        )


# ==============================================================================
# PHASE 5 — REQUEST BODY LIMITS & ABUSE
# ==============================================================================

def test_abuse_01_oversized_json_rejected_safely(client: TestClient):
    """ABUSE-01: Non-multipart request with Content-Length exceeding limit is rejected with 413."""
    # Simulate oversized JSON payload with large declared Content-Length
    oversized_length = str(2 * 1024 * 1024)  # 2 MiB (limit is 1 MiB)
    response = client.post(
        "/api/v1/auth/login",
        content=b"{}",
        headers={"Content-Length": oversized_length, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["error"]["code"] == ERROR_FILE_TOO_LARGE
    assert "maximum allowed size" in data["error"]["message"]


def test_abuse_02_malformed_json_rejected_safely(client: TestClient):
    """ABUSE-02: Malformed JSON syntax is rejected with standard 422 envelope without crashing."""
    response = client.post(
        "/api/v1/auth/login",
        content=b"{malformed_json_without_quotes: 123",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == ERROR_VALIDATION_ERROR
    assert "validation" in data["error"]["message"].lower()


def test_abuse_03_large_request_bounded_memory(client: TestClient):
    """ABUSE-03: Huge declared body size is rejected immediately without unbounded buffering."""
    huge_length = str(500 * 1024 * 1024)  # 500 MiB
    response = client.post(
        "/api/v1/auth/login",
        content=b"",
        headers={"Content-Length": huge_length, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == ERROR_FILE_TOO_LARGE


def test_abuse_04_existing_25mib_upload_limit_enforced(client: TestClient, admin_token_headers: dict[str, str]):
    """ABUSE-04: Streaming file upload retains its dedicated 25 MiB enforcement."""
    # 26 MiB synthetic payload
    oversized_bytes = b"0" * (26 * 1024 * 1024)
    file_payload = {"file": ("large_doc.pdf", io.BytesIO(oversized_bytes), "application/pdf")}
    data_payload = {
        "title": "Oversized Document",
    }

    response = client.post(
        "/api/v1/cases/1/documents",
        files=file_payload,
        data=data_payload,
        headers=admin_token_headers,
    )
    assert response.status_code == 413
    data = response.json()
    assert data["error"]["code"] == ERROR_FILE_TOO_LARGE


def test_abuse_05_upload_validation_streaming_bounded_memory(
    client: TestClient, admin_token_headers: dict[str, str]
):
    """ABUSE-05: Valid upload under 25 MiB passes through streaming check."""
    valid_bytes = b"%PDF-1.4 Mock document content for size verification"
    file_payload = {"file": ("valid.pdf", io.BytesIO(valid_bytes), "application/pdf")}
    data_payload = {
        "title": "Valid Document",
    }

    response = client.post(
        "/api/v1/cases/1/documents",
        files=file_payload,
        data=data_payload,
        headers=admin_token_headers,
    )
    assert response.status_code == 201
    assert "document" in response.json()


# ==============================================================================
# PHASE 6 & 12 — LOGIN ABUSE PROTECTION & RATE LIMITER SECURITY
# ==============================================================================

def test_rate_01_normal_login_succeeds(client: TestClient):
    """RATE-01: Valid login request succeeds without rate limiting."""
    response = client.post("/api/v1/auth/login", json={"username": "docspector.io"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_rate_02_repeated_invalid_login_attempts_receive_429(client: TestClient):
    """RATE-02: Repeated invalid login attempts trigger HTTP 429 after maximum threshold."""
    # Attempt 5 failed logins (max attempts is 5)
    for _ in range(5):
        r = client.post("/api/v1/auth/login", json={"username": "invalid_attacker_user"})
        assert r.status_code == 401

    # 6th attempt should be blocked with 429
    blocked_res = client.post("/api/v1/auth/login", json={"username": "invalid_attacker_user"})
    assert blocked_res.status_code == 429
    assert blocked_res.headers.get("Retry-After") is not None
    data = blocked_res.json()
    assert data["error"]["code"] == ERROR_RATE_LIMIT_EXCEEDED
    assert "Too many failed login attempts" in data["error"]["message"]


def test_rate_03_rate_limit_resets_after_window_expiration():
    """RATE-03: Rate limiter accurately expires entries based on sliding window."""
    limiter = InMemoryRateLimiter(max_keys=100)
    key = "test_key"
    window = 10.0  # 10 seconds

    # Record 5 attempts at t=100.0
    for _ in range(5):
        limiter.record_attempt(key, window_seconds=window, current_time=100.0)

    # Check at t=105.0 -> Still limited
    is_limited, remaining, retry_after = limiter.is_rate_limited(
        key, max_attempts=5, window_seconds=window, current_time=105.0
    )
    assert is_limited is True
    assert retry_after == 5.0

    # Check at t=111.0 -> Expired and reset
    is_limited, remaining, retry_after = limiter.is_rate_limited(
        key, max_attempts=5, window_seconds=window, current_time=111.0
    )
    assert is_limited is False
    assert remaining == 5


def test_rate_04_different_usernames_do_not_share_limits(client: TestClient):
    """RATE-04: Multiple distinct usernames do not cross-contaminate rate limits."""
    # Exhaust attempts for attacker_one
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "attacker_one"})

    # attacker_one is blocked
    r1 = client.post("/api/v1/auth/login", json={"username": "attacker_one"})
    assert r1.status_code == 429

    # attacker_two is NOT blocked on first attempt
    r2 = client.post("/api/v1/auth/login", json={"username": "attacker_two"})
    assert r2.status_code == 401  # 401 invalid credentials, NOT 429


def test_rate_05_successful_login_not_blocked_and_resets_counter(client: TestClient):
    """RATE-05: Successful login clears failed attempt history."""
    # 2 failed attempts with nonexistent user
    for _ in range(2):
        client.post("/api/v1/auth/login", json={"username": "wrong_user"})

    # Valid login succeeds and resets
    res = client.post("/api/v1/auth/login", json={"username": "docspector.io"})
    assert res.status_code == 200

    # User can continue logging in without accumulated penalties
    res2 = client.post("/api/v1/auth/login", json={"username": "docspector.io"})
    assert res2.status_code == 200


def test_rate_06_rate_limit_state_remains_bounded():
    """RATE-06: Rate limiter memory remains strictly bounded under large key volume."""
    limiter = InMemoryRateLimiter(max_keys=50)

    # Insert 200 distinct keys
    for i in range(200):
        limiter.record_attempt(f"key_{i}", window_seconds=60.0)

    assert len(limiter._attempts) <= 50


def test_rate_07_rate_limit_response_follows_standard_error_envelope(client: TestClient):
    """RATE-07: Rate limit error matches the universal API error contract."""
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "rate_limit_envelope_test"})

    response = client.post("/api/v1/auth/login", json={"username": "rate_limit_envelope_test"})
    assert response.status_code == 429
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == ERROR_RATE_LIMIT_EXCEEDED
    assert "request_id" in data["error"]
    assert response.headers.get("X-Request-ID") == data["error"]["request_id"]


# ==============================================================================
# PHASE 9 — REQUEST-ID SECURITY
# ==============================================================================

def test_reqid_01_valid_request_id_accepted(client: TestClient):
    """REQID-01: Valid custom X-Request-ID is preserved and echoed."""
    custom_id = "trace-sec-audit-12345"
    response = client.get("/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_id


def test_reqid_02_oversized_request_id_replaced(client: TestClient):
    """REQID-02: Oversized X-Request-ID (>128 chars) is safely replaced with fresh UUID."""
    oversized_id = "A" * 256
    response = client.get("/health", headers={"X-Request-ID": oversized_id})
    assert response.status_code == 200
    returned_id = response.headers.get("X-Request-ID")
    assert returned_id != oversized_id
    # Must be a valid UUID4 format
    assert uuid.UUID(returned_id)


def test_reqid_03_crlf_injection_sanitized(client: TestClient):
    """REQID-03: CRLF injection in X-Request-ID is sanitized / replaced."""
    crlf_payload = "valid-id\r\nInjected-Header: evil"
    response = client.get("/health", headers={"X-Request-ID": crlf_payload})
    assert response.status_code == 200
    returned_id = response.headers.get("X-Request-ID")
    assert "\r" not in returned_id
    assert "\n" not in returned_id
    assert "Injected-Header" not in response.headers


def test_reqid_04_control_characters_cannot_enter_response_headers(client: TestClient):
    """REQID-04: Control characters and non-alphanumeric chars trigger replacement."""
    bad_id = "req\x00\x08id;drop table"
    response = client.get("/health", headers={"X-Request-ID": bad_id})
    assert response.status_code == 200
    returned_id = response.headers.get("X-Request-ID")
    assert returned_id != bad_id
    assert uuid.UUID(returned_id)


def test_reqid_05_generated_request_ids_valid_uuid(client: TestClient):
    """REQID-05: Missing X-Request-ID automatically generates valid UUID4."""
    response = client.get("/health")
    assert response.status_code == 200
    req_id = response.headers.get("X-Request-ID")
    assert req_id is not None
    assert uuid.UUID(req_id)


# ==============================================================================
# PHASE 10 — ERROR RESPONSE HARDENING
# ==============================================================================

def test_errorsec_01_401_envelope_correct(client: TestClient):
    """ERRORSEC-01: 401 error envelope contains AUTH_REQUIRED code and request_id."""
    response = client.get("/api/v1/cases")
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == ERROR_AUTH_REQUIRED
    assert data["error"]["request_id"] == response.headers.get("X-Request-ID")


def test_errorsec_02_403_envelope_correct(client: TestClient, viewer_token_headers: dict[str, str]):
    """ERRORSEC-02: 403 error envelope contains FORBIDDEN code and request_id."""
    # Viewer attempting to upload a document to Case 1
    file_payload = {"file": ("test.pdf", io.BytesIO(b"%PDF-1.4 sample"), "application/pdf")}
    data_payload = {
        "title": "Unauthorized Document",
    }
    response = client.post(
        "/api/v1/cases/1/documents",
        files=file_payload,
        data=data_payload,
        headers=viewer_token_headers,
    )
    assert response.status_code == 403
    data = response.json()
    assert data["error"]["code"] == ERROR_FORBIDDEN
    assert data["error"]["request_id"] == response.headers.get("X-Request-ID")


def test_errorsec_03_404_envelope_correct(client: TestClient, admin_token_headers: dict[str, str]):
    """ERRORSEC-03: 404 error envelope contains RESOURCE_NOT_FOUND code and request_id."""
    response = client.get(
        "/api/v1/cases/99999",
        headers=admin_token_headers,
    )
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] in (ERROR_RESOURCE_NOT_FOUND, "CASE_ACCESS_DENIED")
    assert "request_id" in data["error"]


def test_errorsec_04_413_envelope_correct(client: TestClient):
    """ERRORSEC-04: 413 error envelope contains FILE_TOO_LARGE code and request_id."""
    response = client.post(
        "/api/v1/auth/login",
        content=b"{}",
        headers={"Content-Length": str(5 * 1024 * 1024), "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["error"]["code"] == ERROR_FILE_TOO_LARGE
    assert data["error"]["request_id"] == response.headers.get("X-Request-ID")


def test_errorsec_05_429_envelope_correct(client: TestClient):
    """ERRORSEC-05: 429 error envelope contains RATE_LIMIT_EXCEEDED code and request_id."""
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "exhaust_limit_user"})

    response = client.post("/api/v1/auth/login", json={"username": "exhaust_limit_user"})
    assert response.status_code == 429
    data = response.json()
    assert data["error"]["code"] == ERROR_RATE_LIMIT_EXCEEDED
    assert data["error"]["request_id"] == response.headers.get("X-Request-ID")


def test_errorsec_06_500_envelope_does_not_expose_internals():
    """ERRORSEC-06: 500 error envelope masks internal exception details and stack traces."""
    def crash_get_db():
        raise RuntimeError("Database connection string postgresql://admin:secret_pw@internal:5432/db failed")

    app.dependency_overrides[get_db] = crash_get_db
    try:
        unhandled_client = TestClient(app, raise_server_exceptions=False)
        response = unhandled_client.post(
            "/api/v1/auth/login",
            json={"username": "docspector.io"},
        )
        assert response.status_code == 500
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == ERROR_INTERNAL_ERROR
        assert "internal server error" in data["error"]["message"].lower()
        assert "secret_pw" not in response.text
        assert "postgresql" not in response.text
    finally:
        app.dependency_overrides.pop(get_db, None)
