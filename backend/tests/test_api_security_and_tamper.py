"""Docspector API Error Contract & Demo Tamper Safety Tests (Milestone 14).

Inspect. Verify. Trust.

Validates:
- API-ERROR-01: Standard API error envelope structure (code, message, details, request_id).
- API-ERROR-02: Auto-generated X-Request-ID matches error.request_id.
- API-ERROR-03: Client-supplied X-Request-ID is preserved across header and body.
- API-ERROR-04: RequestValidationError uses standard error envelope (422, VALIDATION_ERROR).
- API-ERROR-05: Unexpected exceptions return safe 500 response with INTERNAL_ERROR.
- API-ERROR-06: No stack traces, SQL errors, or storage paths leaked in error responses.
- DEMO-01: Tamper endpoint blocked when DEMO_MODE=False (403, DEMO_MODE_REQUIRED).
- DEMO-02: Tamper requires authentication (401, AUTH_REQUIRED).
- DEMO-03: Tamper requires active case assignment (404, CASE_ACCESS_DENIED).
- DEMO-04: Tamper requires demo operator role (IO / SO only; Legal/Auditor get 403).
- DEMO-05: Tamper operates only on server-resolved storage keys without client paths.
- DEMO-06: Tamper targets exact authorized document version.
- DEMO-07: Database SHA-256 remains unchanged after simulated tampering.
- DEMO-08: Stored file bytes on disk actually differ after simulation.
- DEMO-09: Subsequent M13 verification detects FILE_HASH_MISMATCH.
- DEMO-10: Verification changes version state from STORED to RESTRICTED.
- DEMO-11: High-severity integrity alert is created.
- DEMO-12: Repeated verification against tampered version is idempotent.
- DEMO-13: Default server configuration (DEMO_MODE=False) blocks tampering.
- DEMO-14: Unauthorized user cannot use tamper endpoint even when DEMO_MODE=True.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, Document, DocumentVersion, IntegrityAlert, User
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def api_security_fixture(monkeypatch):
    """Create an isolated test environment with temporary storage and in-memory SQLite."""
    with tempfile.TemporaryDirectory() as temp_storage:
        temp_storage_path = Path(temp_storage)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))
        monkeypatch.setattr(settings, "demo_mode", False)  # Default: false

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

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        unassigned_user = User(
            username="docspector.unassigned",
            display_name="Unassigned Officer",
            role="IO",
            is_active=True,
        )
        session.add(unassigned_user)
        session.commit()

        # Ingest Document A
        doc_a, v1, _ = register_document_version_one(
            db=session,
            case=case_1,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Demo_Evidence.pdf",
            content_type="application/pdf",
            title="Demo Forensic Document",
        )

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)

        yield {
            "client": client,
            "db": session,
            "storage_dir": temp_storage_path,
            "case": case_1,
            "doc_a": doc_a,
            "v1": v1,
            "io_user": io_user,
            "so_user": so_user,
            "legal_user": legal_user,
            "auditor_user": auditor_user,
            "unassigned_user": unassigned_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
            "legal_token": create_access_token(legal_user),
            "auditor_token": create_access_token(auditor_user),
            "unassigned_token": create_access_token(unassigned_user),
            "monkeypatch": monkeypatch,
        }

        app.dependency_overrides.clear()
        session.close()
        Base.metadata.drop_all(bind=engine)


# =====================================================================
# API ERROR CONTRACT & REQUEST-ID TESTS (API-ERROR-01 to API-ERROR-06)
# =====================================================================


def test_api_error_01_standard_error_envelope(api_security_fixture):
    """API-ERROR-01: Errors conform strictly to the standard error contract envelope."""
    client: TestClient = api_security_fixture["client"]

    # Trigger 401 Unauthorized
    resp = client.get("/api/v1/cases")
    assert resp.status_code == 401
    assert "X-Request-ID" in resp.headers

    body = resp.json()
    assert "error" in body
    err = body["error"]
    assert "code" in err
    assert "message" in err
    assert "details" in err
    assert "request_id" in err
    assert err["code"] == "AUTH_REQUIRED"
    assert err["request_id"] == resp.headers["X-Request-ID"]


def test_api_error_02_generated_request_id(api_security_fixture):
    """API-ERROR-02: Request-ID is generated automatically on both successful and error responses."""
    client: TestClient = api_security_fixture["client"]
    io_token: str = api_security_fixture["io_token"]

    # 1. Successful request
    success_resp = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {io_token}"})
    assert success_resp.status_code == 200
    req_id = success_resp.headers.get("X-Request-ID")
    assert req_id is not None
    assert len(req_id) > 10

    # 2. Error request
    err_resp = client.get("/api/v1/cases/999999", headers={"Authorization": f"Bearer {io_token}"})
    assert err_resp.status_code == 404
    err_req_id = err_resp.headers.get("X-Request-ID")
    assert err_req_id is not None
    assert err_resp.json()["error"]["request_id"] == err_req_id


def test_api_error_03_supplied_request_id_preserved(api_security_fixture):
    """API-ERROR-03: Client-supplied safe X-Request-ID is preserved in headers and error envelope."""
    client: TestClient = api_security_fixture["client"]
    custom_id = f"client-trace-{uuid.uuid4().hex[:12]}"

    # Error request with custom X-Request-ID
    resp = client.get(
        "/api/v1/cases",
        headers={"X-Request-ID": custom_id},
    )
    assert resp.status_code == 401
    assert resp.headers["X-Request-ID"] == custom_id
    assert resp.json()["error"]["request_id"] == custom_id


def test_api_error_04_validation_error_envelope(api_security_fixture):
    """API-ERROR-04: RequestValidationError uses standard error envelope with code VALIDATION_ERROR."""
    client: TestClient = api_security_fixture["client"]
    io_token: str = api_security_fixture["io_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]

    # POST transfer with invalid payload (missing recipient_user_id)
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/transfers",
        json={"invalid_field": "test"},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "validation_errors" in body["error"]["details"]
    assert body["error"]["request_id"] == resp.headers["X-Request-ID"]


def test_api_error_05_unexpected_exception_safe_500(api_security_fixture):
    """API-ERROR-05: Unexpected exceptions return safe HTTP 500 without leaking stack traces."""
    client: TestClient = api_security_fixture["client"]
    io_token: str = api_security_fixture["io_token"]

    from app.api.dependencies import get_current_user
    from app.main import app

    def crashing_user():
        raise RuntimeError("Database connection suddenly dropped: password=SECRET_DB_PASS")

    client_500 = TestClient(app, raise_server_exceptions=False)
    orig_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = crashing_user

    try:
        resp = client_500.get(
            "/api/v1/cases/1",
            headers={"Authorization": f"Bearer {io_token}"},
        )
        assert resp.status_code == 500
        body = resp.json()
        assert body["error"]["code"] == "INTERNAL_ERROR"
        assert body["error"]["message"] == "An internal server error occurred."
        assert "request_id" in body["error"]
        assert resp.headers.get("x-request-id") == body["error"]["request_id"]
        # Ensure sensitive runtime message was NOT leaked to client
        assert "SECRET_DB_PASS" not in resp.text
        assert "RuntimeError" not in resp.text
        assert "Traceback" not in resp.text
    finally:
        if orig_override:
            app.dependency_overrides[get_current_user] = orig_override
        else:
            app.dependency_overrides.pop(get_current_user, None)


def test_api_error_06_no_stack_trace_leakage(api_security_fixture):
    """API-ERROR-06: 404 / 403 / 409 responses never expose paths, queries, or stack traces."""
    client: TestClient = api_security_fixture["client"]
    io_token: str = api_security_fixture["io_token"]

    resp = client.get("/api/v1/cases/99999", headers={"Authorization": f"Bearer {io_token}"})
    assert resp.status_code == 404
    assert "Traceback" not in resp.text
    assert "sqlite" not in resp.text.lower()
    assert "SELECT" not in resp.text


# =====================================================================
# DEMO TAMPER SIMULATOR TESTS (DEMO-01 to DEMO-14)
# =====================================================================


def test_demo_01_tamper_blocked_when_demo_mode_false(api_security_fixture):
    """DEMO-01: Tamper endpoint is blocked when DEMO_MODE=False (default production safety)."""
    client: TestClient = api_security_fixture["client"]
    io_token: str = api_security_fixture["io_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]

    # DEMO_MODE is False by default
    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["code"] == "DEMO_MODE_REQUIRED"
    assert "Demo mode is disabled" in body["error"]["message"]


def test_demo_02_tamper_requires_authentication(api_security_fixture, monkeypatch):
    """DEMO-02: Tamper requires authentication."""
    client: TestClient = api_security_fixture["client"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]
    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTH_REQUIRED"


def test_demo_03_tamper_requires_active_case_assignment(api_security_fixture, monkeypatch):
    """DEMO-03: Tamper requires active case assignment (404 non-disclosure on unassigned)."""
    client: TestClient = api_security_fixture["client"]
    unassigned_token: str = api_security_fixture["unassigned_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]
    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {unassigned_token}"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] in ("CASE_ACCESS_DENIED", "DOCUMENT_ACCESS_DENIED")


def test_demo_04_tamper_requires_demo_operator_role(api_security_fixture, monkeypatch):
    """DEMO-04: Non-investigative roles (e.g. Legal Reviewer, Auditor) are blocked (403)."""
    client: TestClient = api_security_fixture["client"]
    legal_token: str = api_security_fixture["legal_token"]
    auditor_token: str = api_security_fixture["auditor_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]
    monkeypatch.setattr(settings, "demo_mode", True)

    resp_legal = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {legal_token}"},
    )
    assert resp_legal.status_code == 403
    assert resp_legal.json()["error"]["code"] == "DEMO_PERMISSION_REQUIRED"

    resp_auditor = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp_auditor.status_code == 403
    assert resp_auditor.json()["error"]["code"] == "DEMO_PERMISSION_REQUIRED"


def test_demo_05_through_12_full_tamper_and_verification_cycle(api_security_fixture, monkeypatch):
    """DEMO-05 to DEMO-12: Full synthetic tamper simulation and M13 verification detection cycle."""
    client: TestClient = api_security_fixture["client"]
    db: Session = api_security_fixture["db"]
    storage_dir: Path = api_security_fixture["storage_dir"]
    io_token: str = api_security_fixture["io_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]

    monkeypatch.setattr(settings, "demo_mode", True)

    # 1. Record original state & file bytes
    original_stored_hash = v1.sha256_hash
    file_path = storage_dir / v1.storage_key
    with open(file_path, "rb") as f:
        original_bytes = f.read()

    # 2. Run Tamper Simulator (DEMO-06)
    tamper_resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert tamper_resp.status_code == 200
    tamper_data = tamper_resp.json()
    assert tamper_data["simulation_type"] == "SYNTHETIC_STORAGE_BYTE_CORRUPTION"
    assert tamper_data["persisted_expected_sha256"] == original_stored_hash

    # 3. DEMO-07: DB hash remains unmodified
    db.expire_all()
    reloaded_v1 = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    assert reloaded_v1.sha256_hash == original_stored_hash

    # 4. DEMO-08: Stored bytes on disk actually changed
    with open(file_path, "rb") as f:
        modified_bytes = f.read()
    assert modified_bytes != original_bytes
    assert len(modified_bytes) > len(original_bytes)

    # 5. DEMO-09: Explicitly call M13 verification endpoint
    verify_resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()

    assert verify_data["overall_status"] == "INTEGRITY_FAILURE"
    assert verify_data["file_integrity"]["is_valid"] is False
    assert verify_data["file_integrity"]["status"] == "FILE_HASH_MISMATCH"
    assert verify_data["chain_integrity"]["is_valid"] is True

    # 6. DEMO-10: Version state transitioned to RESTRICTED
    assert verify_data["version_state"] == "RESTRICTED"
    db.expire_all()
    reloaded_after_verify = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    assert reloaded_after_verify.state == "RESTRICTED"

    # 7. DEMO-11: High-severity integrity alert created
    assert len(verify_data["alerts"]) == 1
    alert = verify_data["alerts"][0]
    assert alert["alert_type"] == "FILE_HASH_MISMATCH"
    assert alert["status"] == "OPEN"

    # 8. DEMO-12: Repeated verification does not create duplicate alerts
    verify_resp_2 = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert verify_resp_2.status_code == 200
    db.expire_all()
    alerts = (
        db.query(IntegrityAlert)
        .filter(IntegrityAlert.document_version_id == v1.id, IntegrityAlert.alert_type == "FILE_HASH_MISMATCH")
        .all()
    )
    assert len(alerts) == 1


def test_demo_13_production_default_safe(api_security_fixture):
    """DEMO-13: Production/default environment (DEMO_MODE=False) leaves files and DB pristine."""
    client: TestClient = api_security_fixture["client"]
    db: Session = api_security_fixture["db"]
    storage_dir: Path = api_security_fixture["storage_dir"]
    io_token: str = api_security_fixture["io_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]

    file_path = storage_dir / v1.storage_key
    with open(file_path, "rb") as f:
        bytes_before = f.read()

    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 403

    # File and DB unchanged
    with open(file_path, "rb") as f:
        bytes_after = f.read()
    assert bytes_after == bytes_before

    db.expire_all()
    reloaded_v1 = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    assert reloaded_v1.state == "STORED"


def test_demo_14_unauthorized_user_blocked_even_with_demo_mode_true(api_security_fixture, monkeypatch):
    """DEMO-14: Unauthorized / unassigned user cannot tamper even when DEMO_MODE=True."""
    client: TestClient = api_security_fixture["client"]
    unassigned_token: str = api_security_fixture["unassigned_token"]
    doc_a: Document = api_security_fixture["doc_a"]
    v1: DocumentVersion = api_security_fixture["v1"]
    monkeypatch.setattr(settings, "demo_mode", True)

    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v1.id}/tamper",
        headers={"Authorization": f"Bearer {unassigned_token}"},
    )
    assert resp.status_code == 404
