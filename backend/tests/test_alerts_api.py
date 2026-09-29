"""Docspector Integrity Alerts API Tests (Phase 1 / Milestone 26).

Inspect. Verify. Trust.

Validates:
- ALERT-01: Unauthenticated requests rejected with HTTP 401.
- ALERT-02: IDOR / Unassigned case access rejected with HTTP 404 (non-disclosure).
- ALERT-03: Filter & retrieval of alerts for assigned case.
- ALERT-04: Resolving alert requires non-empty resolution_note (HTTP 400/422).
- ALERT-05: Resolving an already-resolved alert rejected with HTTP 400.
- ALERT-06: CRITICAL SECURITY TEST - Resolving alert fails if underlying document/chain integrity still fails.
- ALERT-07: Valid re-verification permits alert resolution, recording reviewed_by_user_id and reviewed_at while preserving alert history.
"""

import io
from pathlib import Path
import tempfile

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, Document, DocumentVersion, IntegrityAlert, User
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one
from app.services.verification_service import verify_document_version_integrity
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
TAMPERED_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n%TAMPERED_BYTE_PAYLOAD\n"


@pytest.fixture
def alerts_db_fixture(monkeypatch):
    """Set up isolated in-memory SQLite database and temporary storage."""
    with tempfile.TemporaryDirectory() as temp_storage:
        temp_storage_path = Path(temp_storage)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))

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

        seed_session = TestingSessionLocal()
        seed_demo_data(seed_session)

        # Create unassigned user
        unassigned_user = User(
            username="docspector.unassigned",
            display_name="Unassigned Officer",
            role="IO",
            is_active=True,
        )
        seed_session.add(unassigned_user)
        seed_session.commit()
        seed_session.close()

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

        yield {
            "engine": engine,
            "SessionLocal": TestingSessionLocal,
            "storage_dir": temp_storage_path,
        }

        app.dependency_overrides.clear()


def test_alerts_unauthenticated(alerts_db_fixture):
    """Unauthenticated requests to alert endpoints must be rejected with 401."""
    client = TestClient(app)

    r_list = client.get("/api/v1/cases/1/alerts")
    assert r_list.status_code == 401

    r_resolve = client.post("/api/v1/alerts/1/resolve", json={"resolution_note": "Reviewed note"})
    assert r_resolve.status_code == 401


def test_alerts_unassigned_case_idor(alerts_db_fixture):
    """User without active assignment to case receives 404 (non-disclosure IDOR protection)."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    unassigned = db.query(User).filter(User.username == "docspector.unassigned").first()
    assert unassigned is not None
    token = create_access_token(unassigned)
    headers = {"Authorization": f"Bearer {token}"}

    # Access case 1 to which unassigned user has no assignment -> 404
    r = client.get("/api/v1/cases/1/alerts", headers=headers)
    assert r.status_code == 404
    db.close()


def test_get_alerts_list(alerts_db_fixture):
    """Assigned user can list alerts for a case."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()
    assert io_user is not None
    assert case is not None

    alert = IntegrityAlert(
        case_id=case.id,
        document_version_id=None,
        alert_type="TEST_ALERT",
        severity="HIGH",
        message="Test alert message",
        status="OPEN",
    )
    db.add(alert)
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get(f"/api/v1/cases/{case.id}/alerts", headers=headers)
    assert r.status_code == 200
    alerts = r.json()
    assert isinstance(alerts, list)
    assert any(a["alert_type"] == "TEST_ALERT" for a in alerts)
    db.close()


def test_resolve_alert_missing_note(alerts_db_fixture):
    """Resolving an alert without resolution_note must be rejected."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    alert = IntegrityAlert(
        case_id=case.id,
        alert_type="TEST_ALERT",
        severity="HIGH",
        message="Test alert",
        status="OPEN",
    )
    db.add(alert)
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(f"/api/v1/alerts/{alert.id}/resolve", json={"resolution_note": "  "}, headers=headers)
    assert r.status_code in (400, 422)
    db.close()


def test_resolve_alert_already_resolved(alerts_db_fixture):
    """Resolving an alert that is already resolved must be rejected."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    alert = IntegrityAlert(
        case_id=case.id,
        alert_type="TEST_ALERT",
        severity="HIGH",
        message="Test alert",
        status="RESOLVED",
    )
    db.add(alert)
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post(f"/api/v1/alerts/{alert.id}/resolve", json={"resolution_note": "Already done"}, headers=headers)
    assert r.status_code == 400
    db.close()


def test_resolve_alert_unresolved_integrity_failure(alerts_db_fixture):
    """CRITICAL SECURITY TEST: Resolving alert must be REJECTED if file integrity still fails."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # 1. Register a valid document version
    doc_obj, ver_obj, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="evidence.pdf",
        content_type="application/pdf",
        title="Evidence PDF",
    )
    version_id = ver_obj.id

    # 2. Corrupt the file on disk to simulate tampering
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    file_path = Path(alerts_db_fixture["storage_dir"]) / version.storage_key
    file_path.write_bytes(TAMPERED_PDF_BYTES)

    # 3. Run verification so that an OPEN alert is generated and document becomes RESTRICTED
    ver_res = verify_document_version_integrity(
        db=db,
        document_id=doc_obj.id,
        version_id=version_id,
        current_user=io_user,
        storage_dir=alerts_db_fixture["storage_dir"],
    )
    assert ver_res.overall_status == "INTEGRITY_FAILURE"
    assert ver_res.version_state == "RESTRICTED"

    alert = db.query(IntegrityAlert).filter(IntegrityAlert.document_version_id == version_id, IntegrityAlert.status == "OPEN").first()
    assert alert is not None

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Attempt to resolve the alert while file remains tampered
    r = client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        json={"resolution_note": "Attempting to whitewash alert without fixing file"},
        headers=headers,
    )

    # Resolving alert MUST be rejected!
    assert r.status_code == 400
    assert "integrity verification still fails" in r.json()["detail"].lower() or "cannot resolve" in r.json()["detail"].lower()

    # Re-verify alert status remains OPEN and document state remains RESTRICTED
    db.refresh(alert)
    db.refresh(version)
    assert alert.status == "OPEN"
    assert version.state == "RESTRICTED"
    db.close()


def test_resolve_alert_valid_reverification(alerts_db_fixture):
    """Resolving an alert after valid re-verification succeeds and records audit info."""
    db: Session = alerts_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # 1. Register valid document
    doc_obj, ver_obj, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="legit.pdf",
        content_type="application/pdf",
        title="Legit PDF",
    )

    # 2. Create alert for this version manually
    alert = IntegrityAlert(
        case_id=case.id,
        document_version_id=ver_obj.id,
        alert_type="MANUAL_REVIEW_FLAG",
        severity="MEDIUM",
        message="Flagged for manual review",
        status="OPEN",
    )
    db.add(alert)
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Resolve alert - re-verification will pass because file is intact
    r = client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        json={"resolution_note": "Document verified intact by Supervisory Officer."},
        headers=headers,
    )

    assert r.status_code == 200
    res_data = r.json()
    assert res_data["status"] == "RESOLVED"
    assert res_data["reviewed_by_user_id"] == io_user.id
    assert res_data["reviewed_at"] is not None

    # Alert remains in database with RESOLVED status
    db.refresh(alert)
    assert alert.status == "RESOLVED"
    assert alert.reviewed_by_user_id == io_user.id
    db.close()
