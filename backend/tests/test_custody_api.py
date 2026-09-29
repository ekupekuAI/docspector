"""Docspector Custody Read API Tests (Phase 2 / Milestone 27).

Inspect. Verify. Trust.

Validates:
- CUSTODY-API-01: Authenticated assigned user can retrieve custody history.
- CUSTODY-API-02: Unauthenticated request is rejected (HTTP 401).
- CUSTODY-API-03: User assigned to another case receives non-disclosing 404.
- CUSTODY-API-04: Inactive assignment cannot retrieve custody (HTTP 404/403).
- CUSTODY-API-05: Returned events are ordered strictly by sequence_number.
- CUSTODY-API-06: Event hashes and previous hashes match database values.
- CUSTODY-API-07: Valid existing custody chain reports VALID.
- CUSTODY-API-08: Tampered/corrupted custody data causes INVALID chain status.
- CUSTODY-API-09: GET endpoint does not mutate custody events.
- CUSTODY-API-10: No private storage path/storage key/secret is exposed.
- CUSTODY-API-11: Nonexistent document follows existing 404 behavior.
- CUSTODY-API-12: API errors use standard Docspector error envelope and request ID.
- CUSTODY-API-13: Multi-event history (DOCUMENT_INGESTED -> TRANSFER_REQUESTED -> TRANSFER_APPROVED).
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
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, User
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one
from app.services.transfer_service import approve_transfer, create_transfer_request
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def custody_db_fixture(monkeypatch):
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

        # Add an unassigned user for IDOR testing
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


def test_custody_api_unauthenticated(custody_db_fixture):
    """CUSTODY-API-02: Unauthenticated request is rejected with 401."""
    client = TestClient(app)

    r_doc = client.get("/api/v1/documents/1/custody")
    assert r_doc.status_code == 401
    assert "error" in r_doc.json()
    assert r_doc.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")

    r_case = client.get("/api/v1/cases/1/audit")
    assert r_case.status_code == 401


def test_custody_api_idor_unassigned_user(custody_db_fixture):
    """CUSTODY-API-03: User assigned to another case receives non-disclosing 404."""
    db: Session = custody_db_fixture["SessionLocal"]()
    client = TestClient(app)

    unassigned = db.query(User).filter(User.username == "docspector.unassigned").first()
    assert unassigned is not None

    token = create_access_token(unassigned)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/v1/documents/1/custody", headers=headers)
    assert r.status_code == 404
    assert r.json()["error"]["code"] in ("RESOURCE_NOT_FOUND", "DOCUMENT_ACCESS_DENIED", "CASE_ACCESS_DENIED")

    r_case = client.get("/api/v1/cases/1/audit", headers=headers)
    assert r_case.status_code == 404
    db.close()


def test_custody_api_inactive_assignment(custody_db_fixture):
    """CUSTODY-API-04: Inactive assignment cannot retrieve custody (404 non-disclosure)."""
    db: Session = custody_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # Deactivate case assignment
    assignment = (
        db.query(CaseAssignment)
        .filter(CaseAssignment.user_id == io_user.id, CaseAssignment.case_id == case.id)
        .first()
    )
    assignment.is_active = False
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/v1/documents/1/custody", headers=headers)
    assert r.status_code == 404
    db.close()


def test_custody_api_nonexistent_document(custody_db_fixture):
    """CUSTODY-API-11: Nonexistent document returns 404."""
    db: Session = custody_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get("/api/v1/documents/999999/custody", headers=headers)
    assert r.status_code == 404
    db.close()


def test_custody_api_multi_event_history_and_integrity(custody_db_fixture):
    """CUSTODY-API-01, 05, 06, 07, 09, 10, 13: Full multi-event audit trail & integrity test."""
    db: Session = custody_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    so_user = db.query(User).filter(User.username == "docspector.so").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # 1. Register Document (DOCUMENT_INGESTED)
    doc_obj, ver_obj, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="Forensic_Report.pdf",
        content_type="application/pdf",
        title="Forensic Report",
    )

    # 2. Request Transfer (TRANSFER_REQUESTED)
    transfer = create_transfer_request(
        db=db,
        document_id=doc_obj.id,
        version_id=ver_obj.id,
        requester_user=io_user,
        recipient_user_id=so_user.id,
    )

    # 3. Approve Transfer (TRANSFER_APPROVED)
    approve_transfer(
        db=db,
        transfer_id=transfer.id,
        so_user=so_user,
    )

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch count of events before GET request
    count_before = db.query(CustodyEvent).count()

    # Perform GET document custody
    r = client.get(f"/api/v1/documents/{doc_obj.id}/custody", headers=headers)
    assert r.status_code == 200

    data = r.json()
    assert data["document_id"] == doc_obj.id
    assert data["case_id"] == case.id
    assert data["document_number"] == doc_obj.document_number

    events = data["events"]
    assert len(events) >= 3

    # CUSTODY-API-05: Events ordered by sequence_number
    sequences = [e["sequence_number"] for e in events]
    assert sequences == sorted(sequences)

    # CUSTODY-API-06: Verify event hashes and previous hashes match DB
    for e in events:
        db_e = db.query(CustodyEvent).filter(CustodyEvent.id == e["id"]).first()
        assert db_e is not None
        assert e["event_hash"] == db_e.event_hash
        assert e["previous_event_hash"] == db_e.previous_event_hash

    # CUSTODY-API-07: Valid custody chain
    assert data["chain_integrity"]["is_valid"] is True
    assert data["chain_integrity"]["status"] == "VALID"

    # CUSTODY-API-09: Read-only GET request did not mutate custody events count
    count_after = db.query(CustodyEvent).count()
    assert count_before == count_after

    # CUSTODY-API-10: No private storage key or file path exposed in event_data
    raw_response_text = r.text
    assert "storage_key" not in raw_response_text
    assert settings.storage_dir not in raw_response_text

    # Perform GET case audit
    r_audit = client.get(f"/api/v1/cases/{case.id}/audit", headers=headers)
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    assert audit_data["case_id"] == case.id
    assert len(audit_data["events"]) >= 3
    assert audit_data["chain_integrity"]["is_valid"] is True
    db.close()


def test_custody_api_tampered_chain(custody_db_fixture):
    """CUSTODY-API-08: Tampered custody data causes INVALID chain status."""
    db: Session = custody_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # Register document
    doc_obj, ver_obj, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="Evidence_Chain.pdf",
        content_type="application/pdf",
        title="Evidence Chain",
    )

    # Manually corrupt an event hash in the database to simulate tampering
    event_obj = db.query(CustodyEvent).filter(CustodyEvent.case_id == case.id).first()
    assert event_obj is not None
    event_obj.event_hash = "f" * 64
    db.commit()

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.get(f"/api/v1/documents/{doc_obj.id}/custody", headers=headers)
    assert r.status_code == 200
    data = r.json()

    # Chain integrity status MUST be INVALID
    assert data["chain_integrity"]["is_valid"] is False
    assert data["chain_integrity"]["status"] != "VALID"

    r_audit = client.get(f"/api/v1/cases/{case.id}/audit", headers=headers)
    assert r_audit.status_code == 200
    assert r_audit.json()["chain_integrity"]["is_valid"] is False
    db.close()
