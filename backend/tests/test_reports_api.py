"""Docspector Reports API Tests (Phase 3 / Milestone 28).

Inspect. Verify. Trust.

Validates:
- REPORT-01: Authenticated assigned user can retrieve a case report.
- REPORT-02: Unauthenticated request is rejected (HTTP 401).
- REPORT-03: User assigned to another case receives 404 non-disclosure.
- REPORT-04: Inactive case assignment is denied.
- REPORT-05: Document counts are derived from real database records.
- REPORT-06: Version state counts are accurate.
- REPORT-07: Transfer counts are accurate.
- REPORT-08: Integrity alert counts are accurate.
- REPORT-09: Restricted version count is accurate.
- REPORT-10: Custody event count is accurate.
- REPORT-11: Custody chain status comes from existing validation service.
- REPORT-12: Document breakdown contains real documents and real latest version info.
- REPORT-13: No storage key or filesystem path appears in response.
- REPORT-14: Report contains intended disclaimer/scope.
- REPORT-15: Report endpoint does not mutate database records.
- REPORT-16: CRITICAL SECURITY TEST - Cross-case aggregate isolation (Case B data cannot leak into Case A report).
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
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, IntegrityAlert, Transfer, User
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one
from app.services.transfer_service import approve_transfer, create_transfer_request
from app.services.verification_service import verify_document_version_integrity
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
TAMPERED_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n%TAMPERED_BYTE_PAYLOAD\n"


@pytest.fixture
def reports_db_fixture(monkeypatch):
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

        # Create Case B (isolated case)
        case_b = Case(
            case_number="CASE-B-2026-9999",
            title="Isolated Case B",
            description="Isolated case for cross-case aggregation security tests.",
            status="OPEN",
        )
        seed_session.add(case_b)
        seed_session.commit()

        # Assign unassigned_user only to Case B
        assign_b = CaseAssignment(
            case_id=case_b.id,
            user_id=unassigned_user.id,
            is_active=True,
        )
        seed_session.add(assign_b)
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


def test_reports_api_unauthenticated(reports_db_fixture):
    """REPORT-02: Unauthenticated request is rejected with 401."""
    client = TestClient(app)

    r = client.get("/api/v1/cases/1/report")
    assert r.status_code == 401
    assert "error" in r.json()


def test_reports_api_unassigned_case_idor(reports_db_fixture):
    """REPORT-03: User assigned to another case receives 404 non-disclosure."""
    db: Session = reports_db_fixture["SessionLocal"]()
    client = TestClient(app)

    unassigned = db.query(User).filter(User.username == "docspector.unassigned").first()
    assert unassigned is not None

    token = create_access_token(unassigned)
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to fetch report for Case 1 (to which unassigned user is not assigned) -> 404
    r = client.get("/api/v1/cases/1/report", headers=headers)
    assert r.status_code == 404
    db.close()


def test_reports_api_inactive_assignment(reports_db_fixture):
    """REPORT-04: Inactive case assignment is denied with 404."""
    db: Session = reports_db_fixture["SessionLocal"]()
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

    r = client.get(f"/api/v1/cases/{case.id}/report", headers=headers)
    assert r.status_code == 404
    db.close()


def test_reports_api_real_aggregations_and_disclaimer(reports_db_fixture):
    """REPORT-01, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15: Full report aggregation test."""
    db: Session = reports_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    so_user = db.query(User).filter(User.username == "docspector.so").first()
    case = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

    # 1. Ingest Doc 1
    doc1, ver1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="Doc1.pdf",
        content_type="application/pdf",
        title="Document One",
    )

    # 2. Ingest Doc 2
    doc2, ver2, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=io_user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="Doc2.pdf",
        content_type="application/pdf",
        title="Document Two",
    )

    # 3. Create Transfer for Doc 1
    transfer = create_transfer_request(
        db=db,
        document_id=doc1.id,
        version_id=ver1.id,
        requester_user=io_user,
        recipient_user_id=so_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    # 4. Simulate corruption on Doc 2 to generate RESTRICTED state + alert
    file_path = Path(reports_db_fixture["storage_dir"]) / ver2.storage_key
    file_path.write_bytes(TAMPERED_PDF_BYTES)
    verify_document_version_integrity(
        db=db,
        document_id=doc2.id,
        version_id=ver2.id,
        current_user=io_user,
        storage_dir=reports_db_fixture["storage_dir"],
    )

    token = create_access_token(io_user)
    headers = {"Authorization": f"Bearer {token}"}

    # Count database rows before GET
    doc_count_before = db.query(Document).count()
    ver_count_before = db.query(DocumentVersion).count()

    # Execute GET report
    r = client.get(f"/api/v1/cases/{case.id}/report", headers=headers)
    assert r.status_code == 200

    report = r.json()

    # REPORT-14: Disclaimer / Scope
    assert "report_scope" in report
    assert "legal authenticity" in report["report_scope"].lower()

    # REPORT-05: Real Document Counts
    assert report["documents"]["total_documents"] == 2
    assert report["documents"]["total_versions"] == 2

    # REPORT-06: Version State Counts
    assert report["documents"]["by_state"]["STORED"] == 1
    assert report["documents"]["by_state"]["RESTRICTED"] == 1

    # REPORT-07: Transfer Counts
    assert report["transfers"]["total"] == 1
    assert report["transfers"]["APPROVED"] == 1

    # REPORT-08 & 09: Alert & Restricted Counts
    assert report["integrity"]["open_alerts"] >= 1
    assert report["integrity"]["restricted_versions"] == 1

    # REPORT-10 & 11: Custody Event & Chain Status
    assert report["custody"]["total_events"] >= 3
    assert report["integrity"]["custody_chain"]["is_valid"] is True
    assert report["integrity"]["custody_chain"]["status"] == "VALID"

    # REPORT-12: Document Breakdown
    breakdown = report["document_breakdown"]
    assert len(breakdown) == 2
    doc1_item = next(b for b in breakdown if b["document_id"] == doc1.id)
    assert doc1_item["title"] == "Document One"
    assert doc1_item["latest_state"] == "STORED"

    doc2_item = next(b for b in breakdown if b["document_id"] == doc2.id)
    assert doc2_item["latest_state"] == "RESTRICTED"

    # REPORT-13: No private storage key or path in response text
    raw_text = r.text
    assert "storage_key" not in raw_text
    assert settings.storage_dir not in raw_text

    # REPORT-15: Read-only GET did not mutate database
    assert db.query(Document).count() == doc_count_before
    assert db.query(DocumentVersion).count() == ver_count_before
    db.close()


def test_reports_api_cross_case_isolation_security(reports_db_fixture):
    """REPORT-16: CRITICAL SECURITY TEST - Cross-case aggregate isolation.

    Case B data must never leak into Case A's report.
    """
    db: Session = reports_db_fixture["SessionLocal"]()
    client = TestClient(app)

    io_user = db.query(User).filter(User.username == "docspector.io").first()
    unassigned = db.query(User).filter(User.username == "docspector.unassigned").first()
    case_a = db.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()
    case_b = db.query(Case).filter(Case.case_number == "CASE-B-2026-9999").first()

    # Populate Case B with a distinct document and alert
    doc_b, ver_b, _ = register_document_version_one(
        db=db,
        case=case_b,
        current_user=unassigned,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="CaseB_Secret.pdf",
        content_type="application/pdf",
        title="Case B Secret Evidence",
    )

    alert_b = IntegrityAlert(
        case_id=case_b.id,
        document_version_id=ver_b.id,
        alert_type="CASE_B_ALERT",
        severity="CRITICAL",
        message="Case B Secret Alert",
        status="OPEN",
    )
    db.add(alert_b)
    db.commit()

    # User IO has access ONLY to Case A
    token_a = create_access_token(io_user)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    r = client.get(f"/api/v1/cases/{case_a.id}/report", headers=headers_a)
    assert r.status_code == 200
    report_a = r.json()

    # Confirm Case B data does NOT leak into Case A report
    breakdown_ids = [b["document_id"] for b in report_a["document_breakdown"]]
    assert doc_b.id not in breakdown_ids
    assert "CaseB_Secret" not in r.text
    assert "CASE_B_ALERT" not in r.text

    # User IO cannot access Case B report at all (404 non-disclosure)
    r_b_by_a = client.get(f"/api/v1/cases/{case_b.id}/report", headers=headers_a)
    assert r_b_by_a.status_code == 404
    db.close()
