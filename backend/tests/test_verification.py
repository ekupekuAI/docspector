"""Docspector Document & Custody Integrity Verification Tests (Milestone 13).

Inspect. Verify. Trust.

Validates:
- VERIFY-01: Valid stored file + valid custody chain (overall VALID, STORED, 0 alerts).
- VERIFY-02: Modified file bytes on disk detected (FILE_HASH_MISMATCH, RESTRICTED, alert created).
- VERIFY-03: Tampered custody event hash detected (CUSTODY_CHAIN_INVALID, RESTRICTED, alert created).
- VERIFY-04: Corrupted file AND corrupted custody chain detected (both invalid, RESTRICTED).
- VERIFY-05: Missing physical file detected (FILE_MISSING, RESTRICTED, alert created).
- VERIFY-06: Repeated verification of unchanged corruption is idempotent (no duplicate alerts).
- VERIFY-07: RESTRICTED version is never silently restored to STORED on re-verification.
- VERIFY-08: Unauthorized/unassigned user cannot verify inaccessible document (404).
- VERIFY-09: Mismatched document_id and version_id rejected (404).
- VERIFY-10: Approved transfer cannot bypass RESTRICTED state.
- NEGATIVE: Zero auto-repair, zero hash rewriting, strict read-only audit guarantees.
"""

from __future__ import annotations

import io
from pathlib import Path
import tempfile

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, IntegrityAlert, Transfer, User
from app.db.session import get_db
from app.main import app
from app.services.document_registration import register_document_version_one, register_successor_version
from app.services.transfer_service import approve_transfer, can_access_document_version, create_transfer_request
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
TAMPERED_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n%TAMPERED_BYTE_PAYLOAD\n"


@pytest.fixture
def verify_fixture(monkeypatch):
    """Create an isolated test environment for document & custody chain verification."""
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

        session = TestingSessionLocal()
        seed_demo_data(session)

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        unassigned_user = User(
            username="docspector.unassigned",
            display_name="Unassigned Officer",
            role="IO",
            is_active=True,
        )
        session.add(unassigned_user)
        session.commit()

        # Ingest Document A with Version 1
        doc_a, v1, _ = register_document_version_one(
            db=session,
            case=case_1,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Forensic_Doc_A.pdf",
            content_type="application/pdf",
            title="Forensic Document A",
        )

        # Ingest Version 2
        doc_a, v2, _ = register_successor_version(
            db=session,
            document=doc_a,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Forensic_Doc_A_v2.pdf",
            content_type="application/pdf",
        )

        # Dependency override
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
            "v2": v2,
            "io_user": io_user,
            "so_user": so_user,
            "legal_user": legal_user,
            "unassigned_user": unassigned_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
            "legal_token": create_access_token(legal_user),
            "unassigned_token": create_access_token(unassigned_user),
        }

        app.dependency_overrides.clear()
        session.close()
        Base.metadata.drop_all(bind=engine)


# =====================================================================
# CORE VERIFICATION TESTS (VERIFY-01 to VERIFY-10)
# =====================================================================


def test_verify_01_valid_file_and_custody_chain(verify_fixture):
    """VERIFY-01: Valid stored file + valid custody chain."""
    client: TestClient = verify_fixture["client"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "VALID"
    assert data["version_state"] == "STORED"
    assert data["file_integrity"]["is_valid"] is True
    assert data["file_integrity"]["status"] == "VALID"
    assert data["file_integrity"]["stored_hash"] == v1.sha256_hash
    assert data["file_integrity"]["computed_hash"] == v1.sha256_hash
    assert data["chain_integrity"]["is_valid"] is True
    assert data["chain_integrity"]["status"] == "VALID"
    assert len(data["alerts"]) == 0


def test_verify_02_modified_stored_file_bytes(verify_fixture):
    """VERIFY-02: Modify stored file bytes after ingestion -> FILE_HASH_MISMATCH, RESTRICTED, alert."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    storage_dir: Path = verify_fixture["storage_dir"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Tamper with the bytes directly in storage
    file_path = storage_dir / v1.storage_key
    with open(file_path, "wb") as f:
        f.write(TAMPERED_PDF_BYTES)

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "INTEGRITY_FAILURE"
    assert data["version_state"] == "RESTRICTED"
    assert data["file_integrity"]["is_valid"] is False
    assert data["file_integrity"]["status"] == "FILE_HASH_MISMATCH"
    assert data["chain_integrity"]["is_valid"] is True
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_type"] == "FILE_HASH_MISMATCH"
    assert data["alerts"][0]["status"] == "OPEN"

    # Verify DB record state transitioned to RESTRICTED
    db.expire_all()
    reloaded_v1 = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    assert reloaded_v1.state == "RESTRICTED"

    # Verify stored hash was NOT overwritten to match tampered file
    assert reloaded_v1.sha256_hash == v1.sha256_hash


def test_verify_03_tampered_custody_chain(verify_fixture):
    """VERIFY-03: Tampered custody event hash -> CUSTODY_CHAIN_INVALID, RESTRICTED, alert."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Tamper with custody event 1's hash in database
    db.execute(
        text("UPDATE custody_events SET event_hash = 'tamperedhash1234567890abcdef1234567890abcdef1234567890abcdef1234' WHERE case_id = :cid AND sequence_number = 1"),
        {"cid": doc_a.case_id},
    )
    db.commit()

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "INTEGRITY_FAILURE"
    assert data["version_state"] == "RESTRICTED"
    assert data["file_integrity"]["is_valid"] is True
    assert data["chain_integrity"]["is_valid"] is False
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_type"] == "CUSTODY_CHAIN_INVALID"


def test_verify_04_corrupted_file_and_custody_chain(verify_fixture):
    """VERIFY-04: Corrupt both file and custody chain -> both fail, RESTRICTED, 2 alerts."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    storage_dir: Path = verify_fixture["storage_dir"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Corrupt file
    with open(storage_dir / v1.storage_key, "wb") as f:
        f.write(TAMPERED_PDF_BYTES)

    # Corrupt custody event
    db.execute(
        text("UPDATE custody_events SET event_hash = 'corruptchainhash1234567890abcdef1234567890abcdef1234567890abcdef' WHERE case_id = :cid AND sequence_number = 1"),
        {"cid": doc_a.case_id},
    )
    db.commit()

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "INTEGRITY_FAILURE"
    assert data["version_state"] == "RESTRICTED"
    assert data["file_integrity"]["is_valid"] is False
    assert data["chain_integrity"]["is_valid"] is False
    assert len(data["alerts"]) == 2
    alert_types = {a["alert_type"] for a in data["alerts"]}
    assert alert_types == {"FILE_HASH_MISMATCH", "CUSTODY_CHAIN_INVALID"}


def test_verify_05_deleted_physical_file(verify_fixture):
    """VERIFY-05: Delete physical stored file -> FILE_MISSING, RESTRICTED, alert."""
    client: TestClient = verify_fixture["client"]
    storage_dir: Path = verify_fixture["storage_dir"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Delete physical file
    file_path = storage_dir / v1.storage_key
    file_path.unlink()

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "INTEGRITY_FAILURE"
    assert data["version_state"] == "RESTRICTED"
    assert data["file_integrity"]["is_valid"] is False
    assert data["file_integrity"]["status"] == "FILE_MISSING"
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_type"] == "FILE_MISSING"


def test_verify_06_idempotent_alert_creation(verify_fixture):
    """VERIFY-06: Repeated verification against unchanged corruption does not create duplicate alerts."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    storage_dir: Path = verify_fixture["storage_dir"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Corrupt file
    with open(storage_dir / v1.storage_key, "wb") as f:
        f.write(TAMPERED_PDF_BYTES)

    # Run verification 5 times in succession
    for _ in range(5):
        resp = client.post(
            f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
            headers={"Authorization": f"Bearer {io_token}"},
        )
        assert resp.status_code == 200

    # Verify that exactly ONE alert was created in the database
    alerts = (
        db.query(IntegrityAlert)
        .filter(IntegrityAlert.document_version_id == v1.id, IntegrityAlert.alert_type == "FILE_HASH_MISMATCH")
        .all()
    )
    assert len(alerts) == 1


def test_verify_07_restricted_version_never_auto_restored(verify_fixture):
    """VERIFY-07: A RESTRICTED version is never silently restored to STORED even if bytes match."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Manually set version to RESTRICTED (e.g. from previous security audit)
    v1.state = "RESTRICTED"
    db.commit()

    # Verify pristine version
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["file_integrity"]["is_valid"] is True
    assert data["chain_integrity"]["is_valid"] is True
    # Crucial: version_state MUST remain RESTRICTED (no silent restoration)
    assert data["version_state"] == "RESTRICTED"

    reloaded = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    assert reloaded.state == "RESTRICTED"


def test_verify_08_unauthorized_user_cannot_verify(verify_fixture):
    """VERIFY-08: Unauthorized user cannot verify inaccessible document (404 non-disclosure)."""
    client: TestClient = verify_fixture["client"]
    unassigned_token: str = verify_fixture["unassigned_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {unassigned_token}"},
    )
    assert resp.status_code == 404


def test_verify_09_mismatched_document_and_version(verify_fixture):
    """VERIFY-09: Requesting verification with mismatched document_id and version_id returns 404."""
    client: TestClient = verify_fixture["client"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    # Use nonexistent document ID
    resp = client.post(
        f"/api/v1/documents/{doc_a.id + 999}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 404


def test_verify_10_approved_transfer_cannot_bypass_restricted_state(verify_fixture):
    """VERIFY-10: An approved transfer cannot bypass RESTRICTED state."""
    db: Session = verify_fixture["db"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]
    legal_user: User = verify_fixture["legal_user"]
    so_user: User = verify_fixture["so_user"]

    # 1. Create and approve transfer
    transfer = create_transfer_request(
        db=db,
        document_id=doc_a.id,
        version_id=v1.id,
        requester_user=so_user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    # Legal user has access
    assert can_access_document_version(db=db, user=legal_user, version=v1) is True

    # 2. Version becomes RESTRICTED due to tamper
    v1.state = "RESTRICTED"
    db.commit()

    # 3. Transfer access is blocked
    assert can_access_document_version(db=db, user=legal_user, version=v1) is False


def test_negative_no_auto_repair(verify_fixture):
    """NEGATIVE: Verification preserves evidence of tampering without rewriting hashes."""
    client: TestClient = verify_fixture["client"]
    db: Session = verify_fixture["db"]
    storage_dir: Path = verify_fixture["storage_dir"]
    io_token: str = verify_fixture["io_token"]
    doc_a: Document = verify_fixture["doc_a"]
    v1: DocumentVersion = verify_fixture["v1"]

    original_stored_hash = v1.sha256_hash

    # Corrupt file
    with open(storage_dir / v1.storage_key, "wb") as f:
        f.write(TAMPERED_PDF_BYTES)

    client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )

    reloaded = db.query(DocumentVersion).filter(DocumentVersion.id == v1.id).first()
    # Ensure stored expected hash was NOT overwritten with corrupted hash
    assert reloaded.sha256_hash == original_stored_hash
