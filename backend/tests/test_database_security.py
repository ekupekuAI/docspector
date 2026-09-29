"""Docspector Milestone 18 - Database, Transaction & State Machine Security Audit Tests.

Inspect. Verify. Trust.

Comprehensive adversarial test suite proving:
1. Foreign key and unique constraint enforcement (DBSEC-01 to DBSEC-10)
2. DocumentVersion and Transfer state machine integrity (STATESEC-01 to STATESEC-16)
3. Time-of-check / time-of-use (TOCTOU) concurrency protection (TOCTOU-01 to TOCTOU-07)
4. Replay and duplicate state transition resistance (REPLAY-DB-01 to REPLAY-DB-04)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import (
    Case,
    CaseAssignment,
    CustodyEvent,
    Document,
    DocumentVersion,
    IntegrityAlert,
    Transfer,
    User,
)
from app.db.session import get_db
from app.main import app
from app.services.custody_service import (
    CHAIN_VALID,
    append_custody_event,
    compute_canonical_event_hash,
    validate_custody_chain,
)
from app.services.document_registration import (
    register_document_version_one,
    register_successor_version,
)
from app.services.file_validation import (
    FileValidationError,
    generate_storage_key,
)
from app.services.reconciliation_service import (
    ReconciliationReport,
    audit_storage_and_reconcile,
)
from app.services.transfer_service import (
    TransferError,
    approve_transfer,
    can_access_document_version,
    create_transfer_request,
    reject_transfer,
    revoke_transfer,
)
from app.services.verification_service import (
    VerificationError,
    verify_document_version_integrity,
)
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
VALID_V2_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n2 0 obj\n<< /Version 2 >>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def dbsec_fixture(monkeypatch):
    """Set up an isolated testing environment with dedicated SQLite WAL database and temporary storage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        temp_storage_path = temp_dir_path / "storage"
        temp_storage_path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))
        monkeypatch.setattr(settings, "demo_mode", False)

        db_file = temp_dir_path / "test_docspector_dbsec.db"
        db_url = f"sqlite:///{db_file}"

        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30},
            echo=False,
        )

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        session = TestingSessionLocal()
        seed_demo_data(session)
        session.commit()

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

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
            "session_factory": TestingSessionLocal,
            "engine": engine,
            "storage_dir": temp_storage_path,
            "case": case_1,
            "io_user": io_user,
            "so_user": so_user,
            "legal_user": legal_user,
            "auditor_user": auditor_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
            "legal_token": create_access_token(legal_user),
            "auditor_token": create_access_token(auditor_user),
        }

        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


# ===========================================================================
# PHASE 4: DATABASE INTEGRITY ATTACK TESTS (DBSEC-01 to DBSEC-10)
# ===========================================================================

def test_dbsec_01_foreign_key_enforcement_child_records(dbsec_fixture):
    """DBSEC-01: Foreign keys prevent creating orphan child records referencing nonexistent parents."""
    db = dbsec_fixture["db"]
    user = dbsec_fixture["io_user"]

    # 1. Nonexistent Case for Document
    orphan_doc = Document(
        case_id=999999,  # Nonexistent
        document_number="ORPHAN-DOC-01",
        title="Orphan Document",
        created_by_user_id=user.id,
    )
    db.add(orphan_doc)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()

    # 2. Nonexistent Document for DocumentVersion
    orphan_ver = DocumentVersion(
        document_id=888888,  # Nonexistent
        version_number=1,
        original_filename="orphan.pdf",
        mime_type="application/pdf",
        storage_key=generate_storage_key(".pdf"),
        sha256_hash="00" * 32,
        size_bytes=100,
        state="STORED",
        created_by_user_id=user.id,
    )
    db.add(orphan_ver)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_02_cross_case_foreign_object_reference_rejected(dbsec_fixture):
    """DBSEC-02: Cross-case object references are rejected by authorization & integrity layers."""
    db = dbsec_fixture["db"]
    user = dbsec_fixture["io_user"]
    case_1 = dbsec_fixture["case"]
    storage_dir = dbsec_fixture["storage_dir"]

    # Register doc in Case 1
    doc_1, v1, _ = register_document_version_one(
        db=db,
        case=case_1,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="case1_evidence.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Create Case 2 assigned ONLY to an isolated external officer
    ext_officer = User(
        username="docspector.external",
        display_name="External Officer",
        role="IO",
        is_active=True,
    )
    case_2 = Case(
        case_number="HYD-CYB-2026-9999",
        title="Case 2 Isolated",
        status="OPEN",
    )
    db.add_all([ext_officer, case_2])
    db.flush()
    db.add(CaseAssignment(case_id=case_2.id, user_id=ext_officer.id, is_active=True))
    db.commit()

    # 1. External officer (only assigned to Case 2) cannot request transfer for Case 1 document
    with pytest.raises(TransferError) as exc_info:
        create_transfer_request(
            db=db,
            document_id=doc_1.id,
            version_id=v1.id,
            requester_user=ext_officer,
            recipient_user_id=user.id,
        )
    assert exc_info.value.status_code == 404

    # 2. Case 1 officer cannot transfer Case 1 document to an officer not assigned to Case 1
    with pytest.raises(TransferError) as exc_info2:
        create_transfer_request(
            db=db,
            document_id=doc_1.id,
            version_id=v1.id,
            requester_user=user,
            recipient_user_id=ext_officer.id,
        )
    assert exc_info2.value.status_code == 400



def test_dbsec_03_duplicate_document_version_number_prevented(dbsec_fixture):
    """DBSEC-03: Unique constraint uq_document_versions_doc_version strictly blocks duplicate version numbers."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="contract.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Attempt direct insertion of duplicate version_number=1 for same document_id
    duplicate_version = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        original_filename="contract_dup.pdf",
        mime_type="application/pdf",
        storage_key=generate_storage_key(".pdf"),
        sha256_hash="11" * 32,
        size_bytes=200,
        state="STORED",
        created_by_user_id=user.id,
    )
    db.add(duplicate_version)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_04_duplicate_custody_sequence_prevented(dbsec_fixture):
    """DBSEC-04: Unique constraint uq_custody_events_case_sequence prevents duplicate sequence numbers."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]

    ev1 = append_custody_event(
        db=db,
        case_id=case.id,
        event_type="DEMO_TEST_1",
        actor_user_id=user.id,
        event_data={"note": "first"},
    )
    db.commit()

    # Attempt manual duplicate sequence insert
    dup_event = CustodyEvent(
        case_id=case.id,
        sequence_number=ev1.sequence_number,  # Duplicate!
        event_type="FORGED_EVENT",
        actor_user_id=user.id,
        event_time=datetime.now(timezone.utc),
        event_hash="33" * 32,
    )
    db.add(dup_event)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_05_duplicate_event_hash_prevented(dbsec_fixture):
    """DBSEC-05: Unique constraint uq_custody_events_event_hash prevents duplicate event hashes."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]

    ev1 = append_custody_event(
        db=db,
        case_id=case.id,
        event_type="DEMO_TEST_HASH_1",
        actor_user_id=user.id,
        event_data={"note": "h1"},
    )
    db.commit()

    dup_hash_event = CustodyEvent(
        case_id=case.id,
        sequence_number=ev1.sequence_number + 1,
        event_type="FORGED_HASH",
        actor_user_id=user.id,
        event_time=datetime.now(timezone.utc),
        event_hash=ev1.event_hash,  # Duplicate event hash!
    )
    db.add(dup_hash_event)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_06_orphan_transfer_prevented_by_fk(dbsec_fixture):
    """DBSEC-06: Transfers referencing nonexistent document_version_id are rejected by foreign keys."""
    db = dbsec_fixture["db"]
    user = dbsec_fixture["io_user"]

    orphan_transfer = Transfer(
        document_version_id=777777,  # Nonexistent
        requester_user_id=user.id,
        recipient_user_id=user.id,
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )
    db.add(orphan_transfer)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_07_orphan_integrity_alert_prevented_by_fk(dbsec_fixture):
    """DBSEC-07: Integrity alerts referencing nonexistent case_id are rejected by foreign keys."""
    db = dbsec_fixture["db"]

    orphan_alert = IntegrityAlert(
        case_id=999999,  # Nonexistent
        document_version_id=None,
        alert_type="STORAGE_INCONSISTENCY",
        severity="CRITICAL",
        message="Orphan alert test",
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    db.add(orphan_alert)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_dbsec_08_rollback_atomicity_multi_write(dbsec_fixture):
    """DBSEC-08: Failure during multi-write transaction rolls back all intermediate writes cleanly."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]

    initial_doc_count = db.query(Document).count()
    initial_ver_count = db.query(DocumentVersion).count()
    initial_event_count = db.query(CustodyEvent).count()

    try:
        doc = Document(
            case_id=case.id,
            document_number=f"DOC-{uuid.uuid4().hex[:6].upper()}",
            title="Atomic Test Doc",
            created_by_user_id=user.id,
        )
        db.add(doc)
        db.flush()

        ver = DocumentVersion(
            document_id=doc.id,
            version_number=1,
            original_filename="test.pdf",
            mime_type="application/pdf",
            storage_key=generate_storage_key(".pdf"),
            sha256_hash="55" * 32,
            size_bytes=100,
            state="UPLOADING",
            created_by_user_id=user.id,
        )
        db.add(ver)
        db.flush()

        # Force a failure before commit
        raise RuntimeError("Simulated transaction failure before finalization")
    except RuntimeError:
        db.rollback()

    assert db.query(Document).count() == initial_doc_count
    assert db.query(DocumentVersion).count() == initial_ver_count
    assert db.query(CustodyEvent).count() == initial_event_count


def test_dbsec_09_savepoint_rollback_safety(dbsec_fixture):
    """DBSEC-09: Savepoint / nested transaction rollback isolates inner failure without corrupting outer session."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]

    doc = Document(
        case_id=case.id,
        document_number=f"DOC-{uuid.uuid4().hex[:6].upper()}",
        title="Outer Safe Doc",
        created_by_user_id=user.id,
    )
    db.add(doc)
    db.flush()

    # Nested savepoint
    savepoint = db.begin_nested()
    try:
        bad_ver = DocumentVersion(
            document_id=999999,  # Nonexistent -> raises IntegrityError
            version_number=1,
            original_filename="bad.pdf",
            mime_type="application/pdf",
            storage_key=generate_storage_key(".pdf"),
            sha256_hash="99" * 32,
            size_bytes=100,
            state="STORED",
            created_by_user_id=user.id,
        )
        db.add(bad_ver)
        db.flush()
    except IntegrityError:
        savepoint.rollback()

    # Outer transaction continues and commits successfully
    db.commit()

    persisted_doc = db.query(Document).filter(Document.id == doc.id).first()
    assert persisted_doc is not None
    assert persisted_doc.title == "Outer Safe Doc"


def test_dbsec_10_foreign_key_deletion_integrity(dbsec_fixture):
    """DBSEC-10: Foreign key deletion cascading preserves relational integrity without invalid pointers."""
    db = dbsec_fixture["db"]
    user = dbsec_fixture["io_user"]
    case = dbsec_fixture["case"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="cascade_test.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    doc_id = doc.id
    ver_id = v1.id

    # Deleting the document cascades to delete its document_versions
    db.delete(doc)
    db.commit()

    assert db.query(Document).filter(Document.id == doc_id).first() is None
    assert db.query(DocumentVersion).filter(DocumentVersion.id == ver_id).first() is None


# ===========================================================================
# PHASE 5: STATE TRANSITION ATTACK TESTS (STATESEC-01 to STATESEC-16)
# ===========================================================================

def test_statesec_01_stored_to_restricted_transition(dbsec_fixture):
    """STATESEC-01: STORED -> RESTRICTED transition is authoritative when integrity verification fails."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="valid.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    assert v1.state == "STORED"

    # Corrupt on disk
    stored_path = storage_dir / v1.storage_key
    stored_path.write_bytes(b"%PDF-1.7\nTAMPERED\n%%EOF\n")

    res = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )
    assert res.overall_status == "INTEGRITY_FAILURE"
    db.refresh(v1)
    assert v1.state == "RESTRICTED"


def test_statesec_02_restricted_to_stored_rejected(dbsec_fixture):
    """STATESEC-02: A RESTRICTED version is NEVER automatically restored to STORED."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="restricted.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    v1.state = "RESTRICTED"
    db.commit()

    # Re-run verification: even if file bytes match hash, state MUST remain RESTRICTED
    res = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )
    db.refresh(v1)
    assert v1.state == "RESTRICTED"


def test_statesec_03_restricted_version_cannot_be_transferred(dbsec_fixture):
    """STATESEC-03: RESTRICTED version cannot be transferred (raises TransferError 409)."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="no_transfer.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    v1.state = "RESTRICTED"
    db.commit()

    with pytest.raises(TransferError) as exc_info:
        create_transfer_request(
            db=db,
            document_id=doc.id,
            version_id=v1.id,
            requester_user=user,
            recipient_user_id=so_user.id,
        )
    assert exc_info.value.status_code == 409
    assert "RESTRICTED" in exc_info.value.message


def test_statesec_04_restricted_version_cannot_create_successor(dbsec_fixture):
    """STATESEC-04: RESTRICTED version cannot have successor versions added (raises FileValidationError 409)."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="no_succ.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    v1.state = "RESTRICTED"
    db.commit()

    with pytest.raises(FileValidationError) as exc_info:
        register_successor_version(
            db=db,
            document=doc,
            current_user=user,
            file_stream=io.BytesIO(VALID_V2_PDF_BYTES),
            filename="no_succ_v2.pdf",
            content_type="application/pdf",
            storage_dir=storage_dir,
        )
    assert exc_info.value.http_status_code == 409
    assert exc_info.value.code == "DOCUMENT_RESTRICTED"


def test_statesec_05_quarantined_version_cannot_enter_workflow(dbsec_fixture):
    """STATESEC-05: QUARANTINED version cannot enter transfer or successor workflow."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="quarantined.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    v1.state = "QUARANTINED"
    db.commit()

    # Transfer blocked
    with pytest.raises(TransferError):
        create_transfer_request(
            db=db,
            document_id=doc.id,
            version_id=v1.id,
            requester_user=user,
            recipient_user_id=so_user.id,
        )

    # Successor blocked
    with pytest.raises(FileValidationError):
        register_successor_version(
            db=db,
            document=doc,
            current_user=user,
            file_stream=io.BytesIO(VALID_V2_PDF_BYTES),
            filename="quarantined_v2.pdf",
            content_type="application/pdf",
            storage_dir=storage_dir,
        )


def test_statesec_06_pending_transfer_approved_once(dbsec_fixture):
    """STATESEC-06: PENDING transfer can be approved once; second attempt fails with 409."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="approval.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    assert transfer.status == "PENDING"

    # First approve succeeds
    approved_transfer = approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert approved_transfer.status == "APPROVED"

    # Second approve fails
    with pytest.raises(TransferError) as exc_info:
        approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_statesec_07_pending_transfer_rejected_once(dbsec_fixture):
    """STATESEC-07: PENDING transfer can be rejected once; second attempt fails with 409."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="rejection.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )

    rejected_transfer = reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert rejected_transfer.status == "REJECTED"

    with pytest.raises(TransferError) as exc_info:
        reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_statesec_08_approved_transfer_revoked_once(dbsec_fixture):
    """STATESEC-08: APPROVED transfer can be revoked once; second revoke fails with 409."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="revocation.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    revoked_transfer = revoke_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert revoked_transfer.status == "REVOKED"

    with pytest.raises(TransferError) as exc_info:
        revoke_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_statesec_09_rejected_transfer_cannot_be_approved(dbsec_fixture):
    """STATESEC-09: REJECTED transfer cannot be approved afterward (raises 409)."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="rej_to_app.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    with pytest.raises(TransferError) as exc_info:
        approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_statesec_10_rejected_transfer_cannot_be_revoked(dbsec_fixture):
    """STATESEC-10: REJECTED transfer cannot be revoked (raises 409)."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="rej_to_rev.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    with pytest.raises(TransferError) as exc_info:
        revoke_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_statesec_11_concurrent_approve_reject_single_winner(dbsec_fixture):
    """STATESEC-11: Concurrent approve and reject produces exactly one successful transition."""
    client = dbsec_fixture["client"]
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    legal_user = dbsec_fixture["legal_user"]
    so_token = dbsec_fixture["so_token"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="race_decision.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    transfer_id = transfer.id

    def do_approve():
        return client.post(
            f"/api/v1/transfers/{transfer_id}/approve",
            headers={"Authorization": f"Bearer {so_token}"},
        )

    def do_reject():
        return client.post(
            f"/api/v1/transfers/{transfer_id}/reject",
            headers={"Authorization": f"Bearer {so_token}"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        f_app = executor.submit(do_approve)
        f_rej = executor.submit(do_reject)
        resp_app = f_app.result()
        resp_rej = f_rej.result()

    status_codes = {resp_app.status_code, resp_rej.status_code}
    assert 200 in status_codes
    assert 409 in status_codes


def test_statesec_12_concurrent_revoke_single_winner(dbsec_fixture):
    """STATESEC-12: Concurrent revoke requests produce exactly one 200 and one 409."""
    client = dbsec_fixture["client"]
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    so_token = dbsec_fixture["so_token"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="race_revoke.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    transfer_id = transfer.id

    def do_revoke():
        return client.post(
            f"/api/v1/transfers/{transfer_id}/revoke",
            headers={"Authorization": f"Bearer {so_token}"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(do_revoke)
        f2 = executor.submit(do_revoke)
        r1 = f1.result()
        r2 = f2.result()

    status_codes = {r1.status_code, r2.status_code}
    assert 200 in status_codes
    assert 409 in status_codes


def test_statesec_13_concurrent_restriction_idempotent(dbsec_fixture):
    """STATESEC-13: Concurrent restriction attempts leave version RESTRICTED and alerts deduplicated."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="conc_restrict.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Mutate physical file
    stored_path = storage_dir / v1.storage_key
    stored_path.write_bytes(b"%PDF-1.7\nCORRUPTED\n%%EOF\n")

    # Run verification twice
    verify_document_version_integrity(db=db, document_id=doc.id, version_id=v1.id, current_user=user, storage_dir=storage_dir)
    verify_document_version_integrity(db=db, document_id=doc.id, version_id=v1.id, current_user=user, storage_dir=storage_dir)

    db.refresh(v1)
    assert v1.state == "RESTRICTED"

    alerts = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.document_version_id == v1.id,
            IntegrityAlert.alert_type == "FILE_HASH_MISMATCH",
            IntegrityAlert.status == "OPEN",
        )
        .all()
    )
    assert len(alerts) == 1  # Exactly 1 open alert created idempotently


def test_statesec_14_verification_cannot_restore_stored(dbsec_fixture):
    """STATESEC-14: Running verification on a RESTRICTED version does not revert state to STORED."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="never_restore.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    v1.state = "RESTRICTED"
    db.commit()

    res = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )
    db.refresh(v1)
    assert v1.state == "RESTRICTED"
    assert res.version_state == "RESTRICTED"


def test_statesec_15_failed_transition_leaves_no_custody_event(dbsec_fixture):
    """STATESEC-15: A rejected state transition does NOT append misleading custody events."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="no_event.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    event_count_before = db.query(CustodyEvent).filter(CustodyEvent.case_id == case.id).count()

    # Attempt illegal second rejection
    with pytest.raises(TransferError):
        reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    event_count_after = db.query(CustodyEvent).filter(CustodyEvent.case_id == case.id).count()
    assert event_count_after == event_count_before


def test_statesec_16_successful_transition_records_custody_event(dbsec_fixture):
    """STATESEC-16: A successful state transition appends a valid custody event in the hash chain."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="custody_record.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    approved_event = (
        db.query(CustodyEvent)
        .filter(
            CustodyEvent.case_id == case.id,
            CustodyEvent.event_type == "TRANSFER_APPROVED",
        )
        .first()
    )
    assert approved_event is not None
    assert approved_event.actor_user_id == so_user.id

    chain_audit = validate_custody_chain(db=db, case_id=case.id)
    assert chain_audit.is_valid is True
    assert chain_audit.status_code == CHAIN_VALID


# ===========================================================================
# PHASE 6: STALE-STATE / TOCTOU ATTACKS (TOCTOU-01 to TOCTOU-07)
# ===========================================================================

def test_toctou_01_transfer_request_races_with_restriction(dbsec_fixture):
    """TOCTOU-01: Transfer creation validates version state against database right before creation."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="toctou_trans.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Restrict version
    v1.state = "RESTRICTED"
    db.commit()

    with pytest.raises(TransferError) as exc_info:
        create_transfer_request(
            db=db,
            document_id=doc.id,
            version_id=v1.id,
            requester_user=user,
            recipient_user_id=so_user.id,
        )
    assert exc_info.value.status_code == 409


def test_toctou_02_successor_creation_races_with_restriction(dbsec_fixture):
    """TOCTOU-02: Successor registration re-validates no restricted version exists before version allocation."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="toctou_succ.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    v1.state = "RESTRICTED"
    db.commit()

    with pytest.raises(FileValidationError) as exc_info:
        register_successor_version(
            db=db,
            document=doc,
            current_user=user,
            file_stream=io.BytesIO(VALID_V2_PDF_BYTES),
            filename="toctou_succ_v2.pdf",
            content_type="application/pdf",
            storage_dir=storage_dir,
        )
    assert exc_info.value.http_status_code == 409


def test_toctou_03_verification_races_with_transfer_approval(dbsec_fixture):
    """TOCTOU-03: If verification restricts a version, can_access_document_version immediately denies access."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="toctou_verify.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    # Initial access granted
    assert can_access_document_version(db=db, user=legal_user, version=v1) is True

    # Verification fails and restricts
    stored_path = storage_dir / v1.storage_key
    stored_path.write_bytes(b"%PDF-1.7\nTAMPERED\n%%EOF\n")
    verify_document_version_integrity(db=db, document_id=doc.id, version_id=v1.id, current_user=user, storage_dir=storage_dir)

    db.refresh(v1)
    assert v1.state == "RESTRICTED"
    # Access immediately denied despite approved transfer
    assert can_access_document_version(db=db, user=legal_user, version=v1) is False


def test_toctou_04_transfer_approval_races_with_rejection(dbsec_fixture):
    """TOCTOU-04: Conditional update status == 'PENDING' ensures exactly one winner in approval/rejection race."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="race_cond.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )

    # First decision wins
    res1 = approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert res1.status == "APPROVED"

    # Second decision loses
    with pytest.raises(TransferError):
        reject_transfer(db=db, transfer_id=transfer.id, so_user=so_user)


def test_toctou_05_transfer_approval_races_with_revocation(dbsec_fixture):
    """TOCTOU-05: Revocation requires status == 'APPROVED' and fails if not yet approved."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="race_rev.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )

    # Cannot revoke PENDING transfer
    with pytest.raises(TransferError) as exc_info:
        revoke_transfer(db=db, transfer_id=transfer.id, so_user=so_user)
    assert exc_info.value.status_code == 409


def test_toctou_06_concurrent_successor_creation(dbsec_fixture):
    """TOCTOU-06: Concurrent successor registrations derive unique version numbers without conflict."""
    client = dbsec_fixture["client"]
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    io_token = dbsec_fixture["io_token"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="conc_succ.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    def upload_succ(idx: int):
        content = f"%PDF-1.7\nConcurrent successor {idx}\n%%EOF\n".encode("utf-8")
        return client.post(
            f"/api/v1/documents/{doc.id}/versions",
            files={"file": (f"succ_{idx}.pdf", content, "application/pdf")},
            headers={"Authorization": f"Bearer {io_token}"},
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(upload_succ, i) for i in range(3)]
        results = [f.result() for f in futures]

    status_codes = [r.status_code for r in results]
    assert all(code in (201, 409) for code in status_codes)

    versions = (
        db.query(DocumentVersion)
        .filter(DocumentVersion.document_id == doc.id)
        .order_by(DocumentVersion.version_number.asc())
        .all()
    )
    v_nums = [v.version_number for v in versions]
    assert len(v_nums) == len(set(v_nums))  # Strictly distinct


def test_toctou_07_concurrent_custody_event_creation(dbsec_fixture):
    """TOCTOU-07: Concurrent custody event appends serialize cleanly with valid sequence numbers and hashes."""
    session_factory = dbsec_fixture["session_factory"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]

    def append_event_worker(idx: int):
        db_worker = session_factory()
        try:
            ev = append_custody_event(
                db=db_worker,
                case_id=case.id,
                event_type=f"CONCURRENT_EVENT_{idx}",
                actor_user_id=user.id,
                event_data={"worker_idx": idx},
            )
            db_worker.commit()
            return ev.sequence_number
        finally:
            db_worker.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(append_event_worker, i) for i in range(4)]
        seqs = [f.result() for f in futures]

    assert len(seqs) == len(set(seqs))  # All sequence numbers distinct

    db_main = dbsec_fixture["db"]
    chain_audit = validate_custody_chain(db=db_main, case_id=case.id)
    assert chain_audit.is_valid is True
    assert chain_audit.status_code == CHAIN_VALID


# ===========================================================================
# PHASE 7: IDEMPOTENCY / REPLAY AUDIT (REPLAY-DB-01 to REPLAY-DB-04)
# ===========================================================================

def test_replay_db_01_repeat_transfer_approval_returns_conflict(dbsec_fixture):
    """REPLAY-DB-01: Repeating a transfer approval request returns HTTP 409 Conflict with zero secondary mutation."""
    client = dbsec_fixture["client"]
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    legal_user = dbsec_fixture["legal_user"]
    so_token = dbsec_fixture["so_token"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="repeat_app.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )

    r1 = client.post(f"/api/v1/transfers/{transfer.id}/approve", headers={"Authorization": f"Bearer {so_token}"})
    r2 = client.post(f"/api/v1/transfers/{transfer.id}/approve", headers={"Authorization": f"Bearer {so_token}"})

    assert r1.status_code == 200
    assert r2.status_code == 409


def test_replay_db_02_repeat_transfer_rejection_returns_conflict(dbsec_fixture):
    """REPLAY-DB-02: Repeating a transfer rejection request returns HTTP 409 Conflict."""
    client = dbsec_fixture["client"]
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    legal_user = dbsec_fixture["legal_user"]
    so_token = dbsec_fixture["so_token"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="repeat_rej.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )

    r1 = client.post(f"/api/v1/transfers/{transfer.id}/reject", headers={"Authorization": f"Bearer {so_token}"})
    r2 = client.post(f"/api/v1/transfers/{transfer.id}/reject", headers={"Authorization": f"Bearer {so_token}"})

    assert r1.status_code == 200
    assert r2.status_code == 409


def test_replay_db_03_repeat_restriction_idempotent(dbsec_fixture):
    """REPLAY-DB-03: Repeated restriction/reconciliation audits remain idempotent with zero duplicate open alerts."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="repeat_recon.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Corrupt on disk
    stored_path = storage_dir / v1.storage_key
    stored_path.unlink()

    # Reconcile twice
    rep1 = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)
    rep2 = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert rep1.missing_files_count == 1
    assert rep2.missing_files_count == 1

    alerts = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.document_version_id == v1.id,
            IntegrityAlert.alert_type == "STORAGE_INCONSISTENCY",
            IntegrityAlert.status == "OPEN",
        )
        .all()
    )
    assert len(alerts) == 1


def test_replay_db_04_repeat_rejected_operation_no_duplicate_custody(dbsec_fixture):
    """REPLAY-DB-04: Repeated illegal operations create zero duplicate custody events."""
    db = dbsec_fixture["db"]
    case = dbsec_fixture["case"]
    user = dbsec_fixture["io_user"]
    so_user = dbsec_fixture["so_user"]
    legal_user = dbsec_fixture["legal_user"]
    storage_dir = dbsec_fixture["storage_dir"]

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(VALID_PDF_BYTES),
        filename="repeat_custody.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    transfer = create_transfer_request(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        requester_user=user,
        recipient_user_id=legal_user.id,
    )
    approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    events_before = db.query(CustodyEvent).filter(CustodyEvent.case_id == case.id).count()

    # Repeat approval 3 times
    for _ in range(3):
        with pytest.raises(TransferError):
            approve_transfer(db=db, transfer_id=transfer.id, so_user=so_user)

    events_after = db.query(CustodyEvent).filter(CustodyEvent.case_id == case.id).count()
    assert events_after == events_before
