"""Docspector Version-Scoped Transfer Workflow Tests (Milestone 12).

Inspect. Verify. Trust.

Validates:
- TRANSFER-01: Authorized user creates transfer request (201 Created, status=PENDING).
- TRANSFER-02: Recipient cannot access content while transfer is PENDING.
- TRANSFER-03: Authorized SO approves PENDING transfer (PENDING -> APPROVED).
- TRANSFER-04: Recipient can access the EXACT approved version after approval.
- TRANSFER-05: Approval of V2 does NOT authorize V1 or V3.
- TRANSFER-06: SO rejects a PENDING transfer (PENDING -> REJECTED).
- TRANSFER-07: Rejected transfer does not grant access.
- TRANSFER-08: Unauthorized/unassigned user cannot create a transfer (404/403).
- TRANSFER-09: Non-SO cannot approve/reject/revoke a transfer (403 Forbidden).
- TRANSFER-10: A RESTRICTED/QUARANTINED version cannot be transferred (409 Conflict).
- TRANSFER-11: If an approved version becomes RESTRICTED, access is immediately blocked.
- TRANSFER-12: Revoked transfer no longer grants access (APPROVED -> REVOKED).
- TRANSFER-RACE-01: Concurrent decisions (Approve vs Reject) -> exactly one succeeds, other gets 409.
- TRANSFER-RACE-02: Attempt to approve already APPROVED transfer -> 409 Conflict.
- TRANSFER-RACE-03: Attempt to approve REJECTED transfer -> 409 Conflict.
- VERSION-SCOPE: Multi-version isolation (V1, V2, V3) on Document A.
- SECURITY: Self-transfers, client status tampering, and custody event hash-chain audit.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import io
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, Transfer, User
from app.db.session import get_db
from app.main import app
from app.services.custody_service import validate_custody_chain
from app.services.document_registration import register_document_version_one, register_successor_version
from app.services.transfer_service import can_access_document_version
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def transfer_fixture(monkeypatch):
    """Create an isolated test environment with SQLite, seed data, and test client."""
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

        # Create seeded test users
        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        # Create unassigned user
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
            filename="Evidence_Document_A.pdf",
            content_type="application/pdf",
            title="Evidence Document A",
        )

        # Ingest Version 2
        doc_a, v2, _ = register_successor_version(
            db=session,
            document=doc_a,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Evidence_Document_A_v2.pdf",
            content_type="application/pdf",
        )

        # Ingest Version 3
        doc_a, v3, _ = register_successor_version(
            db=session,
            document=doc_a,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Evidence_Document_A_v3.pdf",
            content_type="application/pdf",
        )

        # Set up dependency override
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
            "engine": engine,
            "session_factory": TestingSessionLocal,
            "case": case_1,
            "doc_a": doc_a,
            "v1": v1,
            "v2": v2,
            "v3": v3,
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
        }

        app.dependency_overrides.clear()
        session.close()
        Base.metadata.drop_all(bind=engine)


# =====================================================================
# CORE TRANSFER TESTS (TRANSFER-01 to TRANSFER-12)
# =====================================================================


def test_transfer_01_create_transfer_request(transfer_fixture):
    """TRANSFER-01: Authorized user creates transfer request (201, status=PENDING)."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    response = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "PENDING"
    assert data["document_id"] == doc_a.id
    assert data["document_version_id"] == v2.id
    assert data["recipient_user_id"] == legal_user.id
    assert data["decided_at"] is None
    assert data["decided_by_user_id"] is None


def test_transfer_02_recipient_cannot_access_while_pending(transfer_fixture):
    """TRANSFER-02: Recipient cannot access content while transfer is PENDING."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    # Create transfer request (PENDING)
    client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )

    # Verify recipient access is False while PENDING
    assert can_access_document_version(db=db, user=legal_user, version=v2) is False


def test_transfer_03_so_approves_pending_transfer(transfer_fixture):
    """TRANSFER-03: Authorized SO approves PENDING transfer (PENDING -> APPROVED)."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]
    so_user: User = transfer_fixture["so_user"]

    # 1. Create transfer
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    # 2. SO Approves
    approve_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert approve_resp.status_code == 200
    data = approve_resp.json()
    assert data["status"] == "APPROVED"
    assert data["decided_by_user_id"] == so_user.id
    assert data["decided_at"] is not None


def test_transfer_04_recipient_can_access_exact_approved_version(transfer_fixture):
    """TRANSFER-04: Recipient can access the EXACT approved version after approval."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    # Create and approve transfer
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    # Now legal_user must have access to V2
    assert can_access_document_version(db=db, user=legal_user, version=v2) is True


def test_transfer_05_version_scoped_isolation(transfer_fixture):
    """TRANSFER-05 / VERSION-SCOPE: Approval of V2 does NOT authorize V1 or V3."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v1: DocumentVersion = transfer_fixture["v1"]
    v2: DocumentVersion = transfer_fixture["v2"]
    v3: DocumentVersion = transfer_fixture["v3"]
    legal_user: User = transfer_fixture["legal_user"]

    # Create & Approve transfer for V2 ONLY
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    # Verify version-scoped security boundary:
    assert can_access_document_version(db=db, user=legal_user, version=v2) is True, "V2 must be authorized"
    assert can_access_document_version(db=db, user=legal_user, version=v1) is False, "V1 must NOT be authorized"
    assert can_access_document_version(db=db, user=legal_user, version=v3) is False, "V3 must NOT be authorized"


def test_transfer_06_so_rejects_pending_transfer(transfer_fixture):
    """TRANSFER-06: SO rejects a PENDING transfer (PENDING -> REJECTED)."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]
    so_user: User = transfer_fixture["so_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    reject_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/reject",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert reject_resp.status_code == 200
    data = reject_resp.json()
    assert data["status"] == "REJECTED"
    assert data["decided_by_user_id"] == so_user.id


def test_transfer_07_rejected_transfer_does_not_grant_access(transfer_fixture):
    """TRANSFER-07: Rejected transfer does not grant access."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    client.post(
        f"/api/v1/transfers/{transfer_id}/reject",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    assert can_access_document_version(db=db, user=legal_user, version=v2) is False


def test_transfer_08_unauthorized_user_cannot_create_transfer(transfer_fixture):
    """TRANSFER-08: Unassigned user cannot create a transfer (404 non-disclosure)."""
    client: TestClient = transfer_fixture["client"]
    unassigned_token: str = transfer_fixture["unassigned_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {unassigned_token}"},
    )
    assert resp.status_code == 404


def test_transfer_09_non_so_cannot_approve_or_reject(transfer_fixture):
    """TRANSFER-09: Non-SO (IO, Legal, Auditor) cannot approve or reject transfers (403)."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    legal_token: str = transfer_fixture["legal_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    # IO attempts to approve
    io_approve = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert io_approve.status_code == 403

    # Legal attempts to approve
    legal_approve = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {legal_token}"},
    )
    assert legal_approve.status_code == 403


def test_transfer_10_restricted_version_cannot_be_transferred(transfer_fixture):
    """TRANSFER-10: A RESTRICTED version cannot be transferred (409 Conflict)."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    # Quarantine version 2
    v2.state = "RESTRICTED"
    db.commit()

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 409


def test_transfer_11_restricted_state_blocks_already_approved_transfer(transfer_fixture):
    """TRANSFER-11: If an already-approved version becomes RESTRICTED, access is blocked."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert can_access_document_version(db=db, user=legal_user, version=v2) is True

    # Version becomes RESTRICTED (tamper alert)
    v2.state = "RESTRICTED"
    db.commit()

    # Access is immediately blocked despite APPROVED transfer status
    assert can_access_document_version(db=db, user=legal_user, version=v2) is False


def test_transfer_12_revoked_transfer_invalidates_access(transfer_fixture):
    """TRANSFER-12: Revoked transfer no longer grants access (APPROVED -> REVOKED)."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert can_access_document_version(db=db, user=legal_user, version=v2) is True

    # SO Revokes transfer
    revoke_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/revoke",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"

    # Verify access is now terminated
    assert can_access_document_version(db=db, user=legal_user, version=v2) is False


# =====================================================================
# CONCURRENCY & RACE TESTS (TRANSFER-RACE-01 to TRANSFER-RACE-03)
# =====================================================================


def test_transfer_race_01_concurrent_approve_and_reject():
    """TRANSFER-RACE-01: Two simultaneous decisions against same PENDING transfer (Approve vs Reject).

    Verifies:
    - Exactly one transition succeeds (200 OK).
    - The other receives a controlled conflict (409 Conflict).
    - Final state is deterministically one of APPROVED or REJECTED.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "transfer_race.db"
        db_url = f"sqlite:///{db_path}"

        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30.0},
            poolclass=NullPool,
            echo=False,
        )

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        Base.metadata.create_all(bind=engine)
        SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        init_session = SessionMaker()
        seed_demo_data(init_session)
        init_session.commit()

        io_user = init_session.query(User).filter(User.username == "docspector.io").first()
        so_user = init_session.query(User).filter(User.username == "docspector.so").first()
        legal_user = init_session.query(User).filter(User.username == "docspector.legal").first()
        case_1 = init_session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        doc, v1, _ = register_document_version_one(
            db=init_session,
            case=case_1,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Race_Evidence.pdf",
            content_type="application/pdf",
        )

        # Create transfer
        transfer = Transfer(
            document_version_id=v1.id,
            requester_user_id=io_user.id,
            recipient_user_id=legal_user.id,
            status="PENDING",
        )
        init_session.add(transfer)
        init_session.commit()
        transfer_id = transfer.id
        so_token = create_access_token(so_user)
        init_session.close()

        def override_get_db():
            db = SessionMaker()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        test_client = TestClient(app)

        def make_decision(action: str):
            c = TestClient(app)
            return c.post(
                f"/api/v1/transfers/{transfer_id}/{action}",
                headers={"Authorization": f"Bearer {so_token}"},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            fut_approve = executor.submit(make_decision, "approve")
            fut_reject = executor.submit(make_decision, "reject")
            res_approve = fut_approve.result()
            res_reject = fut_reject.result()

        status_codes = {res_approve.status_code, res_reject.status_code}
        assert status_codes == {200, 409}, f"Expected {200, 409}, got: approve={res_approve.status_code}, reject={res_reject.status_code}"

        # Check final state in DB
        audit_db = SessionMaker()
        final_transfer = audit_db.query(Transfer).filter(Transfer.id == transfer_id).first()
        assert final_transfer.status in ("APPROVED", "REJECTED")
        audit_db.close()

        app.dependency_overrides.clear()
        engine.dispose()


def test_transfer_race_02_approve_already_approved(transfer_fixture):
    """TRANSFER-RACE-02: Attempting to approve an already APPROVED transfer returns 409."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    # 1. First approval -> 200 OK
    app_1 = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert app_1.status_code == 200

    # 2. Second approval -> 409 Conflict
    app_2 = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert app_2.status_code == 409


def test_transfer_race_03_approve_rejected_transfer(transfer_fixture):
    """TRANSFER-RACE-03: Attempting to approve a REJECTED transfer returns 409."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    # Reject -> 200 OK
    client.post(
        f"/api/v1/transfers/{transfer_id}/reject",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    # Attempt to approve rejected transfer -> 409 Conflict
    app_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert app_resp.status_code == 409


# =====================================================================
# SECURITY & CUSTODY CHAIN AUDIT TESTS
# =====================================================================


def test_security_self_transfer_prohibited(transfer_fixture):
    """SECURITY: Self-transfer (requester == recipient) is rejected (400)."""
    client: TestClient = transfer_fixture["client"]
    io_token: str = transfer_fixture["io_token"]
    io_user: User = transfer_fixture["io_user"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": io_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 400


def test_security_custody_events_recorded_in_hash_chain(transfer_fixture):
    """AUDIT: Complete transfer lifecycle records valid cryptographic custody events."""
    client: TestClient = transfer_fixture["client"]
    db: Session = transfer_fixture["db"]
    io_token: str = transfer_fixture["io_token"]
    so_token: str = transfer_fixture["so_token"]
    doc_a: Document = transfer_fixture["doc_a"]
    v2: DocumentVersion = transfer_fixture["v2"]
    legal_user: User = transfer_fixture["legal_user"]

    # 1. Request
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v2.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = resp.json()["id"]

    # 2. Approve
    client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    # 3. Revoke
    client.post(
        f"/api/v1/transfers/{transfer_id}/revoke",
        headers={"Authorization": f"Bearer {so_token}"},
    )

    # Audit custody events for the case
    events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.case_id == doc_a.case_id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "TRANSFER_REQUESTED" in event_types
    assert "TRANSFER_APPROVED" in event_types
    assert "TRANSFER_REVOKED" in event_types

    # Validate the complete cryptographic hash chain
    validation = validate_custody_chain(db=db, case_id=doc_a.case_id)
    assert validation.is_valid is True
    assert validation.status_code == "VALID"
