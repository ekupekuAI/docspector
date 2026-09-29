"""Docspector Authorization Attack / IDOR / Privilege Escalation Security Audit Tests (Milestone 15).

Inspect. Verify. Trust.

Comprehensive adversarial test suite proving that malicious authenticated users cannot:
- AUTHZ-ATTACK-01: Access another case (IDOR case access -> 404 non-disclosure)
- AUTHZ-ATTACK-02: Access or ingest another case's document (IDOR document access -> 404 non-disclosure)
- AUTHZ-ATTACK-03: Create successor version for another case's document (IDOR version access -> 404 non-disclosure)
- AUTHZ-ATTACK-04: Execute privileged actions with unauthorized roles (Legal Reviewer / Auditor -> 403 Forbidden)
- AUTHZ-ATTACK-05: Access cases or documents with inactive assignments -> 404 Not Found
- AUTHZ-ATTACK-06: Manipulate roles via request payload injection -> 422 rejected / server controlled
- AUTHZ-ATTACK-07: Manipulate Case ID in URL to bypass authorization -> 404 Not Found
- AUTHZ-ATTACK-08: Manipulate Document ID in URL to bypass authorization -> 404 Not Found
- AUTHZ-ATTACK-09: Manipulate Version ID with mismatched document relationship -> 404 Not Found
- AUTHZ-ATTACK-10: Perform mass assignment of server-controlled fields -> 422 extra fields forbidden
- AUTHZ-ATTACK-11: Manipulate transfer lifecycle states directly or execute self-transfers -> 400/403/409
- AUTHZ-ATTACK-12: Bypass restricted-state protections (cannot transfer or add successor to RESTRICTED version) -> 409
- AUTHZ-ATTACK-13: Bypass demo-mode safeguards (DEMO_MODE=false or unauthorized role -> 403)
- AUTHZ-ATTACK-14: Forge or tamper with JWT claims (modified sub, altered role, invalid signature -> 401)
- AUTHZ-ATTACK-15: Cross-case object access isolation
- AUTHZ-ATTACK-16: Cross-document version access isolation
- AUTHZ-ATTACK-17: Unauthorized verification attempt on unassigned case -> 404 Not Found
- AUTHZ-ATTACK-18: Privilege escalation attempt by IO attempting SO-only actions -> 403 Forbidden
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.authorization import (
    ROLE_AUDITOR,
    ROLE_IO,
    ROLE_LEGAL_REVIEWER,
    ROLE_SO,
)
from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import (
    Case,
    CaseAssignment,
    Document,
    DocumentVersion,
    Transfer,
    User,
)
from app.db.session import get_db
from app.main import app
from app.services.document_registration import (
    register_document_version_one,
    register_successor_version,
)
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
SAMPLE_TEXT_BYTES = b"Audit log content for security testing."


@pytest.fixture
def authz_attack_fixture(monkeypatch):
    """Set up an isolated adversarial test environment with two distinct cases and multi-role users."""
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

        # 1. Fetch seeded users
        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()

        # 2. Case A (Seeded: HYD-CYB-2026-0147) - assigned to IO, SO, Legal, Auditor
        case_a = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        # 3. Create Case B (Isolated foreign case: HYD-FIN-2026-0999)
        case_b = Case(
            case_number="HYD-FIN-2026-0999",
            title="Foreign Financial Case B",
            description="Isolated case for IDOR testing.",
            status="OPEN",
        )
        session.add(case_b)
        session.flush()

        # 4. Create Foreign Officer assigned ONLY to Case B
        foreign_io = User(
            username="docspector.foreign_io",
            display_name="Foreign Investigating Officer",
            role=ROLE_IO,
            is_active=True,
        )
        # 5. Create Inactive Officer
        inactive_user = User(
            username="docspector.inactive_io",
            display_name="Inactive Officer",
            role=ROLE_IO,
            is_active=False,
        )
        # 6. Create Unassigned Officer
        unassigned_user = User(
            username="docspector.unassigned_io",
            display_name="Unassigned Officer",
            role=ROLE_IO,
            is_active=True,
        )
        session.add_all([foreign_io, inactive_user, unassigned_user])
        session.flush()

        # Assign foreign_io to Case B ONLY
        session.add(
            CaseAssignment(
                case_id=case_b.id,
                user_id=foreign_io.id,
                is_active=True,
            )
        )

        # Inactive assignment: IO user assigned to Case B with is_active=False
        session.add(
            CaseAssignment(
                case_id=case_b.id,
                user_id=io_user.id,
                is_active=False,
            )
        )
        session.commit()

        # Ingest Document A in Case A
        doc_a, v_a1, _ = register_document_version_one(
            db=session,
            case=case_a,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Case_A_Doc.pdf",
            content_type="application/pdf",
            title="Case A Document",
        )

        # Ingest Document B in Case B
        doc_b, v_b1, _ = register_document_version_one(
            db=session,
            case=case_b,
            current_user=foreign_io,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Case_B_Doc.pdf",
            content_type="application/pdf",
            title="Case B Document",
        )

        session.commit()

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
            "case_a": case_a,
            "case_b": case_b,
            "doc_a": doc_a,
            "doc_b": doc_b,
            "v_a1": v_a1,
            "v_b1": v_b1,
            "io_user": io_user,
            "so_user": so_user,
            "legal_user": legal_user,
            "auditor_user": auditor_user,
            "foreign_io": foreign_io,
            "inactive_user": inactive_user,
            "unassigned_user": unassigned_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
            "legal_token": create_access_token(legal_user),
            "auditor_token": create_access_token(auditor_user),
            "foreign_io_token": create_access_token(foreign_io),
            "inactive_token": create_access_token(inactive_user),
            "unassigned_token": create_access_token(unassigned_user),
        }

        app.dependency_overrides.clear()
        session.close()
        Base.metadata.drop_all(bind=engine)


# =====================================================================
# 1. IDOR ATTACKS (AUTHZ-ATTACK-01 to AUTHZ-ATTACK-03)
# =====================================================================


def test_authz_attack_01_idor_case_access(authz_attack_fixture):
    """AUTHZ-ATTACK-01: User assigned to Case A attempts to access Case B -> 404 non-disclosure."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    case_b: Case = authz_attack_fixture["case_b"]

    resp = client.get(
        f"/api/v1/cases/{case_b.id}",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "CASE_ACCESS_DENIED"
    assert body["error"]["message"] == "Case not found"


def test_authz_attack_02_idor_document_access(authz_attack_fixture):
    """AUTHZ-ATTACK-02: User assigned to Case A attempts to upload document to Case B -> 404 non-disclosure."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    case_b: Case = authz_attack_fixture["case_b"]

    resp = client.post(
        f"/api/v1/cases/{case_b.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("injected.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "CASE_ACCESS_DENIED"


def test_authz_attack_03_idor_version_access(authz_attack_fixture):
    """AUTHZ-ATTACK-03: User assigned to Case A attempts to upload successor version to Case B's document -> 404."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_b: Document = authz_attack_fixture["doc_b"]

    resp = client.post(
        f"/api/v1/documents/{doc_b.id}/versions",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("injected_v2.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "DOCUMENT_ACCESS_DENIED"


# =====================================================================
# 2. ROLE ESCALATION & PRIVILEGE VIOLATIONS (AUTHZ-ATTACK-04 to AUTHZ-ATTACK-06)
# =====================================================================


def test_authz_attack_04_wrong_role_rejection(authz_attack_fixture):
    """AUTHZ-ATTACK-04: Legal Reviewer and Auditor cannot ingest documents or create successor versions (403)."""
    client: TestClient = authz_attack_fixture["client"]
    legal_token: str = authz_attack_fixture["legal_token"]
    auditor_token: str = authz_attack_fixture["auditor_token"]
    case_a: Case = authz_attack_fixture["case_a"]
    doc_a: Document = authz_attack_fixture["doc_a"]

    # 1. Legal Reviewer attempts initial document upload
    resp_legal_doc = client.post(
        f"/api/v1/cases/{case_a.id}/documents",
        headers={"Authorization": f"Bearer {legal_token}"},
        files={"file": ("legal_doc.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp_legal_doc.status_code == 403
    assert resp_legal_doc.json()["error"]["code"] == "FORBIDDEN"

    # 2. Auditor attempts successor version upload
    resp_auditor_ver = client.post(
        f"/api/v1/documents/{doc_a.id}/versions",
        headers={"Authorization": f"Bearer {auditor_token}"},
        files={"file": ("auditor_ver.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp_auditor_ver.status_code == 403
    assert resp_auditor_ver.json()["error"]["code"] == "FORBIDDEN"

    # 3. Legal Reviewer attempts transfer initiation
    resp_legal_transfer = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/1/transfers",
        json={"recipient_user_id": 2},
        headers={"Authorization": f"Bearer {legal_token}"},
    )
    assert resp_legal_transfer.status_code == 403
    assert resp_legal_transfer.json()["error"]["code"] == "FORBIDDEN"


def test_authz_attack_05_inactive_assignment(authz_attack_fixture):
    """AUTHZ-ATTACK-05: Inactive case assignments result in 404 non-disclosure."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    case_b: Case = authz_attack_fixture["case_b"]

    # io_user has an assignment to Case B, but is_active is False
    resp = client.get(
        f"/api/v1/cases/{case_b.id}",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "CASE_ACCESS_DENIED"


def test_authz_attack_06_role_manipulation_attempt(authz_attack_fixture):
    """AUTHZ-ATTACK-06: Injecting 'role' or 'is_admin' into login / request payloads is rejected/ignored."""
    client: TestClient = authz_attack_fixture["client"]

    # Attempt to elevate role during login
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "docspector.io", "role": "SO", "is_admin": True},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


# =====================================================================
# 3. ID MANIPULATION & MASS ASSIGNMENT (AUTHZ-ATTACK-07 to AUTHZ-ATTACK-10)
# =====================================================================


def test_authz_attack_07_case_id_manipulation(authz_attack_fixture):
    """AUTHZ-ATTACK-07: Changing case_id in URL cannot access unauthorized foreign case."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]

    for fake_case_id in [9999, 99999, 0, -1]:
        resp = client.get(
            f"/api/v1/cases/{fake_case_id}",
            headers={"Authorization": f"Bearer {io_token}"},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "CASE_ACCESS_DENIED"


def test_authz_attack_08_document_id_manipulation(authz_attack_fixture):
    """AUTHZ-ATTACK-08: Manipulating document_id in URL to access foreign or nonexistent document returns 404."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_b: Document = authz_attack_fixture["doc_b"]

    # Foreign document ID
    resp = client.post(
        f"/api/v1/documents/{doc_b.id}/versions",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("v2.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "DOCUMENT_ACCESS_DENIED"

    # Nonexistent document ID
    resp_none = client.post(
        "/api/v1/documents/99999/versions",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("v2.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp_none.status_code == 404


def test_authz_attack_09_version_id_manipulation(authz_attack_fixture):
    """AUTHZ-ATTACK-09: Manipulating version_id across documents fails verification/transfer (404)."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_b1: DocumentVersion = authz_attack_fixture["v_b1"]

    # Supply Doc A with Version belonging to Doc B
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_b1.id}/verify",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "VERSION_ACCESS_DENIED"


def test_authz_attack_10_mass_assignment_transfer_payload(authz_attack_fixture):
    """AUTHZ-ATTACK-10: Extra fields in TransferCreateRequest are strictly forbidden (422)."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]
    legal_user: User = authz_attack_fixture["legal_user"]

    # Attacker tries to force status="APPROVED" and set approved_by
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/transfers",
        json={
            "recipient_user_id": legal_user.id,
            "status": "APPROVED",
            "decided_by_user_id": 1,
        },
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


# =====================================================================
# 4. TRANSFER LIFECYCLE & PRIVILEGE ATTACKS (AUTHZ-ATTACK-11 & 18)
# =====================================================================


def test_authz_attack_11_transfer_lifecycle_manipulation(authz_attack_fixture):
    """AUTHZ-ATTACK-11: Self-transfer and non-SO approval attempts are rejected."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    legal_token: str = authz_attack_fixture["legal_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]
    io_user: User = authz_attack_fixture["io_user"]
    legal_user: User = authz_attack_fixture["legal_user"]

    # 1. Self-transfer attempt
    resp_self = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/transfers",
        json={"recipient_user_id": io_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_self.status_code == 400
    assert "yourself" in resp_self.json()["error"]["message"].lower()

    # 2. Valid transfer created
    resp_create = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_create.status_code == 201
    transfer_id = resp_create.json()["id"]

    # 3. IO attempts to approve transfer (Privilege Escalation attempt)
    resp_io_approve = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_io_approve.status_code == 403
    assert resp_io_approve.json()["error"]["code"] == "FORBIDDEN"

    # 4. Legal Reviewer attempts to approve transfer
    resp_legal_approve = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {legal_token}"},
    )
    assert resp_legal_approve.status_code == 403


# =====================================================================
# 5. RESTRICTED STATE BYPASS (AUTHZ-ATTACK-12)
# =====================================================================


def test_authz_attack_12_restricted_state_bypass(authz_attack_fixture):
    """AUTHZ-ATTACK-12: RESTRICTED document version cannot be transferred or have successors added."""
    client: TestClient = authz_attack_fixture["client"]
    db: Session = authz_attack_fixture["db"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]
    legal_user: User = authz_attack_fixture["legal_user"]

    # Manually transition version to RESTRICTED
    v_a1.state = "RESTRICTED"
    db.commit()

    # 1. Attempt transfer creation on RESTRICTED version -> 409 Conflict
    resp_transfer = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_transfer.status_code == 409
    assert resp_transfer.json()["error"]["code"] == "INVALID_STATE"

    # 2. Attempt successor version upload when latest version is RESTRICTED -> 409 Conflict
    resp_successor = client.post(
        f"/api/v1/documents/{doc_a.id}/versions",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("v2.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert resp_successor.status_code == 409
    assert resp_successor.json()["error"]["code"] == "INVALID_STATE"


# =====================================================================
# 6. DEMO-MODE SAFEGUARDS & BYPASS PREVENTION (AUTHZ-ATTACK-13)
# =====================================================================


def test_authz_attack_13_demo_mode_authorization_bypass(authz_attack_fixture, monkeypatch):
    """AUTHZ-ATTACK-13: Tamper simulator is rejected when DEMO_MODE=false or caller is unauthorized."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    legal_token: str = authz_attack_fixture["legal_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]
    doc_b: Document = authz_attack_fixture["doc_b"]
    v_b1: DocumentVersion = authz_attack_fixture["v_b1"]

    # 1. DEMO_MODE=false -> 403 DEMO_MODE_REQUIRED
    monkeypatch.setattr(settings, "demo_mode", False)
    resp = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v_a1.id}/tamper",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "DEMO_MODE_REQUIRED"

    # 2. DEMO_MODE=true, but caller is Legal Reviewer -> 403 FORBIDDEN
    monkeypatch.setattr(settings, "demo_mode", True)
    resp_legal = client.post(
        f"/api/v1/demo/documents/{doc_a.id}/versions/{v_a1.id}/tamper",
        headers={"Authorization": f"Bearer {legal_token}"},
    )
    assert resp_legal.status_code == 403
    assert resp_legal.json()["error"]["code"] == "DEMO_PERMISSION_REQUIRED"

    # 3. DEMO_MODE=true, IO caller targets foreign document from Case B -> 404 Not Found
    resp_foreign = client.post(
        f"/api/v1/demo/documents/{doc_b.id}/versions/{v_b1.id}/tamper",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_foreign.status_code == 404
    assert resp_foreign.json()["error"]["code"] in ("CASE_ACCESS_DENIED", "DOCUMENT_ACCESS_DENIED")


# =====================================================================
# 7. JWT / AUTHENTICATION BOUNDARY ATTACKS (AUTHZ-ATTACK-14)
# =====================================================================


def test_authz_attack_14_jwt_claim_manipulation(authz_attack_fixture):
    """AUTHZ-ATTACK-14: Forged JWT signatures, fabricated claims, and expired tokens return 401."""
    client: TestClient = authz_attack_fixture["client"]

    # 1. Forged token with fake secret key
    forged_token = jwt.encode(
        {"sub": "1", "username": "docspector.io", "role": "SO"},
        "ATTACKER_MALICIOUS_SECRET_KEY_32_CHARS_LONG",
        algorithm="HS256",
    )
    resp_forged = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {forged_token}"})
    assert resp_forged.status_code == 401
    assert resp_forged.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")

    # 2. Expired token (signed with correct secret but expired)
    now = datetime.now(timezone.utc)
    expired_token = jwt.encode(
        {
            "sub": "1",
            "username": "docspector.io",
            "role": "IO",
            "iat": now - timedelta(days=2),
            "exp": now - timedelta(days=1),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    resp_expired = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp_expired.status_code == 401
    assert resp_expired.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")

    # 3. Malformed non-JWT string
    resp_malformed = client.get("/api/v1/cases", headers={"Authorization": "Bearer not-a-valid-jwt-token"})
    assert resp_malformed.status_code == 401
    assert resp_malformed.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")


# =====================================================================
# 8. CROSS-CASE & CROSS-DOCUMENT ISOLATION (AUTHZ-ATTACK-15 to AUTHZ-ATTACK-18)
# =====================================================================


def test_authz_attack_15_cross_case_object_isolation(authz_attack_fixture):
    """AUTHZ-ATTACK-15: Case listing strictly isolates cases between users."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    foreign_token: str = authz_attack_fixture["foreign_io_token"]
    case_a: Case = authz_attack_fixture["case_a"]
    case_b: Case = authz_attack_fixture["case_b"]

    # IO sees only Case A
    resp_io = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {io_token}"})
    assert resp_io.status_code == 200
    case_ids_io = [c["id"] for c in resp_io.json()]
    assert case_a.id in case_ids_io
    assert case_b.id not in case_ids_io

    # Foreign IO sees only Case B
    resp_foreign = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {foreign_token}"})
    assert resp_foreign.status_code == 200
    case_ids_foreign = [c["id"] for c in resp_foreign.json()]
    assert case_b.id in case_ids_foreign
    assert case_a.id not in case_ids_foreign


def test_authz_attack_16_cross_document_version_transfer_attempt(authz_attack_fixture):
    """AUTHZ-ATTACK-16: Creating transfer with version belonging to a different document returns 404."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_b1: DocumentVersion = authz_attack_fixture["v_b1"]
    legal_user: User = authz_attack_fixture["legal_user"]

    # Provide Doc A ID with Version B1 ID
    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_b1.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "VERSION_ACCESS_DENIED"


def test_authz_attack_17_unauthorized_verification_attempt(authz_attack_fixture):
    """AUTHZ-ATTACK-17: Unassigned user attempting to verify document returns 404 Not Found."""
    client: TestClient = authz_attack_fixture["client"]
    unassigned_token: str = authz_attack_fixture["unassigned_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]

    resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/verify",
        headers={"Authorization": f"Bearer {unassigned_token}"},
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "DOCUMENT_ACCESS_DENIED"


def test_authz_attack_18_privilege_escalation_attempt(authz_attack_fixture):
    """AUTHZ-ATTACK-18: IO user attempting to revoke transfers or perform supervisor duties receives 403."""
    client: TestClient = authz_attack_fixture["client"]
    io_token: str = authz_attack_fixture["io_token"]
    so_token: str = authz_attack_fixture["so_token"]
    doc_a: Document = authz_attack_fixture["doc_a"]
    v_a1: DocumentVersion = authz_attack_fixture["v_a1"]
    legal_user: User = authz_attack_fixture["legal_user"]

    # Create and approve transfer as SO
    create_resp = client.post(
        f"/api/v1/documents/{doc_a.id}/versions/{v_a1.id}/transfers",
        json={"recipient_user_id": legal_user.id},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    transfer_id = create_resp.json()["id"]

    approve_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/approve",
        headers={"Authorization": f"Bearer {so_token}"},
    )
    assert approve_resp.status_code == 200

    # IO attempts to revoke the approved transfer
    revoke_resp = client.post(
        f"/api/v1/transfers/{transfer_id}/revoke",
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert revoke_resp.status_code == 403
    assert revoke_resp.json()["error"]["code"] == "FORBIDDEN"
