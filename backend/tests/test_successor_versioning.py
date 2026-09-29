"""Tests for Docspector Successor Versioning & Concurrency (Milestone 10).

Validates:
- Endpoint: POST /api/v1/documents/{document_id}/versions
- Append-only immutability: existing versions (V1, V2...) and physical files are preserved.
- Server-derived version numbering (client has zero control).
- Concurrency protection and serialization (no duplicate version numbers).
- Authorization & IDOR protection across cases.
- Custody event chaining for successor versions.
- Failure compensation (rollback DB, remove temp files).
- State/restriction enforcement on locked documents.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import io
from pathlib import Path
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, User
from app.db.session import get_db
from app.main import app
from app.services.file_validation import MAX_FILE_SIZE_BYTES
from scripts.seed_demo import seed_demo_data

settings = get_settings()

V1_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Title (Version 1 Original) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
V2_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n2 0 obj\n<< /Title (Version 2 Successor) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
V3_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n3 0 obj\n<< /Title (Version 3 Successor) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
V4_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n4 0 obj\n<< /Title (Version 4 Successor) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
V5_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n5 0 obj\n<< /Title (Version 5 Successor) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
V6_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n6 0 obj\n<< /Title (Version 6 Successor) >>\nendobj\ntrailer\n<<>>\n%%EOF\n"


@pytest.fixture
def successor_fixture(monkeypatch):
    """Fixture with seeded database, temporary storage, and initial document V1."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        temp_storage_path = temp_dir_path / "storage"
        temp_storage_path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))

        db_file = temp_dir_path / "test_docspector.db"
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

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        # Inactive user for testing access denial
        inactive_user = User(
            username="docspector.inactive",
            display_name="Inactive Officer",
            role="IO",
            is_active=False,
        )
        # Create Case 2 assigned ONLY to SO
        case_2 = Case(
            case_number="HYD-FIN-2026-0002",
            title="Secondary Case",
            status="OPEN",
        )
        session.add_all([inactive_user, case_2])
        session.flush()

        session.add(
            CaseAssignment(
                case_id=case_2.id,
                user_id=so_user.id,
                is_active=True,
            )
        )
        session.commit()

        io_token = create_access_token(io_user)
        so_token = create_access_token(so_user)
        inactive_token = create_access_token(inactive_user)
        case_1_id = case_1.id
        case_2_id = case_2.id
        session.close()

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

        # Upload initial Document V1 for Case 1 using io_token
        with TestClient(app) as client:
            init_resp = client.post(
                f"/api/v1/cases/{case_1_id}/documents",
                headers={"Authorization": f"Bearer {io_token}"},
                files={"file": ("evidence_v1.pdf", V1_PDF_BYTES, "application/pdf")},
                data={"title": "Primary Digital Forensic Report"},
            )
            assert init_resp.status_code == 201
            doc_1_id = init_resp.json()["document"]["id"]

            yield {
                "client": client,
                "db_factory": TestingSessionLocal,
                "storage_dir": temp_storage_path,
                "io_token": io_token,
                "so_token": so_token,
                "inactive_token": inactive_token,
                "case_1_id": case_1_id,
                "case_2_id": case_2_id,
                "doc_1_id": doc_1_id,
            }

        app.dependency_overrides.clear()
        engine.dispose()


def test_ver_01_create_v2_successfully_for_existing_document(successor_fixture):
    """VER-01: Create V2 successfully for an existing document."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("evidence_v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["document"]["id"] == doc_id
    assert data["version"]["version_number"] == 2
    assert data["version"]["state"] == "STORED"
    assert data["version"]["sha256_hash"] == hashlib.sha256(V2_PDF_BYTES).hexdigest()


def test_ver_02_create_v3_after_v2_preserves_immutability(successor_fixture):
    """VER-02: Create V3 after V2 and verify V1 and V2 remain completely unchanged."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    storage_dir = successor_fixture["storage_dir"]
    db_factory = successor_fixture["db_factory"]

    # 1. Upload V2
    resp_v2 = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("evidence_v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert resp_v2.status_code == 201
    assert resp_v2.json()["version"]["version_number"] == 2

    # 2. Upload V3
    resp_v3 = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("evidence_v3.pdf", V3_PDF_BYTES, "application/pdf")},
    )
    assert resp_v3.status_code == 201
    assert resp_v3.json()["version"]["version_number"] == 3

    # 3. Verify in database that V1, V2, V3 all exist independently
    db = db_factory()
    try:
        versions = (
            db.query(DocumentVersion)
            .filter(DocumentVersion.document_id == doc_id)
            .order_by(DocumentVersion.version_number.asc())
            .all()
        )
        assert len(versions) == 3
        v1, v2, v3 = versions[0], versions[1], versions[2]

        assert v1.version_number == 1
        assert v2.version_number == 2
        assert v3.version_number == 3

        # Verify distinct storage keys
        assert v1.storage_key != v2.storage_key
        assert v2.storage_key != v3.storage_key

        # Verify exact bytes and SHA-256 for all 3 versions on physical disk
        file_1 = (storage_dir / v1.storage_key).read_bytes()
        file_2 = (storage_dir / v2.storage_key).read_bytes()
        file_3 = (storage_dir / v3.storage_key).read_bytes()

        assert file_1 == V1_PDF_BYTES
        assert file_2 == V2_PDF_BYTES
        assert file_3 == V3_PDF_BYTES

        assert v1.sha256_hash == hashlib.sha256(V1_PDF_BYTES).hexdigest()
        assert v2.sha256_hash == hashlib.sha256(V2_PDF_BYTES).hexdigest()
        assert v3.sha256_hash == hashlib.sha256(V3_PDF_BYTES).hexdigest()
    finally:
        db.close()


def test_ver_03_unauthorized_user_cannot_create_successor_version(successor_fixture):
    """VER-03: User not assigned to document's case cannot add successor version (returns 404)."""
    client = successor_fixture["client"]
    token = successor_fixture["so_token"]
    case_2_id = successor_fixture["case_2_id"]
    io_token = successor_fixture["io_token"]

    # SO creates a document in Case 2 (IO is not assigned to Case 2)
    resp_case2_doc = client.post(
        f"/api/v1/cases/{case_2_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("case2_doc.pdf", V1_PDF_BYTES, "application/pdf")},
    )
    assert resp_case2_doc.status_code == 201
    doc_case2_id = resp_case2_doc.json()["document"]["id"]

    # IO attempts to create successor version on Case 2's document -> must return 404
    resp_unauthorized = client.post(
        f"/api/v1/documents/{doc_case2_id}/versions",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("intruder_version.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert resp_unauthorized.status_code == 404


def test_concurrency_01_two_simultaneous_successor_requests(successor_fixture):
    """CONCURRENCY-01: Two concurrent successor requests serialize without creating duplicate version numbers."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    db_factory = successor_fixture["db_factory"]

    def upload_version(payload_bytes, filename):
        return client.post(
            f"/api/v1/documents/{doc_id}/versions",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (filename, payload_bytes, "application/pdf")},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(upload_version, V2_PDF_BYTES, "race_v2_a.pdf")
        f2 = executor.submit(upload_version, V3_PDF_BYTES, "race_v2_b.pdf")
        r1 = f1.result()
        r2 = f2.result()

    successful_status_codes = [r.status_code for r in [r1, r2] if r.status_code == 201]
    assert len(successful_status_codes) >= 1

    db = db_factory()
    try:
        versions = (
            db.query(DocumentVersion)
            .filter(DocumentVersion.document_id == doc_id)
            .order_by(DocumentVersion.version_number.asc())
            .all()
        )
        version_numbers = [v.version_number for v in versions]
        assert len(version_numbers) == len(set(version_numbers))
        assert version_numbers[0] == 1
    finally:
        db.close()


def test_concurrency_02_five_successor_requests_create_v1_through_v6(successor_fixture):
    """CONCURRENCY-02: 5 sequential successor requests result in clean V1 to V6."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    db_factory = successor_fixture["db_factory"]
    storage_dir = successor_fixture["storage_dir"]

    payloads = [
        ("v2.pdf", V2_PDF_BYTES),
        ("v3.pdf", V3_PDF_BYTES),
        ("v4.pdf", V4_PDF_BYTES),
        ("v5.pdf", V5_PDF_BYTES),
        ("v6.pdf", V6_PDF_BYTES),
    ]
    for filename, payload in payloads:
        res = client.post(
            f"/api/v1/documents/{doc_id}/versions",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (filename, payload, "application/pdf")},
        )
        assert res.status_code == 201

    db = db_factory()
    try:
        versions = (
            db.query(DocumentVersion)
            .filter(DocumentVersion.document_id == doc_id)
            .order_by(DocumentVersion.version_number.asc())
            .all()
        )
        assert [v.version_number for v in versions] == [1, 2, 3, 4, 5, 6]

        # Verify each version has matching stored file bytes
        all_payloads = [V1_PDF_BYTES, V2_PDF_BYTES, V3_PDF_BYTES, V4_PDF_BYTES, V5_PDF_BYTES, V6_PDF_BYTES]
        for v, expected_p in zip(versions, all_payloads):
            disk_bytes = (storage_dir / v.storage_key).read_bytes()
            assert disk_bytes == expected_p
            assert v.sha256_hash == hashlib.sha256(expected_p).hexdigest()
    finally:
        db.close()


def test_concurrency_03_unique_constraint_enforced_in_db(successor_fixture):
    """CONCURRENCY-03: Direct database attempt to insert duplicate version_number raises IntegrityError."""
    db_factory = successor_fixture["db_factory"]
    doc_id = successor_fixture["doc_1_id"]

    db = db_factory()
    try:
        duplicate_v1 = DocumentVersion(
            document_id=doc_id,
            version_number=1,  # Duplicate
            state="STORED",
            original_filename="duplicate.pdf",
            mime_type="application/pdf",
            size_bytes=100,
            sha256_hash="0" * 64,
            storage_key="duplicate_key.pdf",
            created_by_user_id=1,
        )
        db.add(duplicate_v1)
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_successor_client_cannot_control_version_number(successor_fixture):
    """Security: Client-provided version_number in form data is ignored by server."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("v2.pdf", V2_PDF_BYTES, "application/pdf")},
        data={"version_number": 999},
    )
    assert response.status_code == 201
    assert response.json()["version"]["version_number"] == 2


def test_successor_failed_validation_cleans_up_and_creates_no_version(successor_fixture):
    """Failure: Invalid file payload creates no version and cleans up temporary files."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    storage_dir = successor_fixture["storage_dir"]
    db_factory = successor_fixture["db_factory"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("corrupt.pdf", b"NOT_A_VALID_PDF", "application/pdf")},
    )
    assert response.status_code == 400

    db = db_factory()
    try:
        versions = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).all()
        assert len(versions) == 1
        tmp_files = list(storage_dir.glob("*.tmp"))
        assert len(tmp_files) == 0
    finally:
        db.close()


def test_successor_oversized_file_rejected(successor_fixture):
    """Failure: Successor file exceeding 25 MiB is rejected with 413."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]

    oversized = b"%PDF-1.7\n" + b"X" * (MAX_FILE_SIZE_BYTES + 100)
    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("oversized.pdf", oversized, "application/pdf")},
    )
    assert response.status_code == 413


def test_successor_mismatched_mime_type_rejected(successor_fixture):
    """Failure: Successor file with MIME mismatch is rejected with 415."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("mismatch.pdf", V2_PDF_BYTES, "image/png")},
    )
    assert response.status_code == 415


def test_successor_restricted_document_rejected(successor_fixture):
    """State Check: Document with a RESTRICTED version cannot accept successor versions."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    db_factory = successor_fixture["db_factory"]

    # Mark V1 as RESTRICTED in DB
    db = db_factory()
    try:
        v1 = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        v1.state = "RESTRICTED"
        db.commit()
    finally:
        db.close()

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("blocked.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 409


def test_successor_nonexistent_document_returns_404(successor_fixture):
    """IDOR/404: Nonexistent document returns 404."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]

    response = client.post(
        "/api/v1/documents/99999/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 404


def test_successor_unauthenticated_returns_401(successor_fixture):
    """Auth: Unauthenticated request returns 401."""
    client = successor_fixture["client"]
    doc_id = successor_fixture["doc_1_id"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        files={"file": ("v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 401


def test_successor_inactive_user_returns_error(successor_fixture):
    """Auth: Inactive user account is denied."""
    client = successor_fixture["client"]
    token = successor_fixture["inactive_token"]
    doc_id = successor_fixture["doc_1_id"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code in (401, 403)


def test_successor_custody_event_chaining(successor_fixture):
    """Custody: Successor version creates custody event chained to prior event."""
    client = successor_fixture["client"]
    token = successor_fixture["io_token"]
    doc_id = successor_fixture["doc_1_id"]
    db_factory = successor_fixture["db_factory"]

    response = client.post(
        f"/api/v1/documents/{doc_id}/versions",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("evidence_v2.pdf", V2_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    v2_id = response.json()["version"]["id"]

    db = db_factory()
    try:
        events = (
            db.query(CustodyEvent)
            .filter(CustodyEvent.case_id == 1)
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        )
        assert len(events) >= 2
        e1, e2 = events[0], events[1]

        assert e1.sequence_number == 1
        assert e2.sequence_number == 2
        assert e2.document_version_id == v2_id
        assert e2.previous_event_hash == e1.event_hash
        assert len(e2.event_hash) == 64
    finally:
        db.close()
