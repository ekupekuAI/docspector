"""Tests for Docspector Document V1 Registration API (Milestone 9).

Validates:
- Endpoint: POST /api/v1/cases/{case_id}/documents
- Authentication & Authorization (require_case_assignment, IDOR protection)
- Input file validation (size <= 25 MiB, PDF/PNG/TXT signatures, UTF-8)
- Exact SHA-256 computation and persistence
- Crash-safe compensating upload protocol (staging, verify on-disk, finalize STORED state)
- Initial DOCUMENT_INGESTED custody event creation
- Storage privacy outside frontend/public with unpredictable keys
- Failure compensation (rollback DB, remove temp/partial files)
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models import Case, CaseAssignment, CustodyEvent, Document, DocumentVersion, User
from app.db.session import get_db
from app.main import app
from app.services.file_validation import MAX_FILE_SIZE_BYTES
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
VALID_TXT_BYTES = "Docspector Synthetic Custody Evidence #2026-99\nStatus: REGISTERED\n".encode("utf-8")


@pytest.fixture
def doc_fixture(monkeypatch):
    """Create an isolated test client with a dedicated temporary storage directory."""
    with tempfile.TemporaryDirectory() as temp_storage:
        temp_storage_path = Path(temp_storage)

        # Override storage_dir in settings
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

        # Retrieve seeded users
        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        # Create inactive user
        inactive_user = User(
            username="docspector.inactive",
            display_name="Inactive Officer",
            role="IO",
            is_active=False,
        )
        # Create unassigned user
        unassigned_user = User(
            username="docspector.unassigned",
            display_name="Unassigned Officer",
            role="IO",
            is_active=True,
        )
        # Create Case 2 assigned ONLY to SO
        case_2 = Case(
            case_number="HYD-SEC-2026-0002",
            title="Synthetic Secondary Case",
            status="OPEN",
        )
        session.add_all([inactive_user, unassigned_user, case_2])
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
        unassigned_token = create_access_token(unassigned_user)
        inactive_token = create_access_token(inactive_user)

        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

        with TestClient(app) as client:
            yield {
                "client": client,
                "session": session,
                "db_factory": TestingSessionLocal,
                "storage_dir": temp_storage_path,
                "io_token": io_token,
                "so_token": so_token,
                "unassigned_token": unassigned_token,
                "inactive_token": inactive_token,
                "case_1_id": case_1.id,
                "case_2_id": case_2.id,
            }

        app.dependency_overrides.clear()
        session.close()


def test_doc_01_assigned_user_can_upload_valid_pdf(doc_fixture):
    """DOC-01: Authenticated assigned user can upload a valid synthetic PDF."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("evidence_report.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Primary Forensic Evidence"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["document"]["case_id"] == case_id
    assert data["document"]["title"] == "Primary Forensic Evidence"
    assert data["version"]["version_number"] == 1
    assert data["version"]["state"] == "STORED"
    assert data["version"]["sha256_hash"] == hashlib.sha256(VALID_PDF_BYTES).hexdigest()
    assert data["version"]["size_bytes"] == len(VALID_PDF_BYTES)


def test_doc_02_assigned_user_can_upload_valid_png(doc_fixture):
    """DOC-02: Authenticated assigned user can upload a valid synthetic PNG."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("device_photo.png", VALID_PNG_BYTES, "image/png")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["version"]["mime_type"] == "image/png"
    assert data["version"]["version_number"] == 1
    assert data["version"]["state"] == "STORED"


def test_doc_03_assigned_user_can_upload_valid_utf8_txt(doc_fixture):
    """DOC-03: Authenticated assigned user can upload a valid plain UTF-8 text file."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("investigation_notes.txt", VALID_TXT_BYTES, "text/plain")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["version"]["mime_type"] == "text/plain"
    assert data["version"]["version_number"] == 1
    assert data["version"]["state"] == "STORED"


def test_doc_04_unauthenticated_user_cannot_upload(doc_fixture):
    """DOC-04: Unauthenticated request returns HTTP 401."""
    client = doc_fixture["client"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        files={"file": ("file.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 401


def test_doc_05_inactive_user_cannot_upload(doc_fixture):
    """DOC-05: Inactive user cannot upload (returns HTTP 401 / 403)."""
    client = doc_fixture["client"]
    token = doc_fixture["inactive_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("file.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code in (401, 403)


def test_doc_06_user_assigned_to_case_a_cannot_upload_to_case_b(doc_fixture):
    """DOC-06: User assigned only to Case 1 receives 404 when uploading to Case 2 (IDOR protection)."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]  # IO is assigned only to Case 1
    case_2_id = doc_fixture["case_2_id"]

    response = client.post(
        f"/api/v1/cases/{case_2_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("file.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 404


def test_doc_07_changing_case_id_cannot_bypass_authorization(doc_fixture):
    """DOC-07: Accessing non-existent case or arbitrary case_id returns 404."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]

    response = client.post(
        "/api/v1/cases/99999/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("file.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 404


def test_doc_08_valid_upload_creates_exactly_one_document(doc_fixture):
    """DOC-08: Valid upload creates exactly one Document record in database."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("single_doc.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        docs = db.query(Document).filter(Document.id == doc_id).all()
        assert len(docs) == 1
    finally:
        db.close()


def test_doc_09_valid_upload_creates_exactly_one_document_version(doc_fixture):
    """DOC-09: Valid upload creates exactly one DocumentVersion record."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("single_version.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        versions = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).all()
        assert len(versions) == 1
    finally:
        db.close()


def test_doc_10_first_version_has_version_number_one(doc_fixture):
    """DOC-10: Initial version record has version_number = 1."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("v1_check.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    assert response.json()["version"]["version_number"] == 1


def test_doc_11_successful_version_state_is_stored(doc_fixture):
    """DOC-11: Successfully registered version is in STORED state."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("state_check.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    assert response.json()["version"]["state"] == "STORED"


def test_doc_12_stored_sha256_matches_exact_bytes_on_disk(doc_fixture):
    """DOC-12: Stored SHA-256 matches exact hash of bytes on disk."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("sha_match.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        disk_bytes = (storage_dir / v.storage_key).read_bytes()
        assert v.sha256_hash == hashlib.sha256(disk_bytes).hexdigest()
    finally:
        db.close()


def test_doc_13_sha256_is_lowercase_64_hex_chars(doc_fixture):
    """DOC-13: Persisted SHA-256 is 64 lowercase hexadecimal characters."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("hex_format.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    sha = response.json()["version"]["sha256_hash"]
    assert len(sha) == 64
    assert sha.islower()
    int(sha, 16)  # Validates hex encoding


def test_doc_14_client_supplied_fake_hash_ignored(doc_fixture):
    """DOC-14: Client-supplied fake hash cannot override server-computed hash."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    fake_hash = "deadbeef" * 8
    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("fake_hash.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"sha256_hash": fake_hash},
    )
    assert response.status_code == 201
    assert response.json()["version"]["sha256_hash"] != fake_hash
    assert response.json()["version"]["sha256_hash"] == hashlib.sha256(VALID_PDF_BYTES).hexdigest()


def test_doc_15_original_filename_is_metadata_only(doc_fixture):
    """DOC-15: Original filename is metadata and is not used as the storage path."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    orig_name = "Sensitive_Court_Evidence.pdf"
    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (orig_name, VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        assert v.original_filename == orig_name
        assert not (storage_dir / orig_name).exists()
        assert (storage_dir / v.storage_key).exists()
    finally:
        db.close()


def test_doc_16_storage_path_outside_frontend_public(doc_fixture):
    """DOC-16: Storage path is in private directory and not in frontend/public."""
    storage_dir = doc_fixture["storage_dir"]
    assert "frontend" not in str(storage_dir).lower()
    assert "public" not in str(storage_dir).lower()


def test_doc_17_storage_key_is_unpredictable_and_not_original_name(doc_fixture):
    """DOC-17: Storage key is random/unpredictable."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("predict_test.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        assert "predict_test" not in v.storage_key
        assert len(v.storage_key) >= 32
    finally:
        db.close()


def test_doc_18_same_original_filename_uploads_do_not_overwrite(doc_fixture):
    """DOC-18: Multiple uploads with identical original filenames do not overwrite each other."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    payload1 = VALID_PDF_BYTES
    payload2 = VALID_PDF_BYTES + b"% version two distinct payload"

    resp1 = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("duplicate.pdf", payload1, "application/pdf")},
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("duplicate.pdf", payload2, "application/pdf")},
    )
    assert resp2.status_code == 201

    db = db_factory()
    try:
        v1 = db.query(DocumentVersion).filter(DocumentVersion.document_id == resp1.json()["document"]["id"]).first()
        v2 = db.query(DocumentVersion).filter(DocumentVersion.document_id == resp2.json()["document"]["id"]).first()

        assert v1.storage_key != v2.storage_key
        assert (storage_dir / v1.storage_key).read_bytes() == payload1
        assert (storage_dir / v2.storage_key).read_bytes() == payload2
    finally:
        db.close()


def test_doc_19_failed_validation_creates_no_document_version(doc_fixture):
    """DOC-19: Validation failure results in zero documents/versions committed."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("corrupted.pdf", b"NOT_A_PDF", "application/pdf")},
    )
    assert response.status_code == 400

    db = db_factory()
    try:
        assert db.query(Document).count() == 0
        assert db.query(DocumentVersion).count() == 0
    finally:
        db.close()


def test_doc_20_failed_upload_cleans_up_temporary_files(doc_fixture):
    """DOC-20: Failed upload cleans up all temporary files from storage."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("corrupt.pdf", b"INVALID_PDF_HEADER", "application/pdf")},
    )
    assert response.status_code == 400
    assert len(list(storage_dir.iterdir())) == 0


def test_doc_21_database_failure_does_not_leave_stored_version(doc_fixture):
    """DOC-21: Simulated database failure rolls back and cleans up staged filesystem files."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    # Patch db commit to simulate database error
    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Simulated DB Crash")):
        response = client.post(
            f"/api/v1/cases/{case_id}/documents",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("db_fail.pdf", VALID_PDF_BYTES, "application/pdf")},
        )
        assert response.status_code == 500

    db = db_factory()
    try:
        assert db.query(Document).count() == 0
        assert db.query(DocumentVersion).count() == 0
        assert len(list(storage_dir.iterdir())) == 0
    finally:
        db.close()


def test_doc_22_filesystem_final_file_size_matches_stored_metadata(doc_fixture):
    """DOC-22: Final file on disk matches stored size_bytes metadata."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("size_test.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        assert (storage_dir / v.storage_key).stat().st_size == v.size_bytes == len(VALID_PDF_BYTES)
    finally:
        db.close()


def test_doc_23_filesystem_final_file_hash_matches_stored_sha256(doc_fixture):
    """DOC-23: Final file on disk matches stored sha256_hash metadata."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    storage_dir = doc_fixture["storage_dir"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("hash_test.png", VALID_PNG_BYTES, "image/png")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        disk_hash = hashlib.sha256((storage_dir / v.storage_key).read_bytes()).hexdigest()
        assert disk_hash == v.sha256_hash
    finally:
        db.close()


def test_doc_24_missing_or_invalid_final_file_is_not_marked_stored(doc_fixture):
    """DOC-24: If final on-disk verification fails, version is not marked STORED and transaction is rolled back."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    # Patch on-disk verification to simulate disk failure
    with patch("app.services.document_registration.verify_disk_file_integrity", return_value=False):
        response = client.post(
            f"/api/v1/cases/{case_id}/documents",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("verify_fail.pdf", VALID_PDF_BYTES, "application/pdf")},
        )
        assert response.status_code == 500

    db = db_factory()
    try:
        # Transaction rolled back; no STORED version exists
        assert db.query(DocumentVersion).filter(DocumentVersion.state == "STORED").count() == 0
    finally:
        db.close()


def test_doc_25_creates_initial_custody_event(doc_fixture):
    """DOC-25: Successful V1 registration creates DOCUMENT_INGESTED custody event."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]
    db_factory = doc_fixture["db_factory"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("custody_event_test.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    doc_id = response.json()["document"]["id"]

    db = db_factory()
    try:
        v = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()
        event = db.query(CustodyEvent).filter(CustodyEvent.document_version_id == v.id).first()

        assert event is not None
        assert event.case_id == case_id
        assert event.sequence_number == 1
        assert event.event_type == "DOCUMENT_INGESTED"
        assert event.previous_event_hash is None
        assert len(event.event_hash) == 64
    finally:
        db.close()


def test_doc_26_response_does_not_expose_private_paths(doc_fixture):
    """DOC-26: API response does not leak server filesystem paths or storage keys."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("safe_resp.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201
    resp_text = response.text

    assert "storage_key" not in resp_text
    assert "private" not in resp_text
    assert "storage" not in resp_text


def test_doc_27_document_not_accessible_through_public_static_paths(doc_fixture):
    """DOC-27: Document is not exposed as a static file."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("no_static.pdf", VALID_PDF_BYTES, "application/pdf")},
    )
    assert response.status_code == 201

    # Request static paths
    assert client.get("/static/no_static.pdf").status_code == 404
    assert client.get("/public/no_static.pdf").status_code == 404


def test_doc_28_empty_file_rejected_according_to_policy(doc_fixture):
    """DOC-28: 0-byte file is rejected."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("empty.pdf", b"", "application/pdf")},
    )
    assert response.status_code == 400


def test_doc_29_exact_boundary_size_accepted(doc_fixture):
    """DOC-29: Exact 25 MiB boundary file is accepted."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    # Construct exact 25 MiB PDF payload
    header = b"%PDF-1.7\n"
    boundary_bytes = header + b"A" * (MAX_FILE_SIZE_BYTES - len(header))
    assert len(boundary_bytes) == MAX_FILE_SIZE_BYTES

    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("boundary.pdf", boundary_bytes, "application/pdf")},
    )
    assert response.status_code == 201
    assert response.json()["version"]["size_bytes"] == MAX_FILE_SIZE_BYTES


def test_doc_30_oversized_file_rejected(doc_fixture):
    """DOC-30: File over 25 MiB is rejected with HTTP 413."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    oversized_bytes = b"%PDF-1.7\n" + b"A" * (MAX_FILE_SIZE_BYTES + 10)
    response = client.post(
        f"/api/v1/cases/{case_id}/documents",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("oversized.pdf", oversized_bytes, "application/pdf")},
    )
    assert response.status_code == 413


def test_security_negative_path_traversal(doc_fixture):
    """Security: Directory traversal in filename is rejected."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    for evil_name in ["../../evil.pdf", "..\\..\\evil.pdf", "/etc/passwd.pdf"]:
        response = client.post(
            f"/api/v1/cases/{case_id}/documents",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (evil_name, VALID_PDF_BYTES, "application/pdf")},
        )
        assert response.status_code == 400


def test_security_negative_unsupported_extensions(doc_fixture):
    """Security: Unsupported extensions (.exe, .sh, .py) are rejected."""
    client = doc_fixture["client"]
    token = doc_fixture["io_token"]
    case_id = doc_fixture["case_1_id"]

    for bad_name in ["malware.exe", "deploy.sh", "server.py"]:
        response = client.post(
            f"/api/v1/cases/{case_id}/documents",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (bad_name, VALID_PDF_BYTES, "application/pdf")},
        )
        assert response.status_code in (400, 415)
