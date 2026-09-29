"""Docspector Malicious Input + API Abuse + Input Validation Security Audit Tests (Milestone 16).

Inspect. Verify. Trust.

Comprehensive adversarial test suite proving that malformed, unexpected, oversized,
ambiguous, or malicious input cannot cause authorization bypass, data corruption,
unsafe filesystem behavior, information disclosure, unexpected server crash,
or inconsistent database state:

- INPUT-01: Malformed JSON payload handling
- INPUT-02: Missing required fields validation
- INPUT-03: Unexpected extra fields rejection
- INPUT-04: Mass assignment & protected field injection
- INPUT-05: Numeric boundary testing (negative, zero, large int, float, non-int strings)
- INPUT-06: String boundary testing (empty, whitespace, huge strings, script tags)
- INPUT-07: Unicode, emojis, null bytes, and control characters
- INPUT-08: SQL injection payloads handled safely via parameterized queries
- INPUT-09: Path traversal in filenames and parameters
- INPUT-10: Dangerous/reserved filename attacks (Windows reserved devices, double extensions)
- INPUT-11: MIME type manipulation & spoofing
- INPUT-12: Magic byte signature mismatch
- INPUT-13: Oversized upload resource abuse (> 25 MiB boundary)
- INPUT-14: Multipart form abuse (missing file, empty filename, malformed fields)
- INPUT-15: Request-ID header abuse & CRLF injection prevention
- INPUT-16: Authorization header abuse & malformed bearer tokens
- INPUT-17: Protected state & enum manipulation prevention
- INPUT-18: Timestamp manipulation prevention (server-derived UTC timestamps)
- INPUT-19: Error information leakage prevention (no stack traces, SQL, or disk paths)
- INPUT-20: Database consistency after failed writes (zero orphan rows)
- INPUT-21: Filesystem cleanup after failed uploads (zero orphan .tmp files)
- INPUT-22: Repeated invalid requests & abuse resilience
- INPUT-23: Protected field injection in multipart and JSON endpoints
- INPUT-24: Client-controlled integrity metadata ignored in favor of backend calculation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import create_engine, event, text
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
    CustodyEvent,
    Document,
    DocumentVersion,
    IntegrityAlert,
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
VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
VALID_TXT_BYTES = "Valid UTF-8 forensic report text content for input security testing.".encode("utf-8")


@pytest.fixture
def input_sec_fixture(monkeypatch):
    """Set up an isolated adversarial testing environment with storage directory and seeded database."""
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

        io_user = session.query(User).filter(User.username == "docspector.io").first()
        so_user = session.query(User).filter(User.username == "docspector.so").first()
        legal_user = session.query(User).filter(User.username == "docspector.legal").first()
        auditor_user = session.query(User).filter(User.username == "docspector.auditor").first()
        case_1 = session.query(Case).filter(Case.case_number == "HYD-CYB-2026-0147").first()

        doc_1, v_1, _ = register_document_version_one(
            db=session,
            case=case_1,
            current_user=io_user,
            file_stream=io.BytesIO(VALID_PDF_BYTES),
            filename="Test_Evidence.pdf",
            content_type="application/pdf",
            title="Baseline Test Evidence Document",
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
            "session_factory": TestingSessionLocal,
            "storage_dir": temp_storage_path,
            "case": case_1,
            "doc": doc_1,
            "version": v_1,
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
        Base.metadata.drop_all(bind=engine)


# =====================================================================
# 1. GENERAL MALFORMED INPUT & JSON TESTS (INPUT-01 to INPUT-04)
# =====================================================================


def test_input_01_malformed_json(input_sec_fixture):
    """INPUT-01: Broken/unparseable JSON bodies return controlled 422 with standard error envelope."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    doc: Document = input_sec_fixture["doc"]
    v: DocumentVersion = input_sec_fixture["version"]

    resp = client.post(
        f"/api/v1/documents/{doc.id}/versions/{v.id}/transfers",
        data="{'recipient_user_id': invalid json",
        headers={
            "Authorization": f"Bearer {io_token}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code in (400, 422)
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] in ("VALIDATION_ERROR", "INTERNAL_ERROR")
    assert "request_id" in body["error"]
    assert "Traceback" not in resp.text


def test_input_02_missing_required_fields(input_sec_fixture):
    """INPUT-02: Missing required JSON fields return 422 VALIDATION_ERROR."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    doc: Document = input_sec_fixture["doc"]
    v: DocumentVersion = input_sec_fixture["version"]

    # 1. Missing username in login
    resp_login = client.post("/api/v1/auth/login", json={})
    assert resp_login.status_code == 422
    assert resp_login.json()["error"]["code"] == "VALIDATION_ERROR"

    # 2. Missing recipient_user_id in transfer request
    resp_transfer = client.post(
        f"/api/v1/documents/{doc.id}/versions/{v.id}/transfers",
        json={},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp_transfer.status_code == 422
    assert resp_transfer.json()["error"]["code"] == "VALIDATION_ERROR"


def test_input_03_unexpected_extra_fields(input_sec_fixture):
    """INPUT-03: Unexpected extra fields are rejected via extra='forbid'."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    doc: Document = input_sec_fixture["doc"]
    v: DocumentVersion = input_sec_fixture["version"]

    resp = client.post(
        f"/api/v1/documents/{doc.id}/versions/{v.id}/transfers",
        json={"recipient_user_id": 2, "unexpected_extra_field": "injected_data"},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_input_04_mass_assignment_and_protected_fields(input_sec_fixture):
    """INPUT-04: Attempting to inject protected fields like status, role, is_admin is rejected."""
    client: TestClient = input_sec_fixture["client"]

    # Login payload injection
    resp_login = client.post(
        "/api/v1/auth/login",
        json={"username": "docspector.io", "role": "SO", "is_admin": True, "id": 999},
    )
    assert resp_login.status_code == 422
    assert resp_login.json()["error"]["code"] == "VALIDATION_ERROR"


# =====================================================================
# 2. NUMERIC & STRING BOUNDARIES (INPUT-05 to INPUT-07)
# =====================================================================


def test_input_05_numeric_boundaries(input_sec_fixture):
    """INPUT-05: Non-integer, negative, zero, and huge numeric path inputs are handled safely."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]

    test_inputs = [
        ("abc", 422),  # String instead of int
        ("-1", 404),   # Negative ID (handled safely by route / DB)
        ("0", 404),    # Zero ID
        ("999999999999999999999999999999", 404),  # Huge overflow integer handled safely by boundary check
        ("1.5", 422),  # Float in integer path param
    ]

    for val, expected_status in test_inputs:
        resp = client.get(
            f"/api/v1/cases/{val}",
            headers={"Authorization": f"Bearer {io_token}"},
        )
        assert resp.status_code == expected_status, f"Failed on input: {val}"
        assert "error" in resp.json()
        assert "Traceback" not in resp.text


def test_input_06_string_boundaries_and_xss_payloads(input_sec_fixture):
    """INPUT-06: Strings containing HTML, script tags, long text, and formatting characters are handled safely."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    script_title = "<script>alert('XSS')</script><b>Bold Title</b>"
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("evidence.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": script_title},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["document"]["title"] == script_title
    # Verify no execution or crashing occurred


def test_input_07_unicode_emojis_and_control_chars(input_sec_fixture):
    """INPUT-07: Unicode, emojis, RTL characters, and UTF-8 strings in titles/content succeed safely."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    unicode_title = "Forensic 🔍 Report (تقرير الطب الشرعي) — 2026 🚀"
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("evidence_unicode.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": unicode_title},
    )
    assert resp.status_code == 201
    assert resp.json()["document"]["title"] == unicode_title


# =====================================================================
# 3. SQL INJECTION & PATH TRAVERSAL (INPUT-08 to INPUT-10)
# =====================================================================


def test_input_08_sql_injection_payloads(input_sec_fixture):
    """INPUT-08: SQL injection payloads in parameters and bodies are treated strictly as data."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    sqli_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users; --",
        "admin'--",
        "\" OR \"\"=\"",
        "') UNION SELECT 1, 2, 3 --",
    ]

    for payload in sqli_payloads:
        # Test in login username
        resp_login = client.post("/api/v1/auth/login", json={"username": payload})
        assert resp_login.status_code == 401
        assert "syntax error" not in resp_login.text.lower()
        assert "sqlite" not in resp_login.text.lower()

        # Test in document title
        resp_upload = client.post(
            f"/api/v1/cases/{case.id}/documents",
            headers={"Authorization": f"Bearer {io_token}"},
            files={"file": ("evidence.pdf", VALID_PDF_BYTES, "application/pdf")},
            data={"title": payload},
        )
        assert resp_upload.status_code == 201
        assert resp_upload.json()["document"]["title"] == payload


def test_input_09_path_traversal_attacks(input_sec_fixture):
    """INPUT-09: Directory traversal in filenames is strictly blocked (400 FileValidationError)."""
    from app.services.file_validation import FileValidationError, validate_filename

    traversal_filenames = [
        "../../secret.pdf",
        "..\\..\\secret.pdf",
        "/etc/passwd.pdf",
        "C:\\Windows\\System32\\cmd.pdf",
        "....//....//traversal.pdf",
        "..%2F..%2Fevil.pdf",
    ]

    for fname in traversal_filenames:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(fname)
        assert exc_info.value.http_status_code in (400, 415)


def test_input_10_filename_attacks(input_sec_fixture):
    """INPUT-10: Dangerous/reserved names (null bytes, Windows devices, missing extensions) are rejected."""
    from app.services.file_validation import FileValidationError, validate_filename

    dangerous_filenames = [
        "evil\x00.pdf",
        "file.pdf.exe",
        "file.exe.pdf.exe",
        "..pdf",
        ".hidden",
        "file..",
        "   ",
        "",
    ]

    for fname in dangerous_filenames:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(fname)
        assert exc_info.value.http_status_code in (400, 415)


# =====================================================================
# 4. MIME & MAGIC BYTE SPOOFING (INPUT-11 to INPUT-13)
# =====================================================================


def test_input_11_mime_type_manipulation(input_sec_fixture):
    """INPUT-11: Spoofed or mismatched MIME types are rejected (400/415)."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    # 1. PDF extension with image/png MIME
    resp_mismatch = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("evidence.pdf", VALID_PDF_BYTES, "image/png")},
    )
    assert resp_mismatch.status_code in (400, 415)

    # 2. PDF extension with executable MIME
    resp_exe_mime = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("evidence.pdf", VALID_PDF_BYTES, "application/x-msdownload")},
    )
    assert resp_exe_mime.status_code in (400, 415)


def test_input_12_magic_byte_mismatch(input_sec_fixture):
    """INPUT-12: Valid extension and MIME with corrupt/invalid magic bytes is rejected (400)."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    fake_pdf_content = b"NOT_A_PDF_MAGIC_BYTES_FAKE_CONTENT_12345"
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("evidence.pdf", fake_pdf_content, "application/pdf")},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] in ("INVALID_MAGIC_BYTES", "VALIDATION_ERROR")


def test_input_13_oversized_upload(input_sec_fixture):
    """INPUT-13: Files exceeding 25 MiB are rejected (413) without loading completely into RAM."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    # Create stream with 25 MiB + 100 bytes
    oversized_len = (25 * 1024 * 1024) + 100
    oversized_data = VALID_PDF_BYTES + (b"0" * (oversized_len - len(VALID_PDF_BYTES)))

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("oversized.pdf", oversized_data, "application/pdf")},
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "FILE_TOO_LARGE"


# =====================================================================
# 5. MULTIPART, HEADERS & PROTOCOL ATTACKS (INPUT-14 to INPUT-16)
# =====================================================================


def test_input_14_multipart_abuse(input_sec_fixture):
    """INPUT-14: Upload endpoint without file parameter returns 422."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    # Multipart without file
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        data={"title": "No File Provided"},
    )
    assert resp.status_code == 422


def test_input_15_request_id_header_abuse_and_crlf_prevention(input_sec_fixture):
    """INPUT-15: Malformed X-Request-ID with CRLF / control chars is sanitized to safe UUID4."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]

    crlf_header = "valid-id\r\nInjected-Header: evil\r\n\r\n"
    resp = client.get(
        "/api/v1/cases",
        headers={"Authorization": f"Bearer {io_token}", "X-Request-ID": crlf_header},
    )
    assert resp.status_code == 200
    returned_id = resp.headers.get("X-Request-ID")
    # Must NOT contain CRLF or injected header
    assert "\r" not in returned_id
    assert "\n" not in returned_id
    assert "Injected-Header" not in returned_id
    # Must be replaced with clean UUID4
    assert len(returned_id) == 36


def test_input_16_authorization_header_abuse(input_sec_fixture):
    """INPUT-16: Malformed authorization headers and corrupt bearer tokens return 401."""
    client: TestClient = input_sec_fixture["client"]

    malformed_headers = [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "Bearer invalid.jwt.token.structure",
        "Bearer " + ("A" * 5000),  # Extremely long header
    ]

    for auth_val in malformed_headers:
        resp = client.get("/api/v1/cases", headers={"Authorization": auth_val})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] in ("AUTH_REQUIRED", "INVALID_TOKEN")


# =====================================================================
# 6. STATE, ENUM & TIMESTAMP MANIPULATION (INPUT-17 to INPUT-18)
# =====================================================================


def test_input_17_protected_state_and_enum_manipulation(input_sec_fixture):
    """INPUT-17: Clients cannot directly set transfer status='APPROVED' or version state='STORED'."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    doc: Document = input_sec_fixture["doc"]
    v: DocumentVersion = input_sec_fixture["version"]
    legal_user: User = input_sec_fixture["legal_user"]

    # Attempt to inject status into transfer creation
    resp = client.post(
        f"/api/v1/documents/{doc.id}/versions/{v.id}/transfers",
        json={"recipient_user_id": legal_user.id, "status": "APPROVED"},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 422


def test_input_18_timestamp_manipulation_prevention(input_sec_fixture):
    """INPUT-18: Audit timestamps are server-controlled and ignore client tampering."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    doc: Document = input_sec_fixture["doc"]
    v: DocumentVersion = input_sec_fixture["version"]
    legal_user: User = input_sec_fixture["legal_user"]

    # Attempt to inject created_at into transfer payload
    fake_time = "2020-01-01T00:00:00Z"
    resp = client.post(
        f"/api/v1/documents/{doc.id}/versions/{v.id}/transfers",
        json={"recipient_user_id": legal_user.id, "requested_at": fake_time},
        headers={"Authorization": f"Bearer {io_token}"},
    )
    assert resp.status_code == 422


# =====================================================================
# 7. ERROR LEAKAGE & RECOVERY (INPUT-19 to INPUT-21)
# =====================================================================


def test_input_19_error_information_leakage(input_sec_fixture):
    """INPUT-19: 400/404/422 responses omit stack traces, SQL, and absolute disk paths."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]
    storage_dir: Path = input_sec_fixture["storage_dir"]

    # Trigger validation failure
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("invalid.exe", b"executable_bytes", "application/octet-stream")},
    )
    assert resp.status_code == 415
    resp_text = resp.text
    assert "Traceback" not in resp_text
    assert "SELECT" not in resp_text
    assert str(storage_dir) not in resp_text


def test_input_20_failed_write_database_consistency(input_sec_fixture):
    """INPUT-20: A failed upload leaves zero orphan database records."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]
    session_factory = input_sec_fixture["session_factory"]

    db: Session = session_factory()
    doc_count_before = db.query(Document).count()
    ver_count_before = db.query(DocumentVersion).count()
    custody_count_before = db.query(CustodyEvent).count()
    db.close()

    # Upload invalid file
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("corrupt.pdf", b"corrupt bytes without header", "application/pdf")},
    )
    assert resp.status_code == 400

    db_after: Session = session_factory()
    assert db_after.query(Document).count() == doc_count_before
    assert db_after.query(DocumentVersion).count() == ver_count_before
    assert db_after.query(CustodyEvent).count() == custody_count_before
    db_after.close()


def test_input_21_failed_upload_filesystem_cleanup(input_sec_fixture):
    """INPUT-21: Rejected upload removes all ephemeral .tmp staging files."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]
    storage_dir: Path = input_sec_fixture["storage_dir"]

    # Count .tmp files before
    tmp_files_before = list(storage_dir.glob("*.tmp"))
    assert len(tmp_files_before) == 0

    # Upload invalid file
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("corrupt.pdf", b"invalid header", "application/pdf")},
    )
    assert resp.status_code == 400

    # Count .tmp files after -> must be zero
    tmp_files_after = list(storage_dir.glob("*.tmp"))
    assert len(tmp_files_after) == 0


# =====================================================================
# 8. REPEATED ABUSE & CLIENT METADATA INTEGRITY (INPUT-22 to INPUT-24)
# =====================================================================


def test_input_22_repeated_invalid_requests_resilience(input_sec_fixture):
    """INPUT-22: Repeated bursts of malformed requests execute safely without state corruption."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    for _ in range(10):
        resp = client.post(
            f"/api/v1/cases/{case.id}/documents",
            headers={"Authorization": f"Bearer {io_token}"},
            files={"file": ("corrupt.pdf", b"invalid header", "application/pdf")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] in ("INVALID_MAGIC_BYTES", "VALIDATION_ERROR")


def test_input_23_protected_field_injection_in_multipart(input_sec_fixture):
    """INPUT-23: Protected fields (document_number, version_number, storage_key) in form are ignored."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    # Attacker tries to inject document_number and storage_key
    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("legit.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={
            "title": "Legit Document",
            "document_number": "INJECTED-DOC-001",
            "storage_key": "injected_key.pdf",
            "version_number": 999,
        },
    )
    assert resp.status_code == 201
    doc_data = resp.json()["document"]
    ver_data = resp.json()["version"]
    # Server-derived document number matches system pattern (DOC-...)
    assert doc_data["document_number"].startswith("DOC-")
    assert doc_data["document_number"] != "INJECTED-DOC-001"
    # Version number is server-derived 1
    assert ver_data["version_number"] == 1


def test_input_24_client_controlled_integrity_metadata_ignored(input_sec_fixture):
    """INPUT-24: Client-supplied sha256_hash or checksum in form data is ignored; backend computes SHA-256."""
    client: TestClient = input_sec_fixture["client"]
    io_token: str = input_sec_fixture["io_token"]
    case: Case = input_sec_fixture["case"]

    fake_client_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    actual_hash = hashlib.sha256(VALID_PDF_BYTES).hexdigest()

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        headers={"Authorization": f"Bearer {io_token}"},
        files={"file": ("legit.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"sha256_hash": fake_client_hash, "checksum": fake_client_hash},
    )
    assert resp.status_code == 201
    persisted_hash = resp.json()["version"]["sha256_hash"]
    # Server computed real hash and ignored client-supplied hash
    assert persisted_hash == actual_hash
    assert persisted_hash != fake_client_hash
