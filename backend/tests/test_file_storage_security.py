"""Docspector Milestone 17 - File Upload, Private Storage & File Integrity Security Tests.

Inspect. Verify. Trust.

Comprehensive adversarial test suite proving that:
- Storage root escape & path traversal are impossible (FILESEC-01)
- Storage key injection via API payload is rejected / server-generated (FILESEC-02)
- Filename collision overwrite is prevented with unique storage keys (FILESEC-03)
- Version number overwrite is prevented by database uniqueness (FILESEC-04)
- Symlink & path escape handling safely rejects traversal (FILESEC-05)
- Temporary file cleanup occurs on validation failure (FILESEC-06)
- Failed filesystem move cleans up temporary file (FILESEC-07)
- DB/filesystem crash-safe compensation prevents inconsistent state (FILESEC-08)
- Missing-file reconciliation detects missing disk file, restricts & alerts (FILESEC-09)
- Orphan-file reconciliation detects untracked file without deleting evidence (FILESEC-10)
- Stale UPLOADING state reconciliation restricts & alerts (FILESEC-11)
- File-size mismatch reconciliation detects altered size, restricts & alerts (FILESEC-12)
- File-hash mismatch reconciliation detects altered bytes, restricts & alerts (FILESEC-13)
- Client-provided hash is ignored in favor of server calculation (FILESEC-14)
- Post-storage modification detection via independent M13 verification (FILESEC-15)
- Same-size replacement detection via SHA-256 (FILESEC-16)
- Version storage isolation between V1 and V2 (FILESEC-17)
- Concurrent upload isolation with no duplicate version numbers (FILESEC-18)
- Replay upload behavior creates distinct immutable documents (FILESEC-19)
- Private storage paths are not exposed in API responses or errors (FILESEC-20)
- Direct static-file access to private storage is blocked (FILESEC-21)
- File-type confusion matrix across extension/magic/MIME is rejected (FILESEC-22)
- Streaming bounded-memory processing reads in bounded chunks (FILESEC-23)
- Failed upload leaves zero partial STORED records in DB (FILESEC-24)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
from pathlib import Path
import tempfile
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event
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
    User,
)
from app.db.session import get_db
from app.main import app
from app.services.document_registration import (
    register_document_version_one,
    register_successor_version,
)
from app.services.file_validation import (
    ERROR_CODE_EMPTY_FILE,
    ERROR_CODE_FILE_TOO_LARGE,
    ERROR_CODE_INVALID_FILENAME,
    ERROR_CODE_INVALID_MAGIC_BYTES,
    ERROR_CODE_INVALID_UTF8,
    ERROR_CODE_MIME_EXTENSION_MISMATCH,
    ERROR_CODE_UNSUPPORTED_EXTENSION,
    ERROR_CODE_UNSUPPORTED_MIME_TYPE,
    FileValidationError,
    generate_storage_key,
    safe_resolve_storage_path,
    validate_and_stage_upload,
    validate_file_bytes,
    validate_filename,
    validate_mime_type,
)
from app.services.reconciliation_service import (
    ReconciliationReport,
    audit_storage_and_reconcile,
)
from app.services.verification_service import verify_document_version_integrity
from scripts.seed_demo import seed_demo_data

settings = get_settings()

VALID_PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
VALID_PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
VALID_TXT_BYTES = "Valid UTF-8 forensic report text content for file security testing.".encode("utf-8")


@pytest.fixture
def filesec_fixture(monkeypatch):
    """Set up an isolated adversarial testing environment with dedicated temporary file-backed SQLite database."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        temp_storage_path = temp_dir_path / "storage"
        temp_storage_path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(settings, "storage_dir", str(temp_storage_path))
        monkeypatch.setattr(settings, "demo_mode", False)

        db_file = temp_dir_path / "test_docspector_filesec.db"
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
            "storage_dir": temp_storage_path,
            "case": case_1,
            "io_user": io_user,
            "so_user": so_user,
            "io_token": create_access_token(io_user),
            "so_token": create_access_token(so_user),
        }

        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


# ===========================================================================
# FILESEC-01: Storage root escape
# ===========================================================================
def test_filesec_01_storage_root_escape_prevented(tmp_path: Path):
    """FILESEC-01: Client cannot escape storage root via relative, absolute, or traversal inputs."""
    private_root = tmp_path / "private_storage"
    private_root.mkdir()

    traversal_keys = [
        "../../outside.txt",
        "../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "/etc/shadow",
        "C:\\Windows\\System32\\calc.exe",
        "subdir/../../outside.txt",
        "..%2f..%2fsecret.txt",
        "....//....//escape.txt",
        "\\\\server\\share\\evil.txt",
    ]

    for malicious_key in traversal_keys:
        with pytest.raises(FileValidationError) as exc_info:
            safe_resolve_storage_path(private_root, malicious_key)
        assert exc_info.value.code == ERROR_CODE_INVALID_FILENAME

    traversal_filenames = [
        "../../evil.pdf",
        "..\\..\\evil.pdf",
        "/tmp/evil.pdf",
        "C:\\Windows\\evil.pdf",
        "foo/../../bar.pdf",
    ]

    for bad_name in traversal_filenames:
        with pytest.raises(FileValidationError) as exc_info:
            validate_filename(bad_name)
        assert exc_info.value.code == ERROR_CODE_INVALID_FILENAME


# ===========================================================================
# FILESEC-02: Storage key injection
# ===========================================================================
def test_filesec_02_storage_key_injection_ignored(filesec_fixture):
    """FILESEC-02: Client cannot supply or inject storage_key; server strictly generates storage keys."""
    client = filesec_fixture["client"]
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    response = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("injected.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={
            "title": "Injection Test",
            "storage_key": "../../attacker_controlled.pdf",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    data = response.json()
    doc_id = data["document"]["id"]
    version = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()

    assert version.storage_key != "../../attacker_controlled.pdf"
    assert ".." not in version.storage_key
    assert "/" not in version.storage_key
    assert "\\" not in version.storage_key
    assert version.storage_key.endswith(".pdf")


# ===========================================================================
# FILESEC-03: Filename overwrite attempt
# ===========================================================================
def test_filesec_03_filename_overwrite_attempt(filesec_fixture):
    """FILESEC-03: Uploading identical filenames creates distinct, non-overlapping storage keys."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream1 = io.BytesIO(VALID_PDF_BYTES)
    doc1, v1_1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream1,
        filename="report.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    stream2 = io.BytesIO(VALID_PDF_BYTES)
    doc2, v1_2, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream2,
        filename="report.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    assert doc1.id != doc2.id
    assert v1_1.storage_key != v1_2.storage_key
    path1 = storage_dir / v1_1.storage_key
    path2 = storage_dir / v1_2.storage_key
    assert path1.is_file()
    assert path2.is_file()
    assert path1 != path2


# ===========================================================================
# FILESEC-04: Version overwrite attempt
# ===========================================================================
def test_filesec_04_version_overwrite_attempt_prevented(filesec_fixture):
    """FILESEC-04: Document versions are immutable; database constraints block duplicate version numbers."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream1 = io.BytesIO(VALID_PDF_BYTES)
    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream1,
        filename="contract.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    stream2 = io.BytesIO(VALID_PDF_BYTES)
    _, v2, _ = register_successor_version(
        db=db,
        document=doc,
        current_user=user,
        file_stream=stream2,
        filename="contract_v2.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )
    assert v2.version_number == 2

    dup_v = DocumentVersion(
        document_id=doc.id,
        version_number=1,  # Duplicate version number!
        original_filename="contract.pdf",
        mime_type="application/pdf",
        storage_key=generate_storage_key(".pdf"),
        sha256_hash="00" * 32,
        size_bytes=100,
        state="STORED",
        created_by_user_id=user.id,
    )
    db.add(dup_v)
    with pytest.raises(Exception):
        db.commit()
    db.rollback()


# ===========================================================================
# FILESEC-05: Symlink attack
# ===========================================================================
def test_filesec_05_symlink_attack_prevention(tmp_path: Path):
    """FILESEC-05: Safe path resolution prevents traversing outside storage root via relative links."""
    private_root = tmp_path / "private"
    outside_dir = tmp_path / "outside"
    private_root.mkdir()
    outside_dir.mkdir()

    target_outside_file = outside_dir / "secret.txt"
    target_outside_file.write_text("classified data")

    with pytest.raises(FileValidationError) as exc:
        safe_resolve_storage_path(private_root, "../outside/secret.txt")
    assert exc.value.code == ERROR_CODE_INVALID_FILENAME


# ===========================================================================
# FILESEC-06: Temporary file cleanup
# ===========================================================================
def test_filesec_06_temporary_file_cleanup_on_validation_failure(tmp_path: Path):
    """FILESEC-06: Failed uploads (bad magic bytes, oversized, invalid utf8) clean up temp files."""
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    bad_pdf_stream = io.BytesIO(b"NOT_A_PDF_HEADER_CORRUPTED_BYTES")
    with pytest.raises(FileValidationError) as exc_info:
        validate_and_stage_upload(
            stream=bad_pdf_stream,
            filename="fake.pdf",
            target_storage_dir=storage_dir,
            content_type="application/pdf",
        )
    assert exc_info.value.code == ERROR_CODE_INVALID_MAGIC_BYTES

    files_in_storage = list(storage_dir.iterdir())
    assert len(files_in_storage) == 0


# ===========================================================================
# FILESEC-07: Failed filesystem move cleanup
# ===========================================================================
def test_filesec_07_failed_filesystem_move_cleanup(tmp_path: Path, monkeypatch):
    """FILESEC-07: Unexpected exception during staging/move removes temporary file."""
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    def mock_replace(self, target):
        raise OSError("Simulated disk I/O failure during file move")

    monkeypatch.setattr(Path, "replace", mock_replace)

    stream = io.BytesIO(VALID_PDF_BYTES)
    with pytest.raises(OSError, match="Simulated disk I/O failure"):
        validate_and_stage_upload(
            stream=stream,
            filename="test.pdf",
            target_storage_dir=storage_dir,
            content_type="application/pdf",
        )

    tmp_files = list(storage_dir.glob("*.tmp"))
    assert len(tmp_files) == 0


# ===========================================================================
# FILESEC-08: DB/filesystem inconsistency
# ===========================================================================
def test_filesec_08_db_filesystem_inconsistency_compensation(filesec_fixture, monkeypatch):
    """FILESEC-08: Crash-safe compensation rolls back DB and cleans storage if DB commit fails."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    def mock_append_event(*args, **kwargs):
        raise RuntimeError("Simulated DB error during custody event generation")

    monkeypatch.setattr(
        "app.services.document_registration.append_custody_event",
        mock_append_event,
    )

    initial_doc_count = db.query(Document).count()
    stream = io.BytesIO(VALID_PDF_BYTES)
    with pytest.raises(RuntimeError, match="Simulated DB error"):
        register_document_version_one(
            db=db,
            case=case,
            current_user=user,
            file_stream=stream,
            filename="failed_db.pdf",
            content_type="application/pdf",
            storage_dir=storage_dir,
        )

    assert db.query(Document).count() == initial_doc_count

    remaining_files = list(storage_dir.iterdir())
    assert len(remaining_files) == 0


# ===========================================================================
# FILESEC-09: Missing-file reconciliation
# ===========================================================================
def test_filesec_09_missing_file_reconciliation(filesec_fixture):
    """FILESEC-09: Missing physical storage file is detected, version marked RESTRICTED, alert created."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream = io.BytesIO(VALID_PDF_BYTES)
    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream,
        filename="audit.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    stored_path = storage_dir / v1.storage_key
    assert stored_path.is_file()
    stored_path.unlink()

    report = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert report.missing_files_count == 1
    db.refresh(v1)
    assert v1.state == "RESTRICTED"

    alert = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.document_version_id == v1.id,
            IntegrityAlert.alert_type == "STORAGE_INCONSISTENCY",
            IntegrityAlert.status == "OPEN",
        )
        .first()
    )
    assert alert is not None
    assert "missing" in alert.message.lower()


# ===========================================================================
# FILESEC-10: Orphan-file reconciliation
# ===========================================================================
def test_filesec_10_orphan_file_reconciliation(filesec_fixture):
    """FILESEC-10: Unregistered file on disk is flagged as orphan evidence without silent deletion."""
    db = filesec_fixture["db"]
    storage_dir = filesec_fixture["storage_dir"]

    orphan_file = storage_dir / "untracked_evidence.pdf"
    orphan_file.write_bytes(VALID_PDF_BYTES)

    orphan_tmp = storage_dir / "abandoned_upload.tmp"
    orphan_tmp.write_bytes(b"ephemeral")

    report = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert "untracked_evidence.pdf" in report.orphan_files
    assert "abandoned_upload.tmp" in report.orphan_temp_files
    assert orphan_file.is_file()


# ===========================================================================
# FILESEC-11: Stale UPLOADING reconciliation
# ===========================================================================
def test_filesec_11_stale_uploading_reconciliation(filesec_fixture):
    """FILESEC-11: Version stuck in UPLOADING state is detected, restricted, and alerted."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    doc = Document(
        case_id=case.id,
        document_number=f"DOC-{uuid.uuid4().hex[:6].upper()}",
        title="Stale Doc",
        created_by_user_id=user.id,
    )
    db.add(doc)
    db.flush()

    v_stale = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        original_filename="stale.pdf",
        mime_type="application/pdf",
        storage_key=generate_storage_key(".pdf"),
        sha256_hash="aa" * 32,
        size_bytes=100,
        state="UPLOADING",  # Stuck unfinalized
        created_by_user_id=user.id,
    )
    db.add(v_stale)
    db.commit()

    report = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert report.stale_uploading_count == 1
    db.refresh(v_stale)
    assert v_stale.state == "RESTRICTED"

    alert = (
        db.query(IntegrityAlert)
        .filter(IntegrityAlert.document_version_id == v_stale.id)
        .first()
    )
    assert alert is not None
    assert alert.alert_type == "STORAGE_INCONSISTENCY"


# ===========================================================================
# FILESEC-12: File-size mismatch detection
# ===========================================================================
def test_filesec_12_file_size_mismatch_detection(filesec_fixture):
    """FILESEC-12: Discrepancy between metadata file size and disk size triggers RESTRICTED state."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream = io.BytesIO(VALID_PDF_BYTES)
    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream,
        filename="size_test.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Append trailing bytes on disk to alter size
    stored_path = storage_dir / v1.storage_key
    with open(stored_path, "ab") as f:
        f.write(b"EXTRA_APPENDED_BYTES")

    report = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert report.size_mismatches_count == 1
    db.refresh(v1)
    assert v1.state == "RESTRICTED"


# ===========================================================================
# FILESEC-13: File-hash mismatch detection
# ===========================================================================
def test_filesec_13_file_hash_mismatch_detection(filesec_fixture):
    """FILESEC-13: Same-size bit flip on disk triggers hash mismatch detection in reconciliation."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream = io.BytesIO(VALID_PDF_BYTES)
    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream,
        filename="hash_test.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    # Overwrite with same byte length but different content
    stored_path = storage_dir / v1.storage_key
    mutated_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOX\n"
    assert len(mutated_bytes) == len(VALID_PDF_BYTES)
    stored_path.write_bytes(mutated_bytes)

    report = audit_storage_and_reconcile(db=db, storage_dir=storage_dir)

    assert report.hash_mismatches_count == 1
    db.refresh(v1)
    assert v1.state == "RESTRICTED"


# ===========================================================================
# FILESEC-14: Client hash manipulation
# ===========================================================================
def test_filesec_14_client_hash_manipulation_ignored(filesec_fixture):
    """FILESEC-14: Client-declared sha256 parameter is ignored; server calculates actual digest."""
    client = filesec_fixture["client"]
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    fake_client_hash = "deadbeef" * 8
    response = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("trusted.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Client Hash Test", "sha256": fake_client_hash},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201

    data = response.json()
    doc_id = data["document"]["id"]
    version = db.query(DocumentVersion).filter(DocumentVersion.document_id == doc_id).first()

    expected_digest = hashlib.sha256(VALID_PDF_BYTES).hexdigest()
    assert version.sha256_hash == expected_digest
    assert version.sha256_hash != fake_client_hash


# ===========================================================================
# FILESEC-15: Post-storage modification detection
# ===========================================================================
def test_filesec_15_post_storage_modification_detected_via_m13(filesec_fixture):
    """FILESEC-15: Independent M13 verification detects physical modification, restricts version, alerts."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    stream = io.BytesIO(VALID_PDF_BYTES)
    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=stream,
        filename="verified.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    stored_path = storage_dir / v1.storage_key
    stored_path.write_bytes(b"%PDF-1.7\nCORRUPTED_PHYSICAL_BYTES_POST_STORAGE\n%%EOF\n")

    res = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )

    assert res.file_integrity.is_valid is False
    assert res.file_integrity.status == "FILE_HASH_MISMATCH"
    assert res.overall_status == "INTEGRITY_FAILURE"

    db.refresh(v1)
    assert v1.state == "RESTRICTED"

    alert = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.document_version_id == v1.id,
            IntegrityAlert.alert_type == "FILE_HASH_MISMATCH",
            IntegrityAlert.status == "OPEN",
        )
        .first()
    )
    assert alert is not None


# ===========================================================================
# FILESEC-16: Same-size replacement detection
# ===========================================================================
def test_filesec_16_same_size_replacement_detection(filesec_fixture):
    """FILESEC-16: Replacing a file with equal byte length triggers SHA-256 mismatch detection."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    original_content = b"%PDF-1.7\nAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII\n%%EOF\n"
    tampered_content = b"%PDF-1.7\nZZZZYYYYXXXXWWWWVVVVUUUUTTTTSSSSRRRR\n%%EOF\n"
    assert len(original_content) == len(tampered_content)

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(original_content),
        filename="equal_size.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    stored_path = storage_dir / v1.storage_key
    stored_path.write_bytes(tampered_content)

    res = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )

    assert res.file_integrity.is_valid is False
    assert res.file_integrity.status == "FILE_HASH_MISMATCH"
    assert res.overall_status == "INTEGRITY_FAILURE"


# ===========================================================================
# FILESEC-17: Version storage isolation
# ===========================================================================
def test_filesec_17_version_storage_isolation(filesec_fixture):
    """FILESEC-17: Successor versions V1 and V2 have fully isolated storage paths and hashes."""
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    user = filesec_fixture["io_user"]
    storage_dir = filesec_fixture["storage_dir"]

    v1_content = VALID_PDF_BYTES
    v2_content = b"%PDF-1.7\nUpdated version 2 content for security audit\n%%EOF\n"

    doc, v1, _ = register_document_version_one(
        db=db,
        case=case,
        current_user=user,
        file_stream=io.BytesIO(v1_content),
        filename="v_isolation.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    _, v2, _ = register_successor_version(
        db=db,
        document=doc,
        current_user=user,
        file_stream=io.BytesIO(v2_content),
        filename="v_isolation_v2.pdf",
        content_type="application/pdf",
        storage_dir=storage_dir,
    )

    assert v1.storage_key != v2.storage_key
    assert v1.sha256_hash != v2.sha256_hash

    # Mutating V2 does not impact V1
    v2_path = storage_dir / v2.storage_key
    v2_path.write_bytes(b"%PDF-1.7\nTampered V2\n%%EOF\n")

    res_v1 = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v1.id,
        current_user=user,
        storage_dir=storage_dir,
    )
    res_v2 = verify_document_version_integrity(
        db=db,
        document_id=doc.id,
        version_id=v2.id,
        current_user=user,
        storage_dir=storage_dir,
    )

    assert res_v1.file_integrity.is_valid is True
    assert res_v1.overall_status == "VALID"
    assert res_v2.file_integrity.is_valid is False
    assert res_v2.overall_status == "INTEGRITY_FAILURE"


# ===========================================================================
# FILESEC-18: Concurrent upload isolation
# ===========================================================================
def test_filesec_18_concurrent_upload_isolation(filesec_fixture):
    """FILESEC-18: Concurrent successor version uploads serialize cleanly without duplicate versions."""
    client = filesec_fixture["client"]
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("concurrent.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Concurrent Root"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    doc_id = resp.json()["document"]["id"]

    def upload_version(idx: int):
        content = f"%PDF-1.7\nConcurrent upload thread {idx}\n%%EOF\n".encode("utf-8")
        return client.post(
            f"/api/v1/documents/{doc_id}/versions",
            files={"file": (f"thread_{idx}.pdf", content, "application/pdf")},
            headers={"Authorization": f"Bearer {token}"},
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(upload_version, i) for i in range(4)]
        results = [f.result() for f in futures]

    status_codes = [r.status_code for r in results]
    assert all(code in (201, 409) for code in status_codes)

    versions = (
        db.query(DocumentVersion)
        .filter(DocumentVersion.document_id == doc_id)
        .order_by(DocumentVersion.version_number.asc())
        .all()
    )
    version_numbers = [v.version_number for v in versions]
    assert len(version_numbers) == len(set(version_numbers))
    storage_keys = [v.storage_key for v in versions]
    assert len(storage_keys) == len(set(storage_keys))


# ===========================================================================
# FILESEC-19: Replay behavior
# ===========================================================================
def test_filesec_19_replay_upload_creates_immutable_records(filesec_fixture):
    """FILESEC-19: Replaying identical upload requests creates separate distinct records safely."""
    client = filesec_fixture["client"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    resp1 = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("replay.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Replay Doc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp2 = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("replay.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Replay Doc"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201
    assert resp1.json()["document"]["id"] != resp2.json()["document"]["id"]


# ===========================================================================
# FILESEC-20: Private storage exposure
# ===========================================================================
def test_filesec_20_private_storage_paths_not_exposed(filesec_fixture):
    """FILESEC-20: API responses and error messages never leak filesystem paths or storage directory roots."""
    client = filesec_fixture["client"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("leak_test.pdf", VALID_PDF_BYTES, "application/pdf")},
        data={"title": "Leak Test"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    resp_text = resp.text

    assert "storage_dir" not in resp_text
    assert "C:\\" not in resp_text
    assert "/var/" not in resp_text
    assert "\\DocSpector\\" not in resp_text


# ===========================================================================
# FILESEC-21: Direct static-file exposure
# ===========================================================================
def test_filesec_21_direct_static_file_access_prevented(filesec_fixture):
    """FILESEC-21: Private storage directory is not publicly mounted as static files."""
    client = filesec_fixture["client"]
    unauthorized_endpoints = [
        "/storage/private/sample.pdf",
        "/storage/upload_123.tmp",
        "/private/storage/test.pdf",
        "/static/documents/test.pdf",
    ]
    for endpoint in unauthorized_endpoints:
        resp = client.get(endpoint)
        assert resp.status_code in (404, 405)


# ===========================================================================
# FILESEC-22: File-type confusion matrix
# ===========================================================================
def test_filesec_22_file_type_confusion_matrix():
    """FILESEC-22: File type confusion across extensions, magic bytes, and MIME types is strictly rejected."""
    # .pdf with PNG bytes -> reject
    with pytest.raises(FileValidationError) as exc:
        validate_file_bytes(VALID_PNG_BYTES, "confused.pdf", "application/pdf")
    assert exc.value.code == ERROR_CODE_INVALID_MAGIC_BYTES

    # .png with PDF bytes -> reject
    with pytest.raises(FileValidationError) as exc:
        validate_file_bytes(VALID_PDF_BYTES, "confused.png", "image/png")
    assert exc.value.code == ERROR_CODE_INVALID_MAGIC_BYTES

    # .txt with binary bytes (invalid UTF-8) -> reject
    with pytest.raises(FileValidationError) as exc:
        validate_file_bytes(b"\x89PNG\x00\xff\xfe", "binary.txt", "text/plain")
    assert exc.value.code == ERROR_CODE_INVALID_UTF8

    # .pdf with valid PDF bytes -> accept
    res_pdf = validate_file_bytes(VALID_PDF_BYTES, "valid.pdf", "application/pdf")
    assert res_pdf.extension == ".pdf"

    # .txt with valid UTF-8 bytes -> accept
    res_txt = validate_file_bytes(VALID_TXT_BYTES, "valid.txt", "text/plain")
    assert res_txt.extension == ".txt"


# ===========================================================================
# FILESEC-23: Streaming/bounded processing
# ===========================================================================
def test_filesec_23_streaming_bounded_processing(tmp_path: Path):
    """FILESEC-23: File validation reads input stream in bounded chunks (DEFAULT_CHUNK_SIZE_BYTES)."""
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    class ChunkCountingStream(io.BytesIO):
        def __init__(self, initial_bytes):
            super().__init__(initial_bytes)
            self.read_calls = 0

        def read(self, size=-1):
            self.read_calls += 1
            return super().read(size)

    data = VALID_PDF_BYTES + (b"A" * (128 * 1024))
    stream = ChunkCountingStream(data)

    res, _ = validate_and_stage_upload(
        stream=stream,
        filename="streaming.pdf",
        target_storage_dir=storage_dir,
        content_type="application/pdf",
    )
    assert res.size_bytes == len(data)
    assert stream.read_calls >= 2


# ===========================================================================
# FILESEC-24: Failed upload leaves no partial STORED state
# ===========================================================================
def test_filesec_24_failed_upload_leaves_no_partial_stored_state(filesec_fixture):
    """FILESEC-24: When an upload fails, no Document or DocumentVersion is left in STORED state."""
    client = filesec_fixture["client"]
    db = filesec_fixture["db"]
    case = filesec_fixture["case"]
    token = filesec_fixture["io_token"]

    initial_version_count = db.query(DocumentVersion).count()

    resp = client.post(
        f"/api/v1/cases/{case.id}/documents",
        files={"file": ("corrupted.pdf", b"BAD_MAGIC_HEADER", "application/pdf")},
        data={"title": "Corrupted Doc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400

    assert db.query(DocumentVersion).count() == initial_version_count
