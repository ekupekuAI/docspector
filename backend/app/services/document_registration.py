"""Docspector Document V1 Registration Service (Milestone 9).

Inspect. Verify. Trust.

This module implements the crash-safe compensating protocol for ingesting
and registering the initial document version (V1) into Docspector:
1. Streaming input validation & SHA-256 calculation (Milestone 8 service).
2. Ephemeral staging in private temporary storage.
3. Database transaction initiation with Document and DocumentVersion (state=UPLOADING).
4. Atomic filesystem move to unpredictable server-generated storage key.
5. Disk-level integrity verification (existence, size, SHA-256 match).
6. State progression to STORED and creation of initial DOCUMENT_INGESTED custody event.
7. Full failure compensation (DB rollback + filesystem cleanup on error).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
from typing import IO, Any
import uuid

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models.case import Case
from app.db.models.custody_event import CustodyEvent
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.user import User
from app.services.custody_service import append_custody_event
from app.services.file_validation import (
    DEFAULT_CHUNK_SIZE_BYTES,
    FileValidationError,
    validate_filename,
    validate_mime_type,
    validate_file_stream,
)

settings = get_settings()


def verify_disk_file_integrity(
    file_path: Path,
    expected_size: int,
    expected_sha256: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> bool:
    """Verify that a stored file on disk matches expected size and SHA-256 checksum."""
    if not file_path.is_file():
        return False

    if file_path.stat().st_size != expected_size:
        return False

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest() == expected_sha256


def register_document_version_one(
    db: Session,
    case: Case,
    current_user: User,
    file_stream: IO[bytes],
    filename: str,
    content_type: str | None = None,
    title: str | None = None,
    storage_dir: Path | str | None = None,
) -> tuple[Document, DocumentVersion, CustodyEvent]:
    """Execute the crash-safe document V1 registration workflow.

    Safety & security invariants:
    - Never uses client-provided hashes or paths.
    - Operates outside frontend/public in configured private storage.
    - Never overwrites an existing document version.
    - Transitions version from UPLOADING to STORED only after on-disk SHA-256 verification.
    - Emits initial DOCUMENT_INGESTED custody event.
    - Cleans up filesystem artifacts if database transaction fails.
    """
    private_storage_dir = Path(storage_dir or settings.storage_dir)
    private_storage_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # PHASE 1: Ephemeral Temporary Staging & Stream Validation
    # -------------------------------------------------------------
    temp_filename = f"upload_{uuid.uuid4().hex}.tmp"
    temp_file_path = private_storage_dir / temp_filename
    final_file_path: Path | None = None

    try:
        # Write stream to temp file while validating
        with open(temp_file_path, "wb") as out_file:
            while True:
                chunk = file_stream.read(DEFAULT_CHUNK_SIZE_BYTES)
                if not chunk:
                    break
                out_file.write(chunk)

        # Validate staged temp file using Milestone 8 validation service
        with open(temp_file_path, "rb") as in_file:
            validation_result = validate_file_stream(
                stream=in_file,
                filename=filename,
                content_type=content_type,
            )

    except Exception:
        # Guarantee cleanup of temporary file on validation failure
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except OSError:
                pass
        raise

    # -------------------------------------------------------------
    # PHASE 2: Database Preparation (Document + DocumentVersion V1)
    # -------------------------------------------------------------
    try:
        # Determine document title
        doc_title = title.strip() if title and title.strip() else validation_result.sanitized_filename

        # Generate unique document number for this case
        doc_number = f"DOC-{case.case_number}-{uuid.uuid4().hex[:8].upper()}"

        document = Document(
            case_id=case.id,
            document_number=doc_number,
            title=doc_title,
            created_by_user_id=current_user.id,
        )
        db.add(document)
        db.flush()

        doc_version = DocumentVersion(
            document_id=document.id,
            version_number=1,
            state="UPLOADING",
            original_filename=validation_result.sanitized_filename,
            mime_type=validation_result.media_type,
            size_bytes=validation_result.size_bytes,
            sha256_hash=validation_result.sha256_checksum,
            storage_key=validation_result.storage_key,
            created_by_user_id=current_user.id,
        )
        db.add(doc_version)
        db.flush()

        # ---------------------------------------------------------
        # PHASE 3: Atomic Move to Final Unpredictable Storage Key
        # ---------------------------------------------------------
        final_file_path = private_storage_dir / validation_result.storage_key
        temp_file_path.replace(final_file_path)

        # ---------------------------------------------------------
        # PHASE 4: Verify Final File on Disk
        # ---------------------------------------------------------
        if not verify_disk_file_integrity(
            file_path=final_file_path,
            expected_size=validation_result.size_bytes,
            expected_sha256=validation_result.sha256_checksum,
        ):
            raise RuntimeError(
                f"On-disk integrity verification failed for staged file '{final_file_path.name}'."
            )

        # ---------------------------------------------------------
        # PHASE 5: Finalize Database State & Custody Event
        # ---------------------------------------------------------
        doc_version.state = "STORED"

        event_data = {
            "action": "DOCUMENT_INGESTED",
            "document_id": document.id,
            "document_number": document.document_number,
            "version_number": 1,
            "original_filename": validation_result.sanitized_filename,
            "mime_type": validation_result.media_type,
            "size_bytes": validation_result.size_bytes,
            "sha256_hash": validation_result.sha256_checksum,
        }

        custody_event = append_custody_event(
            db=db,
            case_id=case.id,
            event_type="DOCUMENT_INGESTED",
            actor_user_id=current_user.id,
            document_version_id=doc_version.id,
            event_data=event_data,
        )
        db.commit()

        db.refresh(document)
        db.refresh(doc_version)
        db.refresh(custody_event)

        return document, doc_version, custody_event

    except Exception:
        # ---------------------------------------------------------
        # PHASE 6: Compensation & Rollback
        # ---------------------------------------------------------
        db.rollback()

        # Clean up temp file if still present
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except OSError:
                pass

        # Clean up final file if it was created before failure
        if final_file_path and final_file_path.exists():
            try:
                final_file_path.unlink()
            except OSError:
                pass

        raise


def register_successor_version(
    db: Session,
    document: Document,
    current_user: User,
    file_stream: IO[bytes],
    filename: str,
    content_type: str | None = None,
    storage_dir: Path | str | None = None,
    max_retries: int = 5,
) -> tuple[Document, DocumentVersion, CustodyEvent]:
    """Register an immutable successor version (V2, V3, ...) for an existing document.

    Safety & Concurrency Invariants:
    - Server derives next version_number (max(version_number) + 1); client has zero control.
    - Existing versions and their physical files are NEVER overwritten or modified.
    - Each attempt uses an isolated temporary staging file and cleans up on failure.
    - Bounded retry specifically handles concurrent version allocation collisions
      (violating uq_document_versions_doc_version) or transient SQLite locking (SQLITE_BUSY).
    - Other IntegrityErrors fail immediately without retry.
    - Transitions version from UPLOADING to STORED only after on-disk SHA-256 verification.
    """
    private_storage_dir = Path(storage_dir or settings.storage_dir)
    private_storage_dir.mkdir(parents=True, exist_ok=True)

    # State check: prevent successor version creation if any version is RESTRICTED or QUARANTINED
    restricted_versions = (
        db.query(DocumentVersion)
        .filter(
            DocumentVersion.document_id == document.id,
            DocumentVersion.state.in_(["RESTRICTED", "QUARANTINED"]),
        )
        .all()
    )
    if restricted_versions:
        raise FileValidationError(
            code="DOCUMENT_RESTRICTED",
            message=f"Cannot add version to document '{document.document_number}' in restricted state.",
            http_status_code=409,
            details={"document_id": document.id, "restricted_states": [v.state for v in restricted_versions]},
        )

    # Read the full incoming payload once into an ephemeral buffer if retry is needed
    # (Bounded memory: file size is capped at 25 MiB)
    payload_buffer = io.BytesIO()
    while True:
        chunk = file_stream.read(DEFAULT_CHUNK_SIZE_BYTES)
        if not chunk:
            break
        payload_buffer.write(chunk)
    raw_payload_bytes = payload_buffer.getvalue()

    for attempt in range(max_retries):
        temp_filename = f"upload_succ_{uuid.uuid4().hex}.tmp"
        temp_file_path = private_storage_dir / temp_filename
        final_file_path: Path | None = None

        try:
            # ---------------------------------------------------------
            # PHASE 1: Ephemeral Staging & Input Validation
            # ---------------------------------------------------------
            with open(temp_file_path, "wb") as out_file:
                out_file.write(raw_payload_bytes)

            with open(temp_file_path, "rb") as in_file:
                validation_result = validate_file_stream(
                    stream=in_file,
                    filename=filename,
                    content_type=content_type,
                )

            # ---------------------------------------------------------
            # PHASE 2: Database Preparation & Next Version Calculation
            # ---------------------------------------------------------
            # Re-check restricted status inside attempt to prevent TOCTOU race
            curr_restricted = (
                db.query(DocumentVersion)
                .filter(
                    DocumentVersion.document_id == document.id,
                    DocumentVersion.state.in_(["RESTRICTED", "QUARANTINED"]),
                )
                .first()
            )
            if curr_restricted:
                raise FileValidationError(
                    code="DOCUMENT_RESTRICTED",
                    message=f"Cannot add version to document '{document.document_number}' in restricted state.",
                    http_status_code=409,
                    details={"document_id": document.id, "restricted_state": curr_restricted.state},
                )

            # Determine next version number for this document
            current_max_v = (
                db.query(DocumentVersion.version_number)
                .filter(DocumentVersion.document_id == document.id)
                .order_by(DocumentVersion.version_number.desc())
                .first()
            )
            next_version_number = (current_max_v[0] + 1) if current_max_v else 2

            doc_version = DocumentVersion(
                document_id=document.id,
                version_number=next_version_number,
                state="UPLOADING",
                original_filename=validation_result.sanitized_filename,
                mime_type=validation_result.media_type,
                size_bytes=validation_result.size_bytes,
                sha256_hash=validation_result.sha256_checksum,
                storage_key=validation_result.storage_key,
                created_by_user_id=current_user.id,
            )
            db.add(doc_version)
            db.flush()

            # ---------------------------------------------------------
            # PHASE 3: Atomic Move to Final Storage Key
            # ---------------------------------------------------------
            final_file_path = private_storage_dir / validation_result.storage_key
            temp_file_path.replace(final_file_path)

            # ---------------------------------------------------------
            # PHASE 4: On-Disk Integrity Verification
            # ---------------------------------------------------------
            if not verify_disk_file_integrity(
                file_path=final_file_path,
                expected_size=validation_result.size_bytes,
                expected_sha256=validation_result.sha256_checksum,
            ):
                raise RuntimeError(
                    f"On-disk integrity verification failed for successor file '{final_file_path.name}'."
                )

            # ---------------------------------------------------------
            # PHASE 5: Finalize State & Create Custody Event
            # ---------------------------------------------------------
            doc_version.state = "STORED"

            event_data = {
                "action": "DOCUMENT_INGESTED",
                "document_id": document.id,
                "document_number": document.document_number,
                "version_number": next_version_number,
                "original_filename": validation_result.sanitized_filename,
                "mime_type": validation_result.media_type,
                "size_bytes": validation_result.size_bytes,
                "sha256_hash": validation_result.sha256_checksum,
            }

            custody_event = append_custody_event(
                db=db,
                case_id=document.case_id,
                event_type="DOCUMENT_INGESTED",
                actor_user_id=current_user.id,
                document_version_id=doc_version.id,
                event_data=event_data,
            )
            db.commit()

            db.refresh(document)
            db.refresh(doc_version)
            db.refresh(custody_event)

            return document, doc_version, custody_event

        except Exception as exc:
            # Clean up DB transaction and this attempt's filesystem artifacts
            db.rollback()

            if temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except OSError:
                    pass

            if final_file_path and final_file_path.exists():
                try:
                    final_file_path.unlink()
                except OSError:
                    pass

            # Detect version allocation collision on unique constraint
            err_str = str(exc)
            is_version_collision = (
                "uq_document_versions_doc_version" in err_str
                or ("UNIQUE constraint failed" in err_str and "document_versions.version_number" in err_str)
                or "database is locked" in err_str
                or "SQLITE_BUSY" in err_str
            )

            # If it's a version race conflict and we have retries left, retry with next version number
            if is_version_collision and attempt < max_retries - 1:
                continue

            # Otherwise, re-raise exception (will map to 409 if version conflict, or 400/500)
            if is_version_collision:
                raise FileValidationError(
                    code="VERSION_CONFLICT",
                    message=f"Concurrent successor version conflict on document '{document.document_number}'.",
                    http_status_code=409,
                    details={"document_id": document.id},
                ) from exc

            raise
