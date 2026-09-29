"""Docspector Document Version & Custody Integrity Verification Service (Milestone 13).

Inspect. Verify. Trust.

This module provides the independent two-factor integrity verification engine:
1. File byte integrity verification (recomputing SHA-256 from exact disk bytes).
2. Custody chain cryptographic verification (reusing centralized M11 validator).
3. Independent, non-opaque reporting of both verification dimensions.
4. Automatic transition to RESTRICTED state upon any integrity failure.
5. Idempotent creation of high-severity integrity alerts.
6. Zero auto-repair / zero silent restoration of RESTRICTED records.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models.case_assignment import CaseAssignment
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.integrity_alert import IntegrityAlert
from app.db.models.user import User
from app.schemas.verification import (
    ChainIntegrityDetail,
    FileIntegrityDetail,
    IntegrityAlertSummary,
    VerificationResponse,
)
from app.services.custody_service import CHAIN_VALID, validate_custody_chain
from app.services.file_validation import DEFAULT_CHUNK_SIZE_BYTES

settings = get_settings()


class VerificationError(Exception):
    """Exception raised during integrity verification authorization or validation."""

    def __init__(self, message: str, status_code: int = 400, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def verify_file_bytes(
    storage_dir: Path | str,
    storage_key: str,
    expected_sha256: str,
    expected_size_bytes: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> tuple[bool, str, str | None, int | None, str | None]:
    """Recompute SHA-256 digest from actual on-disk bytes in private storage.

    Returns:
    (is_valid, status_code, computed_hash, actual_size_bytes, error_message)
    """
    file_path = Path(storage_dir) / storage_key

    if not file_path.is_file():
        return (
            False,
            "FILE_MISSING",
            None,
            None,
            "Stored file is missing from private storage directory.",
        )

    try:
        actual_size = file_path.stat().st_size
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)

        computed_hash = sha256.hexdigest().lower()

        if computed_hash != expected_sha256.lower():
            return (
                False,
                "FILE_HASH_MISMATCH",
                computed_hash,
                actual_size,
                f"Computed file hash '{computed_hash}' does not match expected hash '{expected_sha256}'.",
            )

        if actual_size != expected_size_bytes:
            return (
                False,
                "FILE_SIZE_MISMATCH",
                computed_hash,
                actual_size,
                f"Computed file size '{actual_size}' bytes does not match expected size '{expected_size_bytes}' bytes.",
            )

        return True, "VALID", computed_hash, actual_size, None

    except Exception as exc:
        return (
            False,
            "FILE_READ_ERROR",
            None,
            None,
            f"Failed to read stored file: {exc}",
        )


def _get_or_create_alert(
    db: Session,
    case_id: int,
    document_version_id: int,
    alert_type: str,
    message: str,
    severity: str = "CRITICAL",
) -> IntegrityAlert:
    """Idempotently fetch or create an OPEN integrity alert for a failure."""
    existing_alert = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.case_id == case_id,
            IntegrityAlert.document_version_id == document_version_id,
            IntegrityAlert.alert_type == alert_type,
            IntegrityAlert.status == "OPEN",
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    new_alert = IntegrityAlert(
        case_id=case_id,
        document_version_id=document_version_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_alert)
    db.flush()
    return new_alert


def verify_document_version_integrity(
    db: Session,
    document_id: int,
    version_id: int,
    current_user: User,
    storage_dir: Path | str | None = None,
) -> VerificationResponse:
    """Perform independent two-factor verification on a document version and its custody chain.

    Security & Invariants:
    1. Authenticated user must have active assignment to the document's case (404 on unassigned).
    2. Document version must exist and belong to the requested document.
    3. File bytes are read and hashed from disk; chain is cryptographically audited.
    4. If either check fails, version transitions to RESTRICTED and alerts are generated idempotently.
    5. A RESTRICTED version is NEVER automatically restored to STORED.
    """
    if not current_user.is_active:
        raise VerificationError("Inactive user account", status_code=403)

    # 1. Fetch document and verify existence
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise VerificationError("Document not found", status_code=404)

    # 2. Verify case assignment with IDOR non-disclosure
    assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == current_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if assignment is None:
        raise VerificationError("Document not found", status_code=404)

    # 3. Fetch exact version
    version = (
        db.query(DocumentVersion)
        .filter(
            DocumentVersion.id == version_id,
            DocumentVersion.document_id == document.id,
        )
        .first()
    )
    if version is None:
        raise VerificationError("Document version not found", status_code=404)

    # 4. Perform File Integrity Check
    active_storage_dir = Path(storage_dir or settings.storage_dir)
    file_valid, file_status, comp_hash, act_size, file_err = verify_file_bytes(
        storage_dir=active_storage_dir,
        storage_key=version.storage_key,
        expected_sha256=version.sha256_hash,
        expected_size_bytes=version.size_bytes,
    )

    file_detail = FileIntegrityDetail(
        is_valid=file_valid,
        status=file_status,
        stored_hash=version.sha256_hash,
        computed_hash=comp_hash,
        expected_size_bytes=version.size_bytes,
        actual_size_bytes=act_size,
        error_message=file_err,
    )

    # 5. Perform Custody Chain Integrity Check
    chain_result = validate_custody_chain(db=db, case_id=document.case_id)
    chain_detail = ChainIntegrityDetail(
        is_valid=chain_result.is_valid,
        status=chain_result.status_code,
        total_events=chain_result.total_events,
        broken_sequence_number=chain_result.broken_sequence_number,
        error_message=chain_result.error_message,
    )

    # 6. Evaluate Combined Result
    overall_valid = file_valid and chain_result.is_valid
    overall_status = "VALID" if overall_valid else "INTEGRITY_FAILURE"

    created_alerts: list[IntegrityAlert] = []

    # 7. Apply State Progression & Idempotent Alerting on Failure
    if not overall_valid:
        # Quarantine/Restrict version if not already restricted
        if version.state != "RESTRICTED":
            version.state = "RESTRICTED"

        # Generate file integrity alert if file check failed
        if not file_valid:
            file_alert = _get_or_create_alert(
                db=db,
                case_id=document.case_id,
                document_version_id=version.id,
                alert_type=file_status,
                message=(
                    f"File integrity violation on document '{document.document_number}' (V{version.version_number}): "
                    f"{file_err}"
                ),
                severity="CRITICAL",
            )
            created_alerts.append(file_alert)

        # Generate chain integrity alert if custody chain failed
        if not chain_result.is_valid:
            chain_alert = _get_or_create_alert(
                db=db,
                case_id=document.case_id,
                document_version_id=version.id,
                alert_type="CUSTODY_CHAIN_INVALID",
                message=(
                    f"Custody chain violation on case '{document.case_id}': {chain_result.error_message}"
                ),
                severity="CRITICAL",
            )
            created_alerts.append(chain_alert)

        db.commit()
        db.refresh(version)

    # Fetch all open alerts for this document version
    all_open_alerts = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.document_version_id == version.id,
            IntegrityAlert.status == "OPEN",
        )
        .all()
    )

    alert_summaries = [
        IntegrityAlertSummary(
            id=a.id,
            alert_type=a.alert_type,
            severity=a.severity,
            status=a.status,
            message=a.message,
            created_at=a.created_at,
        )
        for a in all_open_alerts
    ]

    return VerificationResponse(
        document_id=document.id,
        document_version_id=version.id,
        version_number=version.version_number,
        case_id=document.case_id,
        overall_status=overall_status,
        version_state=version.state,
        file_integrity=file_detail,
        chain_integrity=chain_detail,
        alerts=alert_summaries,
    )
