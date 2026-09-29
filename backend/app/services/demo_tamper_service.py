"""Docspector Demo Tamper Simulator Service (Milestone 14).

Inspect. Verify. Trust.

Provides strictly controlled, synthetic storage byte manipulation for demonstration:
1. Operates ONLY when DEMO_MODE=True in server configuration.
2. Requires authenticated active user with demo operator permission (IO / SO assigned to the case).
3. Modifies on-disk file bytes in private storage without modifying database SHA-256 or state.
4. Allows M13 independent verification to detect FILE_HASH_MISMATCH and transition version to RESTRICTED.
5. Zero auto-repair / zero database hash overwriting.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import (
    ERROR_CASE_ACCESS_DENIED,
    ERROR_DEMO_MODE_REQUIRED,
    ERROR_DEMO_PERMISSION_REQUIRED,
    ERROR_DOCUMENT_ACCESS_DENIED,
    ERROR_RESOURCE_NOT_FOUND,
    ERROR_VERSION_ACCESS_DENIED,
    AppError,
)
from app.db.models.case_assignment import CaseAssignment
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.user import User
from app.schemas.demo import DemoTamperResponse

settings = get_settings()

DEMO_TAMPER_PAYLOAD = b"\n%DOCSPECTOR_SYNTHETIC_DEMO_TAMPER_MODIFICATION%\n"


def simulate_document_version_tampering(
    db: Session,
    document_id: int,
    version_id: int,
    current_user: User,
    storage_dir: Path | str | None = None,
) -> DemoTamperResponse:
    """Perform deterministic synthetic byte modification on a stored document version in demo mode."""
    # 1. Enforce DEMO_MODE configuration guard
    active_settings = get_settings()
    if not active_settings.demo_mode:
        raise AppError(
            message="Demo mode is disabled on this server. Tamper simulation is prohibited in production mode.",
            code=ERROR_DEMO_MODE_REQUIRED,
            status_code=403,
        )

    # 2. Enforce active user and demo operator role
    if not current_user.is_active:
        raise AppError(
            message="Inactive user account",
            code=ERROR_DEMO_PERMISSION_REQUIRED,
            status_code=403,
        )

    if current_user.role not in ("IO", "SO"):
        raise AppError(
            message="Insufficient permissions to operate demo tamper simulation. Must be an active case officer.",
            code=ERROR_DEMO_PERMISSION_REQUIRED,
            status_code=403,
        )

    # 3. Verify Document and Case Assignment (IDOR protection)
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise AppError(
            message="Document not found",
            code=ERROR_DOCUMENT_ACCESS_DENIED,
            status_code=404,
        )

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
        raise AppError(
            message="Document not found",
            code=ERROR_CASE_ACCESS_DENIED,
            status_code=404,
        )

    # 4. Verify exact DocumentVersion
    version = (
        db.query(DocumentVersion)
        .filter(
            DocumentVersion.id == version_id,
            DocumentVersion.document_id == document.id,
        )
        .first()
    )
    if version is None:
        raise AppError(
            message="Document version not found",
            code=ERROR_VERSION_ACCESS_DENIED,
            status_code=404,
        )

    # 5. Locate physical file in private storage
    active_storage_dir = Path(storage_dir or active_settings.storage_dir)
    file_path = active_storage_dir / version.storage_key
    if not file_path.is_file():
        raise AppError(
            message="Physical storage file not found.",
            code=ERROR_RESOURCE_NOT_FOUND,
            status_code=404,
        )

    # 6. Perform controlled synthetic byte corruption on disk
    with open(file_path, "ab") as f:
        f.write(DEMO_TAMPER_PAYLOAD)

    # 7. CRITICAL: Database SHA-256 remains unmodified (evidence preservation)
    return DemoTamperResponse(
        simulation_type="SYNTHETIC_STORAGE_BYTE_CORRUPTION",
        demo_mode=True,
        document_id=document.id,
        document_version_id=version.id,
        version_number=version.version_number,
        persisted_expected_sha256=version.sha256_hash,
        message=(
            f"Simulated synthetic byte corruption performed on stored file for document "
            f"'{document.document_number}' (V{version.version_number}). Database SHA-256 preserved."
        ),
    )
