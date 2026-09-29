"""Docspector Integrity Alert Management Service (Milestone 26 / Phase 1).

Inspect. Verify. Trust.

This module provides authoritative alert listing and resolution workflows for accessible cases.

Security Invariants:
1. Alert retrieval and resolution require active case assignment (non-disclosure / IDOR protection).
2. Alert resolution requires a mandatory non-empty resolution_note.
3. Mandatory Security Re-Verification:
   Before resolving an alert, the system re-runs authoritative verification on the underlying
   document version and custody chain. If verification still fails:
   - Document remains RESTRICTED.
   - Integrity failure remains authoritative.
   - Alert cannot be falsely marked as resolved (HTTP 400 rejection).
4. Alert history is preserved: alerts are marked RESOLVED with reviewed_at and reviewed_by_user_id,
   never silently deleted.
"""

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.authorization import verify_case_assignment
from app.db.models.document_version import DocumentVersion
from app.db.models.integrity_alert import IntegrityAlert
from app.db.models.user import User
from app.services.custody_service import validate_custody_chain
from app.services.verification_service import verify_document_version_integrity


def get_alerts_for_case(
    db: Session,
    case_id: int,
    current_user: User,
    status_filter: str | None = None,
) -> list[IntegrityAlert]:
    """Retrieve all integrity alerts belonging to a case accessible to current_user.

    Enforces server-side case assignment authorization with 404 non-disclosure on unauthorized or nonexistent cases.
    """
    # 1. Enforce active case assignment authorization
    verify_case_assignment(db, current_user, case_id)

    # 2. Query alerts for case with deterministic ordering
    query = db.query(IntegrityAlert).filter(IntegrityAlert.case_id == case_id)

    if status_filter:
        clean_status = status_filter.strip().upper()
        query = query.filter(IntegrityAlert.status == clean_status)

    return query.order_by(IntegrityAlert.created_at.desc(), IntegrityAlert.id.desc()).all()


def resolve_alert(
    db: Session,
    alert_id: int,
    current_user: User,
    resolution_note: str,
) -> IntegrityAlert:
    """Resolve an integrity alert after mandatory re-verification of document & chain integrity.

    Security Requirements:
    - User must be authenticated, active, and assigned to the alert's case.
    - resolution_note must be non-empty.
    - Alert must currently be OPEN.
    - Re-verification MUST pass before alert can be marked RESOLVED.
    - If re-verification fails, alert resolution is REJECTED (400), document remains RESTRICTED.
    """
    # 1. Validate resolution note presence
    clean_note = resolution_note.strip() if resolution_note else ""
    if not clean_note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Resolution note is required to resolve an alert.",
        )

    # 2. Fetch alert by ID
    alert = db.query(IntegrityAlert).filter(IntegrityAlert.id == alert_id).first()
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    # 3. Enforce case assignment authorization for the alert's case
    verify_case_assignment(db, current_user, alert.case_id)

    # 4. Check if already resolved
    if alert.status in ("RESOLVED", "REVIEWED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alert is already resolved.",
        )

    # 5. Mandatory Security Re-Verification Check
    if alert.document_version_id is not None:
        version = (
            db.query(DocumentVersion)
            .filter(DocumentVersion.id == alert.document_version_id)
            .first()
        )
        if version is not None:
            verification_res = verify_document_version_integrity(
                db=db,
                document_id=version.document_id,
                version_id=version.id,
                current_user=current_user,
            )
            if (
                verification_res.overall_status != "VALID"
                or not verification_res.file_integrity.is_valid
                or not verification_res.chain_integrity.is_valid
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot resolve alert: document version or custody chain integrity verification still fails.",
                )
    else:
        chain_res = validate_custody_chain(db=db, case_id=alert.case_id)
        if not chain_res.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot resolve alert: custody chain integrity verification still fails.",
            )

    # 6. Apply resolution update while preserving history
    alert.status = "RESOLVED"
    alert.reviewed_at = datetime.now(timezone.utc)
    alert.reviewed_by_user_id = current_user.id
    alert.message = f"{alert.message}\n[Resolution Note]: {clean_note}"

    db.commit()
    db.refresh(alert)
    return alert
