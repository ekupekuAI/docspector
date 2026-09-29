"""Docspector Version-Scoped Transfer Service (Milestone 12).

Inspect. Verify. Trust.

This module implements the document transfer workflow:
1. Version-scoped transfer request creation (PENDING).
2. Supervising Officer (SO) approval (APPROVED) and rejection (REJECTED).
3. Supervising Officer (SO) revocation (REVOKED).
4. Strict version-scoped authorization (access to V2 does NOT grant access to V1 or V3).
5. Absolute integrity precedence (RESTRICTED/QUARANTINED versions cannot be transferred or accessed).
6. Race-safe conditional state transitions.
7. Centralized audit logging via M11 custody chain service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.authorization import ROLE_IO, ROLE_SO
from app.db.models.case_assignment import CaseAssignment
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.transfer import Transfer
from app.db.models.user import User
from app.services.custody_service import append_custody_event


class TransferError(Exception):
    """Exception raised for transfer business rule violations."""

    def __init__(self, message: str, status_code: int = 400, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def create_transfer_request(
    db: Session,
    document_id: int,
    version_id: int,
    requester_user: User,
    recipient_user_id: int,
) -> Transfer:
    """Create a new version-scoped transfer request in PENDING state."""
    if not requester_user.is_active:
        raise TransferError("Inactive user account", status_code=403)
    if requester_user.role not in (ROLE_IO, ROLE_SO):
        raise TransferError("Access forbidden: insufficient role permissions", status_code=403)

    # 1. Verify document existence
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise TransferError("Document not found", status_code=404)

    # 2. Verify requester assignment to document's case (IDOR protection)
    requester_assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == requester_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if requester_assignment is None:
        raise TransferError("Document not found", status_code=404)

    # 3. Verify exact version belongs to document
    version = (
        db.query(DocumentVersion)
        .filter(
            DocumentVersion.id == version_id,
            DocumentVersion.document_id == document.id,
        )
        .first()
    )
    if version is None:
        raise TransferError("Document version not found", status_code=404)

    # 4. Check version integrity state
    if version.state in ("RESTRICTED", "QUARANTINED"):
        raise TransferError(
            f"Cannot transfer document version in '{version.state}' state.",
            status_code=409,
            details={"version_id": version.id, "state": version.state},
        )
    if version.state != "STORED":
        raise TransferError(
            f"Cannot transfer document version in '{version.state}' state.",
            status_code=409,
            details={"version_id": version.id, "state": version.state},
        )

    # 5. Verify recipient
    recipient = db.query(User).filter(User.id == recipient_user_id).first()
    if recipient is None or not recipient.is_active:
        raise TransferError("Recipient user not found or inactive", status_code=404)

    if recipient.id == requester_user.id:
        raise TransferError("Cannot transfer document version to yourself", status_code=400)

    # 6. Verify recipient is assigned to the case
    recipient_assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == recipient.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if recipient_assignment is None:
        raise TransferError("Recipient is not assigned to this case", status_code=400)

    # 7. Check for existing active or pending transfer for exact version and recipient
    existing_active = (
        db.query(Transfer)
        .filter(
            Transfer.document_version_id == version.id,
            Transfer.recipient_user_id == recipient.id,
            Transfer.status.in_(["PENDING", "APPROVED"]),
        )
        .first()
    )
    if existing_active:
        raise TransferError(
            f"An active or pending transfer already exists for this version (status: {existing_active.status}).",
            status_code=409,
            details={"transfer_id": existing_active.id, "status": existing_active.status},
        )

    # 8. Create transfer record
    now_utc = datetime.now(timezone.utc)
    transfer = Transfer(
        document_version_id=version.id,
        requester_user_id=requester_user.id,
        recipient_user_id=recipient.id,
        status="PENDING",
        requested_at=now_utc,
    )
    db.add(transfer)
    db.flush()

    # 9. Record custody event via M11 service
    event_data = {
        "action": "TRANSFER_REQUESTED",
        "transfer_id": transfer.id,
        "document_id": document.id,
        "document_number": document.document_number,
        "document_version_id": version.id,
        "version_number": version.version_number,
        "requester_user_id": requester_user.id,
        "recipient_user_id": recipient.id,
    }
    append_custody_event(
        db=db,
        case_id=document.case_id,
        event_type="TRANSFER_REQUESTED",
        actor_user_id=requester_user.id,
        document_version_id=version.id,
        event_data=event_data,
        event_time=now_utc,
    )
    db.commit()
    db.refresh(transfer)
    return transfer


def approve_transfer(
    db: Session,
    transfer_id: int,
    so_user: User,
) -> Transfer:
    """Approve a PENDING document version transfer (Supervising Officer only)."""
    if not so_user.is_active:
        raise TransferError("Inactive user account", status_code=403)
    if so_user.role != ROLE_SO:
        raise TransferError("Only Supervising Officers can approve transfers", status_code=403)

    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if transfer is None:
        raise TransferError("Transfer not found", status_code=404)

    version = db.query(DocumentVersion).filter(DocumentVersion.id == transfer.document_version_id).first()
    if version is None:
        raise TransferError("Document version not found", status_code=404)

    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        raise TransferError("Document not found", status_code=404)

    # Verify SO is assigned to the case
    so_assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == so_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if so_assignment is None:
        raise TransferError("Transfer not found", status_code=404)

    # Check version integrity state
    if version.state in ("RESTRICTED", "QUARANTINED"):
        raise TransferError(
            f"Cannot approve transfer for document version in '{version.state}' state.",
            status_code=409,
            details={"version_id": version.id, "state": version.state},
        )

    now_utc = datetime.now(timezone.utc)

    # Atomic conditional update
    rows_updated = (
        db.query(Transfer)
        .filter(Transfer.id == transfer_id, Transfer.status == "PENDING")
        .update(
            {
                Transfer.status: "APPROVED",
                Transfer.decided_at: now_utc,
                Transfer.decided_by_user_id: so_user.id,
            },
            synchronize_session=False,
        )
    )

    if rows_updated == 0:
        db.refresh(transfer)
        raise TransferError(
            f"Cannot approve transfer in status '{transfer.status}'.",
            status_code=409,
            details={"transfer_id": transfer.id, "status": transfer.status},
        )

    # Record custody event
    event_data = {
        "action": "TRANSFER_APPROVED",
        "transfer_id": transfer.id,
        "document_id": document.id,
        "document_number": document.document_number,
        "document_version_id": version.id,
        "version_number": version.version_number,
        "decided_by_user_id": so_user.id,
        "recipient_user_id": transfer.recipient_user_id,
    }
    append_custody_event(
        db=db,
        case_id=document.case_id,
        event_type="TRANSFER_APPROVED",
        actor_user_id=so_user.id,
        document_version_id=version.id,
        event_data=event_data,
        event_time=now_utc,
    )
    db.commit()
    db.refresh(transfer)
    return transfer


def reject_transfer(
    db: Session,
    transfer_id: int,
    so_user: User,
) -> Transfer:
    """Reject a PENDING document version transfer (Supervising Officer only)."""
    if not so_user.is_active:
        raise TransferError("Inactive user account", status_code=403)
    if so_user.role != ROLE_SO:
        raise TransferError("Only Supervising Officers can reject transfers", status_code=403)

    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if transfer is None:
        raise TransferError("Transfer not found", status_code=404)

    version = db.query(DocumentVersion).filter(DocumentVersion.id == transfer.document_version_id).first()
    if version is None:
        raise TransferError("Document version not found", status_code=404)

    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        raise TransferError("Document not found", status_code=404)

    so_assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == so_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if so_assignment is None:
        raise TransferError("Transfer not found", status_code=404)

    now_utc = datetime.now(timezone.utc)

    # Atomic conditional update
    rows_updated = (
        db.query(Transfer)
        .filter(Transfer.id == transfer_id, Transfer.status == "PENDING")
        .update(
            {
                Transfer.status: "REJECTED",
                Transfer.decided_at: now_utc,
                Transfer.decided_by_user_id: so_user.id,
            },
            synchronize_session=False,
        )
    )

    if rows_updated == 0:
        db.refresh(transfer)
        raise TransferError(
            f"Cannot reject transfer in status '{transfer.status}'.",
            status_code=409,
            details={"transfer_id": transfer.id, "status": transfer.status},
        )

    event_data = {
        "action": "TRANSFER_REJECTED",
        "transfer_id": transfer.id,
        "document_id": document.id,
        "document_number": document.document_number,
        "document_version_id": version.id,
        "version_number": version.version_number,
        "decided_by_user_id": so_user.id,
        "recipient_user_id": transfer.recipient_user_id,
    }
    append_custody_event(
        db=db,
        case_id=document.case_id,
        event_type="TRANSFER_REJECTED",
        actor_user_id=so_user.id,
        document_version_id=version.id,
        event_data=event_data,
        event_time=now_utc,
    )
    db.commit()
    db.refresh(transfer)
    return transfer


def revoke_transfer(
    db: Session,
    transfer_id: int,
    so_user: User,
) -> Transfer:
    """Revoke an already APPROVED document version transfer (Supervising Officer only)."""
    if not so_user.is_active:
        raise TransferError("Inactive user account", status_code=403)
    if so_user.role != ROLE_SO:
        raise TransferError("Only Supervising Officers can revoke transfers", status_code=403)

    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if transfer is None:
        raise TransferError("Transfer not found", status_code=404)

    version = db.query(DocumentVersion).filter(DocumentVersion.id == transfer.document_version_id).first()
    if version is None:
        raise TransferError("Document version not found", status_code=404)

    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        raise TransferError("Document not found", status_code=404)

    so_assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == so_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if so_assignment is None:
        raise TransferError("Transfer not found", status_code=404)

    now_utc = datetime.now(timezone.utc)

    # Atomic conditional update
    rows_updated = (
        db.query(Transfer)
        .filter(Transfer.id == transfer_id, Transfer.status == "APPROVED")
        .update(
            {
                Transfer.status: "REVOKED",
                Transfer.revoked_at: now_utc,
            },
            synchronize_session=False,
        )
    )

    if rows_updated == 0:
        db.refresh(transfer)
        raise TransferError(
            f"Cannot revoke transfer in status '{transfer.status}'. Only APPROVED transfers can be revoked.",
            status_code=409,
            details={"transfer_id": transfer.id, "status": transfer.status},
        )

    event_data = {
        "action": "TRANSFER_REVOKED",
        "transfer_id": transfer.id,
        "document_id": document.id,
        "document_number": document.document_number,
        "document_version_id": version.id,
        "version_number": version.version_number,
        "revoked_by_user_id": so_user.id,
        "recipient_user_id": transfer.recipient_user_id,
    }
    append_custody_event(
        db=db,
        case_id=document.case_id,
        event_type="TRANSFER_REVOKED",
        actor_user_id=so_user.id,
        document_version_id=version.id,
        event_data=event_data,
        event_time=now_utc,
    )
    db.commit()
    db.refresh(transfer)
    return transfer


def can_access_document_version(
    db: Session,
    user: User,
    version: DocumentVersion,
) -> bool:
    """Evaluate whether an authenticated user is authorized to access an exact document version.

    Authorization Invariants:
    1. Integrity Precedence: If version is RESTRICTED or QUARANTINED, access is strictly False.
    2. Primary Case Officers: Active IO/SO assigned to the case have direct version access.
    3. Reviewers & Recipients: Legal Reviewers, Auditors, and other users require an APPROVED
       transfer for the EXACT document_version_id (PENDING, REJECTED, and REVOKED grant ZERO access).
    """
    if not user.is_active:
        return False

    # 1. Integrity check: Restricted versions cannot be accessed under any circumstance
    if version.state in ("RESTRICTED", "QUARANTINED"):
        return False
    if version.state != "STORED":
        return False

    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        return False

    # 2. Check direct case assignment
    assignment = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
    )
    if assignment is None:
        # If user is not assigned to the case at all, check if they hold an approved transfer
        approved_transfer = (
            db.query(Transfer)
            .filter(
                Transfer.document_version_id == version.id,
                Transfer.recipient_user_id == user.id,
                Transfer.status == "APPROVED",
            )
            .first()
        )
        return approved_transfer is not None

    # Primary case officers (IO / SO) assigned to the case have direct access
    if user.role in ("IO", "SO"):
        return True

    # For other roles (e.g. Legal Reviewer, Auditor), access to this specific
    # document version requires an explicit APPROVED transfer
    approved_transfer = (
        db.query(Transfer)
        .filter(
            Transfer.document_version_id == version.id,
            Transfer.recipient_user_id == user.id,
            Transfer.status == "APPROVED",
        )
        .first()
    )
    return approved_transfer is not None
