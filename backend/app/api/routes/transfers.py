from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.db.models.case_assignment import CaseAssignment
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.transfer import Transfer
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.transfer import TransferCreateRequest, TransferResponse
from app.services.transfer_service import (
    TransferError,
    approve_transfer,
    create_transfer_request,
    reject_transfer,
    revoke_transfer,
)

settings = get_settings()

router = APIRouter(prefix=settings.api_v1_prefix, tags=["transfers"])


def _build_transfer_response(transfer: Transfer, db: Session) -> TransferResponse:
    version = db.query(DocumentVersion).filter(DocumentVersion.id == transfer.document_version_id).first()
    if version is None:
        raise HTTPException(status_code=404, detail="Document version not found")
    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")

    return TransferResponse(
        id=transfer.id,
        document_version_id=transfer.document_version_id,
        document_id=document.id,
        case_id=document.case_id,
        requester_user_id=transfer.requester_user_id,
        recipient_user_id=transfer.recipient_user_id,
        status=transfer.status,
        requested_at=transfer.requested_at,
        decided_at=transfer.decided_at,
        decided_by_user_id=transfer.decided_by_user_id,
        revoked_at=transfer.revoked_at,
    )


@router.post(
    "/documents/{document_id}/versions/{version_id}/transfers",
    response_model=TransferResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_version_transfer_request(
    document_id: int,
    version_id: int,
    payload: TransferCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Initiate a version-scoped transfer request for an exact document version."""
    try:
        transfer = create_transfer_request(
            db=db,
            document_id=document_id,
            version_id=version_id,
            requester_user=current_user,
            recipient_user_id=payload.recipient_user_id,
        )
        return _build_transfer_response(transfer, db)
    except TransferError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create transfer request.",
        ) from exc


@router.post(
    "/transfers/{transfer_id}/approve",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
)
def approve_version_transfer(
    transfer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Approve a PENDING version transfer request (Supervising Officer only)."""
    try:
        transfer = approve_transfer(
            db=db,
            transfer_id=transfer_id,
            so_user=current_user,
        )
        return _build_transfer_response(transfer, db)
    except TransferError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve transfer request.",
        ) from exc


@router.post(
    "/transfers/{transfer_id}/reject",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
)
def reject_version_transfer(
    transfer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Reject a PENDING version transfer request (Supervising Officer only)."""
    try:
        transfer = reject_transfer(
            db=db,
            transfer_id=transfer_id,
            so_user=current_user,
        )
        return _build_transfer_response(transfer, db)
    except TransferError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reject transfer request.",
        ) from exc


@router.post(
    "/transfers/{transfer_id}/revoke",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
)
def revoke_version_transfer(
    transfer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Revoke an already APPROVED version transfer request (Supervising Officer only)."""
    try:
        transfer = revoke_transfer(
            db=db,
            transfer_id=transfer_id,
            so_user=current_user,
        )
        return _build_transfer_response(transfer, db)
    except TransferError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke transfer request.",
        ) from exc


@router.get(
    "/transfers/{transfer_id}",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
)
def get_transfer_details(
    transfer_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Get transfer details with IDOR non-disclosure protection."""
    if not current_user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user account")

    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if transfer is None:
        raise HTTPException(status_code=404, detail="Transfer not found")

    version = db.query(DocumentVersion).filter(DocumentVersion.id == transfer.document_version_id).first()
    if version is None:
        raise HTTPException(status_code=404, detail="Transfer not found")

    document = db.query(Document).filter(Document.id == version.document_id).first()
    if document is None:
        raise HTTPException(status_code=404, detail="Transfer not found")

    # Requester, recipient, or user assigned to case can view transfer details
    is_requester = current_user.id == transfer.requester_user_id
    is_recipient = current_user.id == transfer.recipient_user_id
    is_assigned = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == document.case_id,
            CaseAssignment.user_id == current_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .first()
        is not None
    )

    if not (is_requester or is_recipient or is_assigned):
        raise HTTPException(status_code=404, detail="Transfer not found")

    return _build_transfer_response(transfer, db)
