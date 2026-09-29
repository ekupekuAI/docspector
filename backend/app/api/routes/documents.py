from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.authorization import ROLE_IO, ROLE_SO, check_user_role, require_case_assignment
from app.core.config import get_settings
from app.db.models.case import Case
from app.db.models.case_assignment import CaseAssignment
from app.db.models.document import Document
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.document import (
    DocumentRegistrationResponse,
    DocumentResponse,
    DocumentVersionResponse,
)
from app.schemas.verification import VerificationResponse
from app.services.document_registration import (
    register_document_version_one,
    register_successor_version,
)
from app.services.file_validation import FileValidationError
from app.services.verification_service import (
    VerificationError,
    verify_document_version_integrity,
)

settings = get_settings()

router = APIRouter(prefix=settings.api_v1_prefix, tags=["documents"])


@router.post(
    "/cases/{case_id}/documents",
    response_model=DocumentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def upload_and_register_document(
    case_id: int,
    file: UploadFile = File(...),
    title: str | None = Form(default=None),
    case: Case = Depends(require_case_assignment),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentRegistrationResponse:
    """Upload and register a new logical document with initial version (V1).

    Enforces server-side security:
    - Role authorization (only IO and SO may register documents; 403 for unauthorized roles).
    - User authentication and active case-assignment authorization (HTTP 404 for unassigned/nonexistent).
    - Multi-layer input validation (size, extension, MIME, magic bytes, incremental UTF-8).
    - Crash-safe compensating protocol with SHA-256 on-disk verification.
    - Transitions version from UPLOADING to STORED only after full disk verification.
    - Initial DOCUMENT_INGESTED custody event recorded.
    """
    check_user_role(current_user, (ROLE_IO, ROLE_SO))

    try:
        document, doc_version, _ = register_document_version_one(
            db=db,
            case=case,
            current_user=current_user,
            file_stream=file.file,
            filename=file.filename or "",
            content_type=file.content_type,
            title=title,
        )

        version_resp = DocumentVersionResponse.model_validate(doc_version)
        doc_resp = DocumentResponse(
            id=document.id,
            case_id=document.case_id,
            document_number=document.document_number,
            title=document.title,
            created_by_user_id=document.created_by_user_id,
            created_at=document.created_at,
            current_version=version_resp,
        )

        return DocumentRegistrationResponse(
            document=doc_resp,
            version=version_resp,
        )

    except FileValidationError as exc:
        raise HTTPException(
            status_code=exc.http_status_code,
            detail=exc.message,
        ) from exc
    except Exception as exc:
        # Prevent leaking filesystem or database internal details
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register document version.",
        ) from exc


@router.post(
    "/documents/{document_id}/versions",
    response_model=DocumentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def upload_successor_version(
    document_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentRegistrationResponse:
    """Upload and register an immutable successor version (V2, V3, ...) for an existing document.

    Enforces:
    - Role authorization (only IO and SO may create successor versions; 403 for unauthorized roles).
    - Server-derived version numbering (client has zero control).
    - Authorization check ensuring caller has active assignment to document's case (404 on unassigned).
    - Bounded retry for concurrency collisions on unique (document_id, version_number).
    - Immutability of all previous versions and physical files.
    - Crash-safe compensating protocol with on-disk SHA-256 verification.
    """
    check_user_role(current_user, (ROLE_IO, ROLE_SO))

    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # Server-side case assignment check with IDOR non-disclosure
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    try:
        document, doc_version, _ = register_successor_version(
            db=db,
            document=document,
            current_user=current_user,
            file_stream=file.file,
            filename=file.filename or "",
            content_type=file.content_type,
        )

        version_resp = DocumentVersionResponse.model_validate(doc_version)
        doc_resp = DocumentResponse(
            id=document.id,
            case_id=document.case_id,
            document_number=document.document_number,
            title=document.title,
            created_by_user_id=document.created_by_user_id,
            created_at=document.created_at,
            current_version=version_resp,
        )

        return DocumentRegistrationResponse(
            document=doc_resp,
            version=version_resp,
        )

    except FileValidationError as exc:
        raise HTTPException(
            status_code=exc.http_status_code,
            detail=exc.message,
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register successor document version.",
        ) from exc


@router.post(
    "/documents/{document_id}/versions/{version_id}/verify",
    response_model=VerificationResponse,
    status_code=status.HTTP_200_OK,
)
def verify_version_endpoint(
    document_id: int,
    version_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VerificationResponse:
    """Verify independent file byte integrity and custody chain integrity for a document version."""
    try:
        return verify_document_version_integrity(
            db=db,
            document_id=document_id,
            version_id=version_id,
            current_user=current_user,
        )
    except VerificationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify document version integrity.",
        ) from exc

