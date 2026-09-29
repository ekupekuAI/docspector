from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.custody import CaseAuditResponse, DocumentCustodyResponse
from app.services.custody_service import get_case_audit, get_document_custody

settings = get_settings()

router = APIRouter(tags=["custody"])


@router.get(
    f"{settings.api_v1_prefix}/documents/{{document_id}}/custody",
    response_model=DocumentCustodyResponse,
)
def get_document_custody_history(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentCustodyResponse:
    """Retrieve complete chronological custody history and chain verification for a document.

    Authorization & Non-Disclosure:
    - Requires authenticated user actively assigned to the document's case.
    - Fails closed with 404 Not Found for unassigned or nonexistent documents.
    """
    return get_document_custody(
        db=db,
        document_id=document_id,
        current_user=current_user,
    )


@router.get(
    f"{settings.api_v1_prefix}/cases/{{case_id}}/audit",
    response_model=CaseAuditResponse,
)
def get_case_audit_history(
    case_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CaseAuditResponse:
    """Retrieve complete chronological audit events and chain verification for a case.

    Authorization & Non-Disclosure:
    - Requires authenticated user actively assigned to the case.
    - Fails closed with 404 Not Found for unassigned or nonexistent cases.
    """
    return get_case_audit(
        db=db,
        case_id=case_id,
        current_user=current_user,
    )
