from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.authorization import require_case_assignment
from app.core.config import get_settings
from app.db.models.case import Case
from app.db.models.case_assignment import CaseAssignment
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.case import CaseResponse

settings = get_settings()

router = APIRouter(prefix=f"{settings.api_v1_prefix}/cases", tags=["cases"])


@router.get("", response_model=list[CaseResponse])
def list_cases(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CaseResponse]:
    """List all cases that the authenticated user is actively assigned to.

    Server-side authorization and non-disclosure:
    - Filters strictly by active case assignments associated with the authenticated user ID.
    - Prevents IDOR and unauthorized case enumeration across the platform.
    """
    cases = (
        db.query(Case)
        .join(CaseAssignment, Case.id == CaseAssignment.case_id)
        .filter(
            CaseAssignment.user_id == current_user.id,
            CaseAssignment.is_active.is_(True),
        )
        .order_by(Case.id.asc())
        .all()
    )
    return [CaseResponse.model_validate(c) for c in cases]


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case: Case = Depends(require_case_assignment),
) -> CaseResponse:
    """Retrieve details for a specific case.

    Server-side authorization and non-disclosure:
    - Verifies that the case exists and the authenticated user has an active assignment.
    - Enforces IDOR protection and returns HTTP 404 for unassigned or nonexistent cases
      to prevent unauthorized case existence disclosure.
    """
    return CaseResponse.model_validate(case)
