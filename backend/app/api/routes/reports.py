from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.report import CaseReportResponse
from app.services.report_service import generate_case_report

settings = get_settings()

router = APIRouter(tags=["reports"])


@router.get(
    f"{settings.api_v1_prefix}/cases/{{case_id}}/report",
    response_model=CaseReportResponse,
)
def get_case_technical_report(
    case_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CaseReportResponse:
    """Retrieve authoritative technical integrity report for a case.

    Authorization & Non-Disclosure:
    - Requires authenticated user actively assigned to the requested case.
    - Fails closed with 404 Not Found for unassigned or nonexistent cases.
    """
    return generate_case_report(
        db=db,
        case_id=case_id,
        current_user=current_user,
    )
