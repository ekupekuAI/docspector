from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.alert import AlertResolveRequest, AlertResponse
from app.services.alert_service import get_alerts_for_case, resolve_alert

settings = get_settings()

router = APIRouter(tags=["alerts"])


@router.get(f"{settings.api_v1_prefix}/cases/{{case_id}}/alerts", response_model=list[AlertResponse])
def list_case_alerts(
    case_id: int,
    status_filter: str | None = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AlertResponse]:
    """Retrieve integrity alerts for a specific case.

    Authorization & Non-Disclosure:
    - Requires authenticated user actively assigned to the requested case.
    - Fails closed with 404 Not Found for unassigned or nonexistent cases.
    """
    alerts = get_alerts_for_case(
        db=db,
        case_id=case_id,
        current_user=current_user,
        status_filter=status_filter,
    )
    return [AlertResponse.model_validate(a) for a in alerts]


@router.post(f"{settings.api_v1_prefix}/alerts/{{alert_id}}/resolve", response_model=AlertResponse)
def resolve_case_alert(
    alert_id: int,
    body: AlertResolveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Resolve an open integrity alert after mandatory re-verification.

    Security & Authorization:
    - Requires authenticated user actively assigned to the alert's case.
    - Requires non-empty resolution_note.
    - Re-runs authoritative verification on the document version and custody chain.
    - Rejects resolution with 400 Bad Request if verification fails.
    """
    alert = resolve_alert(
        db=db,
        alert_id=alert_id,
        current_user=current_user,
        resolution_note=body.resolution_note,
    )
    return AlertResponse.model_validate(alert)
