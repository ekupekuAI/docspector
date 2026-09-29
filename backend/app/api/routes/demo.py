from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.demo import DemoTamperResponse
from app.services.demo_tamper_service import simulate_document_version_tampering

settings = get_settings()

router = APIRouter(prefix=settings.api_v1_prefix, tags=["demo"])


@router.post(
    "/demo/documents/{document_id}/versions/{version_id}/tamper",
    response_model=DemoTamperResponse,
    status_code=status.HTTP_200_OK,
)
def demo_tamper_version_endpoint(
    document_id: int,
    version_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DemoTamperResponse:
    """Perform synthetic storage tampering for hackathon demonstration.

    Requires:
    - DEMO_MODE=True
    - Authenticated active case officer (IO or SO assigned to the case)
    - Valid document and exact version
    """
    return simulate_document_version_tampering(
        db=db,
        document_id=document_id,
        version_id=version_id,
        current_user=current_user,
    )
