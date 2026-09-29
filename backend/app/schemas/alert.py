from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertResolveRequest(BaseModel):
    """Payload for resolving an integrity alert."""

    resolution_note: str = Field(
        ...,
        min_length=1,
        description="Mandatory justification note explaining the resolution/review.",
    )


class AlertResponse(BaseModel):
    """Schema representing an integrity alert response."""

    id: int
    case_id: int
    document_version_id: int | None = None
    alert_type: str
    severity: str
    message: str
    status: str
    created_at: datetime
    reviewed_at: datetime | None = None
    reviewed_by_user_id: int | None = None

    model_config = ConfigDict(from_attributes=True)
