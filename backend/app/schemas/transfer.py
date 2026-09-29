from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TransferCreateRequest(BaseModel):
    """Request payload to initiate a document version transfer."""

    recipient_user_id: int

    model_config = ConfigDict(extra="forbid")


class TransferResponse(BaseModel):
    """Response payload for a document version transfer."""

    id: int
    document_version_id: int
    document_id: int
    case_id: int
    requester_user_id: int
    recipient_user_id: int
    status: str
    requested_at: datetime
    decided_at: datetime | None = None
    decided_by_user_id: int | None = None
    revoked_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
