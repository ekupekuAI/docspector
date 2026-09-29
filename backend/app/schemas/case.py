from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CaseResponse(BaseModel):
    """Pydantic response schema for case metadata.

    Exposes only safe, public case fields without revealing internal
    SQLAlchemy state, secrets, or storage paths.
    """

    id: int
    case_number: str
    title: str
    description: str | None = None
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
