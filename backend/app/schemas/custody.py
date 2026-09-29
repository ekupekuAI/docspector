import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class ChainIntegritySummary(BaseModel):
    """Summary of custody chain integrity audit."""

    is_valid: bool
    status: str
    total_events: int
    broken_sequence_number: int | None = None
    error_message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class CustodyEventItem(BaseModel):
    """Schema representing an individual custody event entry."""

    id: int
    case_id: int
    sequence_number: int
    event_type: str
    actor_user_id: int
    event_time: datetime
    document_version_id: int | None = None
    previous_event_hash: str | None = None
    event_hash: str
    event_data: Any | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("event_data", mode="before")
    @classmethod
    def parse_event_data(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, dict):
                    parsed.pop("storage_key", None)
                    parsed.pop("file_path", None)
                    parsed.pop("private_storage_path", None)
                return parsed
            except Exception:
                return v
        if isinstance(v, dict):
            clean_dict = dict(v)
            clean_dict.pop("storage_key", None)
            clean_dict.pop("file_path", None)
            clean_dict.pop("private_storage_path", None)
            return clean_dict
        return v


class DocumentCustodyResponse(BaseModel):
    """Response payload for document custody history."""

    document_id: int
    case_id: int
    document_number: str
    events: list[CustodyEventItem]
    chain_integrity: ChainIntegritySummary

    model_config = ConfigDict(from_attributes=True)


class CaseAuditResponse(BaseModel):
    """Response payload for case audit history across all accessible custody events."""

    case_id: int
    case_number: str
    events: list[CustodyEventItem]
    chain_integrity: ChainIntegritySummary

    model_config = ConfigDict(from_attributes=True)
