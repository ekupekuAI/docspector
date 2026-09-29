from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FileIntegrityDetail(BaseModel):
    """Details for file byte integrity verification."""

    is_valid: bool
    status: str
    stored_hash: str
    computed_hash: str | None = None
    expected_size_bytes: int
    actual_size_bytes: int | None = None
    error_message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ChainIntegrityDetail(BaseModel):
    """Details for custody chain hash verification."""

    is_valid: bool
    status: str
    total_events: int
    broken_sequence_number: int | None = None
    error_message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class IntegrityAlertSummary(BaseModel):
    """Summary of an integrity alert created or existing for this failure."""

    id: int
    alert_type: str
    severity: str
    status: str
    message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VerificationResponse(BaseModel):
    """Structured response for document version and custody chain verification."""

    document_id: int
    document_version_id: int
    version_number: int
    case_id: int
    overall_status: str
    version_state: str
    file_integrity: FileIntegrityDetail
    chain_integrity: ChainIntegrityDetail
    alerts: list[IntegrityAlertSummary] = []

    model_config = ConfigDict(from_attributes=True)
