from datetime import datetime

from pydantic import BaseModel, ConfigDict
from app.schemas.custody import ChainIntegritySummary


class CaseReportInfo(BaseModel):
    """Basic case metadata included in technical integrity report."""

    id: int
    case_number: str
    title: str
    description: str | None = None
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DocumentStateCounts(BaseModel):
    """Breakdown of document version states."""

    STORED: int = 0
    RESTRICTED: int = 0
    QUARANTINED: int = 0
    UPLOADING: int = 0


class DocumentSummary(BaseModel):
    """Aggregate document & version metrics."""

    total_documents: int = 0
    total_versions: int = 0
    by_state: DocumentStateCounts


class IntegritySummary(BaseModel):
    """Aggregate integrity and security alert metrics."""

    total_alerts: int = 0
    open_alerts: int = 0
    resolved_alerts: int = 0
    restricted_versions: int = 0
    custody_chain: ChainIntegritySummary


class TransferSummary(BaseModel):
    """Aggregate transfer state metrics."""

    total: int = 0
    PENDING: int = 0
    APPROVED: int = 0
    REJECTED: int = 0
    REVOKED: int = 0


class CustodySummary(BaseModel):
    """Aggregate custody ledger metrics."""

    total_events: int = 0
    first_event_at: datetime | None = None
    latest_event_at: datetime | None = None


class DocumentBreakdownItem(BaseModel):
    """Summary of individual document identity and latest version state."""

    document_id: int
    document_number: str
    title: str
    version_count: int
    latest_version_number: int | None = None
    latest_state: str = "NONE"
    latest_sha256: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseReportResponse(BaseModel):
    """Authoritative technical integrity report response payload for a case."""

    case: CaseReportInfo
    generated_at: datetime
    report_scope: str
    documents: DocumentSummary
    integrity: IntegritySummary
    transfers: TransferSummary
    custody: CustodySummary
    document_breakdown: list[DocumentBreakdownItem]

    model_config = ConfigDict(from_attributes=True)
