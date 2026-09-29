"""Docspector Technical Integrity Report Service (Phase 3 / Milestone 28).

Inspect. Verify. Trust.

Provides authoritative read-only aggregation of case evidence records:
- Real database document & version counts by state.
- Real transfer request status breakdown.
- Real integrity alert counts.
- Real hash-chained custody ledger event metrics and chain audit.
- Real document breakdown with latest immutable version information.

Security & Integrity Guarantees:
1. Strict server-side authorization via case assignment (404 non-disclosure on unauthorized access).
2. All metrics are aggregated directly from authoritative database records for the requested case_id.
3. No cross-case leakage; zero hardcoded/mock data.
4. Read-only operation: GET request never mutates records, states, or hashes.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.authorization import verify_case_assignment
from app.db.models.custody_event import CustodyEvent
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.integrity_alert import IntegrityAlert
from app.db.models.transfer import Transfer
from app.db.models.user import User
from app.schemas.custody import ChainIntegritySummary
from app.schemas.report import (
    CaseReportInfo,
    CaseReportResponse,
    CustodySummary,
    DocumentBreakdownItem,
    DocumentStateCounts,
    DocumentSummary,
    IntegritySummary,
    TransferSummary,
)
from app.services.custody_service import validate_custody_chain

REPORT_DISCLAIMER_SCOPE = (
    "This report summarizes application-level technical integrity and custody verification "
    "records for the specified case. It does not establish legal authenticity, truthfulness, "
    "uploader intent, or judicial admissibility."
)


def generate_case_report(
    db: Session,
    case_id: int,
    current_user: User,
) -> CaseReportResponse:
    """Generate a real technical integrity report for a case assigned to current_user.

    Enforces active case assignment authorization with 404 non-disclosure on unauthorized cases.
    """
    # 1. Verify caller assignment to case
    case = verify_case_assignment(db, current_user, case_id)

    # 2. Fetch documents for this case
    documents = (
        db.query(Document)
        .filter(Document.case_id == case.id)
        .order_by(Document.id.asc())
        .all()
    )
    doc_ids = [d.id for d in documents]

    # 3. Fetch all versions belonging to these documents
    versions: list[DocumentVersion] = []
    if doc_ids:
        versions = (
            db.query(DocumentVersion)
            .filter(DocumentVersion.document_id.in_(doc_ids))
            .all()
        )
    version_ids = [v.id for v in versions]

    # 4. Calculate version state breakdown
    state_counts = DocumentStateCounts(
        STORED=sum(1 for v in versions if v.state == "STORED"),
        RESTRICTED=sum(1 for v in versions if v.state == "RESTRICTED"),
        QUARANTINED=sum(1 for v in versions if v.state == "QUARANTINED"),
        UPLOADING=sum(1 for v in versions if v.state == "UPLOADING"),
    )

    doc_summary = DocumentSummary(
        total_documents=len(documents),
        total_versions=len(versions),
        by_state=state_counts,
    )

    # 5. Fetch and aggregate transfers for these version IDs
    transfers: list[Transfer] = []
    if version_ids:
        transfers = (
            db.query(Transfer)
            .filter(Transfer.document_version_id.in_(version_ids))
            .all()
        )

    transfer_summary = TransferSummary(
        total=len(transfers),
        PENDING=sum(1 for t in transfers if t.status == "PENDING"),
        APPROVED=sum(1 for t in transfers if t.status == "APPROVED"),
        REJECTED=sum(1 for t in transfers if t.status == "REJECTED"),
        REVOKED=sum(1 for t in transfers if t.status == "REVOKED"),
    )

    # 6. Fetch and aggregate integrity alerts for the case
    alerts = (
        db.query(IntegrityAlert)
        .filter(IntegrityAlert.case_id == case.id)
        .all()
    )

    open_alerts_count = sum(1 for a in alerts if a.status == "OPEN")
    resolved_alerts_count = sum(1 for a in alerts if a.status in ("RESOLVED", "REVIEWED"))
    restricted_versions_count = state_counts.RESTRICTED

    chain_res = validate_custody_chain(db=db, case_id=case.id)
    chain_summary = ChainIntegritySummary(
        is_valid=chain_res.is_valid,
        status=chain_res.status_code,
        total_events=chain_res.total_events,
        broken_sequence_number=chain_res.broken_sequence_number,
        error_message=chain_res.error_message,
    )

    integrity_summary = IntegritySummary(
        total_alerts=len(alerts),
        open_alerts=open_alerts_count,
        resolved_alerts=resolved_alerts_count,
        restricted_versions=restricted_versions_count,
        custody_chain=chain_summary,
    )

    # 7. Fetch and aggregate custody events
    custody_events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case.id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )

    custody_summary = CustodySummary(
        total_events=len(custody_events),
        first_event_at=custody_events[0].event_time if custody_events else None,
        latest_event_at=custody_events[-1].event_time if custody_events else None,
    )

    # 8. Build document breakdown items
    breakdown_items: list[DocumentBreakdownItem] = []
    for doc in documents:
        doc_versions = [v for v in versions if v.document_id == doc.id]
        v_count = len(doc_versions)
        if doc_versions:
            latest_v = max(doc_versions, key=lambda v: v.version_number)
            latest_v_num = latest_v.version_number
            latest_st = latest_v.state
            latest_hash = latest_v.sha256_hash
        else:
            latest_v_num = None
            latest_st = "NONE"
            latest_hash = None

        breakdown_items.append(
            DocumentBreakdownItem(
                document_id=doc.id,
                document_number=doc.document_number,
                title=doc.title,
                version_count=v_count,
                latest_version_number=latest_v_num,
                latest_state=latest_st,
                latest_sha256=latest_hash,
                created_at=doc.created_at,
            )
        )

    case_info = CaseReportInfo.model_validate(case)

    return CaseReportResponse(
        case=case_info,
        generated_at=datetime.now(timezone.utc),
        report_scope=REPORT_DISCLAIMER_SCOPE,
        documents=doc_summary,
        integrity=integrity_summary,
        transfers=transfer_summary,
        custody=custody_summary,
        document_breakdown=breakdown_items,
    )
